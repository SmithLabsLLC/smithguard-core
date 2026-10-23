"""Versioned source authorization, accepted-field projection, and decision evidence."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from smithguard.db.models import (
    SourceGovernanceDecisionRecord,
)
from smithguard.identifiers import (
    ACTOR_ID,
    REGISTER_JSON_MAX_DEPTH,
    REGISTER_JSON_MAX_NODES,
    SHA256,
    STABLE_ID,
    canonical_json_bytes,
    sha256_id,
    stable_id,
    strict_json_loads,
    timestamp,
)
from smithguard.source_rights import RightsRegistry, SourceProfile, SourceRightsError

PACKAGE_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_GOVERNANCE_POLICY_PATH = PACKAGE_ROOT / "contracts" / "v1" / "source-governance-policy.json"

FIELD_PATH = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$")
ADAPTER_ID = ACTOR_ID
PUBLIC_STATUS_RANK = {
    "reported": 0,
    "corroborated": 1,
    "confirmed": 2,
    "contained": 2,
    "resolved": 2,
    "disputed": 0,
    "withdrawn": 0,
}
DURABLE_STORAGE_STATES = frozenset({"immutable"})
PUBLICATION_DECISION_STATES = {"pending_qualified_decision", "active"}
RIGHTS_EVIDENCE_STATES = {
    "verified_snapshot",
    "reference_only_unverified",
    "upstream_dispatch_unresolved",
}
OPERATING_MODES = {
    "historical",
    "updates",
    "exact_lookup",
    "reconciliation",
}
OSV_GATEWAY_SOURCE_ID = "gbsec:source:osv-dev"
OSV_GATEWAY_CONNECTOR_ID = "gbsec:connector:osv-gateway-v1"
OSV_API_ROOT = "https://api.osv.dev/v1/vulns/"


class SourceGovernanceError(ValueError):
    """Source policy, connector identity, or accepted representation is unsafe."""


@dataclass(frozen=True, slots=True)
class RightsEvidence:
    evidence_id: str
    url: str
    captured_on: date
    content_sha256: str | None
    state: str


@dataclass(frozen=True, slots=True)
class ConnectorRule:
    connector_id: str
    acquisition_methods: frozenset[str]
    operating_modes: frozenset[str]


@dataclass(frozen=True, slots=True)
class GovernanceSourceRule:
    source_id: str
    enabled: bool
    connectors: tuple[ConnectorRule, ...]
    field_policy_id: str
    authenticated_upstream_source_ids: tuple[str, ...]
    accepted_field_paths: tuple[str, ...]
    attribution_text: str
    license_expression: str | None
    rights_evidence: tuple[RightsEvidence, ...]
    retention_behavior: str
    public_status_ceiling: str
    correction_behavior: str
    withdrawal_behavior: str
    rights_drift_behavior: str


@dataclass(frozen=True, slots=True)
class SourceAuthorization:
    policy_id: str
    policy_version: str
    policy_sha256: str
    rights_register_id: str
    authorized_disposition_adapter_ids: tuple[str, ...]
    source_id: str
    connector_id: str
    acquisition_method: str
    operating_mode: str
    field_policy_id: str
    accepted_field_paths: tuple[str, ...]
    attribution_text: str
    license_expression: str | None
    rights_evidence_ids: tuple[str, ...]
    rights_evidence_verified: bool
    retention_behavior: str
    public_status_ceiling: str
    correction_behavior: str
    withdrawal_behavior: str
    rights_drift_behavior: str
    qualified_publication_decision_id: str | None
    canonical_url: str
    source_record_id: str
    authorized_at: datetime

    def project_body(self, body: bytes) -> bytes:
        """Return only policy-accepted JSON fields in one canonical representation."""
        if not isinstance(body, bytes):
            raise SourceGovernanceError("source body must be bytes")
        if len(body) > 52_428_800:
            raise SourceGovernanceError("source body exceeds the governance byte limit")
        try:
            value = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SourceGovernanceError("source body is not valid JSON") from error
        tree = _field_tree(self.accepted_field_paths)
        if isinstance(value, list):
            if len(value) > 5000:
                raise SourceGovernanceError("source body exceeds the record limit")
            projected = [_project_mapping(item, tree) for item in value]
        elif isinstance(value, Mapping) and "records" in value and "records" not in tree:
            records = value["records"]
            if not isinstance(records, list) or len(records) > 5000:
                raise SourceGovernanceError("source body has an invalid records envelope")
            projected = {"records": [_project_mapping(item, tree) for item in records]}
        elif isinstance(value, Mapping):
            projected = _project_mapping(value, tree)
        else:
            raise SourceGovernanceError("source body has an unsupported JSON root")
        return canonical_json_bytes(projected)

    def validate_request(
        self,
        *,
        source_id: str,
        source_record_id: str,
        canonical_url: str,
        acquisition_method: str,
    ) -> None:
        if (
            source_id != self.source_id
            or source_record_id != self.source_record_id
            or canonical_url != self.canonical_url
            or acquisition_method != self.acquisition_method
        ):
            raise SourceGovernanceError("ingestion request does not match its source authorization")


@dataclass(frozen=True, slots=True)
class GatewaySourceAuthorization:
    """One private shadow authorization joining transport and home-source rights."""

    policy_id: str
    policy_version: str
    policy_sha256: str
    rights_register_id: str
    transport_source_id: str
    transport_connector_id: str
    transport_rights_revision: int
    transport_canonical_url: str
    transport_rights_evidence_ids: tuple[str, ...]
    origin_source_id: str
    origin_rights_revision: int
    origin_canonical_url: str
    origin_rights_evidence_ids: tuple[str, ...]
    origin_attribution_text: str
    origin_license_expression: str
    source_record_id: str
    field_policy_id: str
    accepted_field_paths: tuple[str, ...]
    storage_scope: str
    public_output_authorized: bool
    authorized_at: datetime


@dataclass(frozen=True, slots=True)
class GatewayShadowFieldPolicy:
    """One reviewed minimized projection for a disabled gateway transport."""

    field_policy_id: str
    transport_source_id: str
    origin_source_ids: tuple[str, ...]
    accepted_field_paths: tuple[str, ...]
    storage_scope: str
    public_output_authorized: bool


def _field_tree(paths: tuple[str, ...]) -> dict[str, Any]:
    root: dict[str, Any] = {}
    for path in paths:
        cursor = root
        parts = path.split(".")
        for index, part in enumerate(parts):
            if index == len(parts) - 1:
                cursor[part] = True
                continue
            current = cursor.get(part)
            if current is True:
                break
            if current is None:
                current = {}
                cursor[part] = current
            cursor = current
    return root


def _project_value(value: Any, rule: Any) -> Any:
    if rule is True:
        return value
    if isinstance(value, list):
        return [_project_value(item, rule) for item in value]
    if isinstance(value, Mapping):
        return _project_mapping(value, rule)
    return None


def _project_mapping(value: Any, tree: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise SourceGovernanceError("source record is not an object")
    projected: dict[str, Any] = {}
    for key in sorted(tree):
        if key not in value:
            continue
        rule = tree[key]
        if rule is True:
            projected[key] = value[key]
            continue
        selected = _project_value(value[key], rule)
        if selected is not None:
            projected[key] = selected
    if not projected:
        raise SourceGovernanceError("source record has no policy-accepted fields")
    return projected


def _bounded_ascii(value: Any, *, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or not value.isascii():
        raise SourceGovernanceError(f"{label} is invalid")
    return value


def _stable_id(value: Any, *, label: str) -> str:
    parsed = _bounded_ascii(value, label=label, maximum=160)
    if not STABLE_ID.fullmatch(parsed):
        raise SourceGovernanceError(f"{label} is invalid")
    return parsed


def _https_url(value: Any, *, label: str) -> str:
    parsed_value = _bounded_ascii(value, label=label, maximum=2000)
    parsed = urlsplit(parsed_value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in {None, 443}
        or parsed.fragment
    ):
        raise SourceGovernanceError(f"{label} is invalid")
    return parsed_value


def _exact_keys(value: Mapping[str, Any], expected: set[str], *, label: str) -> None:
    if set(value) != expected:
        raise SourceGovernanceError(f"{label} has an invalid shape")


class SourceGovernancePolicy:
    """Closed policy joining connector, source, rights, fields, and publication."""

    def __init__(self, document: Mapping[str, Any], *, registry: RightsRegistry) -> None:
        _exact_keys(
            document,
            {
                "schema_version",
                "policy_id",
                "policy_version",
                "rights_register_id",
                "publication_decision",
                "evidence_disposition",
                "gateway_shadow_field_policies",
                "rights_evidence_history",
                "sources",
            },
            label="source governance policy",
        )
        if document["schema_version"] != "1.0.0":
            raise SourceGovernanceError("source governance schema is unsupported")
        self.policy_id = _stable_id(document["policy_id"], label="policy ID")
        self.policy_version = _bounded_ascii(
            document["policy_version"],
            label="policy version",
            maximum=100,
        )
        self.rights_register_id = _stable_id(
            document["rights_register_id"],
            label="rights register ID",
        )
        if self.rights_register_id != registry.register_id:
            raise SourceGovernanceError("governance policy and rights register differ")
        self.policy_sha256 = sha256_id(canonical_json_bytes(document))
        decision = document["publication_decision"]
        if not isinstance(decision, Mapping):
            raise SourceGovernanceError("publication decision is invalid")
        _exact_keys(
            decision,
            {"state", "decision_id", "decided_at", "source_ids"},
            label="publication decision",
        )
        state = decision["state"]
        if state not in PUBLICATION_DECISION_STATES:
            raise SourceGovernanceError("publication decision state is invalid")
        source_ids = decision["source_ids"]
        if (
            not isinstance(source_ids, list)
            or len(source_ids) > 50
            or not all(isinstance(value, str) for value in source_ids)
        ):
            raise SourceGovernanceError("publication decision source scope is invalid")
        if state == "active":
            self.publication_decision_id = _stable_id(
                decision["decision_id"],
                label="publication decision ID",
            )
            try:
                self.publication_decided_at = datetime.fromisoformat(
                    str(decision["decided_at"]).replace("Z", "+00:00")
                )
            except ValueError as error:
                raise SourceGovernanceError("publication decision time is invalid") from error
            if (
                self.publication_decided_at.tzinfo is None
                or self.publication_decided_at.utcoffset() is None
            ):
                raise SourceGovernanceError("publication decision time must include a timezone")
            self.publication_source_ids = frozenset(
                _stable_id(value, label="publication source ID") for value in source_ids
            )
            if not self.publication_source_ids:
                raise SourceGovernanceError("active publication decision has no source scope")
        else:
            if (
                decision["decision_id"] is not None
                or decision["decided_at"] is not None
                or source_ids
            ):
                raise SourceGovernanceError("pending publication decision contains approval data")
            self.publication_decision_id = None
            self.publication_decided_at = None
            self.publication_source_ids = frozenset()

        disposition = document["evidence_disposition"]
        if not isinstance(disposition, Mapping):
            raise SourceGovernanceError("evidence disposition policy is invalid")
        _exact_keys(
            disposition,
            {"authorized_adapter_ids"},
            label="evidence disposition policy",
        )
        adapter_ids = disposition["authorized_adapter_ids"]
        if (
            not isinstance(adapter_ids, list)
            or len(adapter_ids) > 20
            or len(set(adapter_ids)) != len(adapter_ids)
            or not all(
                isinstance(value, str) and ADAPTER_ID.fullmatch(value) for value in adapter_ids
            )
        ):
            raise SourceGovernanceError("evidence disposition adapter IDs are invalid")
        self.authorized_disposition_adapter_ids = frozenset(adapter_ids)

        raw_shadow_policies = document["gateway_shadow_field_policies"]
        if (
            not isinstance(raw_shadow_policies, list)
            or not raw_shadow_policies
            or len(raw_shadow_policies) > 20
        ):
            raise SourceGovernanceError("gateway shadow field policies are invalid")
        shadow_policies: dict[str, GatewayShadowFieldPolicy] = {}
        for item in raw_shadow_policies:
            if not isinstance(item, Mapping):
                raise SourceGovernanceError("gateway shadow field policy is invalid")
            _exact_keys(
                item,
                {
                    "field_policy_id",
                    "transport_source_id",
                    "origin_source_ids",
                    "accepted_field_paths",
                    "storage_scope",
                    "public_output_authorized",
                },
                label="gateway shadow field policy",
            )
            transport_source_id = _stable_id(
                item["transport_source_id"],
                label="gateway shadow transport source ID",
            )
            if transport_source_id in shadow_policies:
                raise SourceGovernanceError("gateway shadow transport policy is duplicated")
            raw_origins = item["origin_source_ids"]
            raw_paths = item["accepted_field_paths"]
            if (
                not isinstance(raw_origins, list)
                or not raw_origins
                or len(raw_origins) > 20
                or len(set(raw_origins)) != len(raw_origins)
                or not isinstance(raw_paths, list)
                or not raw_paths
                or len(raw_paths) > 200
                or len(set(raw_paths)) != len(raw_paths)
                or not all(
                    isinstance(path, str) and FIELD_PATH.fullmatch(path) for path in raw_paths
                )
                or item["storage_scope"] != "isolated_shadow"
                or item["public_output_authorized"] is not False
            ):
                raise SourceGovernanceError("gateway shadow field policy boundary is invalid")
            origin_source_ids = tuple(
                _stable_id(value, label="gateway shadow origin source ID") for value in raw_origins
            )
            for source_id in (transport_source_id, *origin_source_ids):
                try:
                    registry.get(source_id)
                except SourceRightsError as error:
                    raise SourceGovernanceError(
                        "gateway shadow field policy source is absent from rights"
                    ) from error
            shadow_policies[transport_source_id] = GatewayShadowFieldPolicy(
                field_policy_id=_stable_id(
                    item["field_policy_id"],
                    label="gateway shadow field policy ID",
                ),
                transport_source_id=transport_source_id,
                origin_source_ids=origin_source_ids,
                accepted_field_paths=tuple(raw_paths),
                storage_scope="isolated_shadow",
                public_output_authorized=False,
            )
        self._gateway_shadow_field_policies = shadow_policies

        raw_sources = document["sources"]
        if not isinstance(raw_sources, list) or not raw_sources:
            raise SourceGovernanceError("source governance policy has no sources")
        sources: dict[str, GovernanceSourceRule] = {}
        connectors: dict[str, str] = {}
        for raw_source in raw_sources:
            if not isinstance(raw_source, Mapping):
                raise SourceGovernanceError("source governance rule is invalid")
            rule = self._parse_source(raw_source, registry=registry)
            if rule.source_id in sources:
                raise SourceGovernanceError("source governance rule is duplicated")
            sources[rule.source_id] = rule
            for connector in rule.connectors:
                if connector.connector_id in connectors:
                    raise SourceGovernanceError("connector identity is duplicated")
                connectors[connector.connector_id] = rule.source_id
        if not self.publication_source_ids.issubset(sources):
            raise SourceGovernanceError("publication decision names an unknown source")
        if not set(shadow_policies).issubset(sources):
            raise SourceGovernanceError("gateway shadow field policy has no governance source")

        raw_evidence_history = document["rights_evidence_history"]
        if not isinstance(raw_evidence_history, list) or len(raw_evidence_history) > 100:
            raise SourceGovernanceError("rights evidence history is invalid")
        active_evidence_ids = {
            evidence.evidence_id
            for source_rule in sources.values()
            for evidence in source_rule.rights_evidence
        }
        history_ids: set[str] = set()
        for item in raw_evidence_history:
            if not isinstance(item, Mapping):
                raise SourceGovernanceError("rights evidence history entry is invalid")
            _exact_keys(
                item,
                {
                    "evidence_id",
                    "url",
                    "captured_on",
                    "content_sha256",
                    "state",
                    "superseded_by",
                },
                label="rights evidence history entry",
            )
            evidence_id = _stable_id(item["evidence_id"], label="historical evidence ID")
            superseded_by = _stable_id(
                item["superseded_by"],
                label="superseding evidence ID",
            )
            if (
                evidence_id in history_ids
                or evidence_id in active_evidence_ids
                or superseded_by not in active_evidence_ids
                or evidence_id == superseded_by
            ):
                raise SourceGovernanceError("rights evidence history identity is invalid")
            _https_url(item["url"], label="historical rights evidence URL")
            try:
                date.fromisoformat(str(item["captured_on"]))
            except ValueError as error:
                raise SourceGovernanceError("historical rights evidence date is invalid") from error
            if item["state"] not in RIGHTS_EVIDENCE_STATES:
                raise SourceGovernanceError("historical rights evidence state is invalid")
            digest = item["content_sha256"]
            if digest is not None and (
                not isinstance(digest, str) or SHA256.fullmatch(digest) is None
            ):
                raise SourceGovernanceError("historical rights evidence digest is invalid")
            history_ids.add(evidence_id)
        self._sources = sources
        self._connector_sources = connectors
        self._registry = registry

    @classmethod
    def from_path(
        cls,
        path: Path,
        *,
        registry: RightsRegistry,
    ) -> SourceGovernancePolicy:
        try:
            document = strict_json_loads(
                path.read_text(encoding="utf-8"),
                max_nodes=REGISTER_JSON_MAX_NODES,
                max_depth=REGISTER_JSON_MAX_DEPTH,
            )
        except (OSError, UnicodeDecodeError, ValueError) as error:
            raise SourceGovernanceError("source governance policy cannot be read") from error
        return cls(document, registry=registry)

    def _parse_source(
        self,
        value: Mapping[str, Any],
        *,
        registry: RightsRegistry,
    ) -> GovernanceSourceRule:
        _exact_keys(
            value,
            {
                "source_id",
                "enabled",
                "connectors",
                "field_policy_id",
                "authenticated_upstream_source_ids",
                "accepted_field_paths",
                "attribution_text",
                "license_expression",
                "rights_evidence",
                "retention_behavior",
                "public_status_ceiling",
                "correction_behavior",
                "withdrawal_behavior",
                "rights_drift_behavior",
            },
            label="source governance rule",
        )
        source_id = _stable_id(value["source_id"], label="source ID")
        try:
            profile = registry.get(source_id)
        except SourceRightsError as error:
            raise SourceGovernanceError("governance source is absent from rights") from error
        enabled = value["enabled"]
        if not isinstance(enabled, bool):
            raise SourceGovernanceError("source enabled state is invalid")
        raw_connectors = value["connectors"]
        if not isinstance(raw_connectors, list) or not raw_connectors:
            raise SourceGovernanceError("source connector rules are invalid")
        connectors: list[ConnectorRule] = []
        for raw_connector in raw_connectors:
            if not isinstance(raw_connector, Mapping):
                raise SourceGovernanceError("source connector rule is invalid")
            _exact_keys(
                raw_connector,
                {"connector_id", "acquisition_methods", "operating_modes"},
                label="source connector rule",
            )
            methods = raw_connector["acquisition_methods"]
            modes = raw_connector["operating_modes"]
            if (
                not isinstance(methods, list)
                or not methods
                or len(set(methods)) != len(methods)
                or not all(method in profile.source["acquisition_methods"] for method in methods)
            ):
                raise SourceGovernanceError("connector acquisition methods are invalid")
            if (
                not isinstance(modes, list)
                or not modes
                or len(set(modes)) != len(modes)
                or not all(mode in OPERATING_MODES for mode in modes)
            ):
                raise SourceGovernanceError("connector operating modes are invalid")
            connectors.append(
                ConnectorRule(
                    connector_id=_stable_id(
                        raw_connector["connector_id"],
                        label="connector ID",
                    ),
                    acquisition_methods=frozenset(methods),
                    operating_modes=frozenset(modes),
                )
            )
        field_policy_id = _stable_id(value["field_policy_id"], label="field policy ID")
        raw_upstream_ids = value["authenticated_upstream_source_ids"]
        if (
            not isinstance(raw_upstream_ids, list)
            or len(raw_upstream_ids) > 50
            or len(set(raw_upstream_ids)) != len(raw_upstream_ids)
        ):
            raise SourceGovernanceError("authenticated upstream source IDs are invalid")
        upstream_ids = tuple(
            _stable_id(item, label="authenticated upstream source ID") for item in raw_upstream_ids
        )
        for upstream_id in upstream_ids:
            try:
                registry.get(upstream_id)
            except SourceRightsError as error:
                raise SourceGovernanceError(
                    "authenticated upstream source is absent from rights"
                ) from error
        raw_paths = value["accepted_field_paths"]
        has_fields = bool(raw_paths)
        has_upstreams = bool(upstream_ids)
        if (
            not isinstance(raw_paths, list)
            or len(raw_paths) > 200
            or not all(isinstance(path, str) and FIELD_PATH.fullmatch(path) for path in raw_paths)
            or len(set(raw_paths)) != len(raw_paths)
            or (has_fields and has_upstreams)
            or (enabled and not has_fields and not has_upstreams)
        ):
            raise SourceGovernanceError("accepted field paths are invalid")
        registered_paths = {
            path
            for field_rule in profile.field_rules
            if field_rule["storage"] in DURABLE_STORAGE_STATES
            for path in field_rule["fields"]
        }
        if not set(raw_paths).issubset(registered_paths):
            raise SourceGovernanceError("accepted field path is not allowed by source rights")
        attribution = _bounded_ascii(
            value["attribution_text"],
            label="attribution text",
            maximum=500,
        )
        if attribution != profile.source["rights"]["attribution_text"]:
            raise SourceGovernanceError("governance attribution differs from source rights")
        license_expression = value["license_expression"]
        if license_expression is not None:
            license_expression = _bounded_ascii(
                license_expression,
                label="license expression",
                maximum=200,
            )
        if license_expression != profile.source["rights"]["license_expression"]:
            raise SourceGovernanceError("governance license differs from source rights")
        raw_evidence = value["rights_evidence"]
        if not isinstance(raw_evidence, list) or not raw_evidence or len(raw_evidence) > 20:
            raise SourceGovernanceError("rights evidence is invalid")
        rights_evidence: list[RightsEvidence] = []
        evidence_ids: set[str] = set()
        evidence_urls: set[str] = set()
        source_rights = profile.source["rights"]
        terms_url = source_rights["terms_url"]
        allowed_evidence_urls = {
            url for url in (terms_url, profile.source["correction_url"]) if url is not None
        }
        rights_reviewed_on = date.fromisoformat(source_rights["reviewed_on"])
        for item in raw_evidence:
            if not isinstance(item, Mapping):
                raise SourceGovernanceError("rights evidence entry is invalid")
            _exact_keys(
                item,
                {"evidence_id", "url", "captured_on", "content_sha256", "state"},
                label="rights evidence entry",
            )
            evidence_state = item["state"]
            if evidence_state not in RIGHTS_EVIDENCE_STATES:
                raise SourceGovernanceError("rights evidence state is invalid")
            digest = item["content_sha256"]
            if digest is not None and (not isinstance(digest, str) or not SHA256.fullmatch(digest)):
                raise SourceGovernanceError("rights evidence digest is invalid")
            if evidence_state == "verified_snapshot" and digest is None:
                raise SourceGovernanceError("verified rights evidence requires a digest")
            try:
                captured_on = date.fromisoformat(str(item["captured_on"]))
            except ValueError as error:
                raise SourceGovernanceError("rights evidence date is invalid") from error
            if captured_on > rights_reviewed_on:
                raise SourceGovernanceError(
                    "rights evidence was captured after the source-rights review"
                )
            evidence_id = _stable_id(item["evidence_id"], label="rights evidence ID")
            evidence_url = _https_url(item["url"], label="rights evidence URL")
            if evidence_id in evidence_ids or evidence_url in evidence_urls:
                raise SourceGovernanceError("rights evidence is duplicated")
            if evidence_url not in allowed_evidence_urls:
                raise SourceGovernanceError(
                    "rights evidence URL differs from the reviewed source rights"
                )
            evidence_ids.add(evidence_id)
            evidence_urls.add(evidence_url)
            rights_evidence.append(
                RightsEvidence(
                    evidence_id=evidence_id,
                    url=evidence_url,
                    captured_on=captured_on,
                    content_sha256=digest,
                    state=evidence_state,
                )
            )
        if terms_url not in evidence_urls:
            raise SourceGovernanceError("rights evidence omits the reviewed terms URL")
        status_ceiling = value["public_status_ceiling"]
        if status_ceiling not in PUBLIC_STATUS_RANK:
            raise SourceGovernanceError("public status ceiling is invalid")
        retention_behavior = _bounded_ascii(
            value["retention_behavior"],
            label="retention behavior",
            maximum=80,
        )
        if retention_behavior != profile.source["rights"]["retention"]:
            raise SourceGovernanceError("governance retention differs from source rights")
        correction_behavior = _bounded_ascii(
            value["correction_behavior"],
            label="correction behavior",
            maximum=80,
        )
        if (
            correction_behavior != "append_corrected_revision"
            or not profile.source["rights"]["correction_required"]
        ):
            raise SourceGovernanceError("governance correction differs from source rights")
        withdrawal_behavior = _bounded_ascii(
            value["withdrawal_behavior"],
            label="withdrawal behavior",
            maximum=80,
        )
        if withdrawal_behavior != profile.source["withdrawal_behavior"]:
            raise SourceGovernanceError("governance withdrawal differs from source rights")
        rights_drift_behavior = _bounded_ascii(
            value["rights_drift_behavior"],
            label="rights drift behavior",
            maximum=80,
        )
        if rights_drift_behavior != "fail_closed_and_reconcile":
            raise SourceGovernanceError("source rights drift behavior must fail closed")
        return GovernanceSourceRule(
            source_id=source_id,
            enabled=enabled,
            connectors=tuple(connectors),
            field_policy_id=field_policy_id,
            authenticated_upstream_source_ids=upstream_ids,
            accepted_field_paths=tuple(raw_paths),
            attribution_text=attribution,
            license_expression=license_expression,
            rights_evidence=tuple(rights_evidence),
            retention_behavior=retention_behavior,
            public_status_ceiling=status_ceiling,
            correction_behavior=correction_behavior,
            withdrawal_behavior=withdrawal_behavior,
            rights_drift_behavior=rights_drift_behavior,
        )

    def authorize_collection(
        self,
        *,
        connector_id: str,
        source_id: str,
        acquisition_method: str,
        operating_mode: str,
        canonical_url: str,
        source_record_id: str,
        authorized_at: datetime,
    ) -> SourceAuthorization:
        if authorized_at.tzinfo is None or authorized_at.utcoffset() is None:
            raise SourceGovernanceError("authorization time must include a timezone")
        if not source_record_id or len(source_record_id) > 512 or not source_record_id.isascii():
            raise SourceGovernanceError("source record ID is invalid")
        try:
            rule = self._sources[source_id]
        except KeyError as error:
            raise SourceGovernanceError("source is absent from governance policy") from error
        if not rule.enabled:
            raise SourceGovernanceError("source is disabled by governance policy")
        if self._connector_sources.get(connector_id) != source_id:
            raise SourceGovernanceError("connector is not authenticated for this source")
        connector = next(item for item in rule.connectors if item.connector_id == connector_id)
        if acquisition_method not in connector.acquisition_methods:
            raise SourceGovernanceError("acquisition method is not authorized")
        if operating_mode not in connector.operating_modes:
            raise SourceGovernanceError("operating mode is not authorized")
        profile = self._registry.get(source_id)
        if not rule.accepted_field_paths:
            raise SourceGovernanceError("source is an identity-dispatch gateway only")
        try:
            profile.authorize_collection(
                method=acquisition_method,
                canonical_url=canonical_url,
                today=authorized_at.astimezone(UTC).date(),
            )
        except SourceRightsError as error:
            raise SourceGovernanceError(str(error)) from error
        return SourceAuthorization(
            policy_id=self.policy_id,
            policy_version=self.policy_version,
            policy_sha256=self.policy_sha256,
            rights_register_id=self.rights_register_id,
            authorized_disposition_adapter_ids=tuple(
                sorted(self.authorized_disposition_adapter_ids)
            ),
            source_id=source_id,
            connector_id=connector_id,
            acquisition_method=acquisition_method,
            operating_mode=operating_mode,
            field_policy_id=rule.field_policy_id,
            accepted_field_paths=rule.accepted_field_paths,
            attribution_text=rule.attribution_text,
            license_expression=rule.license_expression,
            rights_evidence_ids=tuple(evidence.evidence_id for evidence in rule.rights_evidence),
            rights_evidence_verified=all(
                evidence.state == "verified_snapshot" and evidence.content_sha256 is not None
                for evidence in rule.rights_evidence
            ),
            retention_behavior=rule.retention_behavior,
            public_status_ceiling=rule.public_status_ceiling,
            correction_behavior=rule.correction_behavior,
            withdrawal_behavior=rule.withdrawal_behavior,
            rights_drift_behavior=rule.rights_drift_behavior,
            qualified_publication_decision_id=(
                self.publication_decision_id if source_id in self.publication_source_ids else None
            ),
            canonical_url=canonical_url,
            source_record_id=source_record_id,
            authorized_at=authorized_at.astimezone(UTC),
        )

    def resolve_authenticated_upstream(
        self,
        *,
        gateway_connector_id: str,
        upstream_source_id: str,
        authorized_at: datetime,
    ) -> SourceProfile:
        """Dispatch aggregate records only through one closed connector mapping."""
        if authorized_at.tzinfo is None or authorized_at.utcoffset() is None:
            raise SourceGovernanceError("gateway authorization time must include a timezone")
        gateway_source_id = self._connector_sources.get(gateway_connector_id)
        if gateway_source_id is None:
            raise SourceGovernanceError("gateway connector is unknown")
        gateway_rule = self._sources[gateway_source_id]
        if not gateway_rule.enabled:
            raise SourceGovernanceError("gateway source is disabled")
        if upstream_source_id not in gateway_rule.authenticated_upstream_source_ids:
            raise SourceGovernanceError("upstream source is not authenticated for this gateway")
        profile = self._registry.get(upstream_source_id)
        if not profile.is_public_output_approved:
            raise SourceGovernanceError("upstream rights do not allow public normalization")
        try:
            profile.authorize_gateway_dispatch(
                today=authorized_at.astimezone(UTC).date(),
            )
        except SourceRightsError as error:
            raise SourceGovernanceError(str(error)) from error
        return profile

    def authorize_gateway_shadow(
        self,
        *,
        gateway_connector_id: str,
        upstream_source_id: str,
        canonical_url: str,
        source_record_id: str,
        authorized_at: datetime,
    ) -> GatewaySourceAuthorization:
        """Authorize one minimized OSV record for isolated shadow persistence only."""
        if authorized_at.tzinfo is None or authorized_at.utcoffset() is None:
            raise SourceGovernanceError("gateway authorization time must include a timezone")
        if (
            not isinstance(source_record_id, str)
            or not source_record_id
            or len(source_record_id) > 160
            or not source_record_id.isascii()
        ):
            raise SourceGovernanceError("gateway source record ID is invalid")
        if gateway_connector_id != OSV_GATEWAY_CONNECTOR_ID:
            raise SourceGovernanceError("shadow gateway connector is unsupported")
        gateway_source_id = self._connector_sources.get(gateway_connector_id)
        if gateway_source_id != OSV_GATEWAY_SOURCE_ID:
            raise SourceGovernanceError("shadow gateway connector identity differs")
        gateway_rule = self._sources[gateway_source_id]
        if gateway_rule.enabled:
            raise SourceGovernanceError(
                "shadow authorization requires the gateway to stay disabled"
            )
        gateway_connector = next(
            item for item in gateway_rule.connectors if item.connector_id == gateway_connector_id
        )
        if (
            "rest_api" not in gateway_connector.acquisition_methods
            or "reconciliation" not in gateway_connector.operating_modes
        ):
            raise SourceGovernanceError("shadow gateway mode is not reviewed")
        if upstream_source_id not in gateway_rule.authenticated_upstream_source_ids:
            raise SourceGovernanceError("upstream source is not authenticated for this gateway")
        try:
            shadow_policy = self._gateway_shadow_field_policies[gateway_source_id]
        except KeyError as error:
            raise SourceGovernanceError("gateway has no reviewed shadow field policy") from error
        if upstream_source_id not in shadow_policy.origin_source_ids:
            raise SourceGovernanceError("upstream source has no reviewed governance rule")
        expected_url = OSV_API_ROOT + quote(source_record_id, safe="._:+-")
        if canonical_url != expected_url:
            raise SourceGovernanceError("shadow transport URL differs from the exact OSV record")

        gateway_profile = self._registry.get(gateway_source_id)
        try:
            gateway_profile.authorize_collection(
                method="rest_api",
                canonical_url=canonical_url,
                today=authorized_at.astimezone(UTC).date(),
            )
        except SourceRightsError as error:
            raise SourceGovernanceError(str(error)) from error
        transport_rights = gateway_profile.source["rights"]
        if (
            transport_rights["decision"] != "approved_internal"
            or transport_rights["raw_storage"] != "conditional"
            or not all(
                evidence.state == "verified_snapshot" and evidence.content_sha256 is not None
                for evidence in gateway_rule.rights_evidence
            )
        ):
            raise SourceGovernanceError("OSV transport rights evidence is not shadow-ready")

        try:
            origin_rule = self._sources[upstream_source_id]
        except KeyError as error:
            raise SourceGovernanceError(
                "upstream source has no reviewed governance rule"
            ) from error
        origin_profile = self._registry.get(upstream_source_id)
        try:
            origin_profile.authorize_gateway_dispatch(
                today=authorized_at.astimezone(UTC).date(),
            )
        except SourceRightsError as error:
            raise SourceGovernanceError(str(error)) from error
        origin_rights = origin_profile.source["rights"]
        if (
            not origin_profile.is_public_output_approved
            or origin_rights["raw_storage"] != "allowed"
            or origin_rule.license_expression is None
            or not all(
                evidence.state == "verified_snapshot" and evidence.content_sha256 is not None
                for evidence in origin_rule.rights_evidence
            )
        ):
            raise SourceGovernanceError("upstream source rights are not shadow-ready")
        accepted_roots = set(shadow_policy.accepted_field_paths)
        if not accepted_roots.issubset(gateway_profile.allowed_root_fields()) or (
            accepted_roots & origin_profile.prohibited_root_fields()
        ):
            raise SourceGovernanceError("OSV shadow projection exceeds reviewed source fields")

        return GatewaySourceAuthorization(
            policy_id=self.policy_id,
            policy_version=self.policy_version,
            policy_sha256=self.policy_sha256,
            rights_register_id=self.rights_register_id,
            transport_source_id=gateway_source_id,
            transport_connector_id=gateway_connector_id,
            transport_rights_revision=int(gateway_profile.source["revision"]),
            transport_canonical_url=canonical_url,
            transport_rights_evidence_ids=tuple(
                evidence.evidence_id for evidence in gateway_rule.rights_evidence
            ),
            origin_source_id=upstream_source_id,
            origin_rights_revision=int(origin_profile.source["revision"]),
            origin_canonical_url=origin_profile.source["canonical_url"],
            origin_rights_evidence_ids=tuple(
                evidence.evidence_id for evidence in origin_rule.rights_evidence
            ),
            origin_attribution_text=origin_rule.attribution_text,
            origin_license_expression=origin_rule.license_expression,
            source_record_id=source_record_id,
            field_policy_id=shadow_policy.field_policy_id,
            accepted_field_paths=shadow_policy.accepted_field_paths,
            storage_scope=shadow_policy.storage_scope,
            public_output_authorized=shadow_policy.public_output_authorized,
            authorized_at=authorized_at.astimezone(UTC),
        )

    def authorize_stored_publication(
        self,
        decision: SourceGovernanceDecisionRecord,
        *,
        public_status: str,
    ) -> None:
        """Authorize publication from the immutable decision stored with evidence."""
        if (
            decision.policy_id != self.policy_id
            or decision.policy_version != self.policy_version
            or decision.policy_sha256 != self.policy_sha256
            or decision.rights_register_id != self.rights_register_id
        ):
            raise SourceGovernanceError("stored governance decision uses another policy")
        if decision.source_id not in self.publication_source_ids:
            raise SourceGovernanceError("qualified publication decision is not active")
        if not self._registry.get(decision.source_id).is_public_output_approved:
            raise SourceGovernanceError("source rights do not allow public normalization")
        if (
            self.publication_decision_id is None
            or decision.qualified_publication_decision_id != self.publication_decision_id
        ):
            raise SourceGovernanceError("qualified publication decision is missing")
        if not decision.rights_evidence_verified:
            raise SourceGovernanceError("exact rights evidence is not verified")
        if public_status not in PUBLIC_STATUS_RANK:
            raise SourceGovernanceError("public status is unsupported")
        if PUBLIC_STATUS_RANK[public_status] > PUBLIC_STATUS_RANK[decision.public_status_ceiling]:
            raise SourceGovernanceError("public status exceeds the source ceiling")


def governance_policy_sha256(
    path: Path = DEFAULT_GOVERNANCE_POLICY_PATH,
) -> str:
    """Return the canonical digest of the tracked policy without authorizing use."""
    try:
        document = strict_json_loads(
            path.read_text(encoding="utf-8"),
            max_nodes=REGISTER_JSON_MAX_NODES,
            max_depth=REGISTER_JSON_MAX_DEPTH,
        )
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise SourceGovernanceError("source governance policy cannot be read") from error
    if not isinstance(document, Mapping):
        raise SourceGovernanceError("source governance policy is not an object")
    return sha256_id(canonical_json_bytes(document))


def append_governance_decision(
    session: Session,
    *,
    authorization: SourceAuthorization,
    accepted_sha256: str,
    decided_at: datetime,
) -> tuple[SourceGovernanceDecisionRecord, bool]:
    """Append one replay-safe decision for the exact accepted representation."""
    if not SHA256.fullmatch(accepted_sha256):
        raise SourceGovernanceError("accepted representation digest is invalid")
    if decided_at.tzinfo is None or decided_at.utcoffset() is None:
        raise SourceGovernanceError("governance decision time must include a timezone")
    legacy_decision_id = stable_id(
        "source-governance-decision",
        authorization.policy_sha256,
        authorization.source_id,
        authorization.source_record_id,
        accepted_sha256,
    )
    mode_decision_id = stable_id(
        "source-governance-decision",
        authorization.policy_sha256,
        authorization.source_id,
        authorization.source_record_id,
        authorization.operating_mode,
        accepted_sha256,
    )
    existing_by_id = {
        record.decision_id: record
        for record in session.scalars(
            select(SourceGovernanceDecisionRecord).where(
                SourceGovernanceDecisionRecord.decision_id.in_(
                    (legacy_decision_id, mode_decision_id)
                )
            )
        )
    }
    legacy_existing = existing_by_id.get(legacy_decision_id)
    if (
        legacy_existing is not None
        and legacy_existing.operating_mode == authorization.operating_mode
    ):
        # Existing production decisions predate the mode-scoped identity. Reuse a
        # matching legacy row without rewriting its immutable ID.
        decision_id = legacy_decision_id
        existing = legacy_existing
    else:
        # New decisions include the governed operating mode. Distinct modes can
        # now authorize the same immutable source body without racing on one ID.
        decision_id = mode_decision_id
        existing = existing_by_id.get(mode_decision_id)
    values = {
        "decision_id": decision_id,
        "policy_id": authorization.policy_id,
        "policy_version": authorization.policy_version,
        "policy_sha256": authorization.policy_sha256,
        "rights_register_id": authorization.rights_register_id,
        "authorized_disposition_adapter_ids": list(
            authorization.authorized_disposition_adapter_ids
        ),
        "source_id": authorization.source_id,
        "connector_id": authorization.connector_id,
        "source_record_id": authorization.source_record_id,
        "operating_mode": authorization.operating_mode,
        "acquisition_method": authorization.acquisition_method,
        "field_policy_id": authorization.field_policy_id,
        "accepted_sha256": accepted_sha256,
        "attribution_text": authorization.attribution_text,
        "license_expression": authorization.license_expression,
        "rights_evidence_ids": list(authorization.rights_evidence_ids),
        "rights_evidence_verified": authorization.rights_evidence_verified,
        "retention_behavior": authorization.retention_behavior,
        "public_status_ceiling": authorization.public_status_ceiling,
        "correction_behavior": authorization.correction_behavior,
        "withdrawal_behavior": authorization.withdrawal_behavior,
        "rights_drift_behavior": authorization.rights_drift_behavior,
        "qualified_publication_decision_id": (authorization.qualified_publication_decision_id),
        "decided_at": decided_at.astimezone(UTC),
    }
    if existing is not None:
        replay_values = {
            **values,
            "decided_at": existing.decided_at,
        }
        replay_hash_values = {
            **replay_values,
            "decided_at": timestamp(replay_values["decided_at"]),
        }
        if existing.record_hash != sha256_id(canonical_json_bytes(replay_hash_values)):
            raise SourceGovernanceError("governance decision conflicts with history")
        return existing, False
    hash_values = {**values, "decided_at": timestamp(values["decided_at"])}
    record_hash = sha256_id(canonical_json_bytes(hash_values))
    record = SourceGovernanceDecisionRecord(**values, record_hash=record_hash)
    session.add(record)
    session.flush()
    return record, True
