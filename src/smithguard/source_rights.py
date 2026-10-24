"""Fail-closed access to the reviewed source-rights register."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from smithguard.contracts.runtime import parse_contract
from smithguard.identifiers import (
    REGISTER_JSON_MAX_DEPTH,
    REGISTER_JSON_MAX_NODES,
    canonical_json_bytes,
    sha256_id,
    strict_json_loads,
)

PHASE_1_ACTIVATIONS = {
    "phase1_planned_collector",
    "phase1_planned_artifact_enrichment",
    "phase1_planned_query_gateway",
}


class SourceRightsError(ValueError):
    """A source or requested use is not authorized by the reviewed register."""


@dataclass(frozen=True, slots=True)
class SourceProfile:
    """One validated source and its field-level use rules."""

    activation: str
    source: dict[str, Any]
    field_rules: tuple[dict[str, Any], ...]

    @property
    def source_id(self) -> str:
        return self.source["id"]

    @property
    def is_public_output_approved(self) -> bool:
        rights = self.source["rights"]
        return rights["decision"] == "approved_public" and rights[
            "normalized_fact_redistribution"
        ] in {"allowed", "attribution"}

    def authorize_collection(
        self,
        *,
        method: str,
        canonical_url: str,
        today: date | None = None,
    ) -> None:
        """Reject disabled, expired, unapproved, or off-host source use."""
        self.authorize_gateway_dispatch(today=today)
        if method not in self.source["acquisition_methods"]:
            raise SourceRightsError("collection method is not approved")
        parsed = urlsplit(canonical_url)
        host = (parsed.hostname or "").lower().rstrip(".")
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in {None, 443}
            or parsed.fragment
            or host not in set(self.source["allowed_hosts"])
        ):
            raise SourceRightsError("source URL is outside the approved host boundary")

    def authorize_gateway_dispatch(
        self,
        *,
        today: date | None = None,
    ) -> None:
        """Apply source activation, kill-switch, retrieval, and review gates to a gateway."""
        if self.activation not in PHASE_1_ACTIVATIONS:
            raise SourceRightsError("source is not a Phase 1 path")
        if not self.source["kill_switch"]:
            raise SourceRightsError("source kill switch is not enabled")
        rights = self.source["rights"]
        if rights["retrieval"] != "allowed":
            raise SourceRightsError("source retrieval is not approved")
        review_due = date.fromisoformat(rights["review_due_on"])
        if review_due < (today or datetime.now(UTC).date()):
            raise SourceRightsError("source rights review is stale")

    def allowed_root_fields(self) -> frozenset[str]:
        """Return fields with an affirmative storage disposition."""
        allowed: set[str] = set()
        for rule in self.field_rules:
            if rule["storage"] in {
                "immutable",
                "minimal_metadata",
                "checksum_and_verification_state_preferred",
                "source_license_required",
            }:
                allowed.update(field.split(".", 1)[0] for field in rule["fields"])
        return frozenset(allowed)

    def prohibited_root_fields(self) -> frozenset[str]:
        """Return fields that must be omitted before normalized use."""
        prohibited: set[str] = set()
        for rule in self.field_rules:
            if rule["storage"] in {"omit", "prohibited"}:
                prohibited.update(field.split(".", 1)[0] for field in rule["fields"])
        return frozenset(prohibited)


class RightsRegistry:
    """A closed, validated view over the machine-readable source register."""

    def __init__(self, document: Mapping[str, Any]) -> None:
        if set(document) - {"publication_renewals"} != {
            "schema_version",
            "register_id",
            "reviewed_on",
            "default_review_due_on",
            "policy",
            "source_revisions",
            "source_profiles",
        }:
            raise SourceRightsError("source-rights register has an invalid shape")
        if document.get("schema_version") != "1.0.0":
            raise SourceRightsError("unsupported source-rights schema")
        register_id = document.get("register_id")
        if not isinstance(register_id, str) or not register_id:
            raise SourceRightsError("source-rights register identity is invalid")
        profiles = document.get("source_profiles")
        if not isinstance(profiles, list) or not profiles:
            raise SourceRightsError("source-rights register has no profiles")
        by_id: dict[str, SourceProfile] = {}
        for value in profiles:
            if not isinstance(value, Mapping):
                raise SourceRightsError("source profile has an invalid shape")
            if set(value) != {"activation", "source", "field_rules"}:
                raise SourceRightsError("source profile contains an unexpected field")
            source = parse_contract("Source", value["source"]).model_dump(
                mode="json",
                exclude_none=False,
            )
            source_id = source["id"]
            if source_id in by_id:
                raise SourceRightsError("source profile is duplicated")
            field_rules = value["field_rules"]
            if not isinstance(field_rules, list) or not field_rules:
                raise SourceRightsError("source profile has no field rules")
            normalized_rules: list[dict[str, Any]] = []
            for rule in field_rules:
                if not isinstance(rule, Mapping) or set(rule) != {
                    "fields",
                    "storage",
                    "public_output",
                }:
                    raise SourceRightsError("source field rule has an invalid shape")
                fields = rule["fields"]
                if (
                    not isinstance(fields, list)
                    or not fields
                    or not all(isinstance(field, str) and field for field in fields)
                ):
                    raise SourceRightsError("source field rule has invalid fields")
                normalized_rules.append(
                    {
                        "fields": list(fields),
                        "storage": str(rule["storage"]),
                        "public_output": str(rule["public_output"]),
                    }
                )
            by_id[source_id] = SourceProfile(
                activation=str(value["activation"]),
                source=source,
                field_rules=tuple(normalized_rules),
            )
        raw_histories = document.get("source_revisions")
        if not isinstance(raw_histories, list) or not raw_histories:
            raise SourceRightsError("source revision history is missing")
        histories: dict[str, tuple[tuple[int, str], ...]] = {}
        for value in raw_histories:
            if not isinstance(value, Mapping) or set(value) != {
                "source_id",
                "revisions",
            }:
                raise SourceRightsError("source revision history has an invalid shape")
            source_id = value["source_id"]
            if not isinstance(source_id, str) or source_id not in by_id:
                raise SourceRightsError("source revision history names an unknown source")
            if source_id in histories:
                raise SourceRightsError("source revision history is duplicated")
            raw_revisions = value["revisions"]
            if not isinstance(raw_revisions, list) or not raw_revisions or len(raw_revisions) > 100:
                raise SourceRightsError("source revision history is invalid")
            revisions: list[tuple[int, str]] = []
            for expected_revision, entry in enumerate(raw_revisions, start=1):
                if not isinstance(entry, Mapping) or set(entry) != {
                    "revision",
                    "source_sha256",
                }:
                    raise SourceRightsError("source revision entry has an invalid shape")
                revision = entry["revision"]
                source_hash = entry["source_sha256"]
                if (
                    not isinstance(revision, int)
                    or isinstance(revision, bool)
                    or revision != expected_revision
                ):
                    raise SourceRightsError("source revision history is not contiguous")
                if (
                    not isinstance(source_hash, str)
                    or len(source_hash) != 71
                    or not source_hash.startswith("sha256:")
                    or any(character not in "0123456789abcdef" for character in source_hash[7:])
                ):
                    raise SourceRightsError("source revision hash is invalid")
                revisions.append((revision, source_hash))
            current_source = by_id[source_id].source
            if revisions[-1][0] != current_source["revision"]:
                raise SourceRightsError("current source revision is not the recorded head")
            if revisions[-1][1] != sha256_id(canonical_json_bytes(current_source)):
                raise SourceRightsError("current source content differs from its revision history")
            histories[source_id] = tuple(revisions)
        if set(histories) != set(by_id):
            raise SourceRightsError("source revision history coverage is incomplete")
        self._profiles = by_id
        self._revision_histories = histories
        self._register_id = register_id
        self._schema_version = "1.0.0"
        self._publication_renewals = self._validate_publication_renewals(
            document.get("publication_renewals", [])
        )

    def _validate_publication_renewals(self, entries):
        """Permit only explicit, authentic date-only renewals to the current head.

        Each entry supplies complete old Source bytes authenticated by their
        historical hash. Field/activation rules are explicit reviewed declarations
        equal to current rules; legacy hashes do not authenticate those fields.
        No terms, attribution, host, field or other substantive change is inferred
        compatible. Publication and verification check the full current policy;
        the status worker separately enforces current approval, dates and fields.
        """
        if not isinstance(entries, list) or len(entries) > 10_000:
            raise SourceRightsError("publication renewals are invalid")
        accepted = set()
        for entry in entries:
            if not isinstance(entry, Mapping) or set(entry) != {
                "historical_profile",
                "current_revision",
            }:
                raise SourceRightsError("publication renewal has an invalid shape")
            old = entry["historical_profile"]
            if not isinstance(old, Mapping) or set(old) != {"activation", "source", "field_rules"}:
                raise SourceRightsError("publication renewal profile is invalid")
            source = parse_contract("Source", old["source"]).model_dump(
                mode="json", exclude_none=False
            )
            profile = self.get(source["id"])
            revision = source["revision"]
            head = profile.source["revision"]
            if (
                type(entry["current_revision"]) is not int
                or entry["current_revision"] != head
                or revision >= head
                or (revision, sha256_id(canonical_json_bytes(source)))
                not in self.revision_history(source["id"])
            ):
                raise SourceRightsError("publication renewal history is not authentic")
            key = (source["id"], revision)
            if key in accepted:
                raise SourceRightsError("publication renewal is duplicated")
            previous = deepcopy(source)
            current = deepcopy(profile.source)
            for value in (previous, current):
                value.pop("revision")
                value.pop("updated_at")
                value["rights"].pop("reviewed_on")
                value["rights"].pop("review_due_on")
            if (
                previous != current
                or old["activation"] != profile.activation
                or old["field_rules"] != list(profile.field_rules)
            ):
                raise SourceRightsError("publication renewal changes substantive policy")
            if (
                source["rights"]["reviewed_on"] > profile.source["rights"]["reviewed_on"]
                or profile.source["rights"]["reviewed_on"]
                > profile.source["rights"]["review_due_on"]
            ):
                raise SourceRightsError("publication renewal dates are invalid")
            accepted.add(key)
        return frozenset(accepted)

    def permits_publication_revision(self, source_id: str, revision: int) -> bool:
        """Resolve a current revision or an explicitly reviewed date-only renewal."""
        return type(revision) is int and (
            self.get(source_id).source["revision"] == revision
            or (source_id, revision) in self._publication_renewals
        )

    @property
    def register_id(self) -> str:
        return self._register_id

    @property
    def schema_version(self) -> str:
        return self._schema_version

    @classmethod
    def from_path(cls, path: Path) -> RightsRegistry:
        return cls(
            strict_json_loads(
                path.read_text(encoding="utf-8"),
                max_nodes=REGISTER_JSON_MAX_NODES,
                max_depth=REGISTER_JSON_MAX_DEPTH,
            )
        )

    def get(self, source_id: str) -> SourceProfile:
        try:
            return self._profiles[source_id]
        except KeyError as error:
            raise SourceRightsError("source is absent from the reviewed register") from error

    def revision_history(self, source_id: str) -> tuple[tuple[int, str], ...]:
        try:
            return self._revision_histories[source_id]
        except KeyError as error:
            raise SourceRightsError("source is absent from the reviewed register") from error

    def validate_persisted_history(
        self,
        source_id: str,
        persisted: tuple[tuple[int, str], ...],
    ) -> None:
        expected = dict(self.revision_history(source_id))
        for revision, source_hash in persisted:
            if expected.get(revision) != source_hash:
                raise SourceRightsError("stored source history differs from the reviewed register")

    def phase_1_profiles(self) -> tuple[SourceProfile, ...]:
        return tuple(
            profile
            for profile in self._profiles.values()
            if profile.activation in PHASE_1_ACTIVATIONS
        )
