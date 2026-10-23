"""Deterministic normalization of a closed public-artifact record shape."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from math import isfinite
from typing import Any
from urllib.parse import quote, urlsplit

from smithguard.contracts.generated import CoverageState
from smithguard.contracts.runtime import parse_contract
from smithguard.ecosystems import PURL_TYPE_BY_ECOSYSTEM
from smithguard.identifiers import SHA256, stable_id

ARTIFACT_KEYS = {"ecosystem", "name", "version", "digest"}
RECORD_KEYS = {
    "record_id",
    "artifact",
    "claims",
    "affected_ranges",
    "relationships",
    "source_lineage",
}
CLAIM_KEYS = {
    "claim_type",
    "predicate",
    "object_value",
    "confidence",
    "state",
    "valid_from",
    "valid_until",
    "supersedes_claim_id",
}
RANGE_KEYS = {
    "range_type",
    "expression",
    "introduced",
    "fixed",
    "last_affected",
    "evaluation_state",
}
RELATIONSHIP_KEYS = {
    "object_id",
    "relationship_type",
    "confidence",
    "state",
    "valid_from",
    "valid_until",
}
PUBLIC_FACT_RIGHTS = {"allowed", "attribution"}
SAFE_IDENTIFIER_VALUE = re.compile(r"^[A-Za-z0-9@._/+:-]{1,160}$")
SAFE_PREDICATE = re.compile(r"^[a-z][a-z0-9_]{1,119}$")
SAFE_RANGE = re.compile(r"^[A-Za-z0-9.*<>=!~^|, +:_/@-]{1,1000}$")
PYPI_NORMALIZE = re.compile(r"[-_.]+")
ASCII_PACKAGE_PUNCTUATION = frozenset("@._/+:-%")
UNICODE_PACKAGE_CATEGORIES = frozenset({"L", "M", "N"})


class NormalizationRejected(ValueError):
    """A source-controlled record cannot become canonical public state."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class NormalizationContext:
    source: Mapping[str, Any]
    raw_evidence: Mapping[str, Any]
    collection_method: str
    identity_verification: str
    signature_state: str


@dataclass(frozen=True, slots=True)
class NormalizedRecord:
    record_id: str
    artifact: dict[str, Any]
    claims: tuple[dict[str, Any], ...]
    affected_ranges: tuple[dict[str, Any], ...]
    relationships: tuple[dict[str, Any], ...]
    coverage: dict[str, Any]

    @property
    def contract_records(self) -> tuple[tuple[str, dict[str, Any]], ...]:
        return (
            ("Artifact", self.artifact),
            *(("Claim", value) for value in self.claims),
            *(("AffectedRange", value) for value in self.affected_ranges),
            *(("Relationship", value) for value in self.relationships),
        )


def _closed(value: Mapping[str, Any], allowed: set[str], code: str) -> None:
    if set(value) - allowed:
        raise NormalizationRejected(code)


def _required_string(value: Any, code: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise NormalizationRejected(code)
    try:
        value.encode("ascii")
    except UnicodeEncodeError as error:
        raise NormalizationRejected(code) from error
    return value


def _required_package_string(value: Any, code: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise NormalizationRejected(code)
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise NormalizationRejected(code) from error
    return value


def _encode_path(value: str) -> str:
    return "/".join(quote(part, safe=".-_~") for part in value.split("/"))


def _safe_package_name(value: str) -> bool:
    """Accept exact UTF-8 package identity without collapsing confusable names."""
    if not value or value in {".", ".."}:
        return False
    for character in value:
        if character.isascii():
            if not (character.isalnum() or character in ASCII_PACKAGE_PUNCTUATION):
                return False
            continue
        if unicodedata.category(character)[:1] not in UNICODE_PACKAGE_CATEGORIES:
            return False
    return True


def normalize_artifact_identity(value: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize one public artifact and create its Package URL."""
    _closed(value, ARTIFACT_KEYS, "unexpected_artifact_field")
    if set(value) != ARTIFACT_KEYS:
        raise NormalizationRejected("missing_artifact_field")
    ecosystem = _required_string(value["ecosystem"], "invalid_ecosystem", 40).lower()
    name = _required_package_string(value["name"], "invalid_artifact_name", 300)
    version = value["version"]
    digest = value["digest"]
    if version is not None:
        version = _required_string(version, "invalid_artifact_version", 200)
    if digest is not None:
        digest = _required_string(digest, "invalid_artifact_digest", 71).lower()
        if not SHA256.fullmatch(digest):
            raise NormalizationRejected("invalid_artifact_digest")

    if ecosystem == "pypi":
        normalized_name = PYPI_NORMALIZE.sub("-", name).lower()
        purl_type = "pypi"
    elif ecosystem == "npm":
        normalized_name = name
        if normalized_name.startswith("@"):
            parts = normalized_name.split("/")
            if len(parts) != 2 or any(not part for part in parts):
                raise NormalizationRejected("invalid_artifact_name")
        purl_type = "npm"
    elif ecosystem == "github-actions":
        action_name = name
        if name.lower().startswith("https://"):
            if any(character in "\r\n\t" for character in name):
                raise NormalizationRejected("invalid_artifact_name")
            try:
                action_url = urlsplit(name)
                action_port = action_url.port
            except ValueError as error:
                raise NormalizationRejected("invalid_artifact_name") from error
            if (
                action_url.scheme.lower() != "https"
                or action_url.hostname != "github.com"
                or action_url.username is not None
                or action_url.password is not None
                or action_port is not None
                or action_url.netloc.lower() != "github.com"
                or not action_url.path.startswith("/")
                or "%" in action_url.path
                or action_url.query
                or action_url.fragment
            ):
                raise NormalizationRejected("invalid_artifact_name")
            action_name = action_url.path.removeprefix("/")
        normalized_name = action_name.lower()
        action_parts = normalized_name.split("/")
        if len(action_parts) < 2 or any(not part or part in {".", ".."} for part in action_parts):
            raise NormalizationRejected("invalid_artifact_name")
        purl_type = "github"
    elif ecosystem in {"oci", "docker"}:
        normalized_name = name.lower()
        if "/" not in normalized_name:
            raise NormalizationRejected("invalid_artifact_name")
        purl_type = "oci"
    elif ecosystem in PURL_TYPE_BY_ECOSYSTEM:
        normalized_name = name
        purl_type = PURL_TYPE_BY_ECOSYSTEM[ecosystem]
    else:
        raise NormalizationRejected("unsupported_ecosystem")
    if not _safe_package_name(normalized_name):
        raise NormalizationRejected("invalid_artifact_name")

    coordinate = f"pkg:{purl_type}/{_encode_path(normalized_name)}"
    purl_version = digest if ecosystem in {"oci", "docker"} and digest else version
    if purl_version:
        coordinate += "@" + quote(purl_version, safe=".-_~")
    identity_state = "exact" if digest is not None or version is not None else "unresolved"
    return {
        "ecosystem": ecosystem,
        "name": normalized_name,
        "coordinate": coordinate,
        "version": version,
        "digest": digest,
        "identity_state": identity_state,
    }


def _provenance(
    context: NormalizationContext,
    *,
    source_lineage: Mapping[str, Any] | None,
) -> dict[str, Any]:
    source = context.source
    evidence = context.raw_evidence
    lineage = (
        parse_contract("ClaimLineage", source_lineage).model_dump(
            mode="json",
            exclude_none=False,
        )
        if source_lineage is not None
        else None
    )
    return {
        "source_id": source["id"],
        "source_record_id": evidence["source_record_id"],
        "source_url": evidence["canonical_url"],
        "evidence_id": evidence["id"],
        "retrieved_at": evidence["retrieved_at"],
        "source_published_at": evidence.get("source_published_at"),
        "source_modified_at": evidence.get("source_modified_at"),
        "collection_method": context.collection_method,
        "assertion_origin": "declared_by_source",
        "identity_verification": context.identity_verification,
        "signature_state": context.signature_state,
        "claim_lineage": lineage,
    }


def _header(
    *,
    identifier: str,
    kind: str,
    recorded_at: str,
    data_classification: str = "public",
) -> dict[str, Any]:
    return {
        "id": identifier,
        "kind": kind,
        "schema_version": "1.0.0",
        "revision": 1,
        "created_at": recorded_at,
        "updated_at": recorded_at,
        "data_classification": data_classification,
    }


def _safe_object_value(value: Any) -> str | int | float | bool | None:
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float) and isfinite(value):
        return value
    if isinstance(value, str) and SAFE_IDENTIFIER_VALUE.fullmatch(value):
        return value
    raise NormalizationRejected("unsafe_claim_object_value")


def normalize_record(
    value: Mapping[str, Any],
    *,
    context: NormalizationContext,
) -> NormalizedRecord:
    """Normalize one closed source record without retaining source prose."""
    _closed(value, RECORD_KEYS, "unexpected_record_field")
    if not {"record_id", "artifact"} <= set(value):
        raise NormalizationRejected("missing_record_field")
    source = parse_contract("Source", context.source).model_dump(mode="json", exclude_none=False)
    evidence = parse_contract("RawEvidence", context.raw_evidence).model_dump(
        mode="json",
        exclude_none=False,
    )
    rights = source["rights"]
    if (
        rights["decision"] != "approved_public"
        or rights["normalized_fact_redistribution"] not in PUBLIC_FACT_RIGHTS
    ):
        raise NormalizationRejected("normalization_rights_not_approved")
    if evidence["source_id"] != source["id"]:
        raise NormalizationRejected("source_evidence_mismatch")
    record_id = _required_string(value["record_id"], "invalid_record_id", 160)
    artifact_input = value["artifact"]
    if not isinstance(artifact_input, Mapping):
        raise NormalizationRejected("invalid_artifact_shape")
    identity = normalize_artifact_identity(artifact_input)
    recorded_at = evidence["retrieved_at"]
    artifact_id = stable_id("artifact", identity["coordinate"])
    artifact = {
        **_header(identifier=artifact_id, kind="artifact", recorded_at=recorded_at),
        **identity,
    }
    artifact = parse_contract("Artifact", artifact).model_dump(mode="json", exclude_none=False)
    raw_lineage = value.get("source_lineage")
    if raw_lineage is not None and not isinstance(raw_lineage, Mapping):
        raise NormalizationRejected("invalid_source_lineage")
    try:
        provenance = _provenance(context, source_lineage=raw_lineage)
    except (TypeError, ValueError) as error:
        raise NormalizationRejected("invalid_source_lineage") from error

    claims: list[dict[str, Any]] = []
    claim_inputs = value.get("claims", [])
    if not isinstance(claim_inputs, list) or len(claim_inputs) > 100:
        raise NormalizationRejected("claim_limit")
    for index, item in enumerate(claim_inputs):
        if not isinstance(item, Mapping):
            raise NormalizationRejected("invalid_claim_shape")
        _closed(item, CLAIM_KEYS, "unexpected_claim_field")
        if not {
            "claim_type",
            "predicate",
            "object_value",
            "confidence",
            "state",
        } <= set(item):
            raise NormalizationRejected("missing_claim_field")
        predicate = _required_string(item["predicate"], "invalid_claim_predicate", 120)
        if not SAFE_PREDICATE.fullmatch(predicate):
            raise NormalizationRejected("invalid_claim_predicate")
        claim_id = stable_id(
            "claim",
            source["id"],
            evidence["source_record_id"],
            record_id,
            str(index),
            dict(item),
        )
        claim = {
            **_header(identifier=claim_id, kind="claim", recorded_at=recorded_at),
            "claim_type": item["claim_type"],
            "subject_id": artifact_id,
            "predicate": predicate,
            "object_value": _safe_object_value(item["object_value"]),
            "confidence": item["confidence"],
            "state": item["state"],
            "valid_from": item.get("valid_from"),
            "valid_until": item.get("valid_until"),
            "supersedes_claim_id": item.get("supersedes_claim_id"),
            "provenance": provenance,
        }
        claims.append(parse_contract("Claim", claim).model_dump(mode="json", exclude_none=False))

    ranges: list[dict[str, Any]] = []
    range_inputs = value.get("affected_ranges", [])
    if not isinstance(range_inputs, list) or len(range_inputs) > 100:
        raise NormalizationRejected("affected_range_limit")
    for index, item in enumerate(range_inputs):
        if not isinstance(item, Mapping):
            raise NormalizationRejected("invalid_affected_range_shape")
        _closed(item, RANGE_KEYS, "unexpected_affected_range_field")
        if not {"range_type", "expression", "evaluation_state"} <= set(item):
            raise NormalizationRejected("missing_affected_range_field")
        expression = _required_string(item["expression"], "invalid_range_expression", 1000)
        if not SAFE_RANGE.fullmatch(expression):
            raise NormalizationRejected("invalid_range_expression")
        range_id = stable_id(
            "range",
            source["id"],
            evidence["source_record_id"],
            record_id,
            str(index),
            dict(item),
        )
        affected_range = {
            **_header(identifier=range_id, kind="affected_range", recorded_at=recorded_at),
            "artifact_id": artifact_id,
            "range_type": item["range_type"],
            "expression": expression,
            "introduced": item.get("introduced"),
            "fixed": item.get("fixed"),
            "last_affected": item.get("last_affected"),
            "evaluation_state": item["evaluation_state"],
            "provenance": provenance,
        }
        ranges.append(
            parse_contract("AffectedRange", affected_range).model_dump(
                mode="json",
                exclude_none=False,
            )
        )

    relationships: list[dict[str, Any]] = []
    relationship_inputs = value.get("relationships", [])
    if not isinstance(relationship_inputs, list) or len(relationship_inputs) > 100:
        raise NormalizationRejected("relationship_limit")
    for index, item in enumerate(relationship_inputs):
        if not isinstance(item, Mapping):
            raise NormalizationRejected("invalid_relationship_shape")
        _closed(item, RELATIONSHIP_KEYS, "unexpected_relationship_field")
        if not {"object_id", "relationship_type", "confidence", "state"} <= set(item):
            raise NormalizationRejected("missing_relationship_field")
        relationship_id = stable_id(
            "relationship",
            source["id"],
            evidence["source_record_id"],
            record_id,
            str(index),
            dict(item),
        )
        relationship = {
            **_header(
                identifier=relationship_id,
                kind="relationship",
                recorded_at=recorded_at,
            ),
            "subject_id": artifact_id,
            "object_id": item["object_id"],
            "relationship_type": item["relationship_type"],
            "assertion_origin": "declared_by_source",
            "confidence": item["confidence"],
            "valid_from": item.get("valid_from"),
            "valid_until": item.get("valid_until"),
            "state": item["state"],
            "provenance": provenance,
        }
        relationships.append(
            parse_contract("Relationship", relationship).model_dump(
                mode="json",
                exclude_none=False,
            )
        )

    coverage = {
        "ecosystem": identity["ecosystem"],
        "stage": "normalized",
        "result": "supported" if identity["identity_state"] == "exact" else "partial",
        "as_of": recorded_at,
    }
    coverage = CoverageState.model_validate(coverage).model_dump(mode="json")
    return NormalizedRecord(
        record_id=record_id,
        artifact=artifact,
        claims=tuple(claims),
        affected_ranges=tuple(ranges),
        relationships=tuple(relationships),
        coverage=coverage,
    )
