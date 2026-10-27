"""Injected, fixed-boundary collectors for approved Phase 1 sources."""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Callable, Mapping
from contextlib import nullcontext, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from time import monotonic
from typing import Any, Literal
from urllib.parse import parse_qs, quote, urlencode, urlsplit, urlunsplit

import httpx
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from smithguard import __version__
from smithguard.acquisition import (
    AcquisitionLimits,
    AcquisitionRejected,
    AcquisitionRequest,
    OperationDeadline,
)
from smithguard.advisory_catalog import (
    AdvisoryCatalogError,
    AdvisoryCatalogStaleRevision,
    CatalogAppendResult,
    append_github_advisory,
    append_github_inventory_membership,
    append_github_segment_manifest,
)
from smithguard.authority import (
    AuthorityPolicy,
    AuthorityPolicyError,
    evaluate_direct_openssf,
    evaluate_github_malware,
    load_authority_policy,
)
from smithguard.collection_records import (
    RecordAccountingError,
    append_outcome,
    append_page_membership,
    append_replay_membership,
    append_resolution,
    require_resolution_target,
    unresolved_count,
)
from smithguard.db.locks import advisory_xact_lock
from smithguard.db.models import (
    CollectionRecordOutcome,
    CollectorCheckpointRecord,
    CollectorProgressRecord,
)
from smithguard.db.repository import RevisionConflict
from smithguard.evidence import EvidenceStore
from smithguard.identifiers import (
    INGEST_JSON_MAX_DEPTH,
    INGEST_JSON_MAX_NODES,
    DuplicateJsonKeyError,
    canonical_json_bytes,
    parse_timestamp,
    sha256_id,
    stable_id,
    strict_json_loads,
    timestamp,
)
from smithguard.ingestion import (
    DEFAULT_PROCESSING_VERSION,
    IngestionOutcome,
    IngestionReplayConflict,
    IngestionSourceError,
    ingest_bytes,
)
from smithguard.normalization import NormalizationRejected
from smithguard.range_evaluation import normalize_github_npm_advisory_range, osv_intervals
from smithguard.source_governance import (
    DEFAULT_GOVERNANCE_POLICY_PATH,
    SourceGovernanceError,
    SourceGovernancePolicy,
)
from smithguard.source_rights import RightsRegistry

GITHUB_ADVISORY = "gbsec:source:github-advisory-database"
OPENSSF_MALICIOUS = "gbsec:source:openssf-malicious-packages"
PYPA_ADVISORY = "gbsec:source:pypa-advisory-database"

GITHUB_REST_ECOSYSTEMS = frozenset(
    {
        "actions",
        "composer",
        "erlang",
        "go",
        "maven",
        "npm",
        "nuget",
        "other",
        "pip",
        "pub",
        "rubygems",
        "rust",
        "swift",
    }
)
GITHUB_REST_LEGACY_ECOSYSTEM_ALIASES = {
    "github-actions": "github-actions",
    "pypi": "pypi",
}
GITHUB_COMPARATOR_RANGE_PATTERN = re.compile(
    r"(?:<=?|>=?|={1,2}|!=|~=)\s*[A-Za-z0-9._+:/@*()-]{1,200}"
    r"(?:\s*,\s*(?:<=?|>=?|={1,2}|!=|~=)\s*[A-Za-z0-9._+:/@*()-]{1,200})*"
)
GITHUB_MAX_PROVIDER_VULNERABILITIES = 1000
CHECKPOINT_SEQUENCE = "smithguard.collector_checkpoint_sequence"
GITHUB_MAX_REFERENCES = 1_000

ParserKind = Literal[
    "osv",
    "github_advisory_rest",
]


def _bounded_canonical_body(value: object, *, failure: str) -> bytes:
    """Canonical bytes, or the collector boundary error when a number is out of range.

    The shared encoder refuses NaN and infinity; an upstream float literal such as
    1e400 parses to infinity, so the refusal is mapped rather than escaping the lane.
    """
    try:
        return canonical_json_bytes(value)
    except ValueError as error:
        raise CollectorBoundaryError(failure) from error


def _quarantine_body(advisory: object) -> bytes:
    """The quarantine safety net must never throw and must keep the offending bytes.

    An advisory the strict encoder refuses (an out-of-range float) is serialized with
    the pre-consolidation expression, which emits ``Infinity``: the stored evidence
    stays advisory-specific, so its digest, identifier and idempotency key stay
    distinct per advisory exactly as before.
    """
    try:
        return canonical_json_bytes([advisory])
    except ValueError:
        return json.dumps(
            [advisory], sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")


class CollectorBoundaryError(ValueError):
    """A connector attempted to leave its fixed endpoint or activation boundary."""


class CollectorRetryLater(CollectorBoundaryError):
    """A fixed source supplied a bounded retry directive."""

    def __init__(self, *, not_before: datetime) -> None:
        self.not_before = not_before
        super().__init__("GitHub advisory request is rate limited")


@dataclass(frozen=True, slots=True)
class CollectorSpec:
    source_id: str
    connector_id: str
    collection_method: str
    preflight_url: str
    endpoint_hosts: tuple[str, ...]
    endpoint_path_prefixes: tuple[str, ...]
    parser: ParserKind
    public_canonical: bool


@dataclass(frozen=True, slots=True)
class TransportResponse:
    """Already retrieved bytes and bounded metadata supplied by an injected adapter."""

    body: bytes
    canonical_url: str
    media_type: str
    retrieved_at: datetime
    source_record_id: str
    source_published_at: datetime | None = None
    source_modified_at: datetime | None = None
    declared_content_length: int | None = None
    redirect_count: int = 0
    elapsed_seconds: float = 0.0
    checkpoint_token: str | None = None


@dataclass(frozen=True, slots=True)
class CollectorRun:
    checkpoint_event_id: str
    outcome: IngestionOutcome | None


Transport = Callable[[CollectorSpec, str | None], TransportResponse]


COLLECTOR_SPECS: dict[str, CollectorSpec] = {
    GITHUB_ADVISORY: CollectorSpec(
        source_id=GITHUB_ADVISORY,
        connector_id="gbsec:connector:github-advisory-rest-v1",
        collection_method="rest_api",
        preflight_url="https://api.github.com/advisories",
        endpoint_hosts=("api.github.com", "github.com"),
        endpoint_path_prefixes=("/advisories", "/repos/github/advisory-database"),
        parser="github_advisory_rest",
        public_canonical=True,
    ),
    OPENSSF_MALICIOUS: CollectorSpec(
        source_id=OPENSSF_MALICIOUS,
        connector_id="gbsec:connector:openssf-git-v1",
        collection_method="git",
        preflight_url="https://github.com/ossf/malicious-packages",
        endpoint_hosts=("github.com", "raw.githubusercontent.com"),
        endpoint_path_prefixes=("/ossf/malicious-packages",),
        parser="osv",
        public_canonical=True,
    ),
    PYPA_ADVISORY: CollectorSpec(
        source_id=PYPA_ADVISORY,
        connector_id="gbsec:connector:pypa-advisory-git-v1",
        collection_method="git",
        preflight_url="https://github.com/pypa/advisory-database",
        endpoint_hosts=("github.com", "raw.githubusercontent.com"),
        endpoint_path_prefixes=("/pypa/advisory-database",),
        parser="osv",
        public_canonical=True,
    ),
}


def _bounded_ascii(value: Any, *, code: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise NormalizationRejected(code)
    try:
        value.encode("ascii")
    except UnicodeEncodeError as error:
        raise NormalizationRejected(code) from error
    return value


def _ecosystem(value: Any) -> str:
    name = _bounded_ascii(value, code="invalid_osv_ecosystem", maximum=80).lower()
    mapping = {
        "npm": "npm",
        "pypi": "pypi",
        "github actions": "github-actions",
        "github-actions": "github-actions",
        "docker": "docker",
        "oci": "oci",
        "go": "go",
        "crates.io": "rust",
        "rust": "rust",
    }
    try:
        return mapping[name]
    except KeyError as error:
        raise NormalizationRejected("unsupported_osv_ecosystem") from error


def _github_ecosystem(value: Any) -> str:
    name = _bounded_ascii(value, code="invalid_github_ecosystem", maximum=80).lower()
    if name not in GITHUB_REST_ECOSYSTEMS and name not in GITHUB_REST_LEGACY_ECOSYSTEM_ALIASES:
        raise NormalizationRejected("unreviewed_github_ecosystem")
    aliases = {
        "actions": "github-actions",
        "pip": "pypi",
        **GITHUB_REST_LEGACY_ECOSYSTEM_ALIASES,
    }
    return _ecosystem(aliases.get(name, name))


def _range_expression(
    *,
    introduced: str | None,
    fixed: str | None,
    last_affected: str | None,
) -> str:
    parts: list[str] = []
    if introduced is not None and introduced != "0":
        parts.append(f">={introduced}")
    if fixed is not None:
        parts.append(f"<{fixed}")
    if last_affected is not None:
        parts.append(f"<={last_affected}")
    return ", ".join(parts) or "*"


def _osv_ranges(value: Mapping[str, Any], *, ecosystem: str) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    ranges = value.get("ranges", [])
    if not isinstance(ranges, list) or len(ranges) > 100:
        raise NormalizationRejected("invalid_osv_ranges")
    for item in ranges:
        if not isinstance(item, Mapping):
            raise NormalizationRejected("invalid_osv_range")
        range_type = str(item.get("type", "UNKNOWN")).upper()
        if range_type not in {"ECOSYSTEM", "SEMVER", "GIT"}:
            range_type = "UNKNOWN"
        events = item.get("events", [])
        if not isinstance(events, list) or len(events) > 200:
            raise NormalizationRejected("invalid_osv_events")
        for event in events:
            if not isinstance(event, Mapping) or len(event) != 1:
                raise NormalizationRejected("invalid_osv_event")
            key, raw = next(iter(event.items()))
            if key not in ("introduced", "fixed", "last_affected", "limit"):
                raise NormalizationRejected("unsupported_osv_event")
            _bounded_ascii(raw, code="invalid_osv_event_value", maximum=200)
        intervals = osv_intervals(ecosystem, item)
        if intervals is None or not intervals:
            output.append(
                {
                    "range_type": range_type,
                    "expression": "unsupported OSV events",
                    "introduced": None,
                    "fixed": None,
                    "last_affected": None,
                    "evaluation_state": "partial",
                }
            )
            continue
        for interval in intervals:
            output.append(
                {
                    "range_type": range_type,
                    "expression": _range_expression(
                        introduced=interval.introduced,
                        fixed=interval.upper if interval.upper_kind in {"fixed", "limit"} else None,
                        last_affected=interval.upper
                        if interval.upper_kind == "last_affected"
                        else None,
                    ),
                    "introduced": interval.introduced if interval.introduced is not None else "0",
                    "fixed": interval.upper if interval.upper_kind == "fixed" else None,
                    "last_affected": interval.upper
                    if interval.upper_kind == "last_affected"
                    else None,
                    "evaluation_state": "supported",
                }
            )
    versions = value.get("versions", [])
    if not isinstance(versions, list) or len(versions) > 100:
        raise NormalizationRejected("invalid_osv_versions")
    for version in versions:
        parsed = _bounded_ascii(version, code="invalid_osv_version", maximum=200)
        output.append(
            {
                "range_type": "EXACT",
                "expression": parsed,
                "introduced": parsed,
                "fixed": None,
                "last_affected": parsed,
                "evaluation_state": "supported",
            }
        )
    return output


def transform_osv_records(
    records: tuple[Mapping[str, Any], ...],
    *,
    source_id: str,
    authority_policy: AuthorityPolicy | None = None,
    source_url: str = "https://github.com/ossf/malicious-packages",
) -> tuple[Mapping[str, Any], ...]:
    """Convert bounded OSV records to the closed CP-0B2 normalization shape."""
    transformed: list[Mapping[str, Any]] = []
    for source_record in records:
        advisory_id = _bounded_ascii(
            source_record.get("id"),
            code="invalid_osv_id",
            maximum=160,
        )
        affected = source_record.get("affected")
        if not isinstance(affected, list) or not affected or len(affected) > 100:
            raise NormalizationRejected("invalid_osv_affected")
        withdrawn = source_record.get("withdrawn") is not None
        state = "withdrawn" if withdrawn else "active"
        claim_type = "malicious" if source_id == OPENSSF_MALICIOUS else "vulnerable"
        for index, entry in enumerate(affected):
            if not isinstance(entry, Mapping):
                raise NormalizationRejected("invalid_osv_affected_entry")
            package = entry.get("package")
            if not isinstance(package, Mapping):
                raise NormalizationRejected("invalid_osv_package")
            ecosystem = _ecosystem(package.get("ecosystem"))
            name = _bounded_ascii(
                package.get("name"),
                code="invalid_osv_package_name",
                maximum=300,
            )
            ranges = _osv_ranges(entry, ecosystem=ecosystem)
            exact_versions = tuple(
                dict.fromkeys(
                    value["expression"]
                    for value in ranges
                    if value["range_type"] == "EXACT" and value["evaluation_state"] == "supported"
                )
            )
            variants: tuple[tuple[str | None, list[dict[str, Any]]], ...]
            if source_id == OPENSSF_MALICIOUS and exact_versions:
                exact_variants = tuple(
                    (
                        version,
                        [
                            value
                            for value in ranges
                            if value["range_type"] == "EXACT" and value["expression"] == version
                        ],
                    )
                    for version in exact_versions
                )
                nonexact_ranges = [value for value in ranges if value["range_type"] != "EXACT"]
                variants = exact_variants + (((None, nonexact_ranges),) if nonexact_ranges else ())
            else:
                variants = ((None, ranges),)
            for variant_index, (version, variant_ranges) in enumerate(variants):
                lineage = None
                confidence = "probable"
                if source_id == OPENSSF_MALICIOUS:
                    policy = authority_policy or load_authority_policy()
                    try:
                        evaluation = evaluate_direct_openssf(
                            advisory_id=advisory_id,
                            source_url=source_url,
                            ecosystem=ecosystem,
                            exact=version is not None,
                            withdrawn=withdrawn,
                            policy=policy,
                        )
                    except AuthorityPolicyError as error:
                        raise NormalizationRejected("invalid_malware_authority") from error
                    lineage = evaluation.lineage(policy=policy)
                    confidence = evaluation.claim_confidence
                transformed.append(
                    {
                        "record_id": stable_id(
                            "source-record",
                            advisory_id,
                            str(index),
                            str(variant_index),
                            version or "unresolved",
                        ),
                        "artifact": {
                            "ecosystem": ecosystem,
                            "name": name,
                            "version": version,
                            "digest": None,
                        },
                        "claims": [
                            {
                                "claim_type": claim_type,
                                "predicate": "affected_by_advisory",
                                "object_value": stable_id("upstream-advisory", advisory_id),
                                "confidence": confidence,
                                "state": state,
                            }
                        ],
                        "affected_ranges": variant_ranges,
                        "relationships": [],
                        **({"source_lineage": lineage} if lineage is not None else {}),
                    }
                )
    return tuple(transformed)


def _github_exact_version(value: Any) -> str:
    expression = _bounded_ascii(
        value,
        code="invalid_github_vulnerable_range",
        maximum=1000,
    )
    matched = re.fullmatch(r"=\s*([A-Za-z0-9._+:/@-]{1,200})", expression)
    if matched is None:
        raise NormalizationRejected("github_non_exact_malware_range")
    return matched.group(1)


def _github_reviewed_nonexact_range(value: Any) -> None:
    expression = _bounded_ascii(
        value,
        code="invalid_github_vulnerable_range",
        maximum=1000,
    )
    if GITHUB_COMPARATOR_RANGE_PATTERN.fullmatch(expression) is None:
        raise NormalizationRejected("invalid_github_vulnerable_range")


def _minimize_github_reference_scope(references: list[str]) -> tuple[list[str], int]:
    supported: list[str] = []
    excluded = 0
    for reference in references:
        try:
            parsed = urlsplit(reference)
            port = parsed.port
        except ValueError as error:
            raise NormalizationRejected("invalid_github_reference") from error
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or port not in {None, 443}
        ):
            raise NormalizationRejected("invalid_github_reference")
        if parsed.fragment:
            excluded += 1
            continue
        supported.append(reference)
    return supported, excluded


def _canonical_github_reference(value: Any) -> str:
    """Preserve one provider URL while encoding non-ASCII path data safely."""
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise NormalizationRejected("invalid_github_reference")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise NormalizationRejected("invalid_github_reference") from error
    if value.isascii():
        return value
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise NormalizationRejected("invalid_github_reference")
    try:
        parsed = urlsplit(value)
    except ValueError as error:
        raise NormalizationRejected("invalid_github_reference") from error
    if not parsed.scheme.isascii() or not parsed.netloc.isascii():
        raise NormalizationRejected("invalid_github_reference")
    canonical = urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            quote(parsed.path, safe="/:@!$&'()*+,;=-._~%"),
            quote(parsed.query, safe="/?:@!$&'()*+,;=-._~%"),
            quote(parsed.fragment, safe="/?:@!$&'()*+,;=-._~%"),
        )
    )
    if len(canonical) > 2048:
        raise NormalizationRejected("invalid_github_reference")
    return canonical


def _minimize_github_provider_vulnerability_scope(
    advisory: Mapping[str, Any],
) -> tuple[dict[str, Any], int]:
    vulnerabilities = advisory.get("vulnerabilities")
    if (
        not isinstance(vulnerabilities, list)
        or len(vulnerabilities) > GITHUB_MAX_PROVIDER_VULNERABILITIES
    ):
        raise NormalizationRejected("invalid_github_vulnerabilities")
    supported: list[Mapping[str, Any]] = []
    excluded = 0
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, Mapping):
            raise NormalizationRejected("invalid_github_vulnerability")
        package = vulnerability.get("package")
        if not isinstance(package, Mapping):
            raise NormalizationRejected("invalid_github_package")
        try:
            _github_ecosystem(package.get("ecosystem"))
        except NormalizationRejected as error:
            if error.code != "unsupported_osv_ecosystem":
                raise
            excluded += 1
            continue
        supported.append(vulnerability)
    return {**advisory, "vulnerabilities": supported}, excluded


def github_npm_advisory_range_expression(
    ecosystem: str,
    vulnerable_version_range: object,
) -> str | None:
    """Return a reviewed npm range expression only when the entry is non-exact."""
    if ecosystem != "npm":
        return None
    try:
        _github_exact_version(vulnerable_version_range)
    except NormalizationRejected as error:
        if error.code != "github_non_exact_malware_range":
            raise
        return normalize_github_npm_advisory_range(vulnerable_version_range)
    return None


def transform_github_advisories(
    records: tuple[Mapping[str, Any], ...],
    *,
    authority_policy: AuthorityPolicy | None = None,
) -> tuple[Mapping[str, Any], ...]:
    """Reduce GitHub malware advisories to attributable exact or npm-range facts."""
    transformed: list[Mapping[str, Any]] = []
    for source_record in records:
        if source_record.get("type") != "malware":
            raise NormalizationRejected("github_advisory_is_not_malware")
        advisory_id = _bounded_ascii(
            source_record.get("ghsa_id"),
            code="invalid_github_advisory_id",
            maximum=80,
        )
        vulnerabilities = source_record.get("vulnerabilities")
        if not isinstance(vulnerabilities, list) or len(vulnerabilities) > 500:
            raise NormalizationRejected("invalid_github_vulnerabilities")
        state = "withdrawn" if source_record.get("withdrawn_at") is not None else "active"
        policy = authority_policy or load_authority_policy()
        range_groups: dict[tuple[str, str], list[str]] = {}
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, Mapping):
                raise NormalizationRejected("invalid_github_vulnerability")
            package = vulnerability.get("package")
            if not isinstance(package, Mapping):
                raise NormalizationRejected("invalid_github_package")
            ecosystem = _github_ecosystem(package.get("ecosystem"))
            name = _bounded_ascii(
                package.get("name"),
                code="invalid_github_package_name",
                maximum=300,
            )
            raw_range = vulnerability.get("vulnerable_version_range")
            try:
                version = _github_exact_version(raw_range)
            except NormalizationRejected as error:
                if error.code != "github_non_exact_malware_range":
                    raise
                expression = github_npm_advisory_range_expression(ecosystem, raw_range)
                if ecosystem != "npm" or expression is None:
                    raise NormalizationRejected("github_unsupported_malware_range") from error
                expressions = range_groups.setdefault((ecosystem, name), [])
                if expression not in expressions:
                    expressions.append(expression)
                continue
            try:
                evaluation = evaluate_github_malware(
                    source_record,
                    ecosystem=ecosystem,
                    package_name=name,
                    version=version,
                    policy=policy,
                )
            except AuthorityPolicyError as error:
                raise NormalizationRejected("invalid_malware_authority") from error
            transformed.append(
                {
                    "record_id": stable_id(
                        "source-record",
                        advisory_id,
                        ecosystem,
                        name,
                        version,
                    ),
                    "artifact": {
                        "ecosystem": ecosystem,
                        "name": name,
                        "version": version,
                        "digest": None,
                    },
                    "claims": [
                        {
                            "claim_type": "malicious",
                            "predicate": "affected_by_advisory",
                            "object_value": stable_id(
                                "upstream-advisory",
                                advisory_id,
                            ),
                            "confidence": evaluation.claim_confidence,
                            "state": state,
                        }
                    ],
                    "affected_ranges": [
                        {
                            "range_type": "EXACT",
                            "expression": version,
                            "introduced": version,
                            "fixed": None,
                            "last_affected": version,
                            "evaluation_state": "supported",
                        }
                    ],
                    "relationships": [],
                    "source_lineage": evaluation.lineage(policy=policy),
                }
            )
        for (ecosystem, name), expressions in range_groups.items():
            try:
                evaluation = evaluate_github_malware(
                    source_record,
                    ecosystem=ecosystem,
                    package_name=name,
                    version=None,
                    policy=policy,
                )
            except AuthorityPolicyError as error:
                raise NormalizationRejected("invalid_malware_authority") from error
            transformed.append(
                {
                    "record_id": stable_id(
                        "source-record",
                        advisory_id,
                        ecosystem,
                        name,
                        "range-set",
                    ),
                    "artifact": {
                        "ecosystem": ecosystem,
                        "name": name,
                        "version": None,
                        "digest": None,
                    },
                    "claims": [
                        {
                            "claim_type": "malicious",
                            "predicate": "affected_by_advisory",
                            "object_value": stable_id(
                                "upstream-advisory",
                                advisory_id,
                            ),
                            "confidence": evaluation.claim_confidence,
                            "state": state,
                        }
                    ],
                    "affected_ranges": [
                        {
                            "range_type": "SEMVER",
                            "expression": expression,
                            "introduced": None,
                            "fixed": None,
                            "last_affected": None,
                            "evaluation_state": "supported",
                        }
                        for expression in sorted(expressions)
                    ],
                    "relationships": [],
                    "source_lineage": evaluation.lineage(policy=policy),
                }
            )
    return tuple(transformed)


def filter_github_advisory(
    advisory: Mapping[str, Any],
    *,
    preserve_patched_versions: bool = False,
    preserve_public_context: bool = False,
) -> dict[str, Any]:
    """Keep only the reviewed provider fields needed for evidence and policy."""
    required = {
        "ghsa_id",
        "type",
        "published_at",
        "updated_at",
        "withdrawn_at",
        "html_url",
        "vulnerabilities",
    }
    if not required <= set(advisory):
        raise NormalizationRejected("missing_github_advisory_field")
    references = advisory.get("references") or []
    if not isinstance(references, list) or len(references) > GITHUB_MAX_REFERENCES:
        raise NormalizationRejected("invalid_github_references")
    filtered_references: list[str] = []
    for value in references:
        parsed = _canonical_github_reference(value)
        if parsed not in filtered_references:
            filtered_references.append(parsed)
    identifiers = advisory.get("identifiers") or []
    if not isinstance(identifiers, list) or len(identifiers) > 100:
        raise NormalizationRejected("invalid_github_identifiers")
    filtered_identifiers: list[dict[str, str]] = []
    for value in identifiers:
        if not isinstance(value, Mapping) or set(value) != {"type", "value"}:
            raise NormalizationRejected("invalid_github_identifier")
        filtered_identifiers.append(
            {
                "type": _bounded_ascii(
                    value["type"],
                    code="invalid_github_identifier",
                    maximum=40,
                ),
                "value": _bounded_ascii(
                    value["value"],
                    code="invalid_github_identifier",
                    maximum=160,
                ),
            }
        )
    cwes = advisory.get("cwes") or []
    if not isinstance(cwes, list) or len(cwes) > 100:
        raise NormalizationRejected("invalid_github_cwes")
    filtered_cwes: list[dict[str, str]] = []
    for value in cwes:
        if not isinstance(value, Mapping) or not isinstance(value.get("cwe_id"), str):
            raise NormalizationRejected("invalid_github_cwe")
        cwe_id = _bounded_ascii(
            value["cwe_id"],
            code="invalid_github_cwe",
            maximum=20,
        )
        if re.fullmatch(r"CWE-[1-9][0-9]{0,5}", cwe_id) is None:
            raise NormalizationRejected("invalid_github_cwe")
        if {"cwe_id": cwe_id} not in filtered_cwes:
            filtered_cwes.append({"cwe_id": cwe_id})
    vulnerabilities = advisory["vulnerabilities"] or []
    if not isinstance(vulnerabilities, list) or len(vulnerabilities) > 1000:
        raise NormalizationRejected("invalid_github_vulnerabilities")
    filtered_vulnerabilities: list[dict[str, Any]] = []
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, Mapping):
            raise NormalizationRejected("invalid_github_vulnerability")
        package = vulnerability.get("package")
        if package is not None and not isinstance(package, Mapping):
            raise NormalizationRejected("invalid_github_package")
        if package is None:
            filtered_vulnerabilities.append(
                {
                    "package": None,
                    "vulnerable_version_range": vulnerability.get("vulnerable_version_range"),
                }
            )
            continue
        filtered_vulnerabilities.append(
            {
                "package": {
                    "ecosystem": package.get("ecosystem"),
                    "name": package.get("name"),
                },
                "vulnerable_version_range": vulnerability.get("vulnerable_version_range"),
            }
        )
    if preserve_patched_versions:
        for original, filtered in zip(vulnerabilities, filtered_vulnerabilities, strict=True):
            if "first_patched_version" in original:
                patched = original["first_patched_version"]
                if patched is not None and (
                    not isinstance(patched, str)
                    or not 1 <= len(patched) <= 200
                    or not patched.isascii()
                    or not patched.isprintable()
                    or patched.strip() != patched
                ):
                    raise NormalizationRejected("invalid_github_first_patched_version")
                filtered["first_patched_version"] = patched
    context = {}
    if preserve_public_context:
        from smithguard.advisory_context import permitted_github_context

        context = permitted_github_context(advisory)
    return {
        "ghsa_id": advisory["ghsa_id"],
        "type": advisory["type"],
        "published_at": advisory["published_at"],
        "updated_at": advisory["updated_at"],
        "withdrawn_at": advisory["withdrawn_at"],
        "html_url": advisory["html_url"],
        "identifiers": filtered_identifiers,
        "cwes": filtered_cwes,
        "references": filtered_references,
        "vulnerabilities": filtered_vulnerabilities,
        **context,
    }


def _minimize_github_publication_scope(
    advisory: Mapping[str, Any],
) -> tuple[dict[str, Any], int]:
    """Remove entries outside SmithGuard's exact and npm-comparator scope."""
    minimized, reasons = _minimize_github_publication_scope_with_reasons(advisory)
    return minimized, sum(count for _reason, count in reasons)


def _minimize_github_publication_scope_with_reasons(
    advisory: Mapping[str, Any],
) -> tuple[dict[str, Any], tuple[tuple[str, int], ...]]:
    """Return minimized evidence plus bounded private exclusion reason counts."""
    in_scope_advisory, excluded_ecosystems = _minimize_github_provider_vulnerability_scope(advisory)
    reasons: Counter[str] = Counter()
    reasons["unsupported_ecosystem"] += excluded_ecosystems
    filtered = filter_github_advisory(in_scope_advisory)
    references, excluded_references = _minimize_github_reference_scope(filtered["references"])
    reasons["reference_fragment"] += excluded_references
    filtered = {**filtered, "references": references}
    supported: list[dict[str, Any]] = []
    for vulnerability in filtered["vulnerabilities"]:
        package = vulnerability["package"]
        try:
            ecosystem = _github_ecosystem(package.get("ecosystem"))
        except NormalizationRejected as error:
            if error.code != "unsupported_osv_ecosystem":
                raise
            reasons["unsupported_ecosystem"] += 1
            continue
        try:
            _github_exact_version(vulnerability.get("vulnerable_version_range"))
        except NormalizationRejected as error:
            if error.code != "github_non_exact_malware_range":
                raise
            if (
                github_npm_advisory_range_expression(
                    ecosystem,
                    vulnerability.get("vulnerable_version_range"),
                )
                is not None
            ):
                supported.append(vulnerability)
                continue
            _github_reviewed_nonexact_range(vulnerability.get("vulnerable_version_range"))
            reasons["unsupported_range"] += 1
            continue
        supported.append(vulnerability)
    return (
        {**filtered, "vulnerabilities": supported},
        tuple(sorted((reason, count) for reason, count in reasons.items() if count)),
    )


def project_github_advisory_publication_scope(
    advisory: Mapping[str, Any],
) -> tuple[dict[str, Any], int]:
    """Expose the collector's exact reviewed scope for inventory reconciliation."""
    return _minimize_github_publication_scope(advisory)


def _validate_endpoint(spec: CollectorSpec, canonical_url: str) -> None:
    parsed = urlsplit(canonical_url)
    host = (parsed.hostname or "").lower().rstrip(".")
    if host not in spec.endpoint_hosts or not any(
        parsed.path.startswith(prefix) for prefix in spec.endpoint_path_prefixes
    ):
        raise CollectorBoundaryError("transport response is outside the fixed endpoint")


def _append_checkpoint(
    session: Session,
    *,
    source_id: str,
    checkpoint_token: str | None,
    result: str,
    record_count: int,
    byte_count: int,
    duration_ms: int,
    reason_code: str,
    occurred_at: datetime,
) -> CollectorCheckpointRecord:
    sequence = session.scalar(text(f"SELECT nextval('{CHECKPOINT_SEQUENCE}')"))
    if not isinstance(sequence, int) or sequence < 1:
        raise CollectorBoundaryError("collector checkpoint sequence is unavailable")
    token_hash = (
        sha256_id(checkpoint_token.encode("utf-8")) if checkpoint_token is not None else None
    )
    values = {
        "checkpoint_event_id": stable_id("collector-checkpoint", source_id, str(sequence)),
        "source_id": source_id,
        "sequence": sequence,
        "checkpoint_token_hash": token_hash,
        "result": result,
        "record_count": record_count,
        "byte_count": byte_count,
        "duration_ms": duration_ms,
        "reason_code": reason_code,
        "occurred_at": occurred_at,
    }
    hash_values = {**values, "occurred_at": timestamp(occurred_at)}
    record = CollectorCheckpointRecord(
        **values,
        record_hash=sha256_id(canonical_json_bytes(hash_values)),
    )
    session.add(record)
    session.flush()
    return record


class CollectorRunner:
    """Run public collectors only through an explicitly injected transport."""

    def __init__(
        self,
        *,
        registry: RightsRegistry,
        evidence_store: EvidenceStore,
        transport: Transport | None = None,
        clock: Callable[[], datetime] | None = None,
        authority_policy: AuthorityPolicy | None = None,
        governance_policy: SourceGovernancePolicy | None = None,
    ) -> None:
        self._registry = registry
        self._evidence_store = evidence_store
        self._transport = transport
        self._clock = clock or (lambda: datetime.now(UTC))
        self._authority_policy = authority_policy or load_authority_policy()
        self._governance_policy = governance_policy or SourceGovernancePolicy.from_path(
            DEFAULT_GOVERNANCE_POLICY_PATH,
            registry=registry,
        )
        if self._authority_policy.source_rights_register_id != registry.register_id:
            raise CollectorBoundaryError("authority policy and rights register differ")

    def _public_transform(
        self,
        spec: CollectorSpec,
        source_id: str,
        source_url: str,
    ) -> Callable[[tuple[dict[str, Any], ...]], tuple[dict[str, Any], ...]]:
        if spec.parser == "osv":
            return lambda records: transform_osv_records(
                records,
                source_id=source_id,
                authority_policy=self._authority_policy,
                source_url=source_url,
            )
        if spec.parser == "github_advisory_rest":
            return lambda records: transform_github_advisories(
                records,
                authority_policy=self._authority_policy,
            )
        raise CollectorBoundaryError("public collector parser is unsupported")

    def run_public(
        self,
        session: Session,
        *,
        source_id: str,
        previous_checkpoint: str | None = None,
        operating_mode: str = "updates",
        limits: AcquisitionLimits | None = None,
        deadline: OperationDeadline | None = None,
        retry_quarantined: bool = False,
        retry_token: str | None = None,
        processing_version: str = DEFAULT_PROCESSING_VERSION,
        record_transform_override: (
            Callable[[tuple[dict[str, Any], ...]], tuple[dict[str, Any], ...]] | None
        ) = None,
    ) -> CollectorRun:
        spec = COLLECTOR_SPECS[source_id]
        profile = self._registry.get(source_id)
        if not spec.public_canonical or not profile.is_public_output_approved:
            raise CollectorBoundaryError("source is not a public canonical collector")
        if spec.parser not in {"osv", "github_advisory_rest"}:
            raise CollectorBoundaryError("public collector parser is unsupported")
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise CollectorBoundaryError("collector clock must be timezone-aware")
        if self._transport is None:
            checkpoint = _append_checkpoint(
                session,
                source_id=source_id,
                checkpoint_token=previous_checkpoint,
                result="disabled",
                record_count=0,
                byte_count=0,
                duration_ms=0,
                reason_code="transport_not_injected",
                occurred_at=now,
            )
            return CollectorRun(checkpoint.checkpoint_event_id, None)

        try:
            self._governance_policy.authorize_collection(
                connector_id=spec.connector_id,
                source_id=source_id,
                acquisition_method=spec.collection_method,
                operating_mode=operating_mode,
                canonical_url=spec.preflight_url,
                source_record_id=f"preflight:{source_id}",
                authorized_at=now,
            )
        except SourceGovernanceError:
            checkpoint = _append_checkpoint(
                session,
                source_id=source_id,
                checkpoint_token=previous_checkpoint,
                result="disabled",
                record_count=0,
                byte_count=0,
                duration_ms=0,
                reason_code="source_governance_rejected",
                occurred_at=now,
            )
            return CollectorRun(checkpoint.checkpoint_event_id, None)

        response = self._transport(spec, previous_checkpoint)
        _validate_endpoint(spec, response.canonical_url)
        record_transform = record_transform_override or self._public_transform(
            spec,
            source_id,
            response.canonical_url,
        )
        try:
            governance = self._governance_policy.authorize_collection(
                connector_id=spec.connector_id,
                source_id=source_id,
                acquisition_method=spec.collection_method,
                operating_mode=operating_mode,
                canonical_url=response.canonical_url,
                source_record_id=response.source_record_id,
                authorized_at=now,
            )
        except SourceGovernanceError as error:
            raise CollectorBoundaryError(str(error)) from error
        outcome = ingest_bytes(
            session,
            evidence_store=self._evidence_store,
            source=profile.source,
            governance=governance,
            request=AcquisitionRequest(
                source_record_id=response.source_record_id,
                canonical_url=response.canonical_url,
                retrieved_at=response.retrieved_at,
                source_published_at=response.source_published_at,
                source_modified_at=response.source_modified_at,
                media_type=response.media_type,
                declared_content_length=response.declared_content_length,
                redirect_count=response.redirect_count,
                transport_elapsed_seconds=response.elapsed_seconds,
            ),
            body=response.body,
            idempotency_key=(
                response.checkpoint_token
                or sha256_id(response.body) + ":" + response.source_record_id
            ),
            collection_method=spec.collection_method,
            identity_verification="verified",
            signature_state="unsupported",
            limits=limits,
            record_transform=record_transform,
            allow_empty_transformed_records=(
                spec.parser == "github_advisory_rest" or record_transform_override is not None
            ),
            deadline=deadline,
            retry_quarantined=retry_quarantined,
            retry_token=retry_token,
            processing_version=processing_version,
        )
        checkpoint = _append_checkpoint(
            session,
            source_id=source_id,
            checkpoint_token=response.checkpoint_token,
            result=outcome.outcome,
            record_count=outcome.record_count,
            byte_count=len(response.body),
            duration_ms=max(0, round(response.elapsed_seconds * 1000)),
            reason_code=(
                "ingestion_accepted"
                if outcome.outcome == "accepted"
                else outcome.quarantine_reasons[0]
            ),
            occurred_at=response.retrieved_at,
        )
        return CollectorRun(checkpoint.checkpoint_event_id, outcome)


@dataclass(frozen=True, slots=True)
class GitHubAdvisoryCollection:
    advisory_id: str
    published_at: datetime
    updated_at: datetime
    withdrawn: bool
    outcome: IngestionOutcome


@dataclass(frozen=True, slots=True)
class GitHubCollectionRun:
    lane: Literal["historical", "updates"]
    state: Literal["in_progress", "complete", "failed"]
    page_count: int
    source_record_count: int
    normalized_record_count: int
    collections: tuple[GitHubAdvisoryCollection, ...]
    page_processed: bool
    page_source_record_count: int
    page_normalized_record_count: int
    has_scope_gap: bool = False
    page_excluded_scope_entry_count: int = 0
    page_scope_exclusion_reasons: tuple[tuple[str, int], ...] = ()
    reason_code: str | None = None
    not_before: datetime | None = None
    window_ended_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class _GitHubAdvisoryIngestion:
    collection: GitHubAdvisoryCollection | None
    excluded_scope_entries: int
    outcome: IngestionOutcome | None = None
    scope_exclusion_reasons: tuple[tuple[str, int], ...] = ()
    catalog_package_entry_count: int = 0
    catalog_append_result: CatalogAppendResult | None = None


class _GitHubPageFailure(Exception):
    """Leave the page savepoint before persisting its failed progress receipt."""

    def __init__(self, progress: dict[str, Any], result_reason: str | None):
        self.progress = progress
        self.result_reason = result_reason


@dataclass(frozen=True, slots=True)
class GitHubAdvisoryBackfill:
    collection: GitHubAdvisoryCollection
    excluded_scope_entry_count: int
    scope_exclusion_reasons: tuple[tuple[str, int], ...]
    catalog_package_entry_count: int = 0
    catalog_append_result: CatalogAppendResult | None = None


@dataclass(frozen=True, slots=True)
class _BoundedHTTPResponse:
    body: bytes
    url: str
    headers: Mapping[str, str]
    links: Mapping[str, Mapping[str, str]]
    elapsed_seconds: float


class GitHubAdvisoryRestCollector:
    """One-page resumable GitHub advisory collection with isolated type state."""

    BASE_ENDPOINT = "https://api.github.com/advisories"
    MAX_RESPONSE_BYTES = 8 * 1024 * 1024
    MAX_OPERATION_SECONDS = 120.0
    PAGE_SIZE = 100
    PROCESSING_VERSION = "github-advisory-rest-11"
    INITIAL_UPDATE_LOOKBACK = timedelta(hours=24)
    UPDATE_WINDOW_OVERLAP = timedelta(hours=1)
    CURSOR_PATTERN = re.compile(r"^[A-Za-z0-9._~+=%/-]{1,500}$")
    QUARANTINE_GAP_REASONS = frozenset(
        {
            "github_page_accepted_with_quarantine",
            "github_lane_complete_with_quarantine",
            "github_page_quarantined_retryable",
        }
    )
    SCOPE_GAP_REASONS = frozenset(
        {
            "github_page_accepted_with_scope_exclusion",
            "github_page_accepted_after_scope_exclusion",
            "github_lane_complete_with_scope_exclusion",
        }
    )
    TERMINAL_CONFLICT_REASONS = frozenset(
        {
            "github_lane_complete_with_replay_conflict",
            "github_lane_complete_with_revision_conflict",
            "github_lane_complete_with_multiple_conflicts",
        }
    )

    def __init__(
        self,
        *,
        registry: RightsRegistry,
        evidence_store: EvidenceStore,
        client: httpx.Client | None = None,
        clock: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] = monotonic,
        authority_policy: AuthorityPolicy | None = None,
        governance_policy: SourceGovernancePolicy | None = None,
        advisory_type: Literal[
            "legacy-malware", "malware", "reviewed", "unreviewed"
        ] = "legacy-malware",
        catalog_mode: bool = False,
        historical_cutoff: datetime | None = None,
    ) -> None:
        self._registry = registry
        self._evidence_store = evidence_store
        self._client = client
        self._clock = clock or (lambda: datetime.now(UTC))
        self._monotonic_clock = monotonic_clock
        self._authority_policy = authority_policy or load_authority_policy()
        self._governance_policy = governance_policy or SourceGovernancePolicy.from_path(
            DEFAULT_GOVERNANCE_POLICY_PATH,
            registry=registry,
        )
        if advisory_type not in {"legacy-malware", "malware", "reviewed", "unreviewed"}:
            raise CollectorBoundaryError("GitHub advisory type is invalid")
        if catalog_mode != (advisory_type != "legacy-malware"):
            raise CollectorBoundaryError("GitHub catalog mode and advisory type differ")
        self._segment = advisory_type
        self._provider_type = "malware" if advisory_type == "legacy-malware" else advisory_type
        self._catalog_mode = catalog_mode
        self._catalog_processing_version = f"github-advisory-catalog-7-{self._provider_type}"
        if historical_cutoff is not None:
            if historical_cutoff.tzinfo is None or historical_cutoff.utcoffset() is None:
                raise CollectorBoundaryError("GitHub historical cutoff must be timezone-aware")
            historical_cutoff = historical_cutoff.astimezone(UTC)
        self._historical_cutoff = historical_cutoff
        if self._authority_policy.source_rights_register_id != registry.register_id:
            raise CollectorBoundaryError("authority policy and rights register differ")

    @staticmethod
    def _parse_time(value: Any, *, field: str) -> datetime:
        parsed = _bounded_ascii(value, code=f"invalid_github_{field}", maximum=64)
        try:
            return parse_timestamp(parsed, maximum=64)
        except ValueError as error:
            raise CollectorBoundaryError(f"GitHub {field} is invalid") from error

    @staticmethod
    def _decode_page(
        body: bytes,
        *,
        deadline: OperationDeadline,
    ) -> tuple[dict[str, Any], ...]:
        try:
            deadline.check()
            document = strict_json_loads(
                body.decode("utf-8", errors="strict"),
                max_nodes=INGEST_JSON_MAX_NODES,
                max_depth=INGEST_JSON_MAX_DEPTH,
                on_node=deadline.check,
            )
            deadline.check()
        except AcquisitionRejected:
            # The shared deadline fires from inside the parse; it is not a JSON defect.
            raise
        except (UnicodeDecodeError, RecursionError) as error:
            raise CollectorBoundaryError("GitHub response is not valid JSON") from error
        except DuplicateJsonKeyError as error:
            raise CollectorBoundaryError("GitHub response contains a duplicate JSON key") from error
        except ValueError as error:
            reason = getattr(error, "reason", None)
            if reason == "non_finite":
                raise CollectorBoundaryError(
                    "GitHub response has an invalid JSON number"
                ) from error
            if reason in {"too_many_nodes", "too_deep"}:
                raise CollectorBoundaryError("GitHub response exceeds its bounded shape") from error
            raise CollectorBoundaryError("GitHub response is not valid JSON") from error
        if (
            not isinstance(document, list)
            or len(document) > 100
            or not all(isinstance(value, dict) for value in document)
        ):
            raise CollectorBoundaryError("GitHub response has an invalid page shape")
        return tuple(document)

    def _latest_progress(
        self,
        session: Session,
        lane: Literal["historical", "updates"],
    ) -> CollectorProgressRecord | None:
        return session.scalar(
            select(CollectorProgressRecord)
            .where(
                CollectorProgressRecord.source_id == GITHUB_ADVISORY,
                CollectorProgressRecord.segment == self._segment,
                CollectorProgressRecord.lane == lane,
            )
            .order_by(CollectorProgressRecord.sequence.desc())
            .limit(1)
        )

    @staticmethod
    def _progress_time(
        first: datetime | None,
        second: datetime | None,
        *,
        oldest: bool,
    ) -> datetime | None:
        values = [value for value in (first, second) if value is not None]
        if not values:
            return None
        return min(values) if oldest else max(values)

    def _append_progress(
        self,
        session: Session,
        *,
        lane: Literal["historical", "updates"],
        state: Literal["in_progress", "complete", "failed"],
        cursor_parameter: str | None,
        cursor_value: str | None,
        page_count: int,
        source_record_count: int,
        normalized_record_count: int,
        window_started_at: datetime | None,
        window_ended_at: datetime | None,
        oldest_published_at: datetime | None,
        newest_published_at: datetime | None,
        reason_code: str,
        occurred_at: datetime,
        not_before: datetime | None = None,
    ) -> CollectorProgressRecord:
        lock_name = f"collector-progress:{GITHUB_ADVISORY}:{self._segment}:{lane}"
        advisory_xact_lock(session, lock_name)
        sequence = (
            session.scalar(
                select(func.max(CollectorProgressRecord.sequence)).where(
                    CollectorProgressRecord.source_id == GITHUB_ADVISORY,
                    CollectorProgressRecord.segment == self._segment,
                    CollectorProgressRecord.lane == lane,
                )
            )
            or 0
        ) + 1
        values = {
            "progress_event_id": stable_id(
                "collector-progress",
                GITHUB_ADVISORY,
                self._segment,
                lane,
                str(sequence),
            ),
            "source_id": GITHUB_ADVISORY,
            "segment": self._segment,
            "lane": lane,
            "sequence": sequence,
            "state": state,
            "cursor_value": cursor_value,
            "cursor_parameter": cursor_parameter,
            "page_count": page_count,
            "source_record_count": source_record_count,
            "normalized_record_count": normalized_record_count,
            "window_started_at": window_started_at,
            "window_ended_at": window_ended_at,
            "oldest_published_at": oldest_published_at,
            "newest_published_at": newest_published_at,
            "not_before": not_before,
            "reason_code": reason_code,
            "occurred_at": occurred_at,
        }
        hash_values = {
            **values,
            "window_started_at": (
                timestamp(window_started_at) if window_started_at is not None else None
            ),
            "window_ended_at": (
                timestamp(window_ended_at) if window_ended_at is not None else None
            ),
            "oldest_published_at": (
                timestamp(oldest_published_at) if oldest_published_at is not None else None
            ),
            "newest_published_at": (
                timestamp(newest_published_at) if newest_published_at is not None else None
            ),
            "not_before": timestamp(not_before) if not_before is not None else None,
            "occurred_at": timestamp(occurred_at),
        }
        record = CollectorProgressRecord(
            **values,
            record_hash=sha256_id(canonical_json_bytes(hash_values)),
        )
        session.add(record)
        session.flush()
        return record

    @staticmethod
    def _format_search_time(value: datetime) -> str:
        return timestamp(value).replace("+00:00", "Z")

    def _request_parameters(
        self,
        *,
        lane: Literal["historical", "updates"],
        cursor_parameter: str | None,
        cursor_value: str | None,
        window_started_at: datetime | None,
        window_ended_at: datetime | None,
    ) -> dict[str, str]:
        parameters = {
            "type": self._provider_type,
            "sort": "published" if lane == "historical" else "updated",
            "direction": "desc",
            "per_page": str(self.PAGE_SIZE),
        }
        if lane == "updates":
            if window_started_at is None or window_ended_at is None:
                raise CollectorBoundaryError("update collection window is missing")
            parameters["modified"] = (
                f"{self._format_search_time(window_started_at)}"
                f"..{self._format_search_time(window_ended_at)}"
            )
        elif self._catalog_mode:
            if window_ended_at is None:
                raise CollectorBoundaryError("historical collection cutoff is missing")
            parameters["published"] = f"<={self._format_search_time(window_ended_at)}"
        if (cursor_parameter is None) != (cursor_value is None):
            raise CollectorBoundaryError("GitHub cursor is incomplete")
        if cursor_parameter is not None:
            if cursor_parameter not in {"before", "after"}:
                raise CollectorBoundaryError("GitHub cursor parameter is invalid")
            if self.CURSOR_PATTERN.fullmatch(cursor_value or "") is None:
                raise CollectorBoundaryError("GitHub cursor value is invalid")
            parameters[cursor_parameter] = cursor_value or ""
        return parameters

    def _endpoint(self, parameters: Mapping[str, str]) -> str:
        return self.BASE_ENDPOINT + "?" + urlencode(parameters)

    def _next_cursor(
        self,
        response: _BoundedHTTPResponse,
        *,
        expected: Mapping[str, str],
    ) -> tuple[str | None, str | None]:
        link = response.links.get("next")
        if link is None:
            return None, None
        next_url = link.get("url")
        if not isinstance(next_url, str) or len(next_url) > 2000:
            raise CollectorBoundaryError("GitHub next-page link is invalid")
        parsed = urlsplit(next_url)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "api.github.com"
            or parsed.path != "/advisories"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise CollectorBoundaryError("GitHub next-page link left the fixed endpoint")
        query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
        if not all(len(values) == 1 for values in query.values()):
            raise CollectorBoundaryError("GitHub next-page link repeats a parameter")
        flattened = {key: values[0] for key, values in query.items()}
        cursor_parameters = [key for key in ("before", "after") if key in flattened]
        if len(cursor_parameters) != 1:
            raise CollectorBoundaryError("GitHub next-page link has no single cursor")
        cursor_parameter = cursor_parameters[0]
        cursor_value = flattened.pop(cursor_parameter)
        if flattened != dict(expected):
            raise CollectorBoundaryError("GitHub next-page link changed fixed parameters")
        if self.CURSOR_PATTERN.fullmatch(cursor_value) is None:
            raise CollectorBoundaryError("GitHub next-page cursor is invalid")
        return cursor_parameter, cursor_value

    @staticmethod
    def _retry_not_before(
        headers: Mapping[str, str],
        *,
        now: datetime,
    ) -> datetime:
        candidates: list[datetime] = []
        retry_after = headers.get("retry-after")
        if retry_after is not None:
            try:
                seconds = int(retry_after)
            except ValueError:
                try:
                    parsed = parsedate_to_datetime(retry_after)
                except (TypeError, ValueError, OverflowError):
                    parsed = None
                if parsed is not None:
                    if parsed.tzinfo is None or parsed.utcoffset() is None:
                        parsed = parsed.replace(tzinfo=UTC)
                    candidates.append(parsed.astimezone(UTC))
            else:
                if 0 <= seconds <= 86_400:
                    candidates.append(now + timedelta(seconds=seconds))
        reset = headers.get("x-ratelimit-reset")
        if reset is not None:
            with suppress(ValueError, OverflowError, OSError):
                candidates.append(datetime.fromtimestamp(int(reset), tz=UTC))
        selected = max(candidates, default=now + timedelta(minutes=5))
        return min(
            max(selected, now + timedelta(seconds=1)),
            now + timedelta(hours=24),
        )

    def _fetch_page(
        self,
        *,
        endpoint: str,
        headers: Mapping[str, str],
        now: datetime,
        deadline: OperationDeadline,
    ) -> _BoundedHTTPResponse:
        owns_client = self._client is None
        client = self._client or httpx.Client(
            timeout=httpx.Timeout(30.0, connect=10.0),
            follow_redirects=False,
        )
        started = self._monotonic_clock()
        try:
            deadline.check()
            with client.stream(
                "GET",
                endpoint,
                headers={**headers, "Accept-Encoding": "identity"},
                follow_redirects=False,
                timeout=httpx.Timeout(
                    deadline.remaining_seconds(),
                    connect=min(10.0, deadline.remaining_seconds()),
                ),
            ) as response:
                if response.status_code in {403, 429} and (
                    response.status_code == 429
                    or response.headers.get("retry-after") is not None
                    or response.headers.get("x-ratelimit-remaining") == "0"
                ):
                    raise CollectorRetryLater(
                        not_before=self._retry_not_before(response.headers, now=now)
                    )
                response.raise_for_status()
                content_encoding = response.headers.get("content-encoding", "identity").lower()
                if content_encoding not in {"", "identity"}:
                    raise CollectorBoundaryError("GitHub response encoding is invalid")
                content_length = response.headers.get("content-length")
                if content_length is not None:
                    declared_length = int(content_length)
                    if declared_length < 0 or declared_length > self.MAX_RESPONSE_BYTES:
                        raise CollectorBoundaryError("GitHub response exceeds its byte limit")
                media_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
                if media_type != "application/json":
                    raise CollectorBoundaryError("GitHub response content type is invalid")
                if str(response.url) != endpoint:
                    raise CollectorBoundaryError("GitHub response URL changed")
                body = bytearray()
                for chunk in response.iter_bytes(64 * 1024):
                    deadline.check()
                    body.extend(chunk)
                    if len(body) > self.MAX_RESPONSE_BYTES:
                        raise CollectorBoundaryError("GitHub response exceeds its byte limit")
                deadline.check()
                if content_length is not None and len(body) != int(content_length):
                    raise CollectorBoundaryError("GitHub response length changed")
                return _BoundedHTTPResponse(
                    body=bytes(body),
                    url=str(response.url),
                    headers=dict(response.headers),
                    links={key: dict(value) for key, value in response.links.items()},
                    elapsed_seconds=self._monotonic_clock() - started,
                )
        except CollectorRetryLater:
            raise
        except AcquisitionRejected:
            raise
        except (httpx.HTTPError, ValueError) as error:
            raise CollectorBoundaryError("GitHub advisory request failed") from error
        finally:
            if owns_client:
                client.close()

    def _ingest_advisory(
        self,
        session: Session,
        *,
        advisory: Mapping[str, Any],
        now: datetime,
        elapsed: float,
        lane: Literal["historical", "updates"],
        deadline: OperationDeadline,
        retry_token: str,
        source_snapshot: str | None = None,
    ) -> _GitHubAdvisoryIngestion:
        advisory_id = _bounded_ascii(
            advisory.get("ghsa_id"),
            code="invalid_github_advisory_id",
            maximum=80,
        )
        published_at = self._parse_time(
            advisory.get("published_at"),
            field="published_at",
        )
        updated_at = self._parse_time(
            advisory.get("updated_at"),
            field="updated_at",
        )
        canonical_url = _bounded_ascii(
            advisory.get("html_url"),
            code="invalid_github_advisory_url",
            maximum=500,
        )
        if advisory.get("type") != self._provider_type:
            raise CollectorBoundaryError("GitHub advisory crossed its type segment")
        if self._catalog_mode:
            accepted_advisory = filter_github_advisory(
                advisory, preserve_patched_versions=True, preserve_public_context=True
            )
            scope_exclusion_reasons: tuple[tuple[str, int], ...] = ()
        else:
            accepted_advisory, scope_exclusion_reasons = (
                _minimize_github_publication_scope_with_reasons(advisory)
            )
        excluded_scope_entries = sum(count for _reason, count in scope_exclusion_reasons)
        item_body = _bounded_canonical_body(
            [accepted_advisory], failure="GitHub advisory contains an invalid JSON number"
        )

        catalog_documents: list[Mapping[str, Any]] = []

        def capture_governed_catalog(records: tuple[Mapping[str, Any], ...]):
            # Ingestion calls this after policy projection and byte validation, before
            # resolving a prior accepted batch. Use the exact retained representation.
            if len(records) != 1 or records[0].get("ghsa_id") != advisory_id:
                raise NormalizationRejected("invalid_github_catalog_envelope")
            catalog_documents.extend(records)
            return ()

        def transport(
            _spec: CollectorSpec,
            _checkpoint: str | None,
        ) -> TransportResponse:
            return TransportResponse(
                body=item_body,
                canonical_url=canonical_url,
                media_type="application/json",
                retrieved_at=now,
                source_record_id=f"{advisory_id}:{timestamp(updated_at)}",
                source_published_at=published_at,
                source_modified_at=updated_at,
                declared_content_length=len(item_body),
                redirect_count=0,
                elapsed_seconds=elapsed,
                # Governance treats historical and update acquisition as distinct
                # operating modes. Their ingestion identity must therefore remain
                # distinct even when the same immutable advisory appears in both
                # windows. The raw evidence identity still converges on the shared
                # source record and body digest.
                checkpoint_token=(
                    f"{lane}:{advisory_id}:{timestamp(updated_at)}:{sha256_id(item_body)}"
                    + (f":{self._governance_policy.policy_sha256}" if self._catalog_mode else "")
                ),
            )

        run = CollectorRunner(
            registry=self._registry,
            evidence_store=self._evidence_store,
            transport=transport,
            clock=lambda: now,
            authority_policy=self._authority_policy,
            governance_policy=self._governance_policy,
        ).run_public(
            session,
            source_id=GITHUB_ADVISORY,
            operating_mode=lane,
            limits=AcquisitionLimits(
                max_elapsed_seconds=self.MAX_OPERATION_SECONDS,
            ),
            deadline=deadline,
            retry_quarantined=True,
            retry_token=retry_token,
            processing_version=(
                self._catalog_processing_version if self._catalog_mode else self.PROCESSING_VERSION
            ),
            record_transform_override=(capture_governed_catalog if self._catalog_mode else None),
        )
        if run.outcome is None and self._catalog_mode:
            raise IngestionSourceError("GitHub record acquisition was refused")
        if run.outcome is None or run.outcome.outcome != "accepted":
            return _GitHubAdvisoryIngestion(
                collection=None,
                excluded_scope_entries=0,
                outcome=run.outcome,
            )
        catalog_package_entry_count = 0
        appended = None
        if self._catalog_mode:
            if run.outcome.raw_evidence_id is None or run.outcome.governance_decision_id is None:
                raise CollectorBoundaryError("GitHub catalog evidence identity is missing")
            if len(catalog_documents) != 1:
                raise CollectorBoundaryError("GitHub governed catalog document is missing")
            appended = append_github_advisory(
                session,
                document=catalog_documents[0],
                evidence_id=run.outcome.raw_evidence_id,
                governance_decision_id=run.outcome.governance_decision_id,
                observed_at=now,
            )
            catalog_package_entry_count = appended.package_entry_count
            scope_exclusion_reasons = tuple(sorted(appended.package_omission_counts.items()))
            excluded_scope_entries = sum(appended.package_omission_counts.values())
            if lane == "historical":
                if source_snapshot is None:
                    raise CollectorBoundaryError("GitHub historical catalog snapshot is missing")
                append_github_inventory_membership(
                    session,
                    segment=self._provider_type,
                    source_snapshot=source_snapshot,
                    upstream_record_id=advisory_id,
                    appended=appended,
                    observed_at=now,
                )
        return _GitHubAdvisoryIngestion(
            collection=GitHubAdvisoryCollection(
                advisory_id=advisory_id,
                published_at=published_at,
                updated_at=updated_at,
                withdrawn=advisory.get("withdrawn_at") is not None,
                outcome=run.outcome,
            ),
            excluded_scope_entries=excluded_scope_entries,
            outcome=run.outcome,
            scope_exclusion_reasons=scope_exclusion_reasons,
            catalog_package_entry_count=catalog_package_entry_count,
            catalog_append_result=appended,
        )

    def _account_advisory(
        self,
        session: Session,
        *,
        advisory: Mapping[str, Any],
        outcome: IngestionOutcome | None,
        now: datetime,
        lane: Literal["historical", "updates"],
        appended: CatalogAppendResult | None = None,
    ) -> CollectionRecordOutcome:
        if outcome is None:
            raise RecordAccountingError("GitHub accounting requires an ingestion receipt")
        input_digest = sha256_id(_quarantine_body(advisory))
        raw_id = advisory.get("ghsa_id")
        record_key = (
            raw_id
            if isinstance(raw_id, str)
            and re.fullmatch(
                r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}",
                raw_id,
            )
            else f"opaque:{input_digest}"
        )
        authorization = self._governance_policy.authorize_collection(
            connector_id=COLLECTOR_SPECS[GITHUB_ADVISORY].connector_id,
            source_id=GITHUB_ADVISORY,
            acquisition_method="rest_api",
            operating_mode=lane,
            canonical_url=self.BASE_ENDPOINT,
            source_record_id=record_key,
            authorized_at=now,
        )
        try:
            updated_at = self._parse_time(advisory.get("updated_at"), field="updated_at")
        except (CollectorBoundaryError, NormalizationRejected):
            updated_at = None
        return append_outcome(
            session,
            source_id=GITHUB_ADVISORY,
            segment=self._segment,
            record_key=record_key,
            input_sha256=input_digest,
            processing_version=self._catalog_processing_version,
            policy_sha256=authorization.policy_sha256,
            rights_revision=self._registry.get(GITHUB_ADVISORY).source["revision"],
            outcome=outcome,
            catalog_event_id=appended.catalog_event_id if appended else None,
            omissions=appended.package_omission_counts if appended else {},
            source_updated_at=updated_at,
            observed_at=now,
            acquisition_lane=lane,
        )

    def backfill_advisory(
        self,
        session: Session,
        *,
        advisory_id: str,
        token: str | None = None,
        deadline: OperationDeadline | None = None,
        resolve_outcome_id: str | None = None,
    ) -> GitHubAdvisoryBackfill:
        """An unsuccessful exact repair cannot leave partial state if its caller catches it."""
        with session.begin_nested() if self._catalog_mode else nullcontext():
            return self._backfill_advisory(
                session,
                advisory_id=advisory_id,
                token=token,
                deadline=deadline,
                resolve_outcome_id=resolve_outcome_id,
            )

    def _backfill_advisory(
        self,
        session: Session,
        *,
        advisory_id: str,
        token: str | None = None,
        deadline: OperationDeadline | None = None,
        resolve_outcome_id: str | None = None,
    ) -> GitHubAdvisoryBackfill:
        """Refetch and ingest one explicit GitHub advisory without moving lane progress."""
        if re.fullmatch(r"GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}", advisory_id) is None:
            raise CollectorBoundaryError("GitHub backfill advisory ID is invalid")
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise CollectorBoundaryError("collector clock must be timezone-aware")
        now = now.astimezone(UTC)
        if token is not None and (not token or len(token) > 2048 or not token.isascii()):
            raise CollectorBoundaryError("GitHub backfill token is invalid")
        if deadline is not None and deadline.remaining_seconds() > self.MAX_OPERATION_SECONDS:
            raise CollectorBoundaryError("GitHub backfill deadline exceeds operation bound")
        deadline = deadline or OperationDeadline.start(
            self.MAX_OPERATION_SECONDS,
            clock=self._monotonic_clock,
        )
        deadline.check()
        lock_name = f"collector-run:{GITHUB_ADVISORY}:updates"
        advisory_xact_lock(session, lock_name)
        prior_outcome = None
        if self._catalog_mode:
            advisory_xact_lock(session, f"collection-accounting:{GITHUB_ADVISORY}")
        if resolve_outcome_id is not None:
            if not self._catalog_mode:
                raise CollectorBoundaryError("resolution requires catalog mode")
            prior_outcome = require_resolution_target(
                session,
                outcome_id=resolve_outcome_id,
                source_id=GITHUB_ADVISORY,
                segment=self._segment,
                record_key=advisory_id,
            )
        deadline.check()
        parameters = {
            "type": self._provider_type,
            "ghsa_id": advisory_id,
            "per_page": "1",
        }
        endpoint = self._endpoint(parameters)
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": f"SmithGuard/{__version__}",
        }
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        response = self._fetch_page(
            endpoint=endpoint,
            headers=headers,
            now=now,
            deadline=deadline,
        )
        advisories = self._decode_page(response.body, deadline=deadline)
        if len(advisories) != 1 or advisories[0].get("ghsa_id") != advisory_id:
            raise CollectorBoundaryError("GitHub backfill advisory response is not exact")
        ingestion = self._ingest_advisory(
            session,
            advisory=advisories[0],
            now=now,
            elapsed=response.elapsed_seconds,
            lane="updates",
            deadline=deadline,
            retry_token=(
                "backfill:"
                + (
                    self._catalog_processing_version
                    if self._catalog_mode
                    else self.PROCESSING_VERSION
                )
                + f":{advisory_id}"
            ),
        )
        exclusion_counts = dict(ingestion.scope_exclusion_reasons)
        if (
            ingestion.collection is None
            or (
                ingestion.catalog_package_entry_count == 0 and resolve_outcome_id is None
                if self._catalog_mode
                else ingestion.collection.outcome.record_count == 0
            )
            or exclusion_counts.get("unsupported_range", 0)
        ):
            raise CollectorBoundaryError("GitHub backfill advisory range is not publishable")
        if self._catalog_mode:
            accounted = self._account_advisory(
                session,
                advisory=advisories[0],
                outcome=ingestion.outcome,
                appended=ingestion.catalog_append_result,
                now=now,
                lane="updates",
            )
            membership = append_replay_membership(
                session,
                outcome=accounted,
                transport_sha256=sha256_id(response.body),
                observed_at=now,
            )
            if prior_outcome is not None:
                append_resolution(
                    session,
                    prior=prior_outcome,
                    replacement=accounted,
                    membership=membership,
                    resolved_at=now,
                )
        return GitHubAdvisoryBackfill(
            collection=ingestion.collection,
            excluded_scope_entry_count=ingestion.excluded_scope_entries,
            scope_exclusion_reasons=ingestion.scope_exclusion_reasons,
            catalog_package_entry_count=ingestion.catalog_package_entry_count,
            catalog_append_result=ingestion.catalog_append_result,
        )

    def _quarantine_advisory_envelope(
        self,
        session: Session,
        *,
        advisory: Mapping[str, Any],
        now: datetime,
        elapsed: float,
        lane: Literal["historical", "updates"],
        deadline: OperationDeadline,
        retry_token: str,
        failure_reason: str | None = None,
    ) -> IngestionOutcome:
        item_body = _quarantine_body(advisory)
        raw_identifier = advisory.get("ghsa_id")
        if (
            isinstance(raw_identifier, str)
            and raw_identifier.isascii()
            and re.fullmatch(r"[A-Za-z0-9._:-]{3,80}", raw_identifier)
        ):
            identifier = re.sub(r"[^a-z0-9]+", "_", raw_identifier.lower()).strip("_")
        else:
            identifier = sha256_id(item_body).removeprefix("sha256:")[:20]
        if failure_reason not in {
            None,
            "github_advisory_replay_conflict",
            "github_advisory_revision_conflict",
            "github_advisory_stale_revision",
        }:
            raise CollectorBoundaryError("unknown record quarantine reason")
        reason = failure_reason or f"invalid_github_advisory_envelope_{identifier}"[:120]
        profile = self._registry.get(GITHUB_ADVISORY)
        governance = self._governance_policy.authorize_collection(
            connector_id=COLLECTOR_SPECS[GITHUB_ADVISORY].connector_id,
            source_id=GITHUB_ADVISORY,
            acquisition_method="rest_api",
            operating_mode=lane,
            canonical_url=self.BASE_ENDPOINT,
            source_record_id=f"malformed:{identifier}",
            authorized_at=now,
        )

        def reject_envelope(
            _records: tuple[Mapping[str, Any], ...],
        ) -> tuple[Mapping[str, Any], ...]:
            raise NormalizationRejected(reason)

        outcome = ingest_bytes(
            session,
            evidence_store=self._evidence_store,
            source=profile.source,
            governance=governance,
            request=AcquisitionRequest(
                source_record_id=f"malformed:{identifier}",
                canonical_url=self.BASE_ENDPOINT,
                retrieved_at=now,
                source_published_at=None,
                source_modified_at=None,
                media_type="application/json",
                declared_content_length=len(item_body),
                redirect_count=0,
                transport_elapsed_seconds=elapsed,
            ),
            body=item_body,
            idempotency_key=(
                stable_id(
                    "github-malformed",
                    self._segment,
                    reason,
                    lane,
                    governance.policy_sha256,
                    identifier,
                    sha256_id(item_body),
                )
                if self._catalog_mode
                else f"github-malformed:{identifier}:{sha256_id(item_body)}"
            ),
            collection_method="rest_api",
            identity_verification="verified",
            signature_state="unsupported",
            limits=AcquisitionLimits(
                max_elapsed_seconds=self.MAX_OPERATION_SECONDS,
            ),
            record_transform=reject_envelope,
            deadline=deadline,
            retry_quarantined=True,
            retry_token=retry_token,
            processing_version=(
                self._catalog_processing_version if self._catalog_mode else self.PROCESSING_VERSION
            ),
        )
        if outcome.outcome != "quarantined" or outcome.quarantine_reasons != (reason,):
            raise CollectorBoundaryError("malformed GitHub advisory was not quarantined")
        return outcome

    def run(
        self,
        session: Session,
        *,
        lane: Literal["historical", "updates"],
        token: str | None = None,
    ) -> GitHubCollectionRun:
        """Commit page accounting and cursor together, including when callers catch failures."""
        if not self._catalog_mode:
            return self._run_page(session, lane=lane, token=token)
        if lane not in {"historical", "updates"}:
            raise CollectorBoundaryError("GitHub collection lane is invalid")
        # Keep coordination outside the savepoint: failure rolls back page work,
        # then appends the diagnostic without letting another page interleave.
        advisory_xact_lock(session, f"collector-run:{GITHUB_ADVISORY}:{self._segment}:{lane}")
        advisory_xact_lock(session, f"collection-accounting:{GITHUB_ADVISORY}")
        try:
            with session.begin_nested():
                return self._run_page(session, lane=lane, token=token)
        except _GitHubPageFailure as error:
            failed = self._append_progress(session, **error.progress)
            return GitHubCollectionRun(
                lane=lane,
                state="failed",
                page_count=failed.page_count,
                source_record_count=failed.source_record_count,
                normalized_record_count=failed.normalized_record_count,
                collections=(),
                page_processed=False,
                page_source_record_count=0,
                page_normalized_record_count=0,
                reason_code=error.result_reason or failed.reason_code,
                not_before=failed.not_before,
            )

    def _run_page(
        self,
        session: Session,
        *,
        lane: Literal["historical", "updates"],
        token: str | None = None,
    ) -> GitHubCollectionRun:
        """Fetch and persist one bounded page for a resumable collection lane."""
        if lane not in {"historical", "updates"}:
            raise CollectorBoundaryError("GitHub collection lane is invalid")
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise CollectorBoundaryError("collector clock must be timezone-aware")
        now = now.astimezone(UTC)
        if token is not None and (not token or len(token) > 2048 or not token.isascii()):
            raise CollectorBoundaryError("GitHub collection token is invalid")
        lock_name = f"collector-run:{GITHUB_ADVISORY}:{self._segment}:{lane}"
        advisory_xact_lock(session, lock_name)
        if self._catalog_mode:
            # Serialize accounting before any per-record ingestion/catalog locks.
            # This also avoids opposite page ordering deadlocks across lanes.
            advisory_xact_lock(session, f"collection-accounting:{GITHUB_ADVISORY}")
        prior = self._latest_progress(session, lane)
        if prior is not None and prior.not_before is not None and prior.not_before > now:
            return GitHubCollectionRun(
                lane=lane,
                state="failed",
                page_count=prior.page_count,
                source_record_count=prior.source_record_count,
                normalized_record_count=prior.normalized_record_count,
                collections=(),
                page_processed=False,
                page_source_record_count=0,
                page_normalized_record_count=0,
                reason_code=prior.reason_code,
                not_before=prior.not_before,
            )
        terminal_scope_gap = (
            prior is not None and prior.reason_code == "github_lane_complete_with_scope_exclusion"
        )
        terminal_conflict = (
            prior is not None and prior.reason_code in self.TERMINAL_CONFLICT_REASONS
        )
        historical_terminal = (
            lane == "historical"
            and prior is not None
            and (prior.state == "complete" or terminal_scope_gap or terminal_conflict)
        )
        if historical_terminal:
            return GitHubCollectionRun(
                lane=lane,
                state=prior.state,
                page_count=prior.page_count,
                source_record_count=prior.source_record_count,
                normalized_record_count=prior.normalized_record_count,
                collections=(),
                page_processed=False,
                page_source_record_count=0,
                page_normalized_record_count=0,
                has_scope_gap=terminal_scope_gap,
                reason_code=prior.reason_code if terminal_conflict else None,
            )

        terminal_update_gap = lane == "updates" and (terminal_scope_gap or terminal_conflict)
        resume = (
            prior is not None
            and prior.state in {"in_progress", "failed"}
            and not terminal_update_gap
        )
        prior_has_quarantine = (
            prior is not None and prior.reason_code in self.QUARANTINE_GAP_REASONS
        )
        prior_has_scope_gap = False
        if lane == "historical" and prior is not None:
            prior_has_scope_gap = bool(
                session.scalar(
                    select(func.count())
                    .select_from(CollectorProgressRecord)
                    .where(
                        CollectorProgressRecord.source_id == GITHUB_ADVISORY,
                        CollectorProgressRecord.segment == self._segment,
                        CollectorProgressRecord.lane == lane,
                        CollectorProgressRecord.reason_code.in_(self.SCOPE_GAP_REASONS),
                    )
                )
            )
        elif lane == "updates" and resume and prior is not None:
            prior_has_scope_gap = bool(
                session.scalar(
                    select(func.count())
                    .select_from(CollectorProgressRecord)
                    .where(
                        CollectorProgressRecord.source_id == GITHUB_ADVISORY,
                        CollectorProgressRecord.segment == self._segment,
                        CollectorProgressRecord.lane == lane,
                        CollectorProgressRecord.window_started_at == prior.window_started_at,
                        CollectorProgressRecord.window_ended_at == prior.window_ended_at,
                        CollectorProgressRecord.reason_code.in_(self.SCOPE_GAP_REASONS),
                    )
                )
            )
        cursor_parameter = prior.cursor_parameter if resume else None
        cursor_value = prior.cursor_value if resume else None
        if lane == "updates":
            if resume:
                window_started_at = prior.window_started_at
                window_ended_at = prior.window_ended_at
            else:
                # Overlap the previous window: GitHub's search index can lag its writes,
                # and re-reading an unchanged advisory is an idempotent no-op.
                window_started_at = (
                    prior.window_ended_at - self.UPDATE_WINDOW_OVERLAP
                    if prior is not None and prior.window_ended_at is not None
                    else now - self.INITIAL_UPDATE_LOOKBACK
                )
                window_ended_at = now
        else:
            window_started_at = None
            window_ended_at = (
                (
                    prior.window_ended_at
                    if prior is not None and prior.window_ended_at is not None
                    else self._historical_cutoff or now
                )
                if self._catalog_mode
                else None
            )

        page_count = prior.page_count if prior is not None else 0
        source_record_count = prior.source_record_count if prior is not None else 0
        normalized_record_count = prior.normalized_record_count if prior is not None else 0
        oldest_published_at = prior.oldest_published_at if prior is not None else None
        newest_published_at = prior.newest_published_at if prior is not None else None

        def failed_run(
            *,
            reason_code: str,
            collections: tuple[GitHubAdvisoryCollection, ...] = (),
            result_reason: str | None = None,
            not_before: datetime | None = None,
        ) -> GitHubCollectionRun:
            progress_arguments = dict(
                lane=lane,
                state="failed",
                cursor_parameter=cursor_parameter,
                cursor_value=cursor_value,
                page_count=page_count,
                source_record_count=source_record_count,
                normalized_record_count=normalized_record_count,
                window_started_at=window_started_at,
                window_ended_at=window_ended_at,
                oldest_published_at=oldest_published_at,
                newest_published_at=newest_published_at,
                reason_code=reason_code,
                occurred_at=now,
                not_before=not_before,
            )
            if self._catalog_mode:
                raise _GitHubPageFailure(progress_arguments, result_reason)
            failed = self._append_progress(session, **progress_arguments)
            return GitHubCollectionRun(
                lane=lane,
                state="failed",
                page_count=failed.page_count,
                source_record_count=failed.source_record_count,
                normalized_record_count=failed.normalized_record_count,
                collections=collections,
                page_processed=False,
                page_source_record_count=0,
                page_normalized_record_count=0,
                reason_code=result_reason,
                not_before=not_before,
            )

        parameters = self._request_parameters(
            lane=lane,
            cursor_parameter=cursor_parameter,
            cursor_value=cursor_value,
            window_started_at=window_started_at,
            window_ended_at=window_ended_at,
        )
        endpoint = self._endpoint(parameters)
        deadline = OperationDeadline.start(
            self.MAX_OPERATION_SECONDS,
            clock=self._monotonic_clock,
        )
        try:
            deadline.check()
            self._governance_policy.authorize_collection(
                connector_id=COLLECTOR_SPECS[GITHUB_ADVISORY].connector_id,
                source_id=GITHUB_ADVISORY,
                acquisition_method="rest_api",
                operating_mode=lane,
                canonical_url=endpoint,
                source_record_id=f"page:{lane}:{timestamp(now)}",
                authorized_at=now,
            )
            deadline.check()
        except (SourceGovernanceError, AcquisitionRejected) as error:
            return failed_run(
                reason_code="github_operation_deadline"
                if isinstance(error, AcquisitionRejected)
                else "github_source_governance_rejected"
            )
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": f"SmithGuard/{__version__}",
        }
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        retry_token = str((prior.sequence if prior is not None else 0) + 1)
        try:
            response = self._fetch_page(
                endpoint=endpoint,
                headers=headers,
                now=now,
                deadline=deadline,
            )
            advisories = self._decode_page(response.body, deadline=deadline)
            expected = {
                key: value for key, value in parameters.items() if key not in {"before", "after"}
            }
            next_parameter, next_cursor = self._next_cursor(
                response,
                expected=expected,
            )
        except CollectorRetryLater as error:
            return failed_run(
                reason_code="github_rate_limited",
                result_reason="github_rate_limited",
                not_before=error.not_before,
            )
        except AcquisitionRejected:
            return failed_run(reason_code="github_operation_deadline")
        except CollectorBoundaryError:
            return failed_run(reason_code="github_request_or_page_rejected")

        collected: list[GitHubAdvisoryCollection] = []
        page_normalized_record_count = 0
        page_quarantined = False
        page_outcomes: list[CollectionRecordOutcome] = []
        page_has_scope_gap = False
        page_excluded_scope_entries = 0
        page_scope_exclusion_reasons: Counter[str] = Counter()
        page_conflict_reasons: set[str] = set()
        page_oldest_published_at = oldest_published_at
        page_newest_published_at = newest_published_at
        for advisory in advisories:
            try:
                with session.begin_nested() if self._catalog_mode else nullcontext():
                    ingestion = self._ingest_advisory(
                        session,
                        advisory=advisory,
                        now=now,
                        elapsed=response.elapsed_seconds,
                        lane=lane,
                        deadline=deadline,
                        retry_token=retry_token,
                        source_snapshot=(
                            timestamp(window_ended_at)
                            if lane == "historical" and window_ended_at is not None
                            else None
                        ),
                    )
                if self._catalog_mode:
                    page_outcomes.append(
                        self._account_advisory(
                            session,
                            advisory=advisory,
                            outcome=ingestion.outcome,
                            appended=ingestion.catalog_append_result,
                            now=now,
                            lane=lane,
                        )
                    )
                collection = ingestion.collection
                page_excluded_scope_entries += ingestion.excluded_scope_entries
                page_scope_exclusion_reasons.update(dict(ingestion.scope_exclusion_reasons))
                page_has_scope_gap = bool(page_has_scope_gap or ingestion.excluded_scope_entries)
                if collection is not None:
                    page_oldest_published_at = self._progress_time(
                        page_oldest_published_at,
                        collection.published_at,
                        oldest=True,
                    )
                    page_newest_published_at = self._progress_time(
                        page_newest_published_at,
                        collection.published_at,
                        oldest=False,
                    )
                    collected.append(collection)
                    page_normalized_record_count += (
                        ingestion.catalog_package_entry_count
                        if self._catalog_mode
                        else collection.outcome.record_count
                    )
                else:
                    page_quarantined = True
            except (IngestionSourceError, AcquisitionRejected) as error:
                reason_code = (
                    "github_operation_deadline"
                    if isinstance(error, AcquisitionRejected)
                    else "github_source_governance_rejected"
                )
                return failed_run(reason_code=reason_code, collections=tuple(collected))
            except (
                IngestionReplayConflict,
                RevisionConflict,
                AdvisoryCatalogError,
                CollectorBoundaryError,
                NormalizationRejected,
            ) as error:
                conflict_reason = (
                    "github_advisory_replay_conflict"
                    if isinstance(error, IngestionReplayConflict)
                    else "github_advisory_revision_conflict"
                    if isinstance(error, RevisionConflict)
                    else "github_advisory_stale_revision"
                    if isinstance(error, AdvisoryCatalogStaleRevision)
                    else None
                )
                if conflict_reason is not None and not self._catalog_mode:
                    page_conflict_reasons.add(conflict_reason)
                    continue
                try:
                    quarantined = self._quarantine_advisory_envelope(
                        session,
                        advisory=advisory,
                        now=now,
                        elapsed=response.elapsed_seconds,
                        lane=lane,
                        deadline=deadline,
                        retry_token=retry_token,
                        failure_reason=conflict_reason,
                    )
                    if self._catalog_mode:
                        page_outcomes.append(
                            self._account_advisory(
                                session,
                                advisory=advisory,
                                outcome=quarantined,
                                now=now,
                                lane=lane,
                            )
                        )
                except AcquisitionRejected:
                    return failed_run(
                        reason_code="github_operation_deadline", collections=tuple(collected)
                    )
                except (IngestionSourceError, SourceGovernanceError):
                    return failed_run(
                        reason_code="github_source_governance_rejected",
                        collections=tuple(collected),
                    )
                except (IngestionReplayConflict, RevisionConflict) as error:
                    return failed_run(
                        reason_code=(
                            "github_advisory_revision_conflict"
                            if isinstance(error, RevisionConflict)
                            else "github_advisory_replay_conflict"
                        ),
                        collections=tuple(collected),
                    )
                page_quarantined = True
        if page_quarantined and not self._catalog_mode:
            return failed_run(
                reason_code="github_page_quarantined_retryable", collections=tuple(collected)
            )
        oldest_published_at = page_oldest_published_at
        newest_published_at = page_newest_published_at
        normalized_record_count += page_normalized_record_count
        page_count += 1
        source_record_count += len(advisories)
        persistent_gap = (
            self._catalog_mode
            and unresolved_count(
                session,
                source_id=GITHUB_ADVISORY,
                segment=self._segment,
            )
            > 0
        )
        lane_has_scope_gap = prior_has_scope_gap or page_has_scope_gap or persistent_gap
        if page_conflict_reasons:
            state = "failed"
            if next_cursor is None:
                conflict = (
                    next(iter(page_conflict_reasons))
                    if len(page_conflict_reasons) == 1
                    else "github_advisory_multiple_conflicts"
                )
                reason_code = {
                    "github_advisory_replay_conflict": (
                        "github_lane_complete_with_replay_conflict"
                    ),
                    "github_advisory_revision_conflict": (
                        "github_lane_complete_with_revision_conflict"
                    ),
                    "github_advisory_multiple_conflicts": (
                        "github_lane_complete_with_multiple_conflicts"
                    ),
                }[conflict]
            else:
                reason_code = (
                    next(iter(page_conflict_reasons))
                    if len(page_conflict_reasons) == 1
                    else "github_advisory_multiple_conflicts"
                )
        elif next_cursor is not None:
            state: Literal["in_progress", "complete", "failed"] = "in_progress"
            reason_code = (
                "github_page_accepted_with_scope_exclusion"
                if page_has_scope_gap
                else "github_page_accepted_after_scope_exclusion"
                if lane_has_scope_gap
                else "github_page_accepted_after_quarantine"
                if prior_has_quarantine
                else "github_page_accepted"
            )
        elif lane_has_scope_gap:
            # A completed current-update window remains a successful collection
            # even when reviewed publication rules deliberately exclude entries.
            # Historical collection keeps its fail-closed state because that lane
            # makes a bounded coverage claim that the exclusion prevents.
            state = "complete" if lane == "updates" else "failed"
            reason_code = "github_lane_complete_with_scope_exclusion"
        else:
            state = "complete"
            reason_code = "github_lane_complete"
        progress = self._append_progress(
            session,
            lane=lane,
            state=state,
            cursor_parameter=next_parameter,
            cursor_value=next_cursor,
            page_count=page_count,
            source_record_count=source_record_count,
            normalized_record_count=normalized_record_count,
            window_started_at=window_started_at,
            window_ended_at=window_ended_at,
            oldest_published_at=oldest_published_at,
            newest_published_at=newest_published_at,
            reason_code=reason_code,
            occurred_at=now,
        )
        if self._catalog_mode:
            append_page_membership(
                session,
                progress_event_id=progress.progress_event_id,
                outcomes=page_outcomes,
                expected_count=len(advisories),
                transport_sha256=sha256_id(response.body),
                observed_at=now,
            )
        if state == "complete" and self._catalog_mode and lane == "historical":
            snapshot_time = window_ended_at or now
            append_github_segment_manifest(
                session,
                segment=self._provider_type,
                source_snapshot=timestamp(snapshot_time),
                expected_record_count=source_record_count,
                expected_package_entry_count=normalized_record_count,
                observed_at=now,
            )
        return GitHubCollectionRun(
            lane=lane,
            state=state,
            page_count=progress.page_count,
            source_record_count=progress.source_record_count,
            normalized_record_count=progress.normalized_record_count,
            collections=tuple(collected),
            page_processed=True,
            page_source_record_count=len(advisories),
            page_normalized_record_count=page_normalized_record_count,
            has_scope_gap=lane_has_scope_gap,
            page_excluded_scope_entry_count=page_excluded_scope_entries,
            page_scope_exclusion_reasons=tuple(sorted(page_scope_exclusion_reasons.items())),
            reason_code=reason_code if state == "failed" else None,
            window_ended_at=window_ended_at,
        )
