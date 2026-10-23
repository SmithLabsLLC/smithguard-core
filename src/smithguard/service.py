"""One canonical read-only service layer for local REST and feeds."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from smithguard.advisory_catalog import (
    GITHUB_ECOSYSTEMS,
    GITHUB_SOURCE_ID,
    OPENSSF_ECOSYSTEMS,
    OPENSSF_SOURCE_ID,
    AdvisoryCatalogCapacityExceeded,
    CatalogMatchFamily,
    catalog_evidence_for_package,
)
from smithguard.contracts.runtime import parse_contract
from smithguard.coverage import build_coverage_report, refresh_coverage_report
from smithguard.db.models import (
    AffectedRangeRecord,
    ArtifactRecord,
    ClaimRecord,
    IncidentRecord,
    SourceIncidentLinkRecord,
    SourceRecord,
)
from smithguard.ecosystems import REGISTRY_HOSTS_BY_ECOSYSTEM
from smithguard.feeds import SnapshotSigner
from smithguard.identifiers import canonical_json_bytes, stable_id, timestamp
from smithguard.normalization import normalize_artifact_identity
from smithguard.query import (
    ArtifactCandidateBoundExceeded,
    latest_affected_ranges_for_ids,
    latest_incidents_for_artifacts,
    latest_public_claims_for_ids,
    public_artifact_candidates,
)
from smithguard.range_evaluation import range_result
from smithguard.signals import (
    PreliminaryWarningError,
    matching_preliminary_warnings,
)
from smithguard.supplemental_store import (
    GO_SOURCE,
    RUST_SOURCE,
    cve_context,
    origin_context_for_reports,
)
from smithguard.version_order import is_exact_version

ASSESSMENT_SCHEMA_VERSION = "2.2.0"
MAX_LISTED_INCIDENTS = 100
SHORT_REQUEST_FIELDS = frozenset({"ecosystem", "name", "version", "digest", "registry_host"})
# Range syntax and floating names that never identify one exact published version.
RANGE_CHARACTERS = frozenset("^~*<>=|,[]()")
FLOATING_VERSIONS = frozenset(
    {"latest", "next", "stable", "release", "head", "main", "master", "x", "*"}
)
# Ecosystems whose parser is strict enough to reject every non-exact spelling.
STRICT_VERSION_ECOSYSTEMS = frozenset({"npm", "pypi"})
FULL_SEMVER_ECOSYSTEMS = frozenset(
    {"npm", "go", "rust", "swift", "erlang", "vscode", "open-vsx", "pub"}
)
# SemVer 2.0.0 syntax (optional "v" for Go): no empty identifiers, no leading zeros.
_NUMBER = r"(?:0|[1-9][0-9]*)"
_PRE_IDENTIFIER = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
FULL_SEMVER = re.compile(
    rf"^v?{_NUMBER}\.{_NUMBER}\.{_NUMBER}"
    rf"(?:-{_PRE_IDENTIFIER}(?:\.{_PRE_IDENTIFIER})*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
FRESH_STATES = frozenset({"fresh", "complete"})


class ServiceError(ValueError):
    code = "invalid_request"
    status_code = 400
    # Service errors come from the request or from fixed bounds; retrying the same
    # request cannot change them. Transient capacity is reported by the API itself.
    retryable = False


class NotFound(ServiceError):
    code = "not_found"
    status_code = 404


class ResponseLimitExceeded(ServiceError):
    code = "response_limit_exceeded"
    status_code = 413


class ServiceCapacityExceeded(ServiceError):
    code = "service_capacity_exceeded"
    status_code = 503


class InternalStateError(ServiceError):
    code = "internal_state_error"
    status_code = 500


class VersionNotExact(ServiceError):
    code = "version_not_exact"
    status_code = 400


def _composer_moving(lowered: str) -> bool:
    """Branches and wildcards, judged on the version before any +build metadata."""
    base = lowered.split("+", 1)[0]
    return (
        base.startswith("dev-")
        or base.endswith("-dev")
        or any(part in {"x", "*"} for part in base.split("."))
    )


def require_exact_version(ecosystem: str, version: str | None) -> None:
    """Reject ranges, tags like ``latest`` and other values that are not one version."""
    if version is None:
        return
    lowered = version.lower()
    if (
        any(character in RANGE_CHARACTERS or character.isspace() for character in version)
        or lowered in FLOATING_VERSIONS
        or (ecosystem in STRICT_VERSION_ECOSYSTEMS and not is_exact_version(ecosystem, version))
        # SemVer registries publish full X.Y.Z versions; "1.2" is a requirement there.
        or (ecosystem in FULL_SEMVER_ECOSYSTEMS and not FULL_SEMVER.fullmatch(version))
        # Moving builds and wildcards: Composer branches (dev-main, 1.x-dev), wildcard
        # parts (1.x, 1.2.*) and Maven snapshots.
        or (ecosystem == "composer" and _composer_moving(lowered))
        or (ecosystem == "maven" and lowered.endswith("snapshot"))
    ):
        raise VersionNotExact(
            "version must be one exact published version, not a range or tag like latest"
        )


@dataclass(frozen=True, slots=True)
class _AssessmentCorrelations:
    artifacts: tuple[ArtifactRecord, ...]
    artifact_ids: tuple[str, ...]
    relevant_incident_records: list[IncidentRecord]
    claims: tuple[ClaimRecord, ...]
    ranges: tuple[AffectedRangeRecord, ...]
    correlated: list[tuple[Any, tuple[Any, ...]]]


def _correlate_assessment_evidence(
    session: Session,
    identity: dict[str, Any],
) -> _AssessmentCorrelations:
    try:
        artifacts = public_artifact_candidates(
            session,
            ecosystem=identity["ecosystem"],
            normalized_name=identity["name"],
            version=identity["version"],
            digest=identity["digest"],
            limit=101,
        )
    except ArtifactCandidateBoundExceeded as error:
        raise ServiceCapacityExceeded(
            "artifact assessment exceeds the current artifact candidate bound"
        ) from error
    if len(artifacts) > 100:
        raise ServiceCapacityExceeded(
            "artifact assessment exceeds the current artifact candidate bound"
        )
    artifact_ids = tuple(dict.fromkeys(record.id for record in artifacts))
    incident_records = latest_incidents_for_artifacts(
        session,
        artifact_ids,
        public_only=True,
        limit=101,
    )
    if len(incident_records) > 100:
        raise ServiceCapacityExceeded("artifact assessment exceeds the current correlation bound")
    relevant_incident_records = [
        record for record in incident_records if set(record.artifact_ids).intersection(artifact_ids)
    ]
    range_ids = tuple(
        dict.fromkeys(
            range_id
            for record in relevant_incident_records
            for range_id in record.affected_range_ids
        )
    )
    claim_ids = tuple(
        dict.fromkeys(
            claim_id for record in relevant_incident_records for claim_id in record.claim_ids
        )
    )
    if len(range_ids) > 500 or len(claim_ids) > 500:
        raise ServiceCapacityExceeded(
            "artifact assessment exceeds the current evidence correlation bound"
        )
    ranges = latest_affected_ranges_for_ids(
        session,
        range_ids=range_ids,
        artifact_ids=artifact_ids,
        limit=501,
    )
    claims = latest_public_claims_for_ids(session, claim_ids, limit=501)
    if len(ranges) > 500 or len(claims) > 500:
        raise ServiceCapacityExceeded(
            "artifact assessment exceeds the current evidence correlation bound"
        )
    ranges_by_id = {record.id: record for record in ranges}
    claims_by_id = {record.id: record for record in claims}

    def provenance_key(record: Any) -> tuple[Any, ...]:
        provenance = record.provenance
        return (
            provenance.get("source_id"),
            provenance.get("source_record_id"),
            provenance.get("evidence_id"),
        )

    correlated: list[tuple[Any, tuple[Any, ...]]] = []
    for incident_record in relevant_incident_records:
        incident_claims = tuple(
            claims_by_id[value] for value in incident_record.claim_ids if value in claims_by_id
        )
        claim_authority = {
            (record.subject_id, provenance_key(record)) for record in incident_claims
        }
        incident_ranges = tuple(
            ranges_by_id[value]
            for value in incident_record.affected_range_ids
            if value in ranges_by_id
            and ranges_by_id[value].artifact_id in artifact_ids
            and (
                ranges_by_id[value].artifact_id,
                provenance_key(ranges_by_id[value]),
            )
            in claim_authority
        )
        if incident_claims and incident_ranges:
            correlated.append((incident_record, incident_ranges))
    return _AssessmentCorrelations(
        artifacts, artifact_ids, relevant_incident_records, claims, ranges, correlated
    )


def _evaluate_assessment_incidents(
    correlated: list[tuple[Any, tuple[Any, ...]]],
    identity: dict[str, Any],
    catalog_families: tuple[CatalogMatchFamily, ...],
) -> tuple[
    list[dict[str, Any]],
    set[str],
    list[dict[str, Any]],
    str,
    dict[str, tuple[bool | None, tuple[str, ...]]],
]:
    incidents = [record.document for record, _ranges in correlated]
    active_incident_ids = {
        record.id
        for record, _ranges in correlated
        if record.status not in {"withdrawn", "expired", "disputed"}
    }
    range_evaluations_by_incident = {
        incident_record.id: tuple(
            (
                record,
                range_result(
                    artifact={
                        "ecosystem": identity["ecosystem"],
                        "version": identity["version"],
                        "digest": identity["digest"],
                    },
                    affected_range=record.document,
                ),
            )
            for record in incident_ranges
        )
        for incident_record, incident_ranges in correlated
    }
    range_results_by_incident = {
        incident_id: tuple(result for _record, result in evaluations)
        for incident_id, evaluations in range_evaluations_by_incident.items()
    }
    matched_range_ids = {
        record.id
        for incident_id, evaluations in range_evaluations_by_incident.items()
        if incident_id in active_incident_ids
        for record, result in evaluations
        if result is True
    }
    confirmed_incidents = [
        incident
        for incident in incidents
        if incident["id"] in active_incident_ids
        and (
            incident["status"] == "confirmed"
            or (
                incident["status"] in {"contained", "resolved"}
                and isinstance(incident.get("authority"), dict)
                and incident["authority"].get("public_status") == "confirmed"
            )
        )
    ]
    confirmed_incident_ids = {incident["id"] for incident in confirmed_incidents}
    if any(
        incident_id in confirmed_incident_ids and True in incident_range_results
        for incident_id, incident_range_results in range_results_by_incident.items()
    ):
        result = "affected"
    elif any(
        incident_id in active_incident_ids
        and (True in incident_range_results or None in incident_range_results)
        for incident_id, incident_range_results in range_results_by_incident.items()
    ):
        result = "possibly_affected"
    elif active_incident_ids and all(
        incident_id not in active_incident_ids
        or (incident_range_results and all(value is False for value in incident_range_results))
        for incident_id, incident_range_results in range_results_by_incident.items()
    ):
        result = "not_affected"
    else:
        result = "unknown"
    applicability = {
        incident_id: (
            _applies(tuple(result for _record, result in evaluations)),
            tuple(sorted(record.id for record, result in evaluations if result is True)),
        )
        for incident_id, evaluations in range_evaluations_by_incident.items()
    }
    catalog_affected = any(family.authoritative_match for family in catalog_families)
    catalog_possible = any(
        True in family.evaluations or None in family.evaluations for family in catalog_families
    )
    catalog_not_affected = bool(catalog_families) and all(
        family.evaluations and all(value is False for value in family.evaluations)
        for family in catalog_families
    )
    if catalog_affected:
        result = "affected"
    elif catalog_possible and result in {"unknown", "not_affected"}:
        result = "possibly_affected"
    elif catalog_not_affected and result == "unknown":
        result = "not_affected"
    return incidents, matched_range_ids, confirmed_incidents, result, applicability


def _applies(results: tuple[bool | None, ...]) -> bool | None:
    """True if any range matches, False only when every range decided no."""
    if True in results:
        return True
    if not results or None in results:
        return None
    return False


def _merged_applies(left: bool | None, right: bool | None) -> bool | None:
    if left is True or right is True:
        return True
    if left is None or right is None:
        return None
    return False


def _assessment_source_reports(
    session: Session,
    incidents: list[dict[str, Any]],
    artifact_ids: tuple[str, ...],
) -> tuple[
    tuple[SourceIncidentLinkRecord, ...],
    dict[str, str],
    dict[str, list[dict[str, Any]]],
    dict[str, str],
]:
    legacy_incident_ids = tuple(item["id"] for item in incidents)
    latest_link_rank = (
        func.row_number()
        .over(
            partition_by=(
                SourceIncidentLinkRecord.source_id,
                SourceIncidentLinkRecord.upstream_record_id,
                SourceIncidentLinkRecord.artifact_id,
            ),
            order_by=(
                SourceIncidentLinkRecord.sequence.desc(),
                SourceIncidentLinkRecord.observed_at.desc(),
            ),
        )
        .label("position")
    )
    ranked_links = (
        select(
            SourceIncidentLinkRecord.link_event_id.label("link_event_id"),
            latest_link_rank,
        )
        .where(
            SourceIncidentLinkRecord.artifact_id.in_(artifact_ids),
        )
        .subquery()
    )
    source_links = tuple(
        session.scalars(
            select(SourceIncidentLinkRecord)
            .join(
                ranked_links,
                ranked_links.c.link_event_id == SourceIncidentLinkRecord.link_event_id,
            )
            .where(
                ranked_links.c.position == 1,
                SourceIncidentLinkRecord.incident_id.in_(legacy_incident_ids),
            )
            .order_by(
                SourceIncidentLinkRecord.incident_id,
                SourceIncidentLinkRecord.source_id,
                SourceIncidentLinkRecord.upstream_record_id,
                SourceIncidentLinkRecord.artifact_id,
            )
            .limit(10001)
        )
    )
    if len(source_links) > 10000:
        raise ServiceCapacityExceeded("artifact assessment exceeds the current source report bound")
    source_ids = {link.source_id for link in source_links}
    source_rows = tuple(
        session.scalars(
            select(SourceRecord)
            .where(SourceRecord.id.in_(source_ids))
            .order_by(SourceRecord.id, SourceRecord.revision.desc())
        )
    )
    source_names: dict[str, str] = {}
    for source in source_rows:
        source_names.setdefault(source.id, source.name)
    reports_by_incident: dict[str, list[dict[str, Any]]] = {}
    legacy_incident_by_ghsa: dict[str, str] = {}
    for link in source_links:
        reports_by_incident.setdefault(link.incident_id, []).append(
            {
                "source_id": link.source_id,
                "source_name": source_names.get(link.source_id, link.source_id),
                "upstream_record_id": link.upstream_record_id,
                "state": link.state,
                "source_updated_at": timestamp(link.source_updated_at),
                "observed_at": timestamp(link.observed_at),
            }
        )
        upstream_key = link.upstream_record_id.upper()
        if upstream_key.startswith("GHSA-"):
            legacy_incident_by_ghsa.setdefault(upstream_key, link.incident_id)
    return source_links, source_names, reports_by_incident, legacy_incident_by_ghsa


def _project_assessment_incidents(
    incidents: list[dict[str, Any]],
    reports_by_incident: dict[str, list[dict[str, Any]]],
    legacy_incident_by_ghsa: dict[str, str],
    catalog_families: tuple[CatalogMatchFamily, ...],
    applicability: dict[str, tuple[bool | None, tuple[str, ...]]],
) -> list[dict[str, Any]]:
    """Every incident with its applicability; the caller lists and counts them."""
    projected_incidents = []
    for incident in incidents:
        all_reports = sorted(
            reports_by_incident.get(incident["id"], []),
            key=lambda item: (item["source_id"], item["upstream_record_id"]),
        )
        reports = all_reports[:100]
        projected_incidents.append(
            {
                "incident_id": incident["id"],
                "revision": incident["revision"],
                "status": incident["status"],
                "confidence": incident["confidence"],
                "title": incident["title"],
                "last_changed_at": incident["last_changed_at"],
                "report_relationship": (
                    "not_confirmed"
                    if not reports
                    else "single_report"
                    if len(reports) == 1
                    else "same_incident_record"
                ),
                "relationship_basis": ("not_available" if not reports else "catalog_assignment"),
                "source_reports": reports,
                "source_reports_truncated": len(all_reports) > len(reports),
                "applies_to_version": applicability.get(incident["id"], (None, ()))[0],
                "affected_range_ids": list(applicability.get(incident["id"], (None, ()))[1]),
                "fixed_versions": [],
                "aliases": sorted(
                    {
                        report["upstream_record_id"]
                        for report in reports
                        if 0 < len(report["upstream_record_id"]) <= 160
                        and report["upstream_record_id"].isascii()
                        and report["upstream_record_id"].isprintable()
                    }
                )[:20],
                "upstream_urls": [],
            }
        )
    projected_by_id = {item["incident_id"]: item for item in projected_incidents}
    for family in catalog_families:
        legacy_incident_id = legacy_incident_by_ghsa.get(family.family_key.upper())
        if legacy_incident_id is not None and legacy_incident_id in projected_by_id:
            projected = projected_by_id[legacy_incident_id]
            reports = {
                (report["source_id"], report["upstream_record_id"]): report
                for report in projected["source_reports"]
            }
            reports.update(
                {
                    (report["source_id"], report["upstream_record_id"]): report
                    for report in family.source_reports
                }
            )
            all_reports = [reports[key] for key in sorted(reports)]
            projected["source_reports"] = all_reports[:100]
            projected["source_reports_truncated"] = len(all_reports) > 100
            projected["report_relationship"] = (
                "single_report" if len(all_reports) == 1 else "same_incident_record"
            )
            projected["relationship_basis"] = "catalog_assignment"
            # Authority is lent only by a confirmed assertion that matches this version;
            # a reviewed advisory that does not apply keeps its label on its own family.
            if family.authoritative_match or (
                projected["confidence"] != "confirmed" and True in family.evaluations
            ):
                projected["classification"] = family.classification
            if family.authoritative_match:
                projected["confidence"] = "confirmed"
                if projected["status"] not in {
                    "contained",
                    "resolved",
                    "disputed",
                    "withdrawn",
                    "expired",
                }:
                    projected["status"] = "confirmed"
            projected["last_changed_at"] = max(projected["last_changed_at"], family.last_changed_at)
            projected["applies_to_version"] = _merged_applies(
                projected["applies_to_version"], family.applies
            )
            projected["affected_range_ids"] = sorted(
                {*projected["affected_range_ids"], *family.matched_range_ids}
            )
            projected["fixed_versions"] = list(family.fixed_versions)
            projected["aliases"] = sorted({*projected["aliases"], *family.aliases})[:20]
            projected["upstream_urls"] = list(family.upstream_urls)
            continue
        projected_incidents.append(
            {
                "incident_id": family.incident_id,
                "revision": family.revision,
                "status": family.status,
                "confidence": family.confidence,
                "classification": family.classification,
                "title": family.title,
                "last_changed_at": family.last_changed_at,
                "report_relationship": (
                    "single_report" if len(family.source_reports) == 1 else "same_incident_record"
                ),
                "relationship_basis": "catalog_assignment",
                "source_reports": list(family.source_reports),
                "source_reports_truncated": False,
                "applies_to_version": family.applies,
                "affected_range_ids": list(family.matched_range_ids),
                "fixed_versions": list(family.fixed_versions),
                "aliases": list(family.aliases),
                "upstream_urls": list(family.upstream_urls),
            }
        )
    projected_incidents.sort(key=lambda item: item["incident_id"])
    return projected_incidents


def _listed_incidents(
    projected: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int, bool]:
    """Incidents that apply or may apply, the count left out, and whether truncated.

    Incidents whose ranges all exclude the version are counted, not listed. When more
    than 100 remain, the ones known to apply come first.
    """
    candidates = [item for item in projected if item["applies_to_version"] is not False]
    not_applicable = len(projected) - len(candidates)
    ranked = sorted(
        candidates,
        key=lambda item: (item["applies_to_version"] is not True, item["incident_id"]),
    )
    listed = sorted(ranked[:MAX_LISTED_INCIDENTS], key=lambda item: item["incident_id"])
    return listed, not_applicable, len(candidates) > MAX_LISTED_INCIDENTS


def _relevant_sources(source_lanes: tuple[Any, ...], ecosystem: str) -> tuple[Any, ...]:
    """Sources whose current data decides package-version answers for this ecosystem.

    GitHub update lanes, OpenSSF and the matching RustSec/Go origin are included.

    Coverage is by what each source publishes, not by what was collected, so a source
    that has not collected yet is still named as missing.
    """
    covered = {
        GITHUB_SOURCE_ID: frozenset(GITHUB_ECOSYSTEMS.values()),
        OPENSSF_SOURCE_ID: frozenset(OPENSSF_ECOSYSTEMS.values()),
        RUST_SOURCE: frozenset({"rust"}),
        GO_SOURCE: frozenset({"go"}),
    }
    return tuple(
        lane
        for lane in source_lanes
        if ecosystem in covered.get(lane.source_id, frozenset())
        and (lane.lane == "updates" or lane.source_id == OPENSSF_SOURCE_ID)
    )


FRESHNESS_PHRASES = {
    "stale": "out of date",
    "failed": "failing",
    "missing": "not collected yet",
    "in_progress": "still being collected",
    "reconciling": "being reconciled",
    "unresolved": "not reconciled",
}


def _source_unknowns(freshness: tuple[Any, ...]) -> tuple[str, ...]:
    unknowns = []
    for lane in freshness:
        if lane.freshness_state in FRESH_STATES:
            continue
        phrase = FRESHNESS_PHRASES.get(lane.freshness_state, "not current")
        if lane.source_id == OPENSSF_SOURCE_ID:
            subject = "The OpenSSF malicious-package catalog is"
        elif lane.source_id == RUST_SOURCE:
            subject = "RustSec advisory updates are"
        elif lane.source_id == GO_SOURCE:
            subject = "Go Vulnerability Database updates are"
        else:
            kind = lane.record_type.removesuffix("_advisory")
            subject = f"GitHub {kind} advisory updates are"
        unknowns.append(f"{subject} {phrase}, so recent reports may be missing.")
    return tuple(unknowns)


def _evidence_unknowns(
    listed: list[dict[str, Any]],
    confirmed_ids: set[str],
    result: str,
    active_warning_count: int,
) -> tuple[str, ...]:
    """Plain reasons an answer is not definite, by what kind of report was found."""
    unknowns: list[str] = []
    unconfirmed = [
        item
        for item in listed
        if item["confidence"] != "confirmed" and item["incident_id"] not in confirmed_ids
    ]
    kinds = {item.get("classification") for item in unconfirmed}
    if kinds & {"malicious", "compromised"}:
        unknowns.append("A matching malware report is not yet confirmed by a reviewed source.")
    if "vulnerable" in kinds:
        unknowns.append("A matching vulnerability advisory is not yet reviewed by its source.")
    if None in kinds:
        unknowns.append("A matching report is not yet confirmed by an authoritative source.")
    if any(item["applies_to_version"] is None for item in listed):
        unknowns.append("An incident's affected versions could not be compared with this version.")
    if result == "unknown" and not listed:
        unknowns.append(
            "No report in the covered sources names this version; that is not proof it is safe."
        )
    if any(
        {report.get("applies_to_version") for report in item["source_reports"]} >= {True, False}
        for item in listed
    ):
        unknowns.append(
            "Sources disagree about whether this version is affected. Fix versions are "
            "source-reported candidates; assess the exact version before choosing an upgrade."
        )
    if active_warning_count:
        unknowns.append(
            "A matching preliminary warning is unverified and does not authorize action."
        )
    return tuple(unknowns)


class SmithGuardService:
    """Canonical public reads; customer-local and state-changing operations are absent."""

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] | None = None,
        max_output_bytes: int = 1_048_576,
        expected_governance_policy_sha256: str | None = None,
        signer: SnapshotSigner | None = None,
        build_coverage_on_miss: bool = True,
    ) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))
        self._max_output_bytes = max_output_bytes
        self._expected_governance_policy_sha256 = expected_governance_policy_sha256
        self._signer = signer
        self._build_coverage_on_miss = build_coverage_on_miss

    def _bounded(self, value: dict[str, Any]) -> dict[str, Any]:
        if len(canonical_json_bytes(value)) > self._max_output_bytes:
            raise ResponseLimitExceeded("response exceeds its fixed byte limit")
        return value

    def validate_public_artifact_request(
        self,
        request: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Validate one exact public coordinate before database or quota work.

        Accepts the short form (ecosystem, name, version) or the full contract request.
        """
        if "artifact" not in request:
            request = self._expand_short_request(request)
        parsed = parse_contract("PublicArtifactAssessmentRequest", request).model_dump(
            mode="json",
            exclude_none=False,
        )
        supplied = parsed["artifact"]
        expected_registry = REGISTRY_HOSTS_BY_ECOSYSTEM
        if supplied["registry_host"] not in expected_registry[supplied["ecosystem"]]:
            raise ServiceError("registry host does not match the artifact ecosystem")
        if supplied["version"] is None and supplied["digest"] is None:
            raise ServiceError("an exact version or immutable digest is required")
        identity = normalize_artifact_identity(
            {
                "ecosystem": supplied["ecosystem"],
                "name": supplied["name"],
                "version": supplied["version"],
                "digest": supplied["digest"],
            }
        )
        require_exact_version(identity["ecosystem"], identity["version"])
        return parsed, identity

    def _expand_short_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """Build the full contract request from ecosystem, name and version (or digest)."""
        unknown = sorted(set(request) - SHORT_REQUEST_FIELDS)
        if unknown:
            raise ServiceError("unsupported request field: " + unknown[0][:40])
        for field in ("ecosystem", "name"):
            if field not in request:
                raise ServiceError(f"{field} is required")
        if any(not isinstance(value, str) for value in request.values()):
            raise ServiceError("request fields must be strings")
        ecosystem = request["ecosystem"]
        hosts = REGISTRY_HOSTS_BY_ECOSYSTEM.get(ecosystem)
        if hosts is None:
            raise ServiceError("ecosystem is not supported")
        registry_host = request.get("registry_host")
        if registry_host is None:
            if len(hosts) != 1:
                raise ServiceError("registry_host is required for container images")
            (registry_host,) = hosts
        version = request.get("version")
        digest = request.get("digest")
        now = timestamp(self._clock())
        return {
            "id": stable_id(
                "assessment-request",
                ecosystem,
                registry_host,
                request["name"],
                version or "",
                digest or "",
            ),
            "kind": "public_artifact_assessment_request",
            "schema_version": "1.0.0",
            "revision": 1,
            "created_at": now,
            "updated_at": now,
            "data_classification": "public",
            "artifact": {
                "ecosystem": ecosystem,
                "registry_host": registry_host,
                "name": request["name"],
                "version": version,
                "digest": digest,
                "public_visibility": "asserted_public",
            },
        }

    def project_public_artifact_response(
        self,
        response: dict[str, Any],
        parsed_request: dict[str, Any],
    ) -> dict[str, Any]:
        """Project the current request over independently cached evidence.

        Evidence timestamps describe the computation, while the supplied artifact
        and assessment identity belong to this caller, including registry spelling.
        The signature covers this caller's projected document, so it is made last.
        """
        document = {key: value for key, value in response.items() if key != "signature"}
        document.update(
            id=stable_id("assessment", parsed_request["id"], response["feed_revision"]),
            artifact=dict(parsed_request["artifact"]),
        )
        if self._signer is not None:
            document["signature"] = self._signer.signature_for(document)
        return self._bounded(document)

    def assess_public_artifact(
        self,
        session: Session,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        parsed, identity = self.validate_public_artifact_request(request)
        supplied = parsed["artifact"]
        try:
            catalog_evidence = catalog_evidence_for_package(
                session,
                ecosystem=identity["ecosystem"],
                name=identity["name"],
                version=identity["version"],
            )
        except AdvisoryCatalogCapacityExceeded as error:
            raise ServiceCapacityExceeded(str(error)) from error
        catalog_families = catalog_evidence.families
        correlation = _correlate_assessment_evidence(session, identity)
        (
            incidents,
            matched_range_ids,
            confirmed_incidents,
            result,
            applicability,
        ) = _evaluate_assessment_incidents(
            correlation.correlated,
            identity,
            catalog_families,
        )
        report = build_coverage_report(
            session,
            allow_build=self._build_coverage_on_miss,
            measured_at=self._clock(),
            live_collector_uptime="not_measured_public_beta_collector",
            evidence_label="public",
            expected_governance_policy_sha256=(self._expected_governance_policy_sha256),
        )
        lane = next(value for value in report.lanes if value.ecosystem == identity["ecosystem"])
        freshness = _relevant_sources(report.source_lanes, identity["ecosystem"])
        warning_aliases = [identity["coordinate"]]
        exact_marker = identity["digest"] or identity["version"]
        if exact_marker is not None:
            warning_aliases.append(f"{identity['ecosystem']}:{identity['name']}@{exact_marker}")
        try:
            warning_records = matching_preliminary_warnings(
                session,
                affected_artifacts=warning_aliases,
                limit=101,
                now=self._clock(),
            )
        except PreliminaryWarningError as error:
            raise InternalStateError(str(error)) from error
        warnings_truncated = len(warning_records) > 100
        warning_records = warning_records[:100]
        preliminary_warnings = [
            {
                "warning_id": warning.id,
                "revision": warning.revision,
                "state": warning.state,
                "title": warning.document["title"],
                "claim": warning.document["claim"],
                "source_urls": warning.document["source_urls"],
                "evidence_class": warning.document["evidence_class"],
                "confirmation_status": warning.document["confirmation_status"],
                "warning_text": warning.document["warning_text"],
                "observed_at": warning.document["observed_at"],
                "last_checked_at": warning.document["last_checked_at"],
                "expires_at": warning.document["expires_at"],
                "final_reason": warning.document["final_reason"],
            }
            for warning in warning_records
        ]
        active_warning_count = sum(item["state"] == "active" for item in preliminary_warnings)
        if active_warning_count and result in {"unknown", "not_affected"}:
            result = "possibly_affected"
        warning_refs = sorted(
            (item["warning_id"], item["revision"]) for item in preliminary_warnings
        )
        source_links, source_names, reports_by_incident, legacy_incident_by_ghsa = (
            _assessment_source_reports(session, incidents, correlation.artifact_ids)
        )
        all_incidents = _project_assessment_incidents(
            incidents,
            reports_by_incident,
            legacy_incident_by_ghsa,
            catalog_families,
            applicability,
        )
        projected_incidents, not_applicable_count, incidents_truncated = _listed_incidents(
            all_incidents
        )
        now = self._clock()
        origin_context, origin_fingerprint = origin_context_for_reports(
            session,
            [report for incident in projected_incidents for report in incident["source_reports"]],
            now=now,
        )
        for incident in projected_incidents:
            for report in incident["source_reports"]:
                report["origin_context"] = origin_context.get(
                    (report["source_id"], report["upstream_record_id"])
                )
        context, context_fingerprint = cve_context(
            session,
            [alias for incident in projected_incidents for alias in incident["aliases"]],
            now=now,
        )
        incident_refs = sorted((item["incident_id"], item["revision"]) for item in all_incidents)
        feed_revision = stable_id(
            "feed-revision",
            "assessment-evidence-v2",
            ASSESSMENT_SCHEMA_VERSION,
            context_fingerprint,
            origin_fingerprint,
            incident_refs,
            warning_refs,
            catalog_evidence.fingerprint,
            [(link.link_event_id, link.record_hash) for link in source_links],
            [
                sorted((record.id, record.revision, record.record_hash) for record in records)
                for records in (
                    correlation.artifacts,
                    correlation.relevant_incident_records,
                    correlation.claims,
                    correlation.ranges,
                )
            ],
            sorted(source_names.items()),
        )
        if not projected_incidents:
            relationship_state = "no_incidents"
        elif len(projected_incidents) > 1:
            relationship_state = "separate_incident_records"
        elif len(projected_incidents[0]["source_reports"]) > 1:
            relationship_state = "same_incident_record"
        elif len(projected_incidents[0]["source_reports"]) == 1:
            relationship_state = "single_incident_record"
        else:
            relationship_state = "not_confirmed"
        response = {
            "id": stable_id("assessment", parsed["id"], feed_revision),
            "kind": "public_artifact_assessment",
            "schema_version": ASSESSMENT_SCHEMA_VERSION,
            "revision": 1,
            "created_at": timestamp(now),
            "updated_at": timestamp(now),
            "data_classification": "public",
            "artifact": supplied,
            "result": result,
            "relationship_state": relationship_state,
            "incidents": projected_incidents,
            "cve_context": context,
            "preliminary_warnings": preliminary_warnings,
            "preliminary_warnings_truncated": warnings_truncated,
            "incident_ids": [item["incident_id"] for item in projected_incidents],
            "affected_range_ids": sorted(
                matched_range_ids.union(
                    range_id for family in catalog_families for range_id in family.matched_range_ids
                )
            ),
            "recommended_action_ids": [],
            "evidence_maturity": {
                "composition": "present"
                if correlation.artifacts or catalog_families
                else "missing",
                "provenance": "present" if correlation.artifacts or catalog_families else "missing",
                "signature": "unknown",
                "vex": "unknown",
                "deployment": "unknown",
                "runtime": "unknown",
            },
            "coverage": {
                "ecosystem": identity["ecosystem"],
                "stage": lane.stage,
                "result": lane.result,
                "as_of": lane.as_of,
            },
            "registry_state": "unknown",
            "unknowns": [
                *lane.unknowns,
                *_source_unknowns(freshness),
                *_evidence_unknowns(
                    projected_incidents,
                    {item["id"] for item in confirmed_incidents},
                    result,
                    active_warning_count,
                ),
            ],
            "feed_revision": feed_revision,
            "not_applicable_incident_count": not_applicable_count,
            "incidents_truncated": incidents_truncated,
            "source_freshness": [
                {
                    "source_id": item.source_id,
                    "record_type": item.record_type,
                    "freshness_state": item.freshness_state,
                    "last_success_at": item.last_success_at,
                }
                for item in freshness
            ],
        }
        try:
            document = parse_contract("PublicArtifactAssessment", response).model_dump(
                mode="json",
                exclude_none=False,
            )
        except ValueError as error:
            raise InternalStateError("artifact assessment projection is invalid") from error
        return self._bounded(document)

    def refresh_coverage(
        self, session: Session, *, checkpoint: Callable[[], None] | None = None
    ) -> None:
        """Rebuild the shared coverage report in the background (same arguments the
        assessment and coverage reads use), so requests never wait for a rebuild."""
        refresh_coverage_report(
            session,
            measured_at=self._clock(),
            live_collector_uptime="not_measured_public_beta_collector",
            evidence_label="public",
            expected_governance_policy_sha256=self._expected_governance_policy_sha256,
            checkpoint=checkpoint,
        )

    def get_source_coverage(
        self,
        session: Session,
    ) -> dict[str, Any]:
        """Return explicit source, record-type, and ecosystem coverage limits."""
        report = build_coverage_report(
            session,
            allow_build=self._build_coverage_on_miss,
            measured_at=self._clock(),
            live_collector_uptime="not_measured_public_beta_collector",
            evidence_label="public",
            expected_governance_policy_sha256=(self._expected_governance_policy_sha256),
        )
        document = parse_contract(
            "SourceCoverageReport",
            report.as_dict(),
        ).model_dump(mode="json", exclude_none=False)
        return self._bounded(document)
