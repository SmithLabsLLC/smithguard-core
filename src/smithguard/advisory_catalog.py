"""Append-only complete advisory catalog projection and exact package matching."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from sqlalchemy import and_, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, aliased

from smithguard.advisory_context import github_public_context
from smithguard.assessment_evidence import HISTORICAL_GITHUB_POLICIES, source_fix_evidence
from smithguard.collection_records import actionable_quarantines_statement
from smithguard.db.locks import advisory_xact_lock
from smithguard.db.models import (
    AdvisoryCatalogInventoryRecord,
    AdvisoryCatalogManifestRecord,
    AdvisoryCatalogRecord,
    AdvisoryPackageRecord,
    SourceGovernanceDecisionRecord,
    SupplementalPayloadRecord,
)
from smithguard.db.package_lookup import package_name_predicate
from smithguard.identifiers import (
    CWE_ID,
    canonical_json_bytes,
    parse_timestamp,
    require_aware_utc,
    sha256_id,
    stable_id,
    timestamp,
)
from smithguard.normalization import NormalizationRejected, normalize_artifact_identity
from smithguard.range_evaluation import (
    COMPARATOR_WITH_SPACE,
    normalize_github_npm_advisory_range,
    osv_range_matches,
    pep440_matches,
    semver_matches,
)
from smithguard.version_order import (
    COMPARATOR,
    VersionOrderError,
    comparator_list_matches,
    exact_version_matches,
    version_key,
)

GITHUB_SOURCE_ID = "gbsec:source:github-advisory-database"
OPENSSF_SOURCE_ID = "gbsec:source:openssf-malicious-packages"
ORIGIN_SOURCE_IDS = frozenset(
    {
        "gbsec:source:rustsec-advisory-database",
        "gbsec:source:go-vulnerability-database",
    }
)
CATALOG_QUERY_LIMIT = 10_001
CATALOG_ALIAS_LINK_LIMIT = 100_000
GHSA_ID = re.compile(
    r"^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$",
    re.IGNORECASE,
)
EXACT_GITHUB = re.compile(r"^={0,2}\s*([^<>=!~^|,*\s]+)$")

GITHUB_ECOSYSTEMS = {
    "actions": "github-actions",
    "composer": "composer",
    "erlang": "erlang",
    "go": "go",
    "maven": "maven",
    "npm": "npm",
    "nuget": "nuget",
    "pip": "pypi",
    "pub": "pub",
    "rubygems": "rubygems",
    "rust": "rust",
    "swift": "swift",
}
OPENSSF_ECOSYSTEMS = {
    "crates.io": "rust",
    "git": "git",
    "go": "go",
    "maven": "maven",
    "npm": "npm",
    "nuget": "nuget",
    "packagist": "composer",
    "pypi": "pypi",
    "rubygems": "rubygems",
    "vscode": "vscode",
    "vscode:https://open-vsx.org": "open-vsx",
    "vscode:open-vsx.org": "open-vsx",
}
CLASSIFICATION_RANK = {"vulnerable": 0, "compromised": 1, "malicious": 2}


class AdvisoryCatalogError(ValueError):
    """A catalog record crossed the complete reviewed source boundary."""


class AdvisoryCatalogStaleRevision(AdvisoryCatalogError):
    """A legitimate older revision is a conflict, not a malformed source record."""


class AdvisoryCatalogCapacityExceeded(AdvisoryCatalogError):
    """A package has more catalog evidence than the explicit query bound."""


@dataclass(frozen=True, slots=True)
class CatalogAppendResult:
    catalog_event_id: str
    revision: int
    created: bool
    package_entry_count: int
    source_sha256: str
    package_omission_counts: dict[str, int]


@dataclass(frozen=True, slots=True)
class CatalogMatchFamily:
    family_key: str
    incident_id: str
    revision: int
    status: str
    confidence: str
    classification: str
    title: str
    last_changed_at: str
    source_reports: tuple[dict[str, Any], ...]
    evaluations: tuple[bool | None, ...]
    matched_range_ids: tuple[str, ...]
    # True when a record from an authoritative source matches this exact version.
    authoritative_match: bool = False
    fixed_versions: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    upstream_urls: tuple[str, ...] = ()

    @property
    def applies(self) -> bool | None:
        """Whether this incident applies to the requested version (None: undecided)."""
        if True in self.evaluations:
            return True
        if None in self.evaluations or not self.evaluations:
            return None
        return False


@dataclass(frozen=True, slots=True)
class CatalogPackageEvidence:
    families: tuple[CatalogMatchFamily, ...]
    fingerprint: str


def _aware(value: datetime, *, field: str) -> datetime:
    try:
        return require_aware_utc(value)
    except ValueError as error:
        raise AdvisoryCatalogError(f"{field} must include a timezone") from error


def _source_time(value: object, *, field: str, required: bool) -> datetime | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.isascii():
        raise AdvisoryCatalogError(f"{field} is invalid")
    try:
        return parse_timestamp(value, maximum=64)
    except ValueError as error:
        if getattr(error, "reason", None) == "naive":
            raise AdvisoryCatalogError(f"{field} must include a timezone") from error
        raise AdvisoryCatalogError(f"{field} is invalid") from error


def _bounded_identifier(value: object, *, field: str, maximum: int = 160) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or not value.isascii()
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:+-]*", value) is None
    ):
        raise AdvisoryCatalogError(f"{field} is invalid")
    return value


def _canonical_package(ecosystem: object, name: object, *, source: str) -> tuple[str, str, str]:
    if not isinstance(ecosystem, str) or not ecosystem or len(ecosystem) > 100:
        raise AdvisoryCatalogError("package ecosystem is invalid")
    if not isinstance(name, str) or not name or len(name) > 300:
        raise AdvisoryCatalogError("package name is invalid")
    mapping = GITHUB_ECOSYSTEMS if source == "github" else OPENSSF_ECOSYSTEMS
    try:
        canonical_ecosystem = mapping[ecosystem.lower()]
    except KeyError as error:
        raise AdvisoryCatalogError(f"unmapped {source} ecosystem: {ecosystem}") from error
    try:
        normalized = normalize_artifact_identity(
            {
                "ecosystem": canonical_ecosystem,
                "name": name,
                "version": "0",
                "digest": None,
            }
        )
    except NormalizationRejected as error:
        raise AdvisoryCatalogError("package identity is outside the public contract") from error
    return canonical_ecosystem, normalized["name"], ecosystem


def _github_classification(source_type: str, cwe_ids: Sequence[str]) -> tuple[str, str]:
    if source_type == "malware":
        return "malicious", "confirmed"
    if source_type == "reviewed" and "CWE-506" in cwe_ids:
        return "compromised", "confirmed"
    if source_type == "reviewed":
        return "vulnerable", "confirmed"
    if source_type == "unreviewed":
        return "vulnerable", "unverified"
    raise AdvisoryCatalogError("GitHub advisory type is invalid")


def _github_projection(document: Mapping[str, Any]) -> dict[str, Any]:
    upstream_id = _bounded_identifier(document.get("ghsa_id"), field="GitHub advisory ID")
    source_type = _bounded_identifier(
        document.get("type"), field="GitHub advisory type", maximum=40
    )
    if source_type not in {"malware", "reviewed", "unreviewed"}:
        raise AdvisoryCatalogError("GitHub advisory type is outside the complete catalog")
    cwes = document.get("cwes") or []
    if not isinstance(cwes, list) or len(cwes) > 100:
        raise AdvisoryCatalogError("GitHub CWE list is invalid")
    cwe_ids: list[str] = []
    for value in cwes:
        if not isinstance(value, Mapping):
            raise AdvisoryCatalogError("GitHub CWE entry is invalid")
        cwe_id = value.get("cwe_id")
        if not isinstance(cwe_id, str) or CWE_ID.fullmatch(cwe_id) is None:
            raise AdvisoryCatalogError("GitHub CWE identity is invalid")
        if cwe_id not in cwe_ids:
            cwe_ids.append(cwe_id)
    identifiers = document.get("identifiers") or []
    if not isinstance(identifiers, list) or len(identifiers) > 100:
        raise AdvisoryCatalogError("GitHub identifier list is invalid")
    aliases = [upstream_id.upper()]
    for value in identifiers:
        if not isinstance(value, Mapping):
            raise AdvisoryCatalogError("GitHub identifier is invalid")
        identifier = _bounded_identifier(value.get("value"), field="GitHub identifier")
        if identifier not in aliases:
            aliases.append(identifier)
    claim_type, confidence = _github_classification(source_type, cwe_ids)
    published_at = _source_time(document.get("published_at"), field="published_at", required=True)
    updated_at = _source_time(document.get("updated_at"), field="updated_at", required=True)
    vulnerabilities = document.get("vulnerabilities") or []
    if not isinstance(vulnerabilities, list) or len(vulnerabilities) > 1_000:
        raise AdvisoryCatalogError("GitHub vulnerabilities are invalid")
    packages: list[dict[str, Any]] = []
    package_omission_counts: dict[str, int] = defaultdict(int)
    for index, vulnerability in enumerate(vulnerabilities):
        if not isinstance(vulnerability, Mapping):
            raise AdvisoryCatalogError("GitHub vulnerability entry is invalid")
        package = vulnerability.get("package")
        if package is None:
            package_omission_counts["missing_package"] += 1
            continue
        if not isinstance(package, Mapping):
            raise AdvisoryCatalogError("GitHub package entry is invalid")
        raw_ecosystem = package.get("ecosystem")
        if raw_ecosystem is None or (
            isinstance(raw_ecosystem, str) and raw_ecosystem.lower() not in GITHUB_ECOSYSTEMS
        ):
            package_omission_counts["unsupported_ecosystem"] += 1
            continue
        if package.get("name") is None:
            package_omission_counts["missing_package_name"] += 1
            continue
        ecosystem, name, raw_ecosystem = _canonical_package(
            raw_ecosystem, package.get("name"), source="github"
        )
        expression = vulnerability.get("vulnerable_version_range")
        if expression is None:
            package_omission_counts["missing_version_range"] += 1
            affected_ranges: list[dict[str, Any]] = []
            expression_key = None
        elif not isinstance(expression, str) or not 1 <= len(expression) <= 1_000:
            raise AdvisoryCatalogError("GitHub vulnerable range is invalid")
        else:
            affected_ranges = [{"type": "GITHUB", "expression": expression}]
            expression_key = expression
        if "first_patched_version" in vulnerability:
            patched = vulnerability["first_patched_version"]
            if patched is not None and (
                not isinstance(patched, str)
                or not 1 <= len(patched) <= 200
                or not patched.isascii()
                or not patched.isprintable()
                or patched.strip() != patched
            ):
                raise AdvisoryCatalogError("GitHub first patched version is invalid")
            if affected_ranges:
                affected_ranges[0]["first_patched_version"] = patched
        packages.append(
            {
                "entry_key": sha256_id(
                    canonical_json_bytes([index, ecosystem, name, expression_key])
                ),
                "ecosystem": ecosystem,
                "raw_ecosystem": raw_ecosystem,
                "name": name,
                "exact_versions": [],
                "affected_ranges": affected_ranges,
            }
        )
    canonical_url = document.get("html_url")
    if not isinstance(canonical_url, str) or not canonical_url.startswith("https://github.com/"):
        raise AdvisoryCatalogError("GitHub canonical URL is invalid")
    state = "withdrawn" if document.get("withdrawn_at") is not None else "active"
    projection = {
        "upstream_record_id": upstream_id,
        "source_type": source_type,
        "claim_type": claim_type,
        "confidence": confidence,
        "state": state,
        "cwe_ids": sorted(cwe_ids),
        "aliases": sorted(aliases),
        "package_omission_counts": dict(sorted(package_omission_counts.items())),
        "canonical_url": canonical_url,
        "source_published_at": published_at,
        "source_updated_at": updated_at,
        "packages": packages,
    }
    context = github_public_context(document)
    if context is not None:
        projection["public_context"] = context
    return projection


def _openssf_projection(
    document: Mapping[str, Any],
    *,
    canonical_url: str,
    source_state: Literal["active", "withdrawn"],
) -> dict[str, Any]:
    upstream_id = _bounded_identifier(document.get("id"), field="OpenSSF advisory ID")
    aliases_value = document.get("aliases", [])
    if not isinstance(aliases_value, list) or len(aliases_value) > 100:
        raise AdvisoryCatalogError("OpenSSF alias list is invalid")
    aliases: list[str] = []
    for value in aliases_value:
        alias = _bounded_identifier(value, field="OpenSSF alias")
        if alias not in aliases:
            aliases.append(alias)
    affected = document.get("affected")
    if not isinstance(affected, list) or not affected or len(affected) > 1_000:
        raise AdvisoryCatalogError("OpenSSF affected list is invalid")
    packages: list[dict[str, Any]] = []
    omissions: Counter[str] = Counter()
    omitted_inputs = []
    for index, item in enumerate(affected):
        if not isinstance(item, Mapping):
            raise AdvisoryCatalogError("OpenSSF affected entry is invalid")
        package = item.get("package")
        package_less_git = package is None
        untyped = False
        if package_less_git:
            ecosystem = name = raw_ecosystem = ""
        elif isinstance(package, Mapping):
            raw_ecosystem, raw_name = package.get("ecosystem"), package.get("name")
            if (
                not isinstance(raw_ecosystem, str)
                or not 1 <= len(raw_ecosystem) <= 100
                or not isinstance(raw_name, str)
                or not 1 <= len(raw_name) <= 300
            ):
                raise AdvisoryCatalogError("OpenSSF affected package is invalid")
            untyped = raw_ecosystem.lower() not in OPENSSF_ECOSYSTEMS
            if untyped:
                ecosystem, name = "", raw_name
            else:
                ecosystem, name, raw_ecosystem = _canonical_package(
                    raw_ecosystem, raw_name, source="openssf"
                )
        else:
            raise AdvisoryCatalogError("OpenSSF affected package is invalid")
        versions = item.get("versions", [])
        ranges = item.get("ranges", [])
        if not isinstance(versions, list) or len(versions) > 10_000:
            raise AdvisoryCatalogError("OpenSSF version list is invalid")
        if not isinstance(ranges, list) or len(ranges) > 1_000:
            raise AdvisoryCatalogError("OpenSSF range list is invalid")
        exact_versions: list[str] = []
        seen_versions: set[str] = set()
        for version in versions:
            if not isinstance(version, str) or not version or len(version) > 200:
                raise AdvisoryCatalogError("OpenSSF exact version is invalid")
            if version not in seen_versions:
                seen_versions.add(version)
                exact_versions.append(version)
        if package_less_git and not ranges:
            raise AdvisoryCatalogError("OpenSSF package-less GIT coordinate is invalid")
        affected_ranges: list[dict[str, Any]] = []
        for range_value in ranges:
            if not isinstance(range_value, Mapping):
                raise AdvisoryCatalogError("OpenSSF range is invalid")
            range_type = range_value.get("type")
            events = range_value.get("events")
            if package_less_git and (
                range_type != "GIT"
                or not isinstance(range_value.get("repo"), str)
                or not range_value["repo"]
            ):
                raise AdvisoryCatalogError("OpenSSF package-less GIT range is invalid")
            if not isinstance(range_type, str) or range_type not in {"ECOSYSTEM", "GIT", "SEMVER"}:
                raise AdvisoryCatalogError("OpenSSF range type is invalid")
            if not isinstance(events, list) or len(events) > 1_000:
                raise AdvisoryCatalogError("OpenSSF range events are invalid")
            projected_events: list[dict[str, str]] = []
            for event in events:
                if not isinstance(event, Mapping) or len(event) != 1:
                    raise AdvisoryCatalogError("OpenSSF range event is invalid")
                key, value = next(iter(event.items()))
                if key not in {"introduced", "fixed", "last_affected", "limit"}:
                    raise AdvisoryCatalogError("OpenSSF range event type is invalid")
                if not isinstance(value, str) or not value or len(value) > 200:
                    raise AdvisoryCatalogError("OpenSSF range event value is invalid")
                projected_events.append({key: value})
            affected_ranges.append({"type": range_type, "events": projected_events})
        if package_less_git or untyped:
            omitted_inputs.append([index, package, versions, ranges])
            omissions[
                "unsupported_git_coordinate" if package_less_git else "untyped_upstream_ecosystem"
            ] += 1
            continue
        packages.append(
            {
                "entry_key": sha256_id(
                    canonical_json_bytes([index, ecosystem, name, exact_versions, affected_ranges])
                ),
                "ecosystem": ecosystem,
                "raw_ecosystem": raw_ecosystem,
                "name": name,
                "exact_versions": exact_versions,
                "affected_ranges": affected_ranges,
            }
        )
    published_at = _source_time(document.get("published"), field="published", required=False)
    updated_at = _source_time(document.get("modified"), field="modified", required=False)
    if updated_at is None:
        updated_at = published_at
    if updated_at is None:
        raise AdvisoryCatalogError("OpenSSF record has no source time")
    withdrawn = document.get("withdrawn") is not None
    if withdrawn != (source_state == "withdrawn"):
        raise AdvisoryCatalogError("OpenSSF path and withdrawal state differ")
    return {
        "upstream_record_id": upstream_id,
        "source_type": "openssf",
        "claim_type": "malicious",
        "confidence": "confirmed",
        "state": "withdrawn" if withdrawn else "active",
        "cwe_ids": [],
        "aliases": sorted(aliases),
        "package_omission_counts": dict(sorted(omissions.items())),
        "canonical_url": canonical_url,
        "source_published_at": published_at,
        "source_updated_at": updated_at,
        "packages": packages,
        **(
            {"omitted_inputs_sha256": sha256_id(canonical_json_bytes(omitted_inputs))}
            if omitted_inputs
            else {}
        ),
    }


def _projection_source_document(
    projection: Mapping[str, Any],
    source_identity_omits: frozenset[str] = frozenset(),
    *,
    source_id: str | None = None,
) -> dict[str, Any]:
    """Canonical projection; unchanged for historical inputs lacking new fields."""
    if source_id is not None and projection.get("source_type") == "rustsec":
        from smithguard.origin_advisories import _origin_semantic_projection

        projection = _origin_semantic_projection(projection, source_id=source_id)
    source_document = {
        key: projection[key]
        for key in (
            "upstream_record_id",
            "source_type",
            "claim_type",
            "confidence",
            "state",
            "cwe_ids",
            "aliases",
            "package_omission_counts",
            "canonical_url",
            "source_published_at",
            "source_updated_at",
            "packages",
        )
    }
    if "omitted_inputs_sha256" in projection:
        source_document["omitted_inputs_sha256"] = projection["omitted_inputs_sha256"]
    if "origin_context" in projection:
        source_document["origin_context"] = projection["origin_context"]
    if "public_context" in projection:
        source_document["public_context"] = projection["public_context"]
    source_hash_document = {
        **{
            key: value for key, value in source_document.items() if key not in source_identity_omits
        },
        "source_published_at": (
            timestamp(source_document["source_published_at"])
            if source_document["source_published_at"] is not None
            else None
        ),
        "source_updated_at": timestamp(source_document["source_updated_at"]),
    }
    return source_hash_document


def _projection_source_hash(
    projection: Mapping[str, Any],
    source_identity_omits: frozenset[str] = frozenset(),
    *,
    source_id: str | None = None,
) -> str:
    """One semantic identity algorithm shared by append and pre-ingestion checks."""
    return sha256_id(
        canonical_json_bytes(
            _projection_source_document(projection, source_identity_omits, source_id=source_id)
        )
    )


def _append_projection(
    session: Session,
    *,
    source_id: str,
    projection: Mapping[str, Any],
    evidence_id: str,
    governance_decision_id: str,
    observed_at: datetime,
    source_identity_omits: frozenset[str] = frozenset(),
) -> CatalogAppendResult:
    observed_at = _aware(observed_at, field="observed_at")
    upstream_id = str(projection["upstream_record_id"])
    source_sha256 = _projection_source_hash(projection, source_identity_omits, source_id=source_id)
    lock = f"advisory-catalog:{source_id}:{upstream_id}"
    advisory_xact_lock(session, lock)
    latest = session.scalar(
        select(AdvisoryCatalogRecord)
        .where(
            AdvisoryCatalogRecord.source_id == source_id,
            AdvisoryCatalogRecord.upstream_record_id == upstream_id,
        )
        .order_by(AdvisoryCatalogRecord.revision.desc())
        .limit(1)
    )
    if latest is not None and latest.source_sha256 == source_sha256:
        return CatalogAppendResult(
            latest.catalog_event_id,
            latest.revision,
            False,
            len(projection["packages"]),
            latest.source_sha256,
            dict(latest.package_omission_counts),
        )
    if (
        source_id == GITHUB_SOURCE_ID
        and latest is not None
        and projection["source_updated_at"] < latest.source_updated_at
    ):
        raise AdvisoryCatalogStaleRevision(
            "older GitHub source revision cannot replace newer evidence"
        )
    revision = 1 if latest is None else latest.revision + 1
    if "public_context" in projection:
        # The existing append-only content-addressed document store is shared by
        # supplemental facts and catalog projections. Its key remains the hash of
        # the WHOLE stored canonical document; no synthetic key or history rewrite.
        payload = _projection_source_document(
            projection, source_identity_omits, source_id=source_id
        )
        session.execute(
            pg_insert(SupplementalPayloadRecord)
            .values(payload_sha256=source_sha256, document=payload)
            .on_conflict_do_nothing(index_elements=["payload_sha256"])
        )
        if session.get(SupplementalPayloadRecord, source_sha256).document != payload:
            raise AdvisoryCatalogError("catalog context payload identity conflict")
    catalog_event_id = stable_id("advisory-catalog", source_id, upstream_id, str(revision))
    values = {
        "catalog_event_id": catalog_event_id,
        "source_id": source_id,
        "upstream_record_id": upstream_id,
        "revision": revision,
        "source_type": projection["source_type"],
        "claim_type": projection["claim_type"],
        "confidence": projection["confidence"],
        "state": projection["state"],
        "cwe_ids": list(projection["cwe_ids"]),
        "aliases": list(projection["aliases"]),
        "package_omission_counts": dict(projection["package_omission_counts"]),
        "canonical_url": projection["canonical_url"],
        "evidence_id": evidence_id,
        "governance_decision_id": governance_decision_id,
        "source_published_at": projection["source_published_at"],
        "source_updated_at": projection["source_updated_at"],
        "observed_at": observed_at,
        "source_sha256": source_sha256,
    }
    hash_values = {
        **values,
        "source_published_at": (
            timestamp(values["source_published_at"])
            if values["source_published_at"] is not None
            else None
        ),
        "source_updated_at": timestamp(values["source_updated_at"]),
        "observed_at": timestamp(observed_at),
    }
    session.add(
        AdvisoryCatalogRecord(
            **values,
            record_hash=sha256_id(canonical_json_bytes(hash_values)),
        )
    )
    for package in projection["packages"]:
        package_values = {
            "package_event_id": stable_id(
                "advisory-package", source_id, upstream_id, package["entry_key"], str(revision)
            ),
            "catalog_event_id": catalog_event_id,
            "source_id": source_id,
            "upstream_record_id": upstream_id,
            "entry_key": package["entry_key"],
            "revision": revision,
            "ecosystem": package["ecosystem"],
            "raw_ecosystem": package["raw_ecosystem"],
            "name": package["name"],
            "exact_versions": package["exact_versions"],
            "affected_ranges": package["affected_ranges"],
            "state": projection["state"],
            "claim_type": projection["claim_type"],
            "confidence": projection["confidence"],
            "source_updated_at": projection["source_updated_at"],
            "observed_at": observed_at,
            "source_sha256": sha256_id(canonical_json_bytes(package)),
        }
        package_hash_values = {
            **package_values,
            "source_updated_at": timestamp(package_values["source_updated_at"]),
            "observed_at": timestamp(observed_at),
        }
        session.add(
            AdvisoryPackageRecord(
                **package_values,
                record_hash=sha256_id(canonical_json_bytes(package_hash_values)),
            )
        )
    session.flush()
    return CatalogAppendResult(
        catalog_event_id,
        revision,
        True,
        len(projection["packages"]),
        source_sha256,
        dict(projection["package_omission_counts"]),
    )


def append_github_advisory(
    session: Session,
    *,
    document: Mapping[str, Any],
    evidence_id: str,
    governance_decision_id: str,
    observed_at: datetime,
) -> CatalogAppendResult:
    """Append one complete GitHub REST advisory revision and all package entries."""
    return _append_projection(
        session,
        source_id=GITHUB_SOURCE_ID,
        projection=_github_projection(document),
        evidence_id=evidence_id,
        governance_decision_id=governance_decision_id,
        observed_at=observed_at,
    )


def openssf_advisory_identity(
    document: Mapping[str, Any], *, canonical_url: str, source_state: Literal["active", "withdrawn"]
) -> tuple[str, int]:
    """Validate and hash a candidate without writing evidence or catalog revisions."""
    projection = _openssf_projection(
        document, canonical_url=canonical_url, source_state=source_state
    )
    return _projection_source_hash(projection, frozenset({"canonical_url"})), len(
        projection["packages"]
    )


def append_openssf_advisory(
    session: Session,
    *,
    document: Mapping[str, Any],
    canonical_url: str,
    source_state: Literal["active", "withdrawn"],
    evidence_id: str,
    governance_decision_id: str,
    observed_at: datetime,
) -> CatalogAppendResult:
    """Append one complete OpenSSF record revision without an ecosystem allowlist."""
    return _append_projection(
        session,
        source_id=OPENSSF_SOURCE_ID,
        projection=_openssf_projection(
            document,
            canonical_url=canonical_url,
            source_state=source_state,
        ),
        evidence_id=evidence_id,
        governance_decision_id=governance_decision_id,
        observed_at=observed_at,
        # The commit-pinned page is working provenance for the stored revision, but
        # moving repository HEAD alone is not a change to the advisory payload.
        source_identity_omits=frozenset({"canonical_url"}),
    )


def append_github_inventory_membership(
    session: Session,
    *,
    segment: Literal["malware", "reviewed", "unreviewed"],
    source_snapshot: str,
    upstream_record_id: str,
    appended: CatalogAppendResult,
    observed_at: datetime,
) -> AdvisoryCatalogInventoryRecord:
    """Preserve exact membership in one frozen GitHub historical snapshot."""
    _source_time(source_snapshot, field="source_snapshot", required=True)
    observed_at = _aware(observed_at, field="observed_at")
    existing = session.scalar(
        select(AdvisoryCatalogInventoryRecord).where(
            AdvisoryCatalogInventoryRecord.source_id == GITHUB_SOURCE_ID,
            AdvisoryCatalogInventoryRecord.segment == segment,
            AdvisoryCatalogInventoryRecord.source_snapshot == source_snapshot,
            AdvisoryCatalogInventoryRecord.upstream_record_id == upstream_record_id,
        )
    )
    if existing is not None:
        # A later catalog event can return to exactly the same governed content
        # (including updated_at). Keep the original immutable membership/event;
        # internal revision allocation is not a change to this snapshot's bytes.
        if (
            existing.source_sha256 != appended.source_sha256
            or existing.package_entry_count != appended.package_entry_count
        ):
            raise AdvisoryCatalogError(
                "GitHub historical snapshot membership changed during collection"
            )
        return existing
    values = {
        "inventory_event_id": stable_id(
            "advisory-catalog-inventory",
            GITHUB_SOURCE_ID,
            segment,
            source_snapshot,
            upstream_record_id,
        ),
        "catalog_event_id": appended.catalog_event_id,
        "source_id": GITHUB_SOURCE_ID,
        "segment": segment,
        "source_snapshot": source_snapshot,
        "upstream_record_id": upstream_record_id,
        "source_sha256": appended.source_sha256,
        "package_entry_count": appended.package_entry_count,
        "observed_at": observed_at,
    }
    record = AdvisoryCatalogInventoryRecord(
        **values,
        record_hash=sha256_id(
            canonical_json_bytes({**values, "observed_at": timestamp(observed_at)})
        ),
    )
    session.add(record)
    session.flush()
    return record


def append_catalog_manifest(
    session: Session,
    *,
    source_id: str,
    segment: str,
    state: Literal["in_progress", "complete", "failed"],
    source_snapshot: str,
    cursor_value: str | None,
    record_count: int,
    package_entry_count: int,
    manifest_sha256: str,
    observed_at: datetime,
) -> AdvisoryCatalogManifestRecord:
    """Append one full or resumable source manifest receipt."""
    lock = f"advisory-catalog-manifest:{source_id}:{segment}"
    advisory_xact_lock(session, lock)
    sequence = (
        session.scalar(
            select(func.max(AdvisoryCatalogManifestRecord.sequence)).where(
                AdvisoryCatalogManifestRecord.source_id == source_id,
                AdvisoryCatalogManifestRecord.segment == segment,
            )
        )
        or 0
    ) + 1
    observed_at = _aware(observed_at, field="observed_at")
    values = {
        "manifest_event_id": stable_id(
            "advisory-catalog-manifest", source_id, segment, str(sequence)
        ),
        "source_id": source_id,
        "segment": segment,
        "sequence": sequence,
        "state": state,
        "source_snapshot": source_snapshot,
        "cursor_value": cursor_value,
        "record_count": record_count,
        "package_entry_count": package_entry_count,
        "manifest_sha256": manifest_sha256,
        "observed_at": observed_at,
    }
    record = AdvisoryCatalogManifestRecord(
        **values,
        record_hash=sha256_id(
            canonical_json_bytes({**values, "observed_at": timestamp(observed_at)})
        ),
    )
    session.add(record)
    session.flush()
    return record


def append_github_segment_manifest(
    session: Session,
    *,
    segment: Literal["malware", "reviewed", "unreviewed"],
    source_snapshot: str,
    expected_record_count: int,
    expected_package_entry_count: int,
    observed_at: datetime,
) -> AdvisoryCatalogManifestRecord:
    """Manifest exact membership returned for one frozen GitHub type segment."""
    _source_time(source_snapshot, field="source_snapshot", required=True)
    records = [
        [str(upstream_record_id), str(source_sha256)]
        for upstream_record_id, source_sha256 in session.execute(
            select(
                AdvisoryCatalogInventoryRecord.upstream_record_id,
                AdvisoryCatalogInventoryRecord.source_sha256,
            )
            .where(
                AdvisoryCatalogInventoryRecord.source_id == GITHUB_SOURCE_ID,
                AdvisoryCatalogInventoryRecord.segment == segment,
                AdvisoryCatalogInventoryRecord.source_snapshot == source_snapshot,
            )
            .order_by(AdvisoryCatalogInventoryRecord.upstream_record_id)
        )
    ]
    package_entry_count = int(
        session.scalar(
            select(func.sum(AdvisoryCatalogInventoryRecord.package_entry_count)).where(
                AdvisoryCatalogInventoryRecord.source_id == GITHUB_SOURCE_ID,
                AdvisoryCatalogInventoryRecord.segment == segment,
                AdvisoryCatalogInventoryRecord.source_snapshot == source_snapshot,
            )
        )
        or 0
    )
    if len(records) != expected_record_count:
        raise AdvisoryCatalogError(
            "GitHub historical record count differs from the complete catalog"
        )
    if package_entry_count != expected_package_entry_count:
        raise AdvisoryCatalogError(
            "GitHub historical package count differs from the complete catalog"
        )
    manifest_sha256 = sha256_id(canonical_json_bytes(records))
    return append_catalog_manifest(
        session,
        source_id=GITHUB_SOURCE_ID,
        segment=segment,
        state="complete",
        source_snapshot=source_snapshot,
        cursor_value=None,
        record_count=len(records),
        package_entry_count=package_entry_count,
        manifest_sha256=manifest_sha256,
        observed_at=observed_at,
    )


def _github_range_matches(ecosystem: str, version: str, expression: str) -> bool | None:
    exact = EXACT_GITHUB.fullmatch(expression.strip())
    if exact is not None:
        expected = exact.group(1)
        if ecosystem == "npm":
            return semver_matches(version, f"={expected}")
        return exact_version_matches(ecosystem, version, expected)
    if ecosystem == "npm":
        normalized = normalize_github_npm_advisory_range(expression)
        if normalized == "*":
            return True
        return None if normalized is None else semver_matches(version, normalized)
    if ecosystem == "pypi":
        normalized = COMPARATOR_WITH_SPACE.sub(r"\1", expression.strip())
        normalized = re.sub(r",\s+", ",", normalized)
        return pep440_matches(version, normalized)
    # Every other ecosystem: GitHub's comparator list under that ecosystem's ordering.
    return comparator_list_matches(ecosystem, version, expression)


def _openssf_range_matches(
    ecosystem: str,
    version: str,
    affected_range: Mapping[str, Any],
) -> bool | None:
    return osv_range_matches(ecosystem, version, affected_range)


def _package_match(package: AdvisoryPackageRecord, *, version: str | None) -> bool | None:
    if version is None:
        return None
    exact = [
        exact_version_matches(package.ecosystem, version, expected)
        for expected in package.exact_versions
    ]
    if True in exact:
        return True
    # An undecided exact comparison (a spelling outside the implemented order) keeps
    # the package undecided unless a range decides it applies.
    evaluations: list[bool | None] = [None] if None in exact else []
    for affected_range in package.affected_ranges:
        if affected_range.get("type") == "GITHUB":
            evaluations.append(
                _github_range_matches(
                    package.ecosystem,
                    version,
                    str(affected_range.get("expression", "")),
                )
            )
        else:
            evaluations.append(_openssf_range_matches(package.ecosystem, version, affected_range))
    if True in evaluations:
        return True
    if None in evaluations:
        return None
    if evaluations or package.exact_versions:
        return False
    return None


MAX_FIXED_VERSIONS = 20
MAX_ALIASES = 20
MAX_UPSTREAM_URLS = 10
PRINTABLE_ALIAS = re.compile(r"^[ -~]{1,160}$")
PUBLIC_VULNERABILITY_ALIAS = re.compile(
    r"^(?:CVE-[12][0-9]{3}-[0-9]{4,12}|RUSTSEC-[12][0-9]{3}-[0-9]{4}|"
    r"GO-[12][0-9]{3}-[0-9]{4,8}|MAL-[12][0-9]{3}-[0-9]{1,12})$"
)


def _fixed_versions(ecosystem: str, packages: Sequence[AdvisoryPackageRecord]) -> tuple[str, ...]:
    """Source patches, with legacy GitHub upper bounds when no explicit patch is named."""
    found: set[str] = set()
    for package in packages:
        for affected_range in package.affected_ranges:
            range_type = affected_range.get("type")
            if range_type == "GITHUB":
                patched = affected_range.get("first_patched_version")
                if isinstance(patched, str):
                    found.add(patched)
                    continue
                for part in str(affected_range.get("expression", "")).split(","):
                    match = COMPARATOR.fullmatch(part)
                    if match is not None and match.group(1) == "<":
                        found.add(match.group(2))
            elif range_type in ("ECOSYSTEM", "SEMVER"):
                events = affected_range.get("events")
                for event in events if isinstance(events, list) else ():
                    fixed = event.get("fixed") if isinstance(event, Mapping) else None
                    if isinstance(fixed, str):
                        found.add(fixed)
    values = [value for value in found if 0 < len(value) <= 200 and value.isprintable()]
    ordered: list[tuple[Any, str]] = []
    unordered: list[str] = []
    for value in values:
        try:
            ordered.append((version_key(ecosystem, value), value))
        except VersionOrderError:
            unordered.append(value)
    ordered.sort(key=lambda item: item[0])
    return tuple([value for _key, value in ordered] + sorted(unordered))[:MAX_FIXED_VERSIONS]


def _family_references(
    catalogs: Sequence[AdvisoryCatalogRecord],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Public advisory identifiers and upstream record URLs, bounded and sorted."""
    aliases = {
        # GitHub's own spelling: GHSA IDs are stored both upper-cased and as published.
        "GHSA-" + value[5:].lower() if GHSA_ID.fullmatch(value) else value
        for catalog in catalogs
        for value in (catalog.upstream_record_id, *catalog.aliases)
        if isinstance(value, str) and PRINTABLE_ALIAS.fullmatch(value)
    }
    urls = {
        catalog.canonical_url
        for catalog in catalogs
        if catalog.canonical_url.startswith("https://") and len(catalog.canonical_url) <= 2048
    }
    return tuple(sorted(aliases))[:MAX_ALIASES], tuple(sorted(urls))[:MAX_UPSTREAM_URLS]


def _shared_alias(value: object) -> str | None:
    """Only explicitly namespaced advisory identifiers connect separate origins."""
    if not isinstance(value, str) or len(value) > 160:
        return None
    canonical = value.upper()
    if GHSA_ID.fullmatch(canonical) or PUBLIC_VULNERABILITY_ALIAS.fullmatch(canonical):
        return canonical
    return None


def _alias_components(
    values: Sequence[tuple[AdvisoryCatalogRecord, AdvisoryPackageRecord]],
) -> dict[str, list[tuple[AdvisoryCatalogRecord, AdvisoryPackageRecord]]]:
    """Coalesce aliases around direct origins inside one bounded package query.

    Each record's ranges and authority remain separate assertions. A component is
    not evidence of independent corroboration. Withdrawn and omitted memberships
    are excluded by the caller, so they cannot serve as an active alias bridge.
    Components without a RustSec or Go source retain the legacy per-record GHSA
    key (or source/upstream identity), preserving existing public incident IDs.
    """
    parents: dict[tuple[str, str], tuple[str, str]] = {}
    ranks: dict[tuple[str, str], int] = {}
    aliases_by_record: dict[tuple[str, str], tuple[str, ...]] = {}
    owners: dict[str, tuple[str, str]] = {}
    links = 0

    def find(identity: tuple[str, str]) -> tuple[str, str]:
        root = identity
        while parents[root] != root:
            root = parents[root]
        while parents[identity] != identity:
            previous = parents[identity]
            parents[identity] = root
            identity = previous
        return root

    def union(left: tuple[str, str], right: tuple[str, str]) -> None:
        left, right = find(left), find(right)
        if left == right:
            return
        if ranks[left] < ranks[right] or ranks[left] == ranks[right] and left > right:
            left, right = right, left
        parents[right] = left
        if ranks[left] == ranks[right]:
            ranks[left] += 1

    for catalog, _package in values:
        identity = (catalog.source_id, catalog.upstream_record_id)
        if identity in parents:
            continue
        parents[identity], ranks[identity] = identity, 0
        aliases = tuple(
            sorted(
                {
                    alias
                    for value in (catalog.upstream_record_id, *catalog.aliases)
                    if (alias := _shared_alias(value)) is not None
                }
            )
        )
        links += len(aliases)
        if links > CATALOG_ALIAS_LINK_LIMIT:
            raise AdvisoryCatalogCapacityExceeded(
                "catalog package aliases exceed the explicit link bound"
            )
        aliases_by_record[identity] = aliases
        for alias in aliases:
            if alias in owners:
                union(identity, owners[alias])
            else:
                owners[alias] = identity
    by_root: dict[tuple[str, str], list[tuple[AdvisoryCatalogRecord, AdvisoryPackageRecord]]] = (
        defaultdict(list)
    )
    for catalog, package in values:
        by_root[find((catalog.source_id, catalog.upstream_record_id))].append((catalog, package))
    grouped: dict[str, list[tuple[AdvisoryCatalogRecord, AdvisoryPackageRecord]]] = defaultdict(
        list
    )
    for members in by_root.values():
        if not any(catalog.source_id in ORIGIN_SOURCE_IDS for catalog, _package in members):
            for catalog, package in members:
                ghsa = sorted(
                    alias
                    for alias in aliases_by_record[(catalog.source_id, catalog.upstream_record_id)]
                    if GHSA_ID.fullmatch(alias)
                )
                key = ghsa[0] if ghsa else f"{catalog.source_id}:{catalog.upstream_record_id}"
                grouped[key].append((catalog, package))
            continue
        aliases = {
            alias
            for catalog, _package in members
            for alias in aliases_by_record[(catalog.source_id, catalog.upstream_record_id)]
        }
        ghsa = sorted(alias for alias in aliases if GHSA_ID.fullmatch(alias))
        cves = sorted(alias for alias in aliases if alias.startswith("CVE-"))
        key = (
            ghsa
            or cves
            or sorted(aliases)
            or sorted(
                f"{catalog.source_id}:{catalog.upstream_record_id}" for catalog, _package in members
            )
        )[0]
        grouped[key].extend(members)
    return dict(grouped)


def catalog_evidence_for_package(
    session: Session,
    *,
    ecosystem: str,
    name: str,
    version: str | None,
) -> CatalogPackageEvidence:
    """Bind active assertions and all relevant latest revisions in one SQL snapshot."""
    # Start with historical package membership: an omission must not restore an old
    # active assertion or erase the revision that removed it from the fingerprint.
    relevant = (
        select(AdvisoryPackageRecord.source_id, AdvisoryPackageRecord.upstream_record_id)
        .where(
            package_name_predicate(
                AdvisoryPackageRecord.name,
                ecosystem_column=AdvisoryPackageRecord.ecosystem,
                ecosystem=ecosystem,
                name=name,
            ),
        )
        .distinct()
        .order_by(AdvisoryPackageRecord.source_id, AdvisoryPackageRecord.upstream_record_id)
        .limit(CATALOG_QUERY_LIMIT)
        .cte("relevant_catalog_identities")
    )
    newest = aliased(AdvisoryCatalogRecord)
    newest_id = (
        select(newest.catalog_event_id)
        .where(
            newest.source_id == relevant.c.source_id,
            newest.upstream_record_id == relevant.c.upstream_record_id,
        )
        .order_by(newest.revision.desc())
        .limit(1)
        .correlate(relevant)
        .scalar_subquery()
    )
    unresolved = actionable_quarantines_statement(source_id=GITHUB_SOURCE_ID).subquery(
        "unresolved_collection_records"
    )
    rows = tuple(
        session.execute(
            select(
                AdvisoryCatalogRecord,
                AdvisoryPackageRecord,
                unresolved.c.record_key,
                unresolved.c.outcome_id,
                unresolved.c.record_hash,
                SourceGovernanceDecisionRecord.field_policy_id,
            )
            .select_from(relevant)
            .join(AdvisoryCatalogRecord, AdvisoryCatalogRecord.catalog_event_id == newest_id)
            .outerjoin(
                AdvisoryPackageRecord,
                and_(
                    AdvisoryPackageRecord.catalog_event_id
                    == AdvisoryCatalogRecord.catalog_event_id,
                    package_name_predicate(
                        AdvisoryPackageRecord.name,
                        ecosystem_column=AdvisoryPackageRecord.ecosystem,
                        ecosystem=ecosystem,
                        name=name,
                    ),
                ),
            )
            .outerjoin(
                SourceGovernanceDecisionRecord,
                SourceGovernanceDecisionRecord.decision_id
                == AdvisoryCatalogRecord.governance_decision_id,
            )
            .outerjoin(
                unresolved,
                and_(
                    unresolved.c.source_id == AdvisoryCatalogRecord.source_id,
                    unresolved.c.record_key == AdvisoryCatalogRecord.upstream_record_id,
                ),
            )
            .order_by(
                AdvisoryCatalogRecord.source_id,
                AdvisoryCatalogRecord.upstream_record_id,
                AdvisoryPackageRecord.entry_key,
            )
            .limit(CATALOG_QUERY_LIMIT)
        )
    )
    if len(rows) >= CATALOG_QUERY_LIMIT:
        raise AdvisoryCatalogCapacityExceeded(
            "catalog package evidence exceeds the explicit 10000-row bound"
        )
    gap_keys = {
        record_key
        for _catalog, _package, record_key, _outcome, _hash, _policy in rows
        if record_key is not None
    }
    gap_refs = sorted(
        {
            (outcome_id, record_hash)
            for _catalog, _package, _key, outcome_id, record_hash, _policy in rows
            if outcome_id is not None
        }
    )
    active_members = []
    member_refs = [
        ("unresolved_collection", outcome_id, record_hash) for outcome_id, record_hash in gap_refs
    ]
    seen_members = set()
    field_policies = {}
    for catalog, package, _record_key, _outcome_id, _record_hash, field_policy in rows:
        field_policies[catalog.governance_decision_id] = field_policy
        member_key = (catalog.catalog_event_id, package.package_event_id if package else None)
        if member_key in seen_members:
            continue
        seen_members.add(member_key)
        member_refs.append(
            (
                catalog.source_id,
                catalog.upstream_record_id,
                catalog.catalog_event_id,
                catalog.revision,
                catalog.state,
                catalog.record_hash,
                None
                if package is None
                else (
                    package.package_event_id,
                    package.entry_key,
                    package.revision,
                    package.state,
                    package.record_hash,
                ),
            )
        )
        if catalog.state != "active" or package is None or package.state != "active":
            continue
        active_members.append((catalog, package))
    grouped = _alias_components(active_members)
    families: list[CatalogMatchFamily] = []
    for family_key, values in sorted(grouped.items()):
        evaluated_values = tuple(
            (
                catalog,
                package,
                None
                if catalog.source_id == GITHUB_SOURCE_ID and catalog.upstream_record_id in gap_keys
                else _package_match(package, version=version),
            )
            for catalog, package in values
        )
        matched = tuple(value for value in evaluated_values if value[2] is True)
        authoritative_matches = tuple(
            value for value in matched if value[0].confidence == "confirmed"
        )
        # Classification and authority travel with the assertion's own range result.
        # Nonmatches and undecidable assertions cannot lend authority to a match.
        eligible = (
            authoritative_matches
            or matched
            or tuple(value for value in evaluated_values if value[2] is None)
            or evaluated_values
        )
        claim_types = {catalog.claim_type for catalog, _package, _evaluation in eligible}
        classification = (
            "compromised"
            if "compromised" in claim_types
            else max(claim_types, key=CLASSIFICATION_RANK.__getitem__)
        )
        # Confidence is the authority of the assertions relevant to this version: the
        # matching ones when any match, the undecided ones next, and otherwise the whole
        # family, so a reviewed advisory that does not apply keeps its "confirmed" source
        # label (with `applies` false) instead of reading as an unverified report.
        confidence = (
            "confirmed"
            if any(catalog.confidence == "confirmed" for catalog, _package, _ in eligible)
            else "unverified"
        )
        evaluations = tuple(evaluation for _catalog, _package, evaluation in evaluated_values)
        reports: dict[tuple[str, str], dict[str, Any]] = {}
        report_values = defaultdict(list)
        matched_ids: list[str] = []
        latest = max(catalog.source_updated_at for catalog, _package in values)
        family_aliases, family_urls = _family_references([catalog for catalog, _package in values])
        revision = max(catalog.revision for catalog, _package in values)
        for catalog, package, evaluation in evaluated_values:
            report_values[(catalog.source_id, catalog.upstream_record_id)].append(
                (package, evaluation)
            )
            reports[(catalog.source_id, catalog.upstream_record_id)] = {
                "source_id": catalog.source_id,
                "source_name": (
                    {
                        GITHUB_SOURCE_ID: "GitHub Advisory Database",
                        OPENSSF_SOURCE_ID: "OpenSSF Malicious Packages",
                        "gbsec:source:rustsec-advisory-database": "RustSec Advisory Database",
                        "gbsec:source:go-vulnerability-database": "Go Vulnerability Database",
                    }[catalog.source_id]
                ),
                "upstream_record_id": catalog.upstream_record_id,
                "state": catalog.state,
                "source_updated_at": timestamp(catalog.source_updated_at),
                "observed_at": timestamp(catalog.observed_at),
                "catalog_source_sha256": catalog.source_sha256,
                "catalog_event_id": catalog.catalog_event_id,
                "source_revision": catalog.revision,
                "evidence_id": catalog.evidence_id,
                "field_policy_id": field_policies.get(catalog.governance_decision_id),
            }
            if evaluation is True:
                matched_ids.append(package.package_event_id)
        for report_key, entries in report_values.items():
            evaluations_for_report = [evaluation for _package, evaluation in entries]
            reports[report_key]["applies_to_version"] = (
                True
                if True in evaluations_for_report
                else None
                if None in evaluations_for_report
                else False
            )
            reports[report_key]["fixed_versions"] = list(
                _fixed_versions(
                    entries[0][0].ecosystem,
                    []
                    if report_key[0] == GITHUB_SOURCE_ID and report_key[1] in gap_keys
                    else [package for package, _evaluation in entries],
                )
            )
            report = reports[report_key]
            report.update(
                source_fix_evidence(
                    [package for package, _evaluation in entries],
                    ecosystem=ecosystem,
                    github_match=lambda expression: _github_range_matches(
                        ecosystem, version, expression
                    ),
                    osv_match=lambda affected: _openssf_range_matches(ecosystem, version, affected),
                    historical=report["field_policy_id"] in HISTORICAL_GITHUB_POLICIES,
                    unresolved=report_key[0] == GITHUB_SOURCE_ID and report_key[1] in gap_keys,
                )
            )
        families.append(
            CatalogMatchFamily(
                family_key=family_key,
                incident_id=stable_id("catalog-incident", family_key),
                revision=revision,
                status="confirmed" if confidence == "confirmed" else "emerging_unverified",
                confidence=confidence,
                classification=classification,
                title=(f"{classification.capitalize()} package evidence: {family_key}")[:300],
                last_changed_at=timestamp(latest),
                source_reports=tuple(reports[key] for key in sorted(reports)),
                evaluations=evaluations,
                matched_range_ids=tuple(sorted(set(matched_ids))),
                authoritative_match=bool(authoritative_matches),
                fixed_versions=_fixed_versions(
                    values[0][1].ecosystem,
                    [
                        package
                        for catalog, package in values
                        if not (
                            catalog.source_id == GITHUB_SOURCE_ID
                            and catalog.upstream_record_id in gap_keys
                        )
                    ],
                ),
                aliases=family_aliases,
                upstream_urls=family_urls,
            )
        )
    return CatalogPackageEvidence(
        families=tuple(families),
        fingerprint=stable_id(
            "catalog-evidence-v1",
            member_refs,
            [
                (
                    family_key,
                    sorted(
                        (
                            catalog.source_id,
                            catalog.upstream_record_id,
                            catalog.catalog_event_id,
                            package.package_event_id,
                        )
                        for catalog, package in members
                    ),
                )
                for family_key, members in sorted(grouped.items())
            ],
        ),
    )
