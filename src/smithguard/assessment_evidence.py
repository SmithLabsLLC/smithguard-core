"""Bounded, source-specific fix evidence; range ends never become proven repairs."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from smithguard.identifiers import canonical_json_bytes, sha256_id
from smithguard.range_evaluation import osv_intervals
from smithguard.version_order import COMPARATOR, VersionOrderError, version_key

MAX_FIX_EVIDENCE = 40
MAX_RANGE_BOUNDS = 40
MAX_SOURCE_FIXES = 20
HISTORICAL_GITHUB_POLICIES = frozenset({"gbsec:field-policy:github-advisory-catalog-v2"})


def ordered_versions(ecosystem: str, values: Sequence[str]) -> list[str]:
    ordered, unordered = [], []
    for value in set(values):
        try:
            ordered.append((version_key(ecosystem, value), value))
        except VersionOrderError:
            unordered.append(value)
    ordered.sort(key=lambda item: (item[0], item[1]))
    return [value for _key, value in ordered] + sorted(unordered)


def _version(value: object) -> str | None:
    return (
        value
        if isinstance(value, str)
        and 0 < len(value) <= 200
        and value.isascii()
        and value.isprintable()
        and value.strip() == value
        else None
    )


def _range_evidence(
    package: Any,
    index: int,
    affected: Mapping[str, Any],
    *,
    ecosystem: str,
    github_match: Callable[[str], bool | None],
    osv_match: Callable[[Mapping[str, Any]], bool | None],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Keep package/range/branch association and the exact normalized range hash."""
    kind = affected.get("type")
    base = {
        "package_entry_id": package.package_event_id,
        "range_index": index,
        "range_sha256": sha256_id(canonical_json_bytes(affected)),
        "range_type": kind if kind in {"GITHUB", "SEMVER", "ECOSYSTEM", "GIT"} else "other",
        "expression": affected.get("expression") if kind == "GITHUB" else None,
        "introduced_version": None,
        "fixed_version": None,
        "source_field": None,
        "applies_to_requested_version": None,
    }
    bounds = []
    if kind == "GITHUB":
        patch = _version(affected.get("first_patched_version"))
        state = (
            "absent"
            if "first_patched_version" not in affected
            else "explicit_null"
            if affected["first_patched_version"] is None
            else "explicit_value"
            if patch is not None
            else "invalid"
        )
        expression = str(affected.get("expression", ""))
        for part in expression.split(","):
            match = COMPARATOR.fullmatch(part)
            if match and match[1] in {"<", "<="} and _version(match[2]):
                bounds.append(
                    {
                        "package_entry_id": package.package_event_id,
                        "range_index": index,
                        "kind": "exclusive_upper" if match[1] == "<" else "inclusive_upper",
                        "version": match[2],
                    }
                )
        return [
            {
                **base,
                "patch_field_state": state,
                "fixed_version": patch,
                "source_field": "first_patched_version" if patch is not None else None,
                "applies_to_requested_version": github_match(expression),
            }
        ], bounds
    if kind not in {"SEMVER", "ECOSYSTEM"}:
        return [{**base, "patch_field_state": "unsupported_range_type"}], []
    events = affected.get("events")
    events = events if isinstance(events, list) else []
    # Use the same canonical ordering as the matcher. OSV does not require input
    # order. Keep limits separate when pairing fixes, then apply them to each
    # branch's match so a ceiling cannot silently widen applicability.
    limits = [event for event in events if isinstance(event, Mapping) and "limit" in event]
    intervals = osv_intervals(
        ecosystem, {**affected, "events": [event for event in events if event not in limits]}
    )
    branches = {
        interval.upper: interval for interval in intervals or () if interval.upper_kind == "fixed"
    }
    evidence = []
    for event_index, event in enumerate(events):
        if not isinstance(event, Mapping):
            continue
        for field in ("introduced", "fixed", "last_affected", "limit"):
            if field in event and _version(event[field]) is None:
                evidence.append(
                    {
                        **base,
                        "patch_field_state": "invalid",
                        "source_field": f"events[{event_index}].{field}",
                    }
                )
        for boundary in ("last_affected", "limit"):
            value = _version(event.get(boundary))
            if value:
                bounds.append(
                    {
                        "package_entry_id": package.package_event_id,
                        "range_index": index,
                        "kind": boundary,
                        "version": value,
                    }
                )
        fixed = _version(event.get("fixed"))
        # GIT commits need a qualified ancestry evaluator, not release ordering.
        if fixed is not None and kind in {"SEMVER", "ECOSYSTEM"}:
            interval = branches.get(fixed)
            introduced = (interval.introduced or "0") if interval else None
            branch = {
                **affected,
                "events": [{"introduced": introduced}, {"fixed": fixed}, *limits],
            }
            evidence.append(
                {
                    **base,
                    "introduced_version": introduced,
                    "fixed_version": fixed,
                    "patch_field_state": "explicit_value",
                    "source_field": f"events[{event_index}].fixed",
                    "applies_to_requested_version": osv_match(branch) if interval else None,
                }
            )
    if not evidence:
        evidence.append({**base, "patch_field_state": "no_fixed_event"})
    return evidence, bounds


def source_fix_evidence(
    packages: Sequence[Any],
    *,
    ecosystem: str,
    github_match: Callable[[str], bool | None],
    osv_match: Callable[[Mapping[str, Any]], bool | None],
    historical: bool,
    unresolved: bool,
) -> dict[str, Any]:
    evidence, bounds = [], []
    missing_ranges = False
    for package in packages:
        missing_ranges |= not package.affected_ranges
        for index, affected in enumerate(package.affected_ranges):
            fixes, ends = _range_evidence(
                package,
                index,
                affected,
                ecosystem=ecosystem,
                github_match=github_match,
                osv_match=osv_match,
            )
            evidence.extend(fixes)
            bounds.extend(ends)
    versions = ordered_versions(
        ecosystem, [row["fixed_version"] for row in evidence if row["fixed_version"] is not None]
    )
    incomplete = (
        unresolved
        or historical
        or missing_ranges
        or len(evidence) > MAX_FIX_EVIDENCE
        or len(bounds) > MAX_RANGE_BOUNDS
        or len(versions) > MAX_SOURCE_FIXES
        or any(
            row["patch_field_state"] in {"invalid", "unsupported_range_type"}
            or row["fixed_version"] is not None
            and row["applies_to_requested_version"] is None
            for row in evidence
        )
    )
    # A quarantined newer source may have changed its ranges or withdrawn a fix.
    # Retain old range evidence, but do not present old fixes as current evidence.
    if unresolved:
        versions = []
        evidence = [{**row, "applies_to_requested_version": None} for row in evidence]
    return {
        "source_fixed_versions": versions[:MAX_SOURCE_FIXES],
        "fix_evidence": evidence[:MAX_FIX_EVIDENCE],
        "range_bound_evidence": bounds[:MAX_RANGE_BOUNDS],
        "fix_evidence_incomplete": incomplete,
        "historical_metadata_incomplete": historical,
    }


def incident_fix_evidence(
    reports: Sequence[Mapping[str, Any]], ecosystem: str, *, reports_truncated: bool = False
) -> dict[str, Any]:
    """A summary only: recommendations must inspect the individual source branches."""
    versions = ordered_versions(
        ecosystem,
        [value for report in reports for value in report.get("source_fixed_versions", [])],
    )
    return {
        "source_fixed_versions": versions[:MAX_SOURCE_FIXES],
        "fix_evidence_incomplete": (
            not reports
            or reports_truncated
            or len(versions) > MAX_SOURCE_FIXES
            or any(report.get("fix_evidence_incomplete", True) for report in reports)
        ),
    }


def assessment_reason_codes(
    *,
    incidents: Sequence[Mapping[str, Any]],
    result: str,
    range_evaluation: str,
    artifact_evidence: bool,
    freshness: Sequence[Any],
    truncated: bool,
) -> list[str]:
    reasons = {"identity_unverified"}
    if result == "unknown" and not incidents:
        reasons.add("no_matching_advisory")
    if range_evaluation == "not_supported":
        reasons.add("ecosystem_not_covered")
    if not artifact_evidence:
        reasons.add("artifact_evidence_missing")
    for source in freshness:
        if source.freshness_state == "stale":
            reasons.add("source_stale")
        elif source.freshness_state not in {"fresh", "complete"}:
            reasons.add("source_unavailable")
    for incident in incidents:
        reports = incident["source_reports"]
        if incident["applies_to_version"] is None:
            reasons.add("version_not_evaluable")
        if {r.get("applies_to_version") for r in reports} >= {True, False}:
            reasons.add("source_conflict")
        if any(r.get("historical_metadata_incomplete") for r in reports):
            reasons.add("historical_metadata_incomplete")
        if (
            incident.get("fix_evidence_incomplete")
            or incident["source_reports_truncated"]
            or any(
                r.get("fix_evidence_incomplete")
                or r.get("source_context_state") == "omitted_budget"
                for r in reports
            )
        ):
            reasons.add("results_incomplete")
    if result == "conflicting":
        reasons.add("source_conflict")
    if truncated:
        reasons.add("results_incomplete")
    return sorted(reasons)
