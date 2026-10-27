"""Conservative local interpretation; never install, remediate or infer host facts."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from packaging.version import InvalidVersion, Version

from .verification import Verification


def evaluate_conditions(conditions: Mapping[str, Any], facts: Mapping[str, str]) -> str:
    """OR of AND necessary conditions, evaluated only against explicit target facts."""
    if (
        not isinstance(conditions, Mapping)
        or not isinstance(facts, Mapping)
        or any(not isinstance(k, str) or not isinstance(v, str) for k, v in facts.items())
    ):
        return "uncertain"
    if conditions.get("state") != "recorded":
        return "uncertain"
    alternatives = conditions.get("any_of")
    if not isinstance(alternatives, list) or not 1 <= len(alternatives) <= 16:
        return "uncertain"
    outcomes = []
    for alternative in alternatives:
        atoms = alternative.get("all_of") if isinstance(alternative, dict) else None
        if not isinstance(atoms, list) or not 1 <= len(atoms) <= 16:
            return "uncertain"
        values = []
        for atom in atoms:
            if not isinstance(atom, dict):
                return "uncertain"
            key, allowed = atom.get("fact"), atom.get("values")
            if (
                not isinstance(key, str)
                or not isinstance(allowed, list)
                or not 1 <= len(allowed) <= 32
                or any(not isinstance(value, str) for value in allowed)
            ):
                return "uncertain"
            values.append(None if key not in facts else facts[key] in allowed)
        outcomes.append(False if False in values else None if None in values else True)
    if True in outcomes:
        return "conditions_met"
    return "uncertain" if None in outcomes else "conditions_not_met"


def candidate_decision(
    original: Verification,
    candidate: Verification,
    *,
    compatibility: str = "not_evaluated",
    installed_identity: str = "unverified",
) -> dict[str, Any]:
    """Evaluate one exact explicit patch, without a solver or selecting largest versions.

    Positive output only earns application testing; it never authorizes installation.
    Compatibility and installed identity require independent, local evidence.
    """
    reasons = set()
    if not original.current_decision_eligible or not candidate.current_decision_eligible:
        reasons.add("verification_or_freshness_unqualified")
    if compatibility != "reviewed_supported":
        reasons.add("application_compatibility_unverified")
    if installed_identity != "independently_verified":
        reasons.add("installed_identity_unverified")
    if reasons:
        return {"outcome": "no_verified_recommendation", "reasons": sorted(reasons)}
    before, after = original.document, candidate.document
    coordinate = after["artifact"]
    if any(
        before["artifact"][key] != coordinate[key] for key in ("ecosystem", "registry_host", "name")
    ):
        reasons.add("different_package")
    if coordinate["ecosystem"] != "pypi":
        reasons.add("candidate_comparator_unsupported")
    try:
        version = Version(coordinate["version"])
        if version.is_prerelease or version.is_devrelease or version.local is not None:
            reasons.add("candidate_release_unqualified")
        if version <= Version(before["artifact"]["version"]):
            reasons.add("candidate_is_not_an_upgrade")
    except InvalidVersion:
        reasons.add("candidate_comparison_unknown")
    for body in (before, after):
        if body["schema_version"] != "2.4.0":
            reasons.add("source_fix_schema_unavailable")
        if body["coverage"]["result"] != "supported":
            reasons.add("coverage_incomplete")
        if body["registry_state"] != "available":
            reasons.add("registry_state_unqualified")
        if (
            body["incidents_truncated"]
            or body["preliminary_warnings_truncated"]
            or body["preliminary_warnings"]
            or body["unknowns"]
        ):
            reasons.add("assessment_evidence_incomplete")
        if set(body.get("reason_codes") or []) - {"identity_unverified"}:
            reasons.add("assessment_limitations")
        if not body["source_freshness"] or any(
            source["freshness_state"] not in {"fresh", "complete"}
            for source in body["source_freshness"]
        ):
            reasons.add("source_freshness_unqualified")
    if before["feed_revision"] != after["feed_revision"]:
        reasons.add("source_revision_changed_recheck_both")
    if before["result"] != "affected" or not before["incidents"]:
        reasons.add("original_findings_unqualified")
    if after["result"] != "not_affected" or any(
        incident.get("applies_to_version") is not False for incident in after["incidents"]
    ):
        reasons.add("candidate_not_excluded_by_current_evidence")
    matched = []
    for incident in before["incidents"]:
        if (
            incident.get("applies_to_version") is not True
            or incident["source_reports_truncated"]
            or incident.get("fix_evidence_incomplete") is not False
            or not incident["source_reports"]
        ):
            reasons.add("original_finding_incomplete")
        for report in incident["source_reports"]:
            if (
                report.get("state") != "active"
                or report.get("applies_to_version") is not True
                or report.get("fix_evidence_incomplete") is not False
                or report.get("historical_metadata_incomplete") is not False
            ):
                reasons.add("source_fix_unqualified")
                continue
            fixes = [
                row
                for row in (report.get("fix_evidence") or [])
                if row.get("applies_to_requested_version") is True
                and row.get("patch_field_state") == "explicit_value"
                and row.get("fixed_version") == coordinate["version"]
            ]
            if not fixes:
                reasons.add("no_explicit_patch_for_this_issue_and_branch")
            else:
                matched.append(
                    {
                        "incident_id": incident["incident_id"],
                        "source_id": report["source_id"],
                        "upstream_record_id": report["upstream_record_id"],
                        "fix_evidence": fixes,
                    }
                )
    return {
        "outcome": "no_verified_recommendation" if reasons else "candidate_for_application_testing",
        "reasons": sorted(reasons),
        "matched_fix_evidence": matched,
        "assessment_ids": [before["id"], after["id"]],
        "response_sha256": [original.original_sha256, candidate.original_sha256],
        "limits": (
            "Bounded to these sources and times. Review unresolved s"
            "ource conditions and test the parent application before"
            " any separately authorized change."
        ),
    }
