"""Finite orchestration and explicit accounting. Resume never reuses response bodies."""

from __future__ import annotations

import copy
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from .discovery import POLICY_VERSION, coordinate_id
from .interpretation import evaluate_conditions
from .transport import PublicReader, ReadFailure, approved_coordinates
from .verification import canonical

TOOL_VERSION = "0.1.0"
REPORT_BUDGET = 16 * 1024 * 1024
ITEM_BUDGET = 256 * 1024
ANNOTATION_BUDGET = 1024 * 1024
MAX_CONDITION_RESULTS = 10000


def _projection(verified):
    body = verified.document
    service_omissions = [
        name for name in ("incidents_truncated", "preliminary_warnings_truncated") if body[name]
    ]
    if any(i["source_reports_truncated"] for i in body["incidents"]):
        service_omissions.append("source_reports_truncated")
    if any(
        s.get("source_context_state") == "omitted_budget"
        for i in body["incidents"]
        for s in i["source_reports"]
    ):
        service_omissions.append("source_context_omitted_budget")
    return {
        "service_evidence_omissions": service_omissions,
        "assessment_id": body["id"],
        "assessed_at": body["updated_at"],
        "feed_revision": body["feed_revision"],
        "result": body["result"],
        "reason_codes": body.get("reason_codes") or [],
        "unknowns": body["unknowns"],
        "incidents": body["incidents"],
        "preliminary_warnings": body["preliminary_warnings"],
        "incidents_truncated": body["incidents_truncated"],
        "preliminary_warnings_truncated": body["preliminary_warnings_truncated"],
        "source_freshness": body["source_freshness"],
        "coverage": body["coverage"],
        "cve_context": body.get("cve_context"),
        "registry_state": body["registry_state"],
        "registry_project_context": body.get("registry_project_context"),
        "signature_status": verified.status,
        "signature_reason": verified.reason,
        "signature_valid": verified.signature_valid,
        "key_status": verified.key_status,
        "key_status_current": verified.key_status_current,
        "response_fresh": verified.response_fresh,
        "response_sha256": verified.original_sha256,
        "current_decision_eligible": verified.current_decision_eligible,
        "next_step": (
            "Review source-specific fixes, target conditions and par"
            "ent application compatibility. No automatic upgrade rec"
            "ommendation."
        ),
    }


def run(
    preview: dict[str, Any],
    approval: str,
    *,
    reader: PublicReader,
    resume: dict[str, Any] | None = None,
    checkpoint: Callable[[dict[str, Any]], None] | None = None,
    local_facts: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    coordinates = approved_coordinates(preview, approval)
    preview = copy.deepcopy(preview)
    facts = validate_facts(
        local_facts or {}, {x["installation_id"] for x in preview["installations"]}
    )
    if resume is not None and (
        resume.get("approval_sha256") != approval
        or resume.get("tool_version") != TOOL_VERSION
        or resume.get("policy_version") != POLICY_VERSION
    ):
        raise ValueError("changed preview, tool or disclosure policy requires a new run")
    # Previously completed decisions are stale on restart; every approved coordinate
    # needs a fresh read. Minimal prior references are retained only as history.
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    state = {
        "schema_version": "1.0.0",
        "tool_version": TOOL_VERSION,
        "policy_version": POLICY_VERSION,
        "run_id": str(uuid.uuid4()),
        "approval_sha256": approval,
        "started_at": now,
        "previous_run_id": resume.get("run_id") if resume else None,
        "coordinates": {
            coordinate_id(c): {"status": "stale" if resume else "pending"} for c in coordinates
        },
    }
    report = {
        "schema_version": "1.0.0",
        "tool_version": TOOL_VERSION,
        "run_id": state["run_id"],
        "exported_at": now,
        "export_kind": "derived_local_report_not_an_assessment_cache",
        "scopes": preview["scopes"],
        "installations": preview["installations"],
        "relationships": preview["relationships"],
        "discovery_gaps": preview["gaps"],
        "coordinate_results": {
            coordinate_id(c): {"coordinate": c, "status": "not_run", "reason": "not_started"}
            for c in coordinates
        },
        "scope_complete": preview["discovery_complete"],
        "notice": (
            "Private local report. Saved conclusions are historical;"
            " resume rechecks current evidence. A signature authenti"
            "cates the service answer, not source truth or installed"
            " identity."
        ),
    }
    for item in report["installations"]:
        item["local_applicability"] = []
        item["local_applicability_status"] = "not_evaluated"
        supplied = facts.get(item["installation_id"])
        if supplied is not None:
            item["local_facts"] = supplied
            item["local_facts_fresh_at_start"] = facts_current(supplied)
    state["stale_fact_sets_at_start"] = sum(
        item.get("local_facts_fresh_at_start") is False for item in report["installations"]
    )
    used = len(canonical(report))
    # Reserve explicit completion/failure accounting for every selected installation
    # and bounded condition annotations before the first network request.
    reserve = ANNOTATION_BUDGET + len(report["installations"]) * 512 + 65536
    if used + reserve > REPORT_BUDGET:
        raise ValueError("local discovery report exceeds output budget")
    if checkpoint:
        checkpoint(state)
    stop = None
    evidence_ids = {True: (set(), set()), False: (set(), set())}
    report["evidence_complete"] = True
    for coordinate in coordinates:
        identity = coordinate_id(coordinate)
        progress = state["coordinates"][identity]
        if stop:
            progress.update(status="not_run", reason=stop)
            row = {"coordinate": coordinate, **progress}
            used += len(canonical(row)) - len(canonical(report["coordinate_results"][identity]))
            report["coordinate_results"][identity] = row
            continue
        try:
            verified = reader.assess(coordinate)
            if verified.status == "invalid":
                progress.update(status="failed", reason=verified.reason)
                row = {
                    "coordinate": coordinate,
                    **progress,
                    "signature_status": "invalid",
                    "response_sha256": verified.original_sha256,
                }
            elif verified.reason in {
                "unsupported_schema",
                "missing_signature",
                "unsupported_signature_format",
            }:
                progress.update(status="unchecked", reason=verified.reason)
                row = {
                    "coordinate": coordinate,
                    **progress,
                    "signature_status": "unchecked",
                    "response_sha256": verified.original_sha256,
                }
            else:
                projection = _projection(verified)
                status = "completed" if verified.current_decision_eligible else "unchecked"
                row = {"coordinate": coordinate, "status": status, "assessment": projection}
                if status == "unchecked":
                    row["reason"] = (
                        verified.reason
                        if verified.status != "verified"
                        else "key_status_not_current"
                        if not verified.key_status_current
                        else "key_not_active"
                        if verified.key_status != "active"
                        else "response_not_fresh"
                    )
                    progress["reason"] = row["reason"]
                incident_ids = {i["incident_id"] for i in projection["incidents"]}
                source_ids = {
                    (i["incident_id"], s["source_id"], s["upstream_record_id"])
                    for i in projection["incidents"]
                    for s in i["source_reports"]
                }
                if len(canonical(row)) > ITEM_BUDGET:
                    compact_limits = {
                        "preliminary_warning_count": len(projection["preliminary_warnings"]),
                        "preliminary_warning_ids": [
                            x["warning_id"] for x in projection["preliminary_warnings"]
                        ],
                        "incidents_truncated": projection["incidents_truncated"],
                        "preliminary_warnings_truncated": projection[
                            "preliminary_warnings_truncated"
                        ],
                        "coverage_result": projection["coverage"]["result"],
                        "registry_state": projection["registry_state"],
                        "unknown_count": len(projection["unknowns"]),
                    }
                    # Keep authenticated outcome/provenance and complete incident IDs,
                    # but visibly omit bulky source detail. Never stop later reads
                    # merely because one answer needs a compact representation.
                    projection = {
                        k: projection[k]
                        for k in (
                            "assessment_id",
                            "assessed_at",
                            "feed_revision",
                            "result",
                            "signature_status",
                            "signature_reason",
                            "signature_valid",
                            "key_status",
                            "key_status_current",
                            "response_fresh",
                            "response_sha256",
                            "current_decision_eligible",
                            "next_step",
                            "reason_codes",
                            "service_evidence_omissions",
                        )
                    }
                    projection.update(compact_limits)
                    projection.update(
                        evidence_truncated=True,
                        retained_incident_ids=sorted(incident_ids),
                        incident_count=len(incident_ids),
                        source_report_count=len(source_ids),
                        incidents=[],
                        truncation_reason="per_coordinate_detail_budget",
                    )
                    row["assessment"] = projection
                if used + len(canonical(row)) + reserve > REPORT_BUDGET:
                    progress.update(
                        status="failed", reason="report_budget_exceeded_evidence_not_retained"
                    )
                    row = {"coordinate": coordinate, **progress}
                    stop = "report_budget_exhausted"
                else:
                    eligible = verified.current_decision_eligible
                    evidence_ids[eligible][0].update(incident_ids)
                    evidence_ids[eligible][1].update(source_ids)
                    if (
                        projection.get("evidence_truncated")
                        or projection["service_evidence_omissions"]
                    ):
                        report["evidence_complete"] = False
                    progress.update(
                        status=status,
                        assessment_id=projection["assessment_id"],
                        response_sha256=verified.original_sha256,
                        assessed_at=projection["assessed_at"],
                    )
        except ReadFailure as exc:
            progress.update(status="failed", reason=exc.reason)
            row = {"coordinate": coordinate, **progress}
            if exc.stop_run:
                stop = exc.reason
        except KeyboardInterrupt:
            progress.update(status="failed", reason="cancelled")
            row = {"coordinate": coordinate, **progress}
            stop = "cancelled"
        used += len(canonical(row)) - len(canonical(report["coordinate_results"][identity]))
        report["coordinate_results"][identity] = row
        if checkpoint:
            checkpoint(state)
    # Target facts are explicit and fresh. Do not create repeated per-source
    # annotations when no facts were supplied; record not_evaluated instead.
    annotation_bytes = 0
    annotation_count = 0
    report["interpretation_complete"] = True
    for item in report["installations"]:
        coord = item["coordinate"]
        row = report["coordinate_results"].get(coordinate_id(coord)) if coord is not None else None
        item["run_status"] = row["status"] if row else "skipped"
        item["run_reason"] = row.get("reason") if row else item["reason"]
        supplied = facts.get(item["installation_id"])
        if supplied and not facts_current(supplied):
            item["local_applicability_status"] = "facts_supplied_stale_not_evaluated"
            report["interpretation_complete"] = False
            continue
        assessment = row.get("assessment", {}) if row else {}
        if assessment.get("evidence_truncated") or assessment.get("service_evidence_omissions"):
            item["local_applicability_status"] = "evidence_truncated_not_evaluated"
            if supplied:
                report["interpretation_complete"] = False
            continue
        if not (
            row
            and "assessment" in row
            and supplied
            and facts_current(supplied)
            and row["assessment"]["current_decision_eligible"]
        ):
            if supplied:
                item["local_applicability_status"] = "facts_supplied_without_eligible_answer"
                report["interpretation_complete"] = False
            continue
        assessment = row["assessment"]
        total = sum(len(incident["source_reports"]) for incident in assessment["incidents"])
        if total == 0:
            item["local_applicability_status"] = "no_source_reports_for_condition_evaluation"
            report["interpretation_complete"] = False
            continue
        item["local_applicability_status"] = "listed_conditions_evaluated"
        exhausted = False
        for incident in assessment["incidents"]:
            for source in incident["source_reports"]:
                context = source.get("source_context")
                result = {
                    "incident_id": incident["incident_id"],
                    "source_id": source["source_id"],
                    "upstream_record_id": source["upstream_record_id"],
                    "outcome": evaluate_conditions(
                        context.get("conditions", {}) if context else {}, supplied["values"]
                    ),
                    "scope": (
                        "Listed necessary conditions only; original version finding is retained."
                    ),
                }
                size = len(canonical(result)) + 1
                if (
                    annotation_count >= MAX_CONDITION_RESULTS
                    or annotation_bytes + size > ANNOTATION_BUDGET
                ):
                    exhausted = True
                    break
                item["local_applicability"].append(result)
                annotation_count += 1
                annotation_bytes += size
            if exhausted:
                break
        if exhausted:
            item["local_applicability_status"] = "incomplete_output_budget"
            item["local_applicability_omitted"] = total - len(item["local_applicability"])
            report["interpretation_complete"] = False
    incidents, sources = evidence_ids[True]
    unverified_incidents, unverified_sources = evidence_ids[False]
    report["counts"] = {
        "service_incomplete_answers": sum(
            "results_incomplete" in row.get("assessment", {}).get("reason_codes", [])
            for row in report["coordinate_results"].values()
        ),
        "service_truncated_answers": sum(
            bool(row.get("assessment", {}).get("service_evidence_omissions"))
            for row in report["coordinate_results"].values()
        ),
        "supplied_fact_sets": len(facts),
        "supplied_facts_not_fully_evaluated": sum(
            "local_facts" in item
            and item["local_applicability_status"] != "listed_conditions_evaluated"
            for item in report["installations"]
        ),
        "installations": len(report["installations"]),
        "approved_coordinates": len(coordinates),
        "unique_incidents": len(incidents),
        "unique_source_reports": len(sources),
        "unverified_unique_incidents": len(unverified_incidents),
        "unverified_unique_source_reports": len(unverified_sources),
        "evidence_count_scope": "verified_current_eligible_and_unverified_counted_separately",
        "installation_statuses": {
            s: sum(item["run_status"] == s for item in report["installations"])
            for s in ("completed", "unchecked", "failed", "not_run", "skipped")
        },
    }
    report["run_complete"] = not stop and all(
        x["status"] == "completed" for x in state["coordinates"].values()
    )
    if len(canonical(report)) > REPORT_BUDGET:
        raise ValueError("derived report exceeds output budget; narrow the selected scopes")
    state["finished_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    state["run_complete"] = report["run_complete"]
    if checkpoint:
        checkpoint(state)
    return report, state


def validate_facts(facts, installation_ids):
    if not isinstance(facts, dict) or set(facts) - installation_ids:
        raise ValueError("local facts must name discovered installation IDs")
    for supplied in facts.values():
        if (
            not isinstance(supplied, dict)
            or set(supplied) != {"target", "observed_at", "evidence", "values"}
            or any(
                not isinstance(supplied[k], str) or not supplied[k] or len(supplied[k]) > 2000
                for k in ("target", "observed_at", "evidence")
            )
            or not isinstance(supplied["values"], dict)
            or len(supplied["values"]) > 32
            or any(
                not isinstance(k, str) or not isinstance(v, str) or len(k) > 80 or len(v) > 200
                for k, v in supplied["values"].items()
            )
        ):
            raise ValueError("local facts need explicit bounded target, date, evidence and values")
        stamp = datetime.fromisoformat(supplied["observed_at"].replace("Z", "+00:00"))
        if stamp.utcoffset() is None:
            raise ValueError("local fact date requires a timezone")
    if len(canonical(facts)) > 1024 * 1024:
        raise ValueError("local facts exceed aggregate input budget")
    return copy.deepcopy(facts)


def facts_current(supplied):
    stamp = datetime.fromisoformat(supplied["observed_at"].replace("Z", "+00:00"))
    return 0 <= (datetime.now(UTC) - stamp).total_seconds() <= 300
