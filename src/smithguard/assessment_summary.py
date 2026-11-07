"""Pure, bounded projection; original assessments never cross this output boundary."""

from __future__ import annotations

import re
from copy import deepcopy
from datetime import datetime, timedelta
from typing import Any

from jsonschema import Draft202012Validator

from smithguard import summary_contract as contract
from smithguard.contracts.runtime import parse_contract
from smithguard.identifiers import canonical_json_bytes, parse_timestamp, timestamp
from smithguard.normalization import normalize_artifact_identity

# Only canonical record pages, never arbitrary paths, redirects, queries or URLs
# containing a second destination. A new source needs an explicit reviewed rule.
CITATION = re.compile(
    r"https://(?:github\.com/advisories/GHSA-[a-z0-9-]+"
    r"|osv\.dev/vulnerability/[A-Za-z0-9._-]+"
    r"|nvd\.nist\.gov/vuln/detail/CVE-[0-9]{4}-[0-9]+"
    r"|www\.cve\.org/CVERecord\?id=CVE-[0-9]{4}-[0-9]+)\Z"
)


class SummaryRejected(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def validate_summary_identity(document: dict, expected_artifact: dict) -> dict:
    """Compare the evidence identity before caller-specific reprojection can replace it."""

    def normalized(artifact):
        if set(artifact) != set(contract.ARTIFACT["properties"]):
            raise ValueError("unexpected identity fields")
        identity = normalize_artifact_identity(
            {
                key: artifact[key]
                for key in (
                    "ecosystem",
                    "name",
                    "version",
                    "digest",
                )
            }
        )
        return {
            **artifact,
            **{key: identity[key] for key in ("ecosystem", "name", "version", "digest")},
        }

    try:
        expected = normalized(expected_artifact)
        if normalized(document["artifact"]) != expected:
            raise ValueError("different identity")
        Draft202012Validator(contract.ARTIFACT).validate(expected)
        # Equality uses canonical identity; the closed output still belongs to
        # this caller, including accepted PyPI case/punctuation spelling.
        Draft202012Validator(contract.ARTIFACT).validate(expected_artifact)
        return deepcopy(expected_artifact)
    except Exception as error:
        raise SummaryRejected("summary_identity_mismatch") from error


def _select(document: dict, schema: dict) -> dict:
    return {key: deepcopy(document[key]) for key in schema["properties"]}


def _bounded_items(values: list, schema: dict, maximum: int) -> list:
    validator = Draft202012Validator(schema)
    return [deepcopy(value) for value in values if validator.is_valid(value)][:maximum]


def _source(source: dict, *, unresolved: bool) -> dict:
    simple = {
        key: value for key, value in source.items() if key in contract.SOURCE_REPORT["properties"]
    }
    simple["fix_evidence"] = _bounded_items(
        [
            {key: value for key, value in fix.items() if key in contract.FIX["properties"]}
            for fix in source["fix_evidence"]
        ],
        contract.FIX,
        8,
    )
    simple["range_bound_evidence"] = _bounded_items(
        [
            {key: value for key, value in bound.items() if key in contract.BOUND["properties"]}
            for bound in source["range_bound_evidence"]
        ],
        contract.BOUND,
        8,
    )
    simple["source_fixed_versions"] = _bounded_items(
        source["source_fixed_versions"], contract.VERSION_TEXT, 20
    )
    simple["fix_evidence_incomplete"] = source["fix_evidence_incomplete"] or any(
        len(simple[key]) != len(source[key])
        for key in ("fix_evidence", "range_bound_evidence", "source_fixed_versions")
    )
    # Older assessments did not state whether these rows still represented the
    # source's current state. Do not turn missing provenance into current fixes.
    simple["source_state_status"] = source.get("source_state_status") or "unknown"
    if unresolved or simple["source_state_status"] != "current":
        for key in ("fix_evidence", "range_bound_evidence", "source_fixed_versions"):
            simple[key] = []
        simple["fix_evidence_incomplete"] = True
    return simple


def _incident(incident: dict, unresolved_sources: set[str]) -> dict:
    result = {
        key: deepcopy(value)
        for key, value in incident.items()
        if key in contract.INCIDENT["properties"]
    }
    result["aliases"] = _bounded_items(incident["aliases"], contract.RECORD_ID, 20)
    result["citations"] = [url for url in incident["upstream_urls"] if CITATION.fullmatch(url)][:4]
    result["source_reports"] = [
        _source(item, unresolved=item["source_id"] in unresolved_sources)
        for item in incident["source_reports"][:4]
    ]
    result["source_reports_truncated"] = incident["source_reports_truncated"] or (
        len(result["source_reports"]) < len(incident["source_reports"])
    )
    result["fix_evidence_incomplete"] = incident["fix_evidence_incomplete"] or (
        result["source_reports_truncated"]
        or any(source["fix_evidence_incomplete"] for source in result["source_reports"])
    )
    return result


def _omissions(original: dict, selected: list[dict]) -> dict:
    incidents = original["incidents"]
    sources = [source for incident in incidents for source in incident["source_reports"]]
    kept_sources = [source for incident in selected for source in incident["source_reports"]]
    return {
        "incidents": len(incidents) - len(selected),
        "source_reports": len(sources) - len(kept_sources),
        **{
            name: sum(len(source[name]) for source in sources)
            - sum(len(source[name]) for source in kept_sources)
            for name in ("fix_evidence", "range_bound_evidence", "source_fixed_versions")
        },
        "citations": sum(len(item["upstream_urls"]) for item in incidents)
        - sum(len(item["citations"]) for item in selected),
        "aliases": sum(len(item["aliases"]) for item in incidents)
        - sum(len(item["aliases"]) for item in selected),
        "source_contexts": sum(source["source_context"] is not None for source in sources),
        "incident_titles": len(incidents),
        "unknown_texts": len(original["unknowns"]),
        "preliminary_warnings": len(original["preliminary_warnings"]),
        "cve_contexts": len(original["cve_context"]),
        "registry_project_context": original["registry_project_context"] is not None,
        "upstream_incidents_truncated": original["incidents_truncated"],
        "upstream_source_reports_truncated": any(i["source_reports_truncated"] for i in incidents),
        "upstream_warnings_truncated": original["preliminary_warnings_truncated"],
    }


def project_summary(document: dict, expected_artifact: dict, *, now: datetime) -> dict[str, Any]:
    """Validate exact identity and clocks, then emit only the versioned allowlist.

    No cryptographic client verification is performed here. This server projection
    deliberately drops signatures, response IDs, feed references and source prose.
    A failure never substitutes the original document.
    """
    if document.get("schema_version") not in {"2.4.0", "2.5.0"}:
        raise SummaryRejected("summary_schema_unsupported")
    try:
        parse_contract("PublicArtifactAssessment", document)
        expected_artifact = validate_summary_identity(document, expected_artifact)
        unresolved_sources = {
            item["source_id"]
            for item in document["source_freshness"]
            if item["freshness_state"] == "unresolved" or item.get("unresolved_record_count")
        }
        unresolved_sources.update(
            source["source_id"]
            for incident in document["incidents"]
            for source in incident["source_reports"]
            if source.get("source_state_status") == "historical_unresolved"
        )
        if (
            document["schema_version"] == "2.5.0"
            and unresolved_sources
            and document["result"] == "not_affected"
        ):
            raise SummaryRejected("summary_unavailable")
        # Unknown accounting suppresses current advice, but is not affirmative
        # evidence of a gap and must not manufacture a negative-result refusal.
        fix_suppression_sources = unresolved_sources | {
            item["source_id"]
            for item in document["source_freshness"]
            if document["schema_version"] == "2.5.0" and item.get("unresolved_record_count") is None
        }
        created = parse_timestamp(document["created_at"])
        updated = parse_timestamp(document["updated_at"])
        if created > updated or updated > now + timedelta(seconds=30):
            raise SummaryRejected("summary_time_invalid")
        valid_until = updated + timedelta(seconds=contract.MAX_AGE_SECONDS)
        stale = now >= valid_until
        result = {
            "summary_schema_version": contract.VERSION,
            "projection_version": contract.VERSION,
            "report_origin": "hosted_projection",
            "client_signature_verified": False,
            "action_authorized": False,
            "check_state": "completed",
            "artifact": deepcopy(expected_artifact),
            "assessment": _select(document, contract.SUMMARY["properties"]["assessment"]),
            "generated_at": timestamp(now),
            "valid_until": timestamp(valid_until),
            "assessment_freshness": "stale" if stale else "fresh",
            **{
                key: deepcopy(document[key])
                for key in (
                    "result",
                    "reason_codes",
                    "identity_assurance",
                    "local_applicability",
                    "registry_state",
                    "coverage",
                    "not_applicable_incident_count",
                )
            },
            "source_freshness": [
                {**deepcopy(item), "unresolved_record_count": item.get("unresolved_record_count")}
                for item in document["source_freshness"]
            ],
            "incidents": [
                _incident(item, fix_suppression_sources) for item in document["incidents"][:8]
            ],
            "limitations": deepcopy(contract.SUMMARY["properties"]["limitations"]["const"]),
        }
        while True:
            result["omissions"] = _omissions(document, result["incidents"])
            result["check_state"] = (
                "partial"
                if (
                    stale
                    or any(result["omissions"].values())
                    or result["coverage"]["result"] != "supported"
                    or any(
                        lane["freshness_state"] not in {"fresh", "complete"}
                        for lane in result["source_freshness"]
                    )
                    or any(item["fix_evidence_incomplete"] for item in result["incidents"])
                )
                else "completed"
            )
            if len(canonical_json_bytes(result)) <= contract.MAX_BYTES:
                break
            if not result["incidents"]:
                raise SummaryRejected("summary_limit_exceeded")
            result["incidents"].pop()
        contract.SUMMARY_VALIDATOR.validate(result)
        return result
    except SummaryRejected:
        raise
    except Exception as error:
        raise SummaryRejected("summary_unavailable") from error
