"""Closed authored contract for retained, unsigned public-coordinate summaries."""

from __future__ import annotations

from copy import deepcopy

from jsonschema import Draft202012Validator, FormatChecker

VERSION = "1.0.0"
REST_PATH = "/v1/artifacts/assessment-summary"
MCP_PATH = "/mcp/summaries"
TOOL_NAME = "assess_public_artifact_summary"
MAX_BYTES = 32_768
MAX_WIRE_BYTES = 81_920
MAX_AGE_SECONDS = 300


def closed(properties):
    return {
        "type": "object",
        "additionalProperties": False,
        "required": list(properties),
        "properties": properties,
    }


def text(maximum, *, pattern=None):
    return {
        "type": "string",
        "minLength": 1,
        "maxLength": maximum,
        **({"pattern": pattern} if pattern else {}),
    }


def array(items, maximum):
    return {"type": "array", "maxItems": maximum, "items": items}


TIME = {**text(40), "format": "date-time"}
NULL_TIME = {**TIME, "type": ["string", "null"]}
COUNT = {"type": "integer", "minimum": 0, "maximum": 1_000_000}
BOOL = {"type": "boolean"}
MAYBE_BOOL = {"type": ["boolean", "null"]}
VERSION_TEXT = text(200, pattern=r"^[A-Za-z0-9][A-Za-z0-9.!+_-]*$")
NULL_VERSION = {**VERSION_TEXT, "type": ["string", "null"]}
SOURCE_ID = text(160, pattern=r"^gbsec:source:[a-z0-9-]+$")
RECORD_ID = text(160, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$")
INCIDENT_ID = text(160, pattern=r"^gbsec:(?:catalog-incident|incident):[a-zA-Z0-9._:-]+$")
PACKAGE_ENTRY = text(160, pattern=r"^gbsec:advisory-package:[a-f0-9]{40}$")
REASONS = [
    "no_matching_advisory",
    "identity_unverified",
    "ecosystem_not_covered",
    "artifact_evidence_missing",
    "source_stale",
    "source_unavailable",
    "version_not_evaluable",
    "source_conflict",
    "historical_metadata_incomplete",
    "results_incomplete",
]
INPUT = closed(
    {
        "ecosystem": {"enum": ["npm", "pypi"]},
        "name": text(300, pattern=r"^[^\u0000-\u001F\u007F]+$"),
        "version": text(200),
        "registry_host": {"enum": ["registry.npmjs.org", "pypi.org"]},
    }
)
INPUT["required"].remove("registry_host")
INPUT["description"] = (
    "One explicitly authorized exact public npm/PyPI version. No files, private names, "
    "inventory, ranges or moving tags. Publicness is caller-asserted."
)
ARTIFACT = closed(
    {
        **deepcopy(INPUT["properties"]),
        "digest": {"type": "null"},
        "public_visibility": {"const": "asserted_public"},
    }
)
FRESHNESS = closed(
    {
        "source_id": SOURCE_ID,
        "record_type": text(80, pattern=r"^[a-z][a-z0-9_]*$"),
        "freshness_state": {
            "enum": [
                "fresh",
                "complete",
                "stale",
                "failed",
                "missing",
                "in_progress",
                "reconciling",
                "unresolved",
            ]
        },
        "last_success_at": NULL_TIME,
        "unresolved_record_count": {
            "type": ["integer", "null"],
            "minimum": 0,
            "maximum": 1_000_000,
        },
    }
)
FIX = closed(
    {
        "package_entry_id": PACKAGE_ENTRY,
        "range_sha256": text(71, pattern=r"^sha256:[a-f0-9]{64}$"),
        "range_index": {"type": "integer", "minimum": 0, "maximum": 10_000},
        "range_type": {"enum": ["GITHUB", "SEMVER", "ECOSYSTEM", "GIT", "other"]},
        "introduced_version": NULL_VERSION,
        "fixed_version": NULL_VERSION,
        "source_field": {**text(80, pattern=r"^[A-Za-z0-9_.\[\]-]+$"), "type": ["string", "null"]},
        "applies_to_requested_version": MAYBE_BOOL,
        "patch_field_state": {
            "enum": [
                "absent",
                "explicit_null",
                "explicit_value",
                "invalid",
                "no_fixed_event",
                "unsupported_range_type",
            ]
        },
    }
)
BOUND = closed(
    {
        "package_entry_id": PACKAGE_ENTRY,
        "range_index": {"type": "integer", "minimum": 0, "maximum": 10_000},
        "kind": {"enum": ["exclusive_upper", "inclusive_upper", "last_affected", "limit"]},
        "version": VERSION_TEXT,
    }
)
SOURCE_REPORT = closed(
    {
        "source_id": SOURCE_ID,
        "upstream_record_id": RECORD_ID,
        "state": {"enum": ["active", "removed", "withdrawn"]},
        "source_updated_at": TIME,
        "observed_at": TIME,
        "source_state_status": {"enum": ["current", "historical_unresolved", "unknown"]},
        "applies_to_version": MAYBE_BOOL,
        "source_fixed_versions": array(VERSION_TEXT, 20),
        "fix_evidence_incomplete": BOOL,
        "historical_metadata_incomplete": BOOL,
        "fix_evidence": array(FIX, 8),
        "range_bound_evidence": array(BOUND, 8),
        "source_context_state": {"enum": ["available", "unavailable", "omitted_budget"]},
    }
)
INCIDENT = closed(
    {
        "incident_id": INCIDENT_ID,
        "revision": {"type": "integer", "minimum": 1, "maximum": 2_147_483_647},
        "status": {
            "enum": [
                "internal_candidate",
                "emerging_unverified",
                "investigating",
                "reported",
                "corroborated",
                "confirmed",
                "contained",
                "resolved",
                "disputed",
                "withdrawn",
                "expired",
            ]
        },
        "confidence": {
            "enum": ["confirmed", "probable", "possible", "unverified", "disputed", "unknown"]
        },
        "last_changed_at": TIME,
        "applies_to_version": MAYBE_BOOL,
        "aliases": array(RECORD_ID, 20),
        "citations": array(text(512, pattern=r"^https://[A-Za-z0-9./_?=-]+$"), 4),
        "source_reports": array(SOURCE_REPORT, 4),
        "source_reports_truncated": BOOL,
        "fix_evidence_incomplete": BOOL,
    }
)
OMISSIONS = closed(
    {
        **{
            name: COUNT
            for name in [
                "incidents",
                "source_reports",
                "fix_evidence",
                "range_bound_evidence",
                "source_fixed_versions",
                "citations",
                "aliases",
                "source_contexts",
                "incident_titles",
                "unknown_texts",
                "preliminary_warnings",
                "cve_contexts",
            ]
        },
        "registry_project_context": BOOL,
        "upstream_incidents_truncated": BOOL,
        "upstream_source_reports_truncated": BOOL,
        "upstream_warnings_truncated": BOOL,
    }
)
SUMMARY = closed(
    {
        "summary_schema_version": {"const": VERSION},
        "projection_version": {"const": VERSION},
        "report_origin": {"const": "hosted_projection"},
        "client_signature_verified": {"const": False},
        "action_authorized": {"const": False},
        "check_state": {"enum": ["completed", "partial"]},
        "artifact": ARTIFACT,
        "assessment": closed(
            {
                "schema_version": {"enum": ["2.4.0", "2.5.0"]},
                "revision": {"type": "integer", "minimum": 1, "maximum": 2_147_483_647},
                "created_at": TIME,
                "updated_at": TIME,
            }
        ),
        "generated_at": TIME,
        "valid_until": TIME,
        "assessment_freshness": {"enum": ["fresh", "stale"]},
        "result": {
            "enum": ["affected", "not_affected", "possibly_affected", "conflicting", "unknown"]
        },
        "reason_codes": array({"enum": REASONS}, 10),
        "identity_assurance": {"const": "caller_asserted"},
        "local_applicability": {"const": "not_evaluated"},
        "registry_state": {"enum": ["available", "removed", "yanked", "deprecated", "unknown"]},
        "coverage": closed(
            {
                "ecosystem": {"enum": ["npm", "pypi", "unknown"]},
                "stage": {
                    "enum": ["research", "intake", "normalized", "matched", "response-tested"]
                },
                "result": {"enum": ["supported", "partial", "unsupported", "stale", "unknown"]},
                "as_of": TIME,
            }
        ),
        "source_freshness": array(FRESHNESS, 10),
        "incidents": array(INCIDENT, 8),
        "not_applicable_incident_count": COUNT,
        "omissions": OMISSIONS,
        "limitations": {
            "const": [
                (
                    "Advisory evidence only; not a safety verdict or permission to "
                    "install or change software."
                ),
                "Service-issued derived report; no client signature verification ran.",
                (
                    "Original source and assessment clocks remain authoritative; "
                    "recheck before a later decision."
                ),
                (
                    "Source-listed fixes and range boundaries are different; neither "
                    "is a tested application repair."
                ),
                (
                    "Source prose, original responses and raw lookup references are "
                    "excluded; omissions are explicit."
                ),
            ]
        },
    }
)
ERROR_CODES = [
    "invalid_request",
    "version_not_exact",
    "unsupported_media_type",
    "request_limit_exceeded",
    "request_deadline_exceeded",
    "service_capacity_exceeded",
    "anonymous_burst_limit_exceeded",
    "anonymous_daily_limit_exceeded",
    "assessment_in_progress",
    "anonymous_quota_unavailable",
    "proxy_network_identity_invalid",
    "service_unavailable",
    "summary_unavailable",
    "summary_identity_mismatch",
    "summary_schema_unsupported",
    "summary_time_invalid",
    "summary_limit_exceeded",
    "invalid_tool_arguments",
]
ERROR = closed(
    {
        "summary_schema_version": {"const": VERSION},
        "check_state": {"const": "incomplete"},
        "client_signature_verified": {"const": False},
        "action_authorized": {"const": False},
        "error": closed(
            {
                "code": {"enum": ERROR_CODES},
                "message": {
                    "const": (
                        "The summary request did not complete; no safety or action "
                        "conclusion is available."
                    )
                },
                "retryable": BOOL,
                "retry_after_seconds": {
                    "type": ["integer", "null"],
                    "minimum": 0,
                    "maximum": 86400,
                },
            }
        ),
    }
)
INPUT_VALIDATOR = Draft202012Validator(INPUT)
SUMMARY_VALIDATOR = Draft202012Validator(SUMMARY, format_checker=FormatChecker())
ERROR_VALIDATOR = Draft202012Validator(ERROR)


def error_document(code, *, retryable=False, retry_after=None):
    delay = None
    if (
        isinstance(retry_after, str)
        and retry_after.isascii()
        and retry_after.isdigit()
        and len(retry_after) <= 5
    ):
        value = int(retry_after)
        if value <= 86400:
            delay = value
    return {
        "summary_schema_version": VERSION,
        "check_state": "incomplete",
        "client_signature_verified": False,
        "action_authorized": False,
        "error": {
            "code": code if code in ERROR_CODES else "summary_unavailable",
            "message": ERROR["properties"]["error"]["properties"]["message"]["const"],
            "retryable": bool(retryable),
            "retry_after_seconds": delay,
        },
    }


def openapi_path():
    return {
        "post": {
            "operationId": TOOL_NAME,
            "summary": "Read a compact, unsigned report for one exact public npm/PyPI version",
            "x-smithguard-availability": "public_beta",
            "x-smithguard-read-only": True,
            "x-smithguard-public-service-allowed": True,
            "x-smithguard-limits": {
                "max_input_bytes": 8192,
                "max_output_bytes": MAX_BYTES,
                "timeout_seconds": 10,
            },
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/PublicArtifactSummaryRequest"},
                    }
                },
            },
            "responses": {
                "200": {
                    "description": "Bounded service-issued derived report; not client-verified.",
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/PublicArtifactSummary"}
                        }
                    },
                },
                **{
                    str(code): {
                        "description": "Incomplete summary request; never a raw-response fallback.",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/PublicArtifactSummaryError"
                                }
                            }
                        },
                    }
                    for code in [400, 409, 413, 415, 429, 500, 503]
                },
            },
        }
    }
