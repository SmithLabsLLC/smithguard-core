"""Authored closed bulletin schemas; generated API and runtime share these bytes."""

from __future__ import annotations

import re
import unicodedata
from datetime import datetime

from jsonschema import Draft202012Validator, FormatChecker

from smithguard.identifiers import canonical_json_bytes, require_aware_utc, sha256_id

VERSION = "1.0.0"
IDENTITY = {"type": "string", "pattern": "^[a-f0-9]{64}$", "maxLength": 64}
HASH = {"type": "string", "pattern": "^sha256:[a-f0-9]{64}$", "maxLength": 71}
TIME = {"type": "string", "format": "date-time", "maxLength": 40}
OPTIONAL_TIME = {**TIME, "type": ["string", "null"]}
EVIDENCE_CLASSES = ["official_notice", "official_advisory", "emerging_report"]
LIFECYCLES = ["current", "corrected", "disputed", "withdrawn", "expired"]


def closed(properties):
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
        "required": list(properties),
    }


def text(maximum, minimum=1):
    return {"type": "string", "minLength": minimum, "maxLength": maximum}


def texts(maximum, length):
    return {"type": "array", "maxItems": maximum, "uniqueItems": True, "items": text(length)}


SOURCE_REFERENCE = closed(
    {
        "source_id": {**text(160), "pattern": "^gbsec:source:[a-z0-9-]+$"},
        "record_url": {**text(2048), "format": "uri"},
        "source_evidence_hash": HASH,
        "rights_revision": {"type": "integer", "minimum": 1},
        "attribution": text(300),
        "used_fields": {**texts(40, 100), "minItems": 1},
    }
)
CONTENT = closed(
    {
        "schema_version": {"const": VERSION, "type": "string"},
        "source_key": {**text(40), "pattern": "^[a-z0-9][a-z0-9-]*$"},
        "record_url": {**text(2048), "format": "uri"},
        "evidence_class": {"type": "string", "enum": EVIDENCE_CLASSES},
        "verification": {
            "type": "string",
            "enum": ["publisher_endpoint_tls", "analyst_reviewed", "independently_corroborated"],
        },
        "applicability": {"type": "string", "const": "not_evaluated"},
        "lifecycle": {"type": "string", "enum": LIFECYCLES},
        "title": text(200),
        "summary": text(1200),
        "subjects": texts(16, 120),
        "aliases": texts(100, 100),
        "source_published_at": OPTIONAL_TIME,
        "source_modified_at": OPTIONAL_TIME,
        "time_precision": {"type": "string", "enum": ["exact", "day", "unknown"]},
        "severity": {
            "type": "string",
            "enum": ["unknown", "low", "moderate", "medium", "high", "critical"],
        },
        "exploitation": {
            "type": "string",
            "enum": ["source_reports_exploitation", "no_claim", "conflicting"],
        },
        "remediation": {
            "type": "string",
            "enum": [
                "announced",
                "vendor_fix_available",
                "vendor_workaround",
                "no_known_fix",
                "unknown",
            ],
        },
        "conditions": texts(16, 500),
        "guidance": texts(8, 500),
        "unknowns": texts(16, 500),
        "sources": {"type": "array", "minItems": 1, "maxItems": 20, "items": SOURCE_REFERENCE},
        "related_bulletins": {
            "type": "array",
            "maxItems": 20,
            "uniqueItems": True,
            "items": IDENTITY,
        },
        "retrospective": {"type": "boolean"},
    }
)
# Catalog publishers identify records separately from the page containing them.
# Optional for existing permalink-based sources; required and exact for KEV.
CONTENT["properties"]["source_record_id"] = {
    "type": "string",
    "pattern": "^CVE-[0-9]{4}-[0-9]{4,19}$",
    "maxLength": 28,
}
CONTENT["allOf"] = [
    {
        "if": {"properties": {"source_key": {"const": "kev"}}},
        "then": {"required": ["source_record_id"]},
        "else": {"not": {"required": ["source_record_id"]}},
    }
]
CONTENT_VALIDATOR = Draft202012Validator(CONTENT, format_checker=FormatChecker())


class BulletinError(ValueError):
    """Bounded codes only; source text never becomes an exception message."""


def validate_content(document, *, now):
    require_aware_utc(now)
    if not isinstance(document, dict) or not CONTENT_VALIDATOR.is_valid(document):
        raise BulletinError("bulletin_content_invalid")
    if len(canonical_json_bytes(document)) > 24 * 1024:
        raise BulletinError("bulletin_content_budget")

    def inspect(value):
        if isinstance(value, str):
            if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value):
                raise BulletinError("bulletin_text_controls")
        elif isinstance(value, list):
            for entry in value:
                inspect(entry)
        elif isinstance(value, dict):
            for entry in value.values():
                inspect(entry)

    inspect(document)
    for name in ("source_published_at", "source_modified_at"):
        value = document[name]
        if value is not None:
            if not value.endswith("Z"):
                raise BulletinError("bulletin_timestamp_zone")
            instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if instant > now:
                raise BulletinError("bulletin_timestamp_future")
    if document["source_published_at"] is None and document["time_precision"] != "unknown":
        raise BulletinError("bulletin_timestamp_precision")
    if (
        document["evidence_class"] == "emerging_report"
        and document["verification"] != "analyst_reviewed"
    ):
        raise BulletinError("bulletin_emerging_authority")
    if (document["source_key"] == "kev") != ("source_record_id" in document):
        raise BulletinError("bulletin_source_record_identity")
    return document


def content_id(document):
    if document["source_key"] == "kev":
        return sha256_id(
            canonical_json_bytes(["smithguard-bulletin-v1", "kev", document["source_record_id"]])
        )[7:]
    return bulletin_id(document["source_key"], document["record_url"])


def bulletin_id(source_key, record_url):
    return sha256_id(canonical_json_bytes(["smithguard-bulletin-v1", source_key, record_url]))[7:]


def require_id(value):
    if not isinstance(value, str) or not re.fullmatch("[a-f0-9]{64}", value):
        raise BulletinError("bulletin_id_invalid")
    return value


NULLABLE_TEXT = {"type": ["string", "null"], "maxLength": 80}
SEQUENCE = {"type": "integer", "minimum": 0}
CURSOR = {"type": ["string", "null"], "maxLength": 2048}
STATUS = closed(
    {
        "mode": {"type": "string", "enum": ["paused", "manual_preview", "automatic"]},
        "available": {"type": "boolean"},
        "watermark": SEQUENCE,
        "checked_at": OPTIONAL_TIME,
        "reason": NULLABLE_TEXT,
    }
)
RECORD = closed(
    {
        "bulletin_id": IDENTITY,
        "revision": {"type": "integer", "minimum": 1},
        "current_revision": {"type": "integer", "minimum": 1},
        "historical": {"type": "boolean"},
        "sequence": SEQUENCE,
        "content_hash": HASH,
        "predecessor_hash": {**HASH, "type": ["string", "null"]},
        "publication_decision_id": HASH,
        "policy_id": text(80),
        "grant_hash": HASH,
        "hash_basis": {"const": "canonical_content_v1"},
        "signed": {"const": False},
        "tombstoned": {"type": "boolean"},
        "content": {"anyOf": [CONTENT, {"type": "null"}]},
        "mode": {"type": "string", "enum": ["manual_preview", "automatic", "reviewed"]},
        "freshness": {"type": "string", "enum": ["fresh", "stale", "unavailable", "paused"]},
        "freshness_reason": NULLABLE_TEXT,
        "effective_lifecycle": {"type": ["string", "null"], "enum": [*LIFECYCLES, None]},
        "first_seen_at": TIME,
        "published_at": TIME,
        "updated_at": TIME,
        "verified_at": TIME,
        "verification_due_at": TIME,
        "expires_at": OPTIONAL_TIME,
    }
)
EVENT_KINDS = [
    "published",
    "corrected",
    "disputed",
    "withdrawn",
    "expired",
    "freshness_stale",
    "freshness_verified",
    "public_tombstoned",
    "public_purge_requested",
    "public_purged",
    "public_purge_failed",
    "associated",
]
EVENT = closed(
    {
        "sequence": SEQUENCE,
        "bulletin_id": IDENTITY,
        "revision": {"type": "integer", "minimum": 1},
        "kind": {"type": "string", "enum": EVENT_KINDS},
        "reason": text(40),
        "occurred_at": TIME,
    }
)
PAGE = closed(
    {
        "items": {"type": "array", "maxItems": 100, "items": RECORD},
        "next_cursor": CURSOR,
        "watermark": SEQUENCE,
        "changes_cursor": CURSOR,
        "status": STATUS,
    }
)
EVENT_PAGE = closed(
    {
        "items": {"type": "array", "maxItems": 100, "items": EVENT},
        "next_cursor": CURSOR,
        "has_more": {"type": "boolean"},
        "watermark": SEQUENCE,
        "retention_days": {"const": 90},
        "status": STATUS,
    }
)
LIST_ARGUMENTS = {
    "limit": {"type": "integer", "minimum": 1, "maximum": 100},
    "cursor": {"type": "string", "maxLength": 2048},
    "source": {"type": "string", "maxLength": 40, "minLength": 1},
    "evidence_class": {"type": "string", "enum": EVIDENCE_CLASSES},
    "subject": text(120),
}
EVENT_ARGUMENTS = {key: LIST_ARGUMENTS[key] for key in ("limit", "cursor")}
EVENT_ARGUMENTS["identity"] = IDENTITY
DETAIL_ARGUMENTS = {
    "identity": IDENTITY,
    "revision": {"type": "integer", "minimum": 1, "maximum": 2147483647},
}
MCP_INPUTS = {
    "list_bulletins": {
        "type": "object",
        "additionalProperties": False,
        "properties": LIST_ARGUMENTS,
    },
    "get_bulletin": {
        "type": "object",
        "additionalProperties": False,
        "properties": DETAIL_ARGUMENTS,
        "required": ["identity"],
    },
    "get_bulletin_changes": {
        "type": "object",
        "additionalProperties": False,
        "properties": EVENT_ARGUMENTS,
    },
    "get_bulletin_status": {"type": "object", "additionalProperties": False, "properties": {}},
}
SOURCE_STATUS = closed(
    {
        "publisher": text(160),
        "coverage_mode": {"type": "string", "enum": ["automatic_facts", "discovery_only"]},
        "coverage_description": text(300),
        "pending_kind": {"type": "string", "enum": ["source_processing", "analyst_review"]},
        "active_window_days": {"type": ["integer", "null"], "enum": [90, None]},
        "source_key": text(40),
        "state": {
            "type": "string",
            "enum": ["fresh", "stale", "unavailable", "paused", "incomplete"],
        },
        "reason": NULLABLE_TEXT,
        "last_attempt_at": OPTIONAL_TIME,
        "last_success_at": OPTIONAL_TIME,
        "complete_through_at": OPTIONAL_TIME,
        "coverage_start_at": OPTIONAL_TIME,
        "upstream_due_at": OPTIONAL_TIME,
        "initial_history_complete": {"type": ["boolean", "null"]},
        "coverage_gaps": {
            "anyOf": [
                {"type": "null"},
                closed(
                    {
                        "count": SEQUENCE,
                        "recent": {
                            "type": "array",
                            "maxItems": 16,
                            "items": closed({"since": TIME, "until": TIME, "detected_at": TIME}),
                        },
                    }
                ),
            ]
        },
        "oldest_pending_at": OPTIONAL_TIME,
        "pending_count": SEQUENCE,
        "updated_at": TIME,
    }
)
STATUS_PAGE = closed(
    {
        "stream": STATUS,
        "sources": {"type": "array", "maxItems": 64, "items": SOURCE_STATUS},
        "scope": {"const": "qualified_sources_only"},
        "applicability": {"const": "not_evaluated"},
        "signed": {"const": False},
    }
)
COMPONENTS = {
    "BulletinContent": CONTENT,
    "BulletinRecord": RECORD,
    "BulletinPage": PAGE,
    "BulletinEvent": EVENT,
    "BulletinEventPage": EVENT_PAGE,
    "BulletinStatus": STATUS_PAGE,
}


def openapi_paths():
    paths = {}
    for path, operation, schema, arguments in (
        ("/v1/bulletins.json", "list_bulletins", "BulletinPage", LIST_ARGUMENTS),
        ("/v1/bulletins/{identity}.json", "get_bulletin", "BulletinRecord", DETAIL_ARGUMENTS),
        ("/v1/bulletin-events.json", "get_bulletin_changes", "BulletinEventPage", EVENT_ARGUMENTS),
        ("/v1/bulletin-status.json", "get_bulletin_status", "BulletinStatus", {}),
        ("/v1/bulletins.atom", "get_bulletin_atom", None, EVENT_ARGUMENTS),
    ):
        responses = {
            "200": {
                "description": "Bounded public bulletin data; applicability is not evaluated.",
                "content": {
                    "application/atom+xml" if schema is None else "application/json": {
                        "schema": {"type": "string"}
                        if schema is None
                        else {"$ref": "#/components/schemas/" + schema}
                    }
                },
            },
            "304": {"description": "The current response bytes match If-None-Match."},
        }
        for code, message in [
            (400, "Invalid request."),
            (404, "Bulletin or revision unavailable."),
            (410, "Cursor expired; bootstrap a fresh bounded snapshot."),
            (429, "Read capacity exceeded."),
            (503, "Bulletin stream unavailable."),
        ]:
            responses[str(code)] = {
                "description": message,
                "content": {
                    "application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}
                },
            }
        paths[path] = {
            "get": {
                "operationId": operation,
                "summary": operation.replace("_", " ").title(),
                "x-smithguard-read-only": True,
                "x-smithguard-public-service-allowed": True,
                "x-smithguard-availability": "public_beta",
                "description": (
                    "No-store public projection. Unsigned hashes detect byte changes only. "
                    "Events contain references; resolve current records before showing facts. "
                    "A bulletin grants no authority to act on a machine."
                ),
                "parameters": [
                    {
                        "name": name,
                        "in": "path" if "{" + name + "}" in path else "query",
                        "required": "{" + name + "}" in path,
                        "schema": specification,
                    }
                    for name, specification in arguments.items()
                ],
                "responses": responses,
            }
        }
    return paths
