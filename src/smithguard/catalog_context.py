"""Read bounded context from immutable, content-addressed catalog projections."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from smithguard.advisory_context import unknown_conditions
from smithguard.db.models import SupplementalPayloadRecord
from smithguard.identifiers import canonical_json_bytes
from smithguard.openssf_attribution import LICENSE, SOURCE_NAME, verified_record_url
from smithguard.openssf_git import OPENSSF_MALICIOUS

MAX_CONTEXT_REPORTS = 100
MAX_CONTEXT_BYTES = 131_072


class RequiredAttributionUnavailable(ValueError):
    """A displayed source assertion lacks a verified retained record URL."""


class RequiredAttributionLimit(ValueError):
    """The display cannot carry all mandatory credit inside its fixed bounds."""


def openssf_record_context(canonical_url: str, upstream_record_id: str) -> dict[str, Any] | None:
    url = verified_record_url(canonical_url, upstream_record_id=upstream_record_id)
    if url is None:
        return None
    return {
        "title": None,
        "description": None,
        "severity": None,
        "attribution": SOURCE_NAME,
        "license_expression": LICENSE,
        "source_url": url,
        "title_sha256": None,
        "description_sha256": None,
        "title_truncated": False,
        "description_truncated": False,
        "conditions": unknown_conditions(),
    }


def attach_catalog_context(session: Session, reports: list[dict[str, Any]]) -> None:
    """Read only the context subdocument; never retrieve full package projections.

    The writer verifies the complete document against its content-addressed key.
    Append-only DB protection and each catalog's exact hash bind this lookup, just
    as they bind existing supplemental facts. Missing old payloads remain unknown.
    """
    # Reserve mandatory credit before spending the remaining budget on optional prose.
    optional = []
    used = 0
    required = 0
    for report in reports:
        if report["source_id"] != OPENSSF_MALICIOUS:
            optional.append(report)
            continue
        context = report.get("source_context")
        if context is None:
            raise RequiredAttributionUnavailable("OpenSSF source attribution is unavailable")
        required += 1
        used += len(canonical_json_bytes(context))
        if required > MAX_CONTEXT_REPORTS or used > MAX_CONTEXT_BYTES:
            raise RequiredAttributionLimit("OpenSSF attribution exceeds the context limit")
        report["source_context_state"] = "available"
    hashes = list(
        dict.fromkeys(
            r["catalog_source_sha256"] for r in optional if r.get("catalog_source_sha256")
        )
    )
    selected = hashes[: MAX_CONTEXT_REPORTS - required]
    payloads = (
        dict(
            session.execute(
                select(
                    SupplementalPayloadRecord.payload_sha256,
                    SupplementalPayloadRecord.document["public_context"],
                ).where(SupplementalPayloadRecord.payload_sha256.in_(selected))
            ).all()
        )
        if selected
        else {}
    )
    for report in optional:
        digest = report.get("catalog_source_sha256")
        context = payloads.get(digest)
        state = "unavailable"
        if digest and digest not in selected:
            state = "omitted_budget"
        elif isinstance(context, dict):
            size = len(canonical_json_bytes(context))
            if used + size <= MAX_CONTEXT_BYTES:
                used += size
                state = "available"
            else:
                state = "omitted_budget"
                context = None
        report["source_context"] = context if state == "available" else None
        report["source_context_state"] = state
