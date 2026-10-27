"""Read bounded context from immutable, content-addressed catalog projections."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from smithguard.db.models import SupplementalPayloadRecord
from smithguard.identifiers import canonical_json_bytes

MAX_CONTEXT_REPORTS = 100
MAX_CONTEXT_BYTES = 131_072


def attach_catalog_context(session: Session, reports: list[dict[str, Any]]) -> None:
    """Read only the context subdocument; never retrieve full package projections.

    The writer verifies the complete document against its content-addressed key.
    Append-only DB protection and each catalog's exact hash bind this lookup, just
    as they bind existing supplemental facts. Missing old payloads remain unknown.
    """
    hashes = list(
        dict.fromkeys(r["catalog_source_sha256"] for r in reports if r.get("catalog_source_sha256"))
    )
    selected = hashes[:MAX_CONTEXT_REPORTS]
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
    used = 0
    for report in reports:
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
