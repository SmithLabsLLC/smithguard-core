"""Private 30-day retention of final warning-lane provider output (owner decision,
September 24, 2026). Only the output text and citation list are kept, never reasoning;
the public API role cannot read the table, and rows are purged after expiry."""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import delete
from sqlalchemy.orm import Session

from smithguard.db.models import WarningLaneOutputRecord
from smithguard.identifiers import canonical_json_bytes, require_aware_utc, sha256_id

OUTPUT_RETENTION = timedelta(days=30)
MAX_OUTPUT_CHARACTERS = 262_144
MAX_CITATIONS = 500


def _needs_escape(value: str) -> bool:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return True  # lone surrogates from escaped JSON
    return "\x00" in value


def _escape(value: str) -> str:
    """Reversible storage form PostgreSQL accepts: backslashes doubled, NUL as \\x00,
    lone surrogates as \\udXXX (read back with the "unicode_escape" rules)."""
    escaped = value.replace("\\", "\\\\").replace("\x00", "\\x00")
    return escaped.encode("utf-8", "backslashreplace").decode("utf-8")


def record_output(
    session: Session,
    *,
    run_id: str,
    job_id: str,
    attempt: int,
    stage: str,
    response_id: str,
    output_text: str,
    citation_urls: tuple[str, ...],
    now: datetime,
) -> None:
    """Keep one attempt's final output text and citations until the retention ends."""
    now = require_aware_utc(now)
    citations = [value for value in citation_urls[:MAX_CITATIONS] if isinstance(value, str)]
    escaped = _needs_escape(output_text) or any(_needs_escape(value) for value in citations)
    if escaped:
        output_text = _escape(output_text)
        citations = [_escape(value) for value in citations]
    job_hash = sha256_id(job_id.encode("utf-8", "backslashreplace"))
    output_id = sha256_id(canonical_json_bytes([job_hash, attempt, stage]))
    if session.get(WarningLaneOutputRecord, output_id) is not None:
        return
    session.add(
        WarningLaneOutputRecord(
            output_id=output_id,
            run_id=run_id,
            job_id_sha256=job_hash,
            attempt=attempt,
            stage=stage,
            response_id_sha256=sha256_id(response_id.encode("utf-8", "backslashreplace")),
            output_text=output_text[:MAX_OUTPUT_CHARACTERS],
            output_truncated=len(output_text) > MAX_OUTPUT_CHARACTERS,
            output_encoding="escaped" if escaped else "text",
            citation_urls=citations,
            created_at=now,
            expires_at=now + OUTPUT_RETENTION,
        )
    )
    session.flush()


def purge_expired_outputs(session: Session, *, now: datetime) -> int:
    """Delete retained output whose 30 days have passed; returns the count."""
    result = session.execute(
        delete(WarningLaneOutputRecord).where(
            WarningLaneOutputRecord.expires_at <= require_aware_utc(now)
        )
    )
    return int(result.rowcount or 0)
