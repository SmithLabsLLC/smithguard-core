"""Atomic immutable supplementary source facts; none decides package applicability."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, insert, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from smithguard.cve_enrichment import EPSS_MAX_CURRENT_AGE
from smithguard.db.locks import advisory_xact_lock
from smithguard.db.models import (
    SupplementalFactRecord,
    SupplementalPayloadRecord,
    SupplementalSnapshotRecord,
)
from smithguard.identifiers import (
    canonical_json_bytes,
    require_aware_utc,
    sha256_id,
    stable_id,
    timestamp,
)

EPSS_SOURCE = "gbsec:source:first-epss"
KEV_SOURCE = "gbsec:source:cisa-kev"
RUST_SOURCE = "gbsec:source:rustsec-advisory-database"
GO_SOURCE = "gbsec:source:go-vulnerability-database"
SOURCE_NAMES = {
    EPSS_SOURCE: "FIRST Exploit Prediction Scoring System",
    KEV_SOURCE: "CISA Known Exploited Vulnerabilities Catalog",
    RUST_SOURCE: "RustSec Advisory Database",
    GO_SOURCE: "Go Vulnerability Database",
}
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z")
MAX_FACTS = 200_000
MAX_FACT_BYTES = 160 * 1024
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
MAX_AGE = timedelta(hours=30)
MIN_COLLECTION_INTERVAL = timedelta(hours=20)
# Small/date-specific documents cost less inline than another row and index key.
SHARED_PAYLOAD_MIN_BYTES = 512


class SupplementalStoreError(ValueError):
    """The proposed source receipt cannot be accepted."""


def next_collection_at(
    source_id: str,
    observed_at: datetime,
    source_as_of: datetime | None,
    *,
    complete: bool = True,
) -> datetime:
    """Normal holdoff, shortened only to refresh aging complete EPSS data."""
    observed_at = require_aware_utc(observed_at)
    due = observed_at + MIN_COLLECTION_INTERVAL
    if source_id == EPSS_SOURCE and complete:
        if source_as_of is None:
            raise SupplementalStoreError("complete EPSS snapshot has no source date")
        due = min(due, require_aware_utc(source_as_of) + EPSS_MAX_CURRENT_AGE)
    return due


def latest_snapshot(
    session: Session, source_id: str, *, mode: str = "public", complete_only: bool = False
) -> SupplementalSnapshotRecord | None:
    statement = select(SupplementalSnapshotRecord).where(
        SupplementalSnapshotRecord.source_id == source_id,
        SupplementalSnapshotRecord.mode == mode,
    )
    if complete_only:
        statement = statement.where(SupplementalSnapshotRecord.state == "complete")
    return session.scalar(statement.order_by(SupplementalSnapshotRecord.sequence.desc()).limit(1))


@dataclass(frozen=True, slots=True)
class SourceReceipts:
    """Latest attempt and last complete receipt from one database view."""

    attempt: SupplementalSnapshotRecord | None
    complete: SupplementalSnapshotRecord | None


def load_latest_receipts(
    session: Session,
    source_ids: Iterable[str] = tuple(SOURCE_NAMES),
    *,
    mode: str = "public",
) -> dict[str, SourceReceipts]:
    """Load at most two receipts per exact source in one bounded statement."""
    ids = tuple(sorted(set(source_ids)))
    if mode not in {"public", "shadow"} or not set(ids) <= SOURCE_NAMES.keys():
        raise SupplementalStoreError("source receipt batch identity is invalid")
    if not ids:
        return {}
    ranked = (
        select(
            SupplementalSnapshotRecord.snapshot_id,
            func.row_number()
            .over(
                partition_by=(
                    SupplementalSnapshotRecord.source_id,
                    SupplementalSnapshotRecord.state,
                ),
                order_by=SupplementalSnapshotRecord.sequence.desc(),
            )
            .label("position"),
        )
        .where(
            SupplementalSnapshotRecord.source_id.in_(ids),
            SupplementalSnapshotRecord.mode == mode,
        )
        .subquery()
    )
    rows = session.scalars(
        select(SupplementalSnapshotRecord)
        .join(ranked, ranked.c.snapshot_id == SupplementalSnapshotRecord.snapshot_id)
        .where(ranked.c.position == 1)
    )
    result = {source_id: SourceReceipts(None, None) for source_id in ids}
    for row in rows:
        previous = result[row.source_id]
        attempt = previous.attempt
        if attempt is None or row.sequence > attempt.sequence:
            attempt = row
        result[row.source_id] = SourceReceipts(
            attempt, row if row.state == "complete" else previous.complete
        )
    return result


def append_snapshot(
    session: Session,
    *,
    source_id: str,
    mode: str,
    state: str,
    observed_at: datetime,
    source_as_of: datetime | None,
    document: Mapping[str, Any],
    facts: Mapping[str, Mapping[str, Any]],
) -> SupplementalSnapshotRecord:
    """Append exactly one all-or-nothing snapshot under the caller's transaction."""
    observed_at = require_aware_utc(observed_at)
    if source_as_of is not None:
        source_as_of = require_aware_utc(source_as_of)
        if source_as_of > observed_at + timedelta(minutes=5):
            raise SupplementalStoreError("source time is in the future")
    if (
        source_id not in SOURCE_NAMES
        or mode not in {"shadow", "public"}
        or state not in {"complete", "failed"}
    ):
        raise SupplementalStoreError("source receipt identity is invalid")
    if len(facts) > MAX_FACTS or (state == "failed" and facts):
        raise SupplementalStoreError("source fact count is invalid")
    if len(canonical_json_bytes(document)) > 65536:
        raise SupplementalStoreError("source receipt is too large")
    checked = []
    total = 0
    for subject, fact in sorted(facts.items()):
        if not isinstance(subject, str) or not subject.isascii() or not 1 <= len(subject) <= 160:
            raise SupplementalStoreError("source subject is invalid")
        if source_id in {EPSS_SOURCE, KEV_SOURCE} and CVE.fullmatch(subject) is None:
            raise SupplementalStoreError("CVE subject is invalid")
        body = canonical_json_bytes(fact)
        total += len(body)
        if len(body) > MAX_FACT_BYTES or total > MAX_SNAPSHOT_BYTES:
            raise SupplementalStoreError("source facts exceed the bounded snapshot")
        checked.append((subject, dict(fact)))
    advisory_xact_lock(session, f"supplemental-source:{source_id}:{mode}")
    previous = latest_snapshot(session, source_id, mode=mode)
    if previous is not None and observed_at < previous.observed_at:
        raise SupplementalStoreError("source observation moved backward")
    sequence = 1 if previous is None else previous.sequence + 1
    snapshot_id = stable_id("supplemental-snapshot", source_id, mode, str(sequence))
    values = {
        "snapshot_id": snapshot_id,
        "source_id": source_id,
        "mode": mode,
        "sequence": sequence,
        "state": state,
        "observed_at": observed_at,
        "source_as_of": source_as_of,
        "record_count": len(checked),
        "document": dict(document),
    }
    fact_rows = [
        {
            "snapshot_id": snapshot_id,
            "subject_id": key,
            "document": value,
            "record_hash": sha256_id(
                canonical_json_bytes(
                    {"snapshot_id": snapshot_id, "subject_id": key, "document": value}
                )
            ),
        }
        for key, value in checked
    ]
    record = SupplementalSnapshotRecord(
        **values,
        record_hash=sha256_id(
            canonical_json_bytes(
                {
                    **values,
                    "observed_at": timestamp(observed_at),
                    "source_as_of": timestamp(source_as_of) if source_as_of else None,
                    "facts_sha256": sha256_id(
                        canonical_json_bytes(
                            [(row["subject_id"], row["record_hash"]) for row in fact_rows]
                        )
                    ),
                }
            )
        ),
    )
    session.add(record)
    session.flush()
    # Compute evidence hashes above from the complete original document. Storage
    # normalization must never alter the historical fact or snapshot hash format.
    payloads = {}
    for row in fact_rows:
        row["payload_sha256"] = None
        body = canonical_json_bytes(row["document"])
        if len(body) >= SHARED_PAYLOAD_MIN_BYTES:
            digest = sha256_id(body)
            payloads[digest] = {"payload_sha256": digest, "document": row["document"]}
            row["payload_sha256"] = digest
            row["document"] = None
    # Deterministic ordering also keeps concurrent sources from taking conflicting
    # unique-key locks in opposite order. Existing immutable payloads are untouched.
    payload_rows = [payloads[key] for key in sorted(payloads)]
    for offset in range(0, len(payload_rows), 500):
        session.execute(
            pg_insert(SupplementalPayloadRecord)
            .values(payload_rows[offset : offset + 500])
            .on_conflict_do_nothing(index_elements=["payload_sha256"])
        )
    for offset in range(0, len(fact_rows), 500):
        # Explicit SQL NULLs keep mixed inline/shared facts in the same bulk
        # statement instead of fragmenting every alternating row into an INSERT.
        session.execute(
            insert(SupplementalFactRecord).execution_options(render_nulls=True),
            fact_rows[offset : offset + 500],
        )
    return record


def snapshot_facts(
    session: Session, snapshot_id: str, subjects: Iterable[str]
) -> dict[str, dict[str, Any]]:
    """Resolve exact requested membership from legacy or shared payload storage."""
    ids = sorted(set(subjects))
    if len(ids) > 2000:
        raise SupplementalStoreError("snapshot fact query exceeds its bound")
    if not ids:
        return {}
    rows = session.execute(
        select(
            SupplementalFactRecord.subject_id,
            func.coalesce(
                SupplementalFactRecord.document, SupplementalPayloadRecord.document
            ).label("document"),
        )
        .outerjoin(
            SupplementalPayloadRecord,
            SupplementalPayloadRecord.payload_sha256 == SupplementalFactRecord.payload_sha256,
        )
        .where(
            SupplementalFactRecord.snapshot_id == snapshot_id,
            SupplementalFactRecord.subject_id.in_(ids),
        )
    )
    return {row.subject_id: row.document for row in rows}


def source_state(
    session: Session,
    source_id: str,
    *,
    now: datetime,
    receipts: Mapping[str, SourceReceipts] | None = None,
) -> tuple[str, SupplementalSnapshotRecord | None]:
    now = require_aware_utc(now)
    loaded = load_latest_receipts(session, (source_id,)) if receipts is None else receipts
    if source_id not in loaded:
        raise SupplementalStoreError("source is absent from the verified receipt batch")
    attempt, complete = loaded[source_id].attempt, loaded[source_id].complete
    if attempt is None:
        return "missing", None
    if attempt.state == "failed":
        return "failed", complete
    if complete is None:
        return "missing", None
    if now < complete.observed_at or now - complete.observed_at > MAX_AGE:
        return "stale", complete
    # EPSS describes a dated model output; re-fetching old scores cannot refresh it.
    if source_id == EPSS_SOURCE and (
        complete.source_as_of is None or now - complete.source_as_of > timedelta(hours=48)
    ):
        return "stale", complete
    return "fresh", complete


def cve_context(
    session: Session, cves: list[str], *, now: datetime
) -> tuple[list[dict[str, Any]], str]:
    """Return exact CVE context and a fingerprint that includes corrections/failures."""
    subjects = sorted({value for value in cves if isinstance(value, str) and CVE.fullmatch(value)})
    if len(subjects) > 2000:
        raise SupplementalStoreError("CVE context query exceeds its bound")
    current: dict[
        str, tuple[str, SupplementalSnapshotRecord | None, dict[str, dict[str, Any]]]
    ] = {}
    fingerprint = []
    receipts = load_latest_receipts(session, (EPSS_SOURCE, KEV_SOURCE))
    for source_id in (EPSS_SOURCE, KEV_SOURCE):
        state, snapshot = source_state(session, source_id, now=now, receipts=receipts)
        attempt = receipts[source_id].attempt
        fingerprint.append(
            (
                source_id,
                state,
                attempt.record_hash if attempt else None,
                snapshot.record_hash if snapshot else None,
            )
        )
        facts = {}
        if snapshot is not None and subjects:
            facts = snapshot_facts(session, snapshot.snapshot_id, subjects)
        current[source_id] = state, snapshot, facts
    result = []
    for cve in subjects:
        item: dict[str, Any] = {"cve": cve}
        for source_id, key in ((EPSS_SOURCE, "epss"), (KEV_SOURCE, "kev")):
            state, snapshot, facts = current[source_id]
            fact = facts.get(cve)
            entry: dict[str, Any] = {
                "source_id": source_id,
                "attribution": SOURCE_NAMES[source_id],
                "state": state,
                "observed_at": timestamp(snapshot.observed_at) if snapshot else None,
                "source_as_of": timestamp(snapshot.source_as_of)
                if snapshot and snapshot.source_as_of
                else None,
                "source_url": snapshot.document.get("source_url") if snapshot else None,
                "snapshot_id": snapshot.snapshot_id if snapshot else None,
                "value": fact,
            }
            if key == "kev" and snapshot is not None:
                entry["listed"] = fact is not None
            else:
                entry["listed"] = None
            item[key] = entry
        result.append(item)
    return result, stable_id("cve-context", fingerprint)


def origin_context_for_reports(
    session: Session, reports: list[dict[str, Any]], *, now: datetime
) -> tuple[dict[tuple[str, str], dict[str, Any]], str]:
    """Read only the precise origin records requested by current package reports."""
    selected = {
        (report["source_id"], report["upstream_record_id"])
        for report in reports
        if report["source_id"] in {RUST_SOURCE, GO_SOURCE}
    }
    if len(selected) > 1000:
        raise SupplementalStoreError("origin context exceeds its bounded report query")
    result = {}
    fingerprint = []
    receipts = load_latest_receipts(session, {source for source, _ in selected})
    for source_id in (RUST_SOURCE, GO_SOURCE):
        ids = sorted(record_id for source, record_id in selected if source == source_id)
        if not ids:
            continue
        state, snapshot = source_state(session, source_id, now=now, receipts=receipts)
        attempt = receipts[source_id].attempt
        fingerprint.append(
            (
                source_id,
                state,
                attempt.record_hash if attempt else None,
                snapshot.record_hash if snapshot else None,
            )
        )
        if snapshot is None:
            continue
        facts = snapshot_facts(session, snapshot.snapshot_id, ids)
        for subject, document in facts.items():
            result[(source_id, subject)] = {
                "state": state,
                "snapshot_id": snapshot.snapshot_id,
                "observed_at": timestamp(snapshot.observed_at),
                "source_as_of": timestamp(snapshot.source_as_of) if snapshot.source_as_of else None,
                "source_sha256": document["source_sha256"],
                "license_expression": document["license_expression"],
                "attribution_urls": document["attribution_urls"],
                "context": document["context"],
            }
    return result, stable_id("origin-context", fingerprint)
