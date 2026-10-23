"""Immutable official feed receipts, separate from AI job queues."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from smithguard.db.jobs import enqueue
from smithguard.db.models import JobRecord
from smithguard.emerging_leads import record_lead
from smithguard.identifiers import canonical_json_bytes, require_aware_utc, sha256_id, timestamp

QUEUE = "official-notice-receipts"
MAX_RECORDS = 20000
MAX_RECORD_BYTES = 16 * 1024
MAX_KNOWN = 1024


def receipt(session: Session, *, identity: str, kind: str, now: datetime, data: dict) -> JobRecord:
    require_aware_utc(now)
    if set(data) & {"schema_version", "kind", "occurred_at"}:
        raise ValueError("official_reserved_receipt_fields")
    if kind not in {"started", "fetch", "notice", "completed", "available"}:
        raise ValueError("official_receipt_kind")
    payload = {"schema_version": 1, "kind": kind, "occurred_at": timestamp(now), **data}
    if len(canonical_json_bytes(payload)) > MAX_RECORD_BYTES:
        raise ValueError("official_receipt_bytes")
    row, created = enqueue(
        session,
        queue=QUEUE,
        job_type="official_notice_receipt",
        idempotency_key=identity,
        payload=payload,
        payload_classification="internal_control",
        max_attempts=1,
        available_at=now,
        now=now,
    )
    if created:
        row.state = "succeeded"
        row.completed_at = now
        row.updated_at = now
        session.flush()
    elif row.state != "succeeded" or row.payload != payload:
        raise ValueError("official_receipt_history_conflict")
    return row


def all_count(session):
    return session.scalar(
        select(func.count()).select_from(JobRecord).where(JobRecord.queue == QUEUE)
    )


def started_hour(session, run_id):
    return (
        session.scalar(
            select(JobRecord)
            .where(
                JobRecord.queue == QUEUE,
                JobRecord.payload["kind"].as_string() == "started",
                JobRecord.payload["run_id"].as_string() == run_id,
            )
            .limit(1)
        )
        is not None
    )


def latest_fetches(session, source, limit=3):
    return list(
        session.scalars(
            select(JobRecord)
            .where(
                JobRecord.queue == QUEUE,
                JobRecord.payload["kind"].as_string() == "fetch",
                JobRecord.payload["source"].as_string() == source,
            )
            .order_by(JobRecord.created_at.desc(), JobRecord.job_id)
            .limit(limit)
        )
    )


def status(session, *, now):
    """Bounded read-only operational facts; no retrieval or applicability claims."""
    now = require_aware_utc(now)
    started = session.scalar(
        select(JobRecord)
        .where(JobRecord.queue == QUEUE, JobRecord.payload["kind"].as_string() == "started")
        .order_by(JobRecord.created_at.desc(), JobRecord.job_id)
        .limit(1)
    )
    run_id = started.payload["run_id"] if started else None
    rows = (
        list(
            session.scalars(
                select(JobRecord)
                .where(
                    JobRecord.queue == QUEUE,
                    JobRecord.payload["run_id"].as_string() == run_id,
                    JobRecord.payload["kind"].as_string().in_(("completed", "available")),
                )
                .limit(2)
            )
        )
        if run_id
        else []
    )
    closing = {row.payload["kind"]: row.payload for row in rows}
    completed = closing.get("completed")
    available = closing.get("available")
    sources = {}
    for source in ("php", "mozilla"):
        latest = latest_fetches(session, source, 1)
        last_good = session.scalar(
            select(JobRecord)
            .where(
                JobRecord.queue == QUEUE,
                JobRecord.payload["kind"].as_string() == "fetch",
                JobRecord.payload["source"].as_string() == source,
                JobRecord.payload["cursor_committed"].as_boolean().is_(True),
            )
            .order_by(JobRecord.created_at.desc(), JobRecord.job_id)
            .limit(1)
        )
        age = (now - last_good.created_at).total_seconds() if last_good else None
        payload = latest[0].payload if latest else {}
        last_parsed = session.scalar(
            select(JobRecord)
            .where(
                JobRecord.queue == QUEUE,
                JobRecord.payload["kind"].as_string() == "fetch",
                JobRecord.payload["source"].as_string() == source,
                JobRecord.payload["http_status"].as_integer() == 200,
            )
            .order_by(JobRecord.created_at.desc(), JobRecord.job_id)
            .limit(1)
        )
        parser = last_parsed.payload.get("parser") if last_parsed else None
        sources[source] = {
            "last_outcome": payload.get("outcome"),
            "last_attempt_observed_at": payload.get("occurred_at"),
            "last_reason": payload.get("reason"),
            "last_success_observed_at": timestamp(last_good.created_at) if last_good else None,
            "fresh": age is not None and 0 <= age <= 2 * 3600,
            "parser": parser,
            "parser_observed_at": timestamp(last_parsed.created_at) if last_parsed else None,
            "feed_entry_budget_warning": bool(
                parser and parser["feed_entries"] >= int(parser["entry_limit"] * 0.8)
            ),
            "unprocessed": payload.get("unprocessed"),
            "degradation_reason": payload.get("degradation_reason"),
            "observation_gap_seconds": payload.get("observation_gap_seconds"),
        }
    count = all_count(session)
    known_count = sum(len(known_notices(session, source)) for source in ("php", "mozilla"))
    return {
        "schema_version": 1,
        "observed_at": timestamp(now),
        "run_id": run_id,
        "status": completed["status"] if completed else "incomplete" if started else "never_run",
        "last_started_at": timestamp(started.created_at) if started else None,
        "internal_available_upper_bound": available["occurred_at"] if available else None,
        "sources": sources,
        "receipt_count": count,
        "receipt_limit": MAX_RECORDS,
        "known_notice_count": known_count,
        "known_notice_limit": MAX_KNOWN,
        "identity_budget_warning": known_count >= int(MAX_KNOWN * 0.8),
        "storage_budget_paused": count > MAX_RECORDS - 10,
        "storage_budget_warning": count >= int(MAX_RECORDS * 0.8),
        "empty_run_hours_remaining": max(0, (MAX_RECORDS - 10 - count) // 5),
        "minimum_full_run_slots_remaining": max(0, (MAX_RECORDS - 10 - count) // 9),
        "publication": "ineligible",
        "artifact_applicability": "unknown",
        "retrieval_recall": None,
    }


def last_successful_fetch(session, source):
    return session.scalar(
        select(JobRecord)
        .where(
            JobRecord.queue == QUEUE,
            JobRecord.payload["kind"].as_string() == "fetch",
            JobRecord.payload["source"].as_string() == source,
            JobRecord.payload["cursor_committed"].as_boolean().is_(True),
        )
        .order_by(JobRecord.created_at.desc(), JobRecord.job_id)
        .limit(1)
    )


def cursor(session, source):
    row = last_successful_fetch(session, source)
    return (
        {"etag": row.payload["etag"], "modified": row.payload["modified"]}
        if row
        else {"etag": None, "modified": None}
    )


def known_notices(session, source):
    url = JobRecord.payload["url"].as_string()
    rows = list(
        session.scalars(
            select(JobRecord)
            .where(
                JobRecord.queue == QUEUE,
                JobRecord.payload["kind"].as_string() == "notice",
                JobRecord.payload["source"].as_string() == source,
            )
            .distinct(url)
            .order_by(url, JobRecord.created_at.desc(), JobRecord.job_id)
            .limit(MAX_KNOWN + 1)
        )
    )
    if len(rows) > MAX_KNOWN:
        raise ValueError("official_known_notice_budget")
    return {row.payload["url"]: row.payload for row in rows}


def notice_document(notice):
    return {
        "source": notice.source,
        "url": notice.url,
        "title": notice.title,
        "context": notice.context,
        "published_at": timestamp(notice.published),
        "modified_at": timestamp(notice.modified) if notice.modified else None,
        "withdrawn": notice.withdrawn,
        "entry_sha256": notice.entry_sha256,
        "content_sha256": notice.content_sha256,
    }


def semantic_hash(document):
    return sha256_id(
        canonical_json_bytes(
            {key: value for key, value in document.items() if key != "entry_sha256"}
        )
    )


def candidate(document, now):
    return {
        "lead_id": sha256_id(
            canonical_json_bytes(["official_announcement", document["source"], document["url"]])
        )[7:],
        "provenance_kind": "official_announcement",
        "subject": "PHP" if document["source"] == "php" else "Mozilla",
        "allegation": document["title"],
        "sources": [
            {
                "url": document["url"],
                "context": document["context"],
                "context_provenance": "official_structured_feed",
                "citation_bound": True,
                "published_at": document["published_at"],
                "time_precision": "exact",
            }
        ],
        "observed_at": timestamp(now),
        "artifact_applicability": "unknown",
    }


def project_lead(session, lead, *, withdrawn, now):
    if lead.get("provenance_kind") != "official_announcement":
        raise ValueError("official_provenance_required")
    row, created = record_lead(
        session,
        lead,
        state="withdrawn" if withdrawn else "needs_enrichment",
        reason="official_notice_withdrawn" if withdrawn else "official_applicability_unknown",
        now=now,
    )
    return {"revision": row.revision, "state": row.state, "created": created}


def notice_changes(notices, known, limit):
    """Plan changes before DB writes, never silently advance past overflow."""
    unchanged, changes = 0, []
    for notice in notices:
        document = notice_document(notice)
        previous = known.get(notice.url)
        if previous is not None and notice.withdrawn:
            document["published_at"] = previous["published_at"]
        if (
            previous is not None
            and previous.get("modified_at")
            and document["modified_at"]
            and document["modified_at"] < previous["modified_at"]
        ):
            raise ValueError("official_source_revision_regressed")
        digest = semantic_hash(document)
        if previous is not None and previous["semantic_sha256"] == digest:
            unchanged += 1
            continue
        changes.append(
            {
                "document": document,
                "semantic_sha256": digest,
                "prior_semantic_sha256": previous["semantic_sha256"] if previous else None,
                "change": "withdrawn" if notice.withdrawn else "corrected" if previous else "new",
            }
        )
    # Deterministic ordering gives the pending tail a chance on the next fetch.
    changes.sort(key=lambda item: (item["document"]["published_at"], item["document"]["url"]))
    return {
        "changes": changes[:limit],
        "unchanged": unchanged,
        "overflow": len(changes) > limit,
        "unprocessed": max(0, len(changes) - limit),
    }
