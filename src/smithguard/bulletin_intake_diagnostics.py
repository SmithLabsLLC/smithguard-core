"""Closed failure categories; private identities, never exception text or source prose."""

import subprocess
from datetime import timedelta

from sqlalchemy import func, select

from smithguard.bulletin_contract import BulletinError
from smithguard.bulletin_store import capacity
from smithguard.db.bulletin_models import BulletinMaintenanceReceipt, OfficialNoticePending
from smithguard.identifiers import canonical_json_bytes, sha256_id, timestamp
from smithguard.official_notice_fetch import FetchError

ESCALATION_COUNT = 3
MAX_FAILURE_COUNT = 65535


def category(error, *, phase):
    """Only our own fixed phase and explicitly recognized error codes leave this boundary."""
    if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
        return "timeout"
    if isinstance(error, FetchError):
        return "timeout" if str(error) == "fetch_deadline" else "transport"
    if isinstance(error, BulletinError):
        code = str(error)
        if code == "bulletin_network_budget":
            return "budget"
        if code == "bulletin_detail_http":
            return "http_status"
        if code in {"cisco_detail_dates", "bulletin_source_future", "bulletin_source_day"}:
            return "source_dates"
        if code in {
            "bulletin_detail_identity",
            "mozilla_detail_identity",
            "ubuntu_detail_identity",
            "gitlab_detail_identity",
            "fortinet_detail_identity",
            "paloalto_detail_identity",
        }:
            return "source_identity"
    return {
        "rights": "rights",
        "fetch": "transport",
        "parse": "source_shape",
        "persist": "storage",
    }.get(phase, "unknown")


def record_failure(session, pending, *, now, category):
    """Keep bounded retry state even when no additional diagnostic receipt fits."""
    pending.failure_count = min(MAX_FAILURE_COUNT, pending.failure_count + 1)
    pending.failure_category = category
    pending.first_failure_at = pending.first_failure_at or now
    pending.last_failure_at = now
    pending.next_attempt_at = now + timedelta(hours=6)
    try:
        capacity(session, new_identity=False)
    except BulletinError as error:
        if str(error) != "bulletin_storage_capacity":
            raise
        return  # Existing-row updates and the idempotent stale transition still commit.
    document = {
        "schema_version": 1,
        "kind": "detail_qualification_failure",
        "source_key": pending.source_key,
        "record_key": pending.record_key,
        "source_evidence_hash": pending.evidence_id,
        "observed_at": timestamp(now),
        "category": category,
        "consecutive_failures": pending.failure_count,
        "next_attempt_at": timestamp(pending.next_attempt_at),
        "escalated": pending.failure_count >= ESCALATION_COUNT,
    }
    session.add(
        BulletinMaintenanceReceipt(
            receipt_id=sha256_id(canonical_json_bytes(document)), document=document, created_at=now
        )
    )


def pending_failures(session, *, now, limit=50):
    query = select(OfficialNoticePending).where(
        OfficialNoticePending.processed_at.is_(None),
        OfficialNoticePending.failure_count > 0,
    )
    total = session.scalar(select(func.count()).select_from(query.subquery()))
    rows = session.scalars(
        query.order_by(
            OfficialNoticePending.failure_count.desc(),
            OfficialNoticePending.first_failure_at,
            OfficialNoticePending.source_key,
            OfficialNoticePending.record_key,
        ).limit(limit)
    ).all()
    return {
        "pending": total,
        "items": [
            {
                "source_key": row.source_key,
                "record_key": row.record_key,
                "url": row.record_url,
                "category": row.failure_category,
                "consecutive_failures": row.failure_count,
                "first_failure_at": timestamp(row.first_failure_at),
                "last_failure_at": timestamp(row.last_failure_at),
                "next_attempt_at": timestamp(row.next_attempt_at) if row.next_attempt_at else None,
                "age_seconds": max(0, int((now - row.first_failure_at).total_seconds())),
                "escalated": row.failure_count >= ESCALATION_COUNT,
            }
            for row in rows
        ],
    }
