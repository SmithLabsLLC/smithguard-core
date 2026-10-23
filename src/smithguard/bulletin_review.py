"""Bounded private analyst work with immutable, optimistic resolution receipts."""

import re
from datetime import UTC, datetime

from sqlalchemy import func, select

from smithguard.bulletin_contract import BulletinError
from smithguard.bulletin_store import capacity, lock_stream
from smithguard.db.bulletin_models import (
    BulletinCurrent,
    BulletinMaintenanceReceipt,
    BulletinReviewQueue,
    OfficialNoticeEvidence,
)
from smithguard.identifiers import canonical_json_bytes, sha256_id, timestamp


def queue(session, *, limit=50, now=None):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise BulletinError("bulletin_review_limit")
    rows = session.scalars(
        select(BulletinReviewQueue)
        .where(BulletinReviewQueue.state == "pending")
        .order_by(BulletinReviewQueue.created_at, BulletinReviewQueue.review_id)
        .limit(limit)
    ).all()
    items = []
    for row in rows:
        evidence_id = row.document.get("source_evidence_hash")
        evidence = session.get(OfficialNoticeEvidence, evidence_id) if evidence_id else None
        items.append(
            {
                "review_id": row.review_id,
                "source_key": row.source_key,
                "reason": row.reason,
                "document": row.document,
                "document_hash": sha256_id(canonical_json_bytes(row.document)),
                "observed_at": timestamp(row.created_at),
                "source_evidence": evidence.document if evidence else None,
            }
        )
    count = session.scalar(
        select(func.count())
        .select_from(BulletinReviewQueue)
        .where(BulletinReviewQueue.state == "pending")
    )
    from smithguard.bulletin_intake_diagnostics import pending_failures

    return {
        "pending": count,
        "returned": len(items),
        "items": items,
        "public": False,
        "detail_failures": pending_failures(session, now=now or datetime.now(UTC), limit=limit),
    }


def resolve(session, value, *, now):
    fields = {
        "review_id",
        "expected_document_hash",
        "outcome",
        "reason",
        "evidence_hashes",
        "bulletin_id",
        "expected_revision",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise BulletinError("bulletin_review_resolution_shape")
    if (
        value["outcome"] not in {"resolved", "dismissed"}
        or value["reason"]
        not in {
            "published",
            "corrected",
            "verified_unchanged",
            "duplicate",
            "insufficient_evidence",
            "outside_scope",
            "revoked",
        }
        or not isinstance(value["evidence_hashes"], list)
        or not 1 <= len(value["evidence_hashes"]) <= 10
        or any(
            not isinstance(h, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", h)
            for h in value["evidence_hashes"]
        )
    ):
        raise BulletinError("bulletin_review_resolution_invalid")
    lock_stream(session, now=now)
    row = session.get(BulletinReviewQueue, value["review_id"])
    if (
        row is None
        or row.state != "pending"
        or sha256_id(canonical_json_bytes(row.document)) != value["expected_document_hash"]
    ):
        raise BulletinError("bulletin_review_changed")
    if value["bulletin_id"] is not None:
        public = session.get(BulletinCurrent, value["bulletin_id"])
        if public is None or public.revision != value["expected_revision"]:
            raise BulletinError("bulletin_review_public_changed")
    elif value["expected_revision"] is not None or value["reason"] in {
        "published",
        "corrected",
        "verified_unchanged",
        "duplicate",
        "revoked",
    }:
        raise BulletinError("bulletin_review_public_required")
    receipt = {
        "schema_version": 1,
        "kind": "analyst_review",
        "decision": value,
        "source_document": row.document,
        "decided_at": timestamp(now),
    }
    capacity(session, new_identity=False)
    identity = sha256_id(canonical_json_bytes(receipt))
    session.add(BulletinMaintenanceReceipt(receipt_id=identity, document=receipt, created_at=now))
    row.state, row.updated_at = value["outcome"], now
    session.flush()
    return {"review_id": row.review_id, "state": row.state, "receipt_id": identity}
