"""Exact-target UTC-derived expiry correction, preserving content and first admission."""

import re
from datetime import UTC, timedelta

from smithguard.bulletin_contract import BulletinError
from smithguard.bulletin_sources import SOURCE_IDS
from smithguard.bulletin_store import _decision, capacity, lock_stream
from smithguard.db.bulletin_models import (
    BulletinCurrent,
    BulletinMaintenanceReceipt,
    BulletinRevision,
)
from smithguard.identifiers import parse_timestamp, sha256_id, timestamp


def repair(session, request, *, grant, now):
    if (
        not isinstance(request, dict)
        or set(request) != {"operation_id", "targets"}
        or not isinstance(request["operation_id"], str)
        or not re.fullmatch(r"[0-9]{8}-[a-f0-9]{32}", request["operation_id"])
        or not isinstance(request["targets"], list)
        or not 1 <= len(request["targets"]) <= 10
    ):
        raise BulletinError("bulletin_expiry_repair_shape")
    identity = sha256_id(("expiry_repair:" + request["operation_id"]).encode())
    stream = lock_stream(session, now=now)
    if session.get(BulletinMaintenanceReceipt, identity) is not None:
        raise BulletinError("bulletin_expiry_repair_consumed")
    if grant["mode"] != "automatic" or not parse_timestamp(
        grant["effective_at"]
    ) <= now < parse_timestamp(grant["review_due_at"]):
        raise BulletinError("bulletin_expiry_repair_grant")
    changes, seen = [], set()
    for target in request["targets"]:
        if (
            not isinstance(target, dict)
            or set(target)
            != {"bulletin_id", "expected_revision", "content_hash", "first_seen_at", "expires_at"}
            or type(target["expected_revision"]) is not int
        ):
            raise BulletinError("bulletin_expiry_repair_target")
        key = target["bulletin_id"]
        if not isinstance(key, str) or not re.fullmatch("[a-f0-9]{64}", key) or key in seen:
            raise BulletinError("bulletin_expiry_repair_target")
        seen.add(key)
        row = session.get(BulletinCurrent, key)
        version = session.get(BulletinRevision, (key, target["expected_revision"]))
        if (
            row is None
            or version is None
            or row.revision != target["expected_revision"]
            or version.content_hash != target["content_hash"]
            or row.tombstoned
            or row.mode != "automatic"
            or row.source_key not in SOURCE_IDS
            or row.source_key not in grant["source_keys"]
            or row.first_seen_at != parse_timestamp(target["first_seen_at"])
            or row.expires_at != parse_timestamp(target["expires_at"])
        ):
            raise BulletinError("bulletin_expiry_repair_state_changed")
        corrected = row.first_seen_at.astimezone(UTC) + timedelta(days=90)
        if (
            abs(corrected - row.expires_at) != timedelta(hours=1)
            or min(corrected, row.expires_at) <= now
        ):
            raise BulletinError("bulletin_expiry_repair_not_one_hour_live_drift")
        changes.append((row, corrected))
    capacity(session, new_identity=False)
    results = []
    for row, corrected in changes:
        before = row.expires_at
        row.expires_at = corrected
        sequence, decision = _decision(
            session,
            stream,
            row,
            kind="source_updated",
            reason="expiry_utc_corrected",
            now=now,
            document={
                "operation_id": request["operation_id"],
                "previous_expires_at": timestamp(before),
                "expires_at": timestamp(corrected),
                "first_seen_at": timestamp(row.first_seen_at),
                "content_unchanged": True,
                "verification_unchanged": True,
            },
        )
        results.append(
            {
                "bulletin_id": row.bulletin_id,
                "sequence": sequence,
                "decision_id": decision,
                "expires_at": timestamp(corrected),
            }
        )
    document = {
        "schema_version": 1,
        "kind": "expiry_utc_repair",
        "request": request,
        "changes": results,
        "completed_at": timestamp(now),
    }
    session.add(BulletinMaintenanceReceipt(receipt_id=identity, document=document, created_at=now))
    session.flush()
    return {"receipt_id": identity, "changes": results}
