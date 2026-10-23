"""Repair only reviewed, still-live one-hour drift; never rewrite content or replay."""

from copy import deepcopy
from datetime import UTC, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from smithguard.bulletin_contract import BulletinError
from smithguard.bulletin_expiry_repair import repair
from smithguard.db.bulletin_models import BulletinCurrent, BulletinEvent, BulletinRevision
from smithguard.identifiers import timestamp
from tests.test_bulletin_automation import AUTO, NOW, run


def prepared(database):
    run(database)
    with Session(database.engine) as session, session.begin():
        row = session.scalar(select(BulletinCurrent))
        row.expires_at += timedelta(hours=1)
        version = session.get(BulletinRevision, (row.bulletin_id, row.revision))
        request = {
            "operation_id": "20261023-" + "c" * 32,
            "targets": [
                {
                    "bulletin_id": row.bulletin_id,
                    "expected_revision": row.revision,
                    "content_hash": version.content_hash,
                    "first_seen_at": timestamp(row.first_seen_at),
                    "expires_at": timestamp(row.expires_at),
                }
            ],
        }
        original = (
            row.first_seen_at,
            row.verified_at,
            row.verification_due_at,
            row.revision,
            deepcopy(version.document),
            version.content_hash,
        )
    grant = {
        **AUTO,
        "effective_at": timestamp(NOW - timedelta(hours=1)),
        "review_due_at": timestamp(NOW + timedelta(days=1)),
    }
    return request, original, grant


def test_expiry_repair_preserves_first_seen_content_and_verification(database):
    request, original, grant = prepared(database)
    with Session(database.engine) as session, session.begin():
        result = repair(session, request, grant=grant, now=NOW + timedelta(minutes=1))
        assert len(result["changes"]) == 1
    with Session(database.engine) as session:
        row = session.scalar(select(BulletinCurrent))
        version = session.get(BulletinRevision, (row.bulletin_id, row.revision))
        assert row.expires_at.astimezone(UTC) - row.first_seen_at.astimezone(UTC) == timedelta(
            days=90
        )
        assert (
            row.first_seen_at,
            row.verified_at,
            row.verification_due_at,
            row.revision,
            version.document,
            version.content_hash,
        ) == original
        event = session.scalar(select(BulletinEvent).order_by(BulletinEvent.sequence.desc()))
        assert event.kind == "source_updated" and event.reason == "expiry_utc_corrected"
    with (
        Session(database.engine) as session,
        session.begin(),
        pytest.raises(BulletinError, match="consumed"),
    ):
        repair(session, request, grant=grant, now=NOW + timedelta(minutes=2))


@pytest.mark.parametrize(
    "fault", ["revision", "content", "first_seen", "expired", "two_hours", "grant"]
)
def test_wrong_target_and_expired_record_are_not_repaired(database, fault):
    request, original, grant = prepared(database)
    with Session(database.engine) as session, session.begin():
        row = session.scalar(select(BulletinCurrent))
        if fault == "revision":
            request["targets"][0]["expected_revision"] += 1
        elif fault == "content":
            request["targets"][0]["content_hash"] = "sha256:" + "0" * 64
        elif fault == "first_seen":
            request["targets"][0]["first_seen_at"] = timestamp(NOW - timedelta(hours=1))
        elif fault == "two_hours":
            row.expires_at += timedelta(hours=1)
            request["targets"][0]["expires_at"] = timestamp(row.expires_at)
        elif fault == "grant":
            grant["source_keys"] = []
    instant = NOW + timedelta(days=91) if fault == "expired" else NOW
    if fault == "expired":
        grant.update(
            effective_at=timestamp(instant), review_due_at=timestamp(instant + timedelta(hours=1))
        )
    with Session(database.engine) as session, session.begin(), pytest.raises(BulletinError):
        repair(session, request, grant=grant, now=instant)
