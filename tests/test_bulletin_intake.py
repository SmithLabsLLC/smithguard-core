"""Real PostgreSQL catch-up, correction priority, durable tails and consumed hours."""

from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from smithguard import bulletin_intake as intake
from smithguard import bulletin_intake_store as store
from smithguard import bulletin_store
from smithguard import official_notice_coordinator as legacy
from smithguard.bulletin_publisher import processor
from smithguard.db.bulletin_models import (
    BulletinCurrent,
    BulletinEvent,
    BulletinRevision,
    BulletinSourceStatus,
    OfficialIntakeRun,
    OfficialNoticeCurrent,
    OfficialNoticePending,
    OfficialSourceCheckpoint,
)
from smithguard.db.models import JobRecord
from smithguard.identifiers import timestamp
from smithguard.official_notice_fetch import FetchResult
from smithguard.official_notice_store import QUEUE

from .test_bulletins import GRANT, REGISTRY
from .test_official_notice_parser import NOW, URL, entry, feed

MOZILLA = (Path(__file__).parent / "fixtures/social-security/mozilla-feed.xml").read_bytes()
BASELINE = NOW.replace(day=20, hour=18)


def options(now=NOW):
    return {
        "registry": REGISTRY,
        "enabled": lambda: True,
        "now": now,
        "artifact_commit": "a" * 40,
        "invocation_id": "b" * 32,
    }


def seed(database):
    with Session(database.engine) as session, session.begin():
        store.cutover(session, now=BASELINE)


def body(extra=None):
    old = entry(
        url="https://www.php.net/archive/2026.php#2026-10-19-1",
        date="2026-10-19T00:00:00Z",
        title="Conference",
        content="Tickets",
    )
    return feed(old + (entry() if extra is None else extra))


def fetcher(php=None, calls=None):
    def fetch(source, **conditional):
        if calls is not None:
            calls.append((source, conditional))
        return FetchResult(
            200,
            (body() if php is None else php) if source == "php" else MOZILLA,
            '"cursor"',
            None,
            "a" * 64,
        )

    return fetch


def test_compact_runs_retain_work_and_do_not_append_legacy_receipts(database):
    seed(database)
    calls = []
    first = intake.run(database.engine, fetch=fetcher(calls=calls), **options())
    assert first["status"] == "complete", first
    assert [r["accepted"]["new"] for r in first["sources"]] == [1, 1]
    assert (
        intake.run(database.engine, fetch=fetcher(calls=calls), **options())["status"]
        == "hour_consumed"
    )
    assert len(calls) == 2
    with Session(database.engine) as session:
        assert (
            session.scalar(
                select(func.count()).select_from(JobRecord).where(JobRecord.queue == QUEUE)
            )
            == 0
        )
        assert session.scalar(select(func.count()).select_from(OfficialIntakeRun)) == 3
        assert session.scalar(select(func.count()).select_from(OfficialNoticeCurrent)) == 2


def test_long_outage_keeps_unseen_older_than_24_hours(database):
    seed(database)
    first = intake.run(database.engine, fetch=fetcher(), **options())
    assert first["status"] == "complete"
    extra = entry() + entry(
        url="https://www.php.net/archive/2026.php#2026-10-22-1", date="2026-10-22T05:00:00Z"
    )
    report = intake.run(
        database.engine, fetch=fetcher(body(extra)), **options(NOW + timedelta(days=4))
    )
    assert report["sources"][0]["accepted"]["new"] == 1, report
    assert report["sources"][0]["state"] == "fresh"


def test_pending_tail_survives_unsolicited_304_and_drains_same_day(database):
    seed(database)
    entries = "".join(
        entry(url=f"https://www.php.net/archive/2026.php#2026-10-20-{i}") for i in range(1, 111)
    )
    first = intake.run(database.engine, fetch=fetcher(body(entries)), **options())
    assert first["sources"][0]["pending"] == 10, first
    assert first["sources"][0]["accepted"]["new"] == 100
    calls = []

    def not_modified(source, **conditional):
        calls.append((source, conditional))
        return FetchResult(304, b"", '"cursor"', None, None)

    second = intake.run(database.engine, fetch=not_modified, **options(NOW + timedelta(hours=1)))
    assert calls[0][1] == {"etag": None, "modified": None}
    assert second["sources"][0]["reason"] == "unsolicited_not_modified"
    assert second["sources"][0]["accepted"]["new"] == 10
    assert second["sources"][0]["pending"] == 0
    with Session(database.engine) as session:
        checkpoint = session.get(OfficialSourceCheckpoint, "php").document
        assert checkpoint["complete_through"] is None
        assert (
            session.scalar(
                select(func.count())
                .select_from(OfficialNoticeCurrent)
                .where(OfficialNoticeCurrent.source_key == "php")
            )
            == 110
        )


def test_correction_precedes_full_new_queue_and_work_bound(database):
    seed(database)
    assert intake.run(database.engine, fetch=fetcher(), **options())["status"] == "complete"
    entries = "".join(
        entry(url=f"https://www.php.net/archive/2026.php#2026-10-20-{i}") for i in range(2, 112)
    )
    entries += entry(url=URL, content="Corrected security notice")
    observed = []

    def process(session, current, *, now):
        observed.append(current.document["document"]["context"])
        return True

    second = intake.run(
        database.engine,
        fetch=fetcher(body(entries)),
        process=process,
        **options(NOW + timedelta(hours=1)),
    )
    assert second["sources"][0]["accepted"] == {"corrected": 1, "withdrawn": 0, "new": 99}, second
    assert observed[0] == "Corrected security notice"
    assert second["sources"][0]["pending"] == 11


def test_finite_feed_gap_does_not_advance_complete_cursor(database):
    seed(database)
    assert intake.run(database.engine, fetch=fetcher(), **options())["status"] == "complete"
    recent = feed(
        entry(url="https://www.php.net/archive/2026.php#2026-10-24-1", date="2026-10-24T00:00:00Z")
    )
    report = intake.run(database.engine, fetch=fetcher(recent), **options(NOW + timedelta(days=4)))
    assert report["sources"][0]["reason"] == "finite_feed_gap"
    with Session(database.engine) as session:
        assert session.get(OfficialSourceCheckpoint, "php").document[
            "complete_through"
        ] == timestamp(NOW)

    recovered_at = NOW + timedelta(days=4, hours=1)
    recovered = intake.run(database.engine, fetch=fetcher(), **options(recovered_at))
    assert recovered["sources"][0]["state"] == "fresh"
    with Session(database.engine) as session:
        checkpoint = session.get(OfficialSourceCheckpoint, "php").document
        assert checkpoint["gap_since"] is None
        assert checkpoint["complete_through"] == timestamp(recovered_at)
        proof = checkpoint["last_recovered_gap"]
        assert proof["recovered_at"] == timestamp(recovered_at)
        closure = session.get(OfficialIntakeRun, (recovered["run_id"], "closure"))
        assert closure.document["sources"][0]["recovered_gap"] == proof


def test_storage_admission_reserve_preserves_accepted_corrections(database, monkeypatch):
    from smithguard.bulletin_contract import BulletinError

    seed(database)
    entries = "".join(
        entry(url=f"https://www.php.net/archive/2026.php#2026-10-20-{i}") for i in range(1, 103)
    )
    first = intake.run(
        database.engine, fetch=fetcher(body(entries)), source_keys=["php"], **options()
    )
    assert first["sources"][0]["pending"] == 2
    with Session(database.engine) as session:
        accepted_url = session.scalar(select(OfficialNoticeCurrent)).document["document"]["url"]

    def reserve(session, *, new_identity):
        if new_identity:
            raise BulletinError("bulletin_storage_capacity")

    monkeypatch.setattr(store, "capacity", reserve)
    corrected = "".join(
        entry(
            url=(url := f"https://www.php.net/archive/2026.php#2026-10-20-{i}"),
            **({"content": "Corrected retained security context"} if url == accepted_url else {}),
        )
        for i in range(1, 103)
    )
    result = intake.run(
        database.engine,
        fetch=fetcher(body(corrected)),
        source_keys=["php"],
        **options(NOW + timedelta(days=1)),
    )
    assert result["sources"][0]["accepted"]["corrected"] == 1
    assert result["sources"][0]["pending"] == 2
    with Session(database.engine) as session:
        contexts = [
            r.document["document"]["context"]
            for r in session.scalars(select(OfficialNoticeCurrent))
        ]
        assert "Corrected retained security context" in contexts


def test_old_pending_work_is_not_fresh_evidence_after_a_failed_fetch(database):
    seed(database)
    entries = "".join(
        entry(url=f"https://www.php.net/archive/2026.php#2026-10-20-{i}") for i in range(1, 103)
    )
    process = processor(registry=REGISTRY, grant_reader=lambda **_: {**GRANT, "mode": "automatic"})
    intake.run(database.engine, fetch=fetcher(body(entries)), process=process, **options())
    with Session(database.engine) as session:
        before = session.scalar(select(func.count()).select_from(BulletinCurrent))

    def unavailable(source, **kwargs):
        raise OSError("synthetic source failure")

    later = NOW + timedelta(days=1)
    intake.run(database.engine, fetch=unavailable, process=process, **options(later))
    with Session(database.engine) as session:
        assert session.scalar(select(func.count()).select_from(BulletinCurrent)) == before
        pending = session.scalars(
            select(OfficialNoticeCurrent).where(
                OfficialNoticeCurrent.source_key == "php",
                OfficialNoticeCurrent.publication_pending.is_(True),
            )
        ).all()
        assert len(pending) == 2
        assert all(row.updated_at == NOW for row in pending)
    intake.run(
        database.engine,
        fetch=fetcher(body(entries)),
        process=process,
        **options(later + timedelta(hours=1)),
    )
    with Session(database.engine) as session:
        assert session.scalar(select(func.count()).select_from(BulletinCurrent)) == before + 2


def test_source_failure_does_not_block_other_source_or_leak_exception(database):
    seed(database)

    def fail(source, **kwargs):
        if source == "php":
            raise OSError("private error content")
        return fetcher()(source, **kwargs)

    result = intake.run(database.engine, fetch=fail, **options())
    assert result["sources"][0]["state"] == "unavailable"
    assert result["sources"][1]["state"] == "fresh"
    assert "private error" not in str(result)


def test_legacy_guard_and_interrupted_intent_reconciliation(database):
    seed(database)
    assert (
        legacy.run(
            database.engine,
            enabled=lambda: True,
            now=NOW,
            fetch=lambda *a, **k: pytest.fail("legacy fetch"),
        )["status"]
        == "bulletin_intake_selected"
    )
    epoch = NOW.strftime("%Y%m%dT%H")
    with Session(database.engine) as session, session.begin():
        store.record_run(session, epoch, "intent", {"synthetic_interruption": True}, now=NOW)
    assert (
        intake.run(database.engine, fetch=lambda *a, **k: pytest.fail("replay"), **options())[
            "status"
        ]
        == "hour_consumed"
    )
    intake.run(database.engine, fetch=fetcher(), **options(NOW + timedelta(hours=1)))
    with Session(database.engine) as session:
        assert (
            session.get(OfficialIntakeRun, (epoch, "closure")).document["status"] == "interrupted"
        )


def test_backlog_pointer_is_retained_after_processing(database):
    seed(database)
    intake.run(database.engine, fetch=fetcher(), **options())
    with Session(database.engine) as session:
        pending = session.scalars(select(OfficialNoticePending)).all()
        assert len(pending) == 2 and all(v.processed_at is not None for v in pending)


def test_intake_publication_rechecks_without_hourly_revision_or_event_growth(database):
    seed(database)
    process = processor(registry=REGISTRY, grant_reader=lambda **k: {**GRANT, "mode": "automatic"})
    first = intake.run(database.engine, fetch=fetcher(), process=process, **options())
    assert first["status"] == "complete", first
    with Session(database.engine) as session:
        assert session.scalar(select(func.count()).select_from(BulletinRevision)) == 2
        assert session.scalar(select(func.count()).select_from(BulletinEvent)) == 2
    intake.run(
        database.engine, fetch=fetcher(), process=process, **options(NOW + timedelta(hours=1))
    )
    with Session(database.engine) as session:
        assert session.scalar(select(func.count()).select_from(BulletinEvent)) == 2
    intake.run(
        database.engine, fetch=fetcher(), process=process, **options(NOW + timedelta(hours=22))
    )
    with Session(database.engine) as session:
        assert session.scalar(select(func.count()).select_from(BulletinRevision)) == 2
        assert session.scalar(select(func.count()).select_from(BulletinEvent)) == 4


def test_source_outage_cannot_leave_current_bulletin_looking_fresh(database):
    seed(database)
    process = processor(registry=REGISTRY, grant_reader=lambda **k: {**GRANT, "mode": "automatic"})
    intake.run(database.engine, fetch=fetcher(), process=process, **options())

    def fail(source, **kwargs):
        if source == "php":
            raise OSError("unavailable")
        return fetcher()(source, **kwargs)

    later = NOW + timedelta(hours=1)
    intake.run(database.engine, fetch=fail, process=process, **options(later))
    with Session(database.engine) as session:
        for row in session.scalars(select(BulletinCurrent)):
            record = bulletin_store.detail(session, row.bulletin_id, now=later)
            assert record["freshness"] == ("unavailable" if row.source_key == "php" else "fresh")


def test_missing_publication_grant_preserves_intake_and_visible_pending_work(database):
    seed(database)

    def missing(**kwargs):
        raise FileNotFoundError("synthetic missing grant")

    process = processor(registry=REGISTRY, grant_reader=missing)
    result = intake.run(database.engine, fetch=fetcher(), process=process, **options())
    assert result["status"] == "degraded"
    assert all(r["reason"] == "publication_pending" for r in result["sources"])
    with Session(database.engine) as session:
        assert session.scalar(select(func.count()).select_from(OfficialNoticeCurrent)) == 2
        assert session.scalar(select(func.count()).select_from(BulletinCurrent)) == 0
        for source in ("php", "mozilla"):
            row = session.get(BulletinSourceStatus, source)
            assert row.state == "incomplete" and row.pending_count == 1


def test_date_only_rights_renewal_keeps_automatic_notice_bytes(database):
    from smithguard.source_rights import RightsRegistry

    from .test_source_rights import renewed_register

    seed(database)
    process = processor(registry=REGISTRY, grant_reader=lambda **_: {**GRANT, "mode": "automatic"})
    intake.run(database.engine, fetch=fetcher(), process=process, **options())
    with Session(database.engine) as session:
        before = {r.bulletin_id: r.content_hash for r in session.scalars(select(BulletinRevision))}
    registry = RightsRegistry(renewed_register("gbsec:source:php-security-notices"))
    later = NOW + timedelta(days=3)
    process = processor(registry=registry, grant_reader=lambda **_: {**GRANT, "mode": "automatic"})
    intake.run(database.engine, fetch=fetcher(), process=process, **options(later))
    with Session(database.engine) as session:
        rows = session.scalars(select(BulletinCurrent)).all()
        assert all(row.revision == 1 and row.verified_at == later for row in rows)
        assert {
            r.bulletin_id: r.content_hash for r in session.scalars(select(BulletinRevision))
        } == before
        assert set(session.scalars(select(BulletinEvent.kind))) == {
            "published",
            "freshness_verified",
        }
