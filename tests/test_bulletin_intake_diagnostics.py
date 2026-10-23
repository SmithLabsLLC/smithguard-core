"""Failures survive cooldown, escalate, stay private, and clear only after real success."""

from dataclasses import replace
from datetime import timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from smithguard import bulletin_automation as automation
from smithguard import bulletin_intake_store as store
from smithguard import bulletin_store
from smithguard.bulletin_contract import BulletinError
from smithguard.bulletin_intake_diagnostics import category, record_failure
from smithguard.bulletin_intake_parser import parse_complete
from smithguard.bulletin_review import queue
from smithguard.bulletin_source_parser import parse_index, publisher_detail
from smithguard.db.bulletin_models import (
    BulletinCurrent,
    BulletinDecision,
    BulletinEvent,
    BulletinMaintenanceReceipt,
    OfficialNoticeCurrent,
    OfficialNoticeEvidence,
    OfficialNoticePending,
)
from smithguard.identifiers import sha256_id
from smithguard.official_notice_fetch import FetchResult
from tests.test_bulletin_automation import (
    MOZILLA_DETAIL,
    MOZILLA_INDEX,
    NOW,
    REGISTRY,
    URL,
    fetcher,
    rss,
    run,
)
from tests.test_official_notice_parser import entry, feed


@pytest.mark.parametrize(
    "error,phase,expected",
    [
        (TimeoutError("private text"), "fetch", "timeout"),
        (BulletinError("cisco_detail_dates"), "parse", "source_dates"),
        (BulletinError("bulletin_network_budget"), "fetch", "budget"),
        (BulletinError("bulletin_detail_http"), "fetch", "http_status"),
        (ValueError("arbitrary_secret_looking_text"), "parse", "source_shape"),
        (ValueError("arbitrary_secret_looking_text"), "other", "unknown"),
    ],
)
def test_closed_error_categories(error, phase, expected):
    assert category(error, phase=phase) == expected


def test_cooldown_escalation_and_recovery_keep_immutable_failure_evidence(database):
    calls = []

    def fetch(source, **kw):
        if kw.get("url"):
            calls.append(kw["url"])
            raise TimeoutError("do not store this upstream prose or credentials")
        return fetcher(MOZILLA_INDEX)()

    for hour in (0, 1, 6, 12):
        run(database, source="mozilla-mfsa", now=NOW + timedelta(hours=hour), fetch=fetch)
    assert len(calls) == 3
    with Session(database.engine) as session:
        result = queue(session, now=NOW + timedelta(hours=12))["detail_failures"]
        assert result["pending"] == 1
        row = result["items"][0]
        assert row["consecutive_failures"] == 3 and row["escalated"]
        assert row["category"] == "timeout" and row["age_seconds"] == 12 * 3600
        receipts = list(session.scalars(select(BulletinMaintenanceReceipt)))
        failures = [
            r.document for r in receipts if r.document["kind"] == "detail_qualification_failure"
        ]
        assert len(failures) == 3
        assert "upstream prose" not in str(failures)
    run(
        database,
        source="mozilla-mfsa",
        now=NOW + timedelta(hours=18),
        fetch=lambda source, **kw: fetcher(MOZILLA_DETAIL if kw.get("url") else MOZILLA_INDEX)(),
    )
    with Session(database.engine) as session:
        pending = session.scalar(select(OfficialNoticePending))
        assert pending.failure_count == 0 and pending.failure_category is None
        assert queue(session)["detail_failures"]["pending"] == 0
        remaining = [
            r.document
            for r in session.scalars(select(BulletinMaintenanceReceipt))
            if r.document["kind"] == "detail_qualification_failure"
        ]
        assert remaining == failures


def test_full_storage_preserves_cooldown_staleness_and_continues_details(database, monkeypatch):
    run(database)
    observed = NOW + timedelta(hours=22)
    with Session(database.engine) as session, session.begin():
        candidates = parse_index("ubuntu-usn", rss(), now=observed) + parse_index(
            "ubuntu-usn", rss(URL.replace("9000", "9001")), now=observed
        )
        automation.stage(
            session,
            "ubuntu-usn",
            candidates,
            now=observed,
            baseline=NOW - timedelta(days=14),
        )
        published = session.scalar(select(BulletinCurrent))
        identity, revision, verified_at = (
            published.bulletin_id,
            published.revision,
            published.verified_at,
        )
        evidence_count = session.scalar(select(func.count()).select_from(OfficialNoticeEvidence))
        receipt_count = session.scalar(select(func.count()).select_from(BulletinMaintenanceReceipt))
        decision_count = session.scalar(select(func.count()).select_from(BulletinDecision))
        event_count = session.scalar(select(func.count()).select_from(BulletinEvent))

    # Exhaust the admission budget while retaining its reserved transaction room
    # for bounded bookkeeping and the one neutral stale transition.
    monkeypatch.setattr(
        bulletin_store,
        "allocated_bytes",
        lambda session: bulletin_store.MAX_ADDITIONAL_BYTES - 256 * 1024 + 1,
    )
    calls = []

    def fetch(source, *, url):
        calls.append(url)
        record_id = url.rsplit("/", 1)[-1]
        body = (
            f'<link rel="canonical" href="{url}"><main><h1>{record_id}: synthetic</h1>'
            "<p>CVE-2026-12345</p></main>"
        ).encode()
        return FetchResult(200, body, None, None, sha256_id(body))

    for hour in (0, 1, 6):
        now = observed + timedelta(hours=hour)
        with database.engine.connect() as connection:
            result = automation.qualify_details(
                connection,
                "ubuntu-usn",
                now=now,
                fetch=fetch,
                registry=REGISTRY,
                enabled=lambda: True,
            )
        expected = 0 if hour == 1 else 2
        assert result == {
            "attempted": expected,
            "failed": expected,
            "failure_categories": {"storage": 2} if expected else {},
        }
        with Session(database.engine) as session:
            pending = session.scalars(select(OfficialNoticePending)).all()
            assert len(pending) == 2
            for row in pending:
                assert row.failure_count == (1 if hour < 6 else 2)
                assert row.failure_category == "storage"
                assert row.first_failure_at == observed
                assert row.last_failure_at == observed + timedelta(hours=0 if hour < 6 else 6)
                assert row.next_attempt_at == observed + timedelta(hours=6 if hour < 6 else 12)
                assert row.qualification_required and row.processed_at is None
            published = session.get(BulletinCurrent, identity)
            assert published.freshness_reason == "verification_pending"
            assert published.revision == revision and published.verified_at == verified_at
            assert bulletin_store.detail(session, identity, now=now)["freshness"] == "stale"
            assert (
                session.scalar(select(func.count()).select_from(OfficialNoticeEvidence))
                == evidence_count
            )
            assert (
                session.scalar(select(func.count()).select_from(BulletinMaintenanceReceipt))
                == receipt_count
            )
            # One neutral transition is retained; repeated failures append nothing.
            assert (
                session.scalar(select(func.count()).select_from(BulletinDecision))
                == decision_count + 1
            )
            assert (
                session.scalar(select(func.count()).select_from(BulletinEvent)) == event_count + 1
            )
    assert len(calls) == 4 and set(calls) == {candidate.url for candidate in candidates}


@pytest.mark.parametrize("restaging", ["processed", "qualified", "continuing"])
def test_restage_resets_only_completed_or_no_detail_failure_lifecycle(database, restaging):
    observed = NOW + timedelta(hours=13)
    candidate = parse_index("mozilla-mfsa", MOZILLA_INDEX, now=NOW)[0]
    with Session(database.engine) as session, session.begin():
        automation.stage(
            session, "mozilla-mfsa", [candidate], now=NOW, baseline=NOW - timedelta(days=14)
        )
        pending = session.scalar(select(OfficialNoticePending))
        for hour in (0, 6, 12):
            record_failure(session, pending, now=NOW + timedelta(hours=hour), category="timeout")
        session.flush()
        failures = [row.document for row in session.scalars(select(BulletinMaintenanceReceipt))]
        assert len(failures) == 3
        if restaging == "processed":
            pending.processed_at = NOW + timedelta(hours=12)
        elif restaging == "qualified":
            candidate = publisher_detail(candidate, MOZILLA_DETAIL, now=observed)
        automation.stage(
            session,
            "mozilla-mfsa",
            [candidate],
            now=observed,
            baseline=NOW - timedelta(days=14),
        )

    with Session(database.engine) as session:
        pending = session.scalar(select(OfficialNoticePending))
        result = queue(session, now=observed)["detail_failures"]
        if restaging == "continuing":
            assert pending.failure_count == 3 and pending.failure_category == "timeout"
            assert pending.first_failure_at == NOW
            assert pending.last_failure_at == NOW + timedelta(hours=12)
            assert pending.next_attempt_at == NOW + timedelta(hours=18)
            assert result["pending"] == 1 and result["items"][0]["escalated"]
        else:
            assert pending.failure_count == 0 and pending.failure_category is None
            assert pending.first_failure_at is None and pending.last_failure_at is None
            assert pending.next_attempt_at is None
            assert result["pending"] == 0
        assert pending.qualification_required is (restaging != "qualified")
        assert pending.processed_at is None
        assert [r.document for r in session.scalars(select(BulletinMaintenanceReceipt))] == failures

    def fail(*args, **kwargs):
        raise TimeoutError("new detail attempt")

    later = observed + timedelta(hours=6)
    with database.engine.connect() as connection:
        result = automation.qualify_details(
            connection,
            "mozilla-mfsa",
            now=later,
            fetch=fail,
            registry=REGISTRY,
            enabled=lambda: True,
        )
    assert result["attempted"] == (0 if restaging == "qualified" else 1)
    with Session(database.engine) as session:
        pending = session.scalar(select(OfficialNoticePending))
        if restaging == "processed":
            assert pending.failure_count == 1 and pending.first_failure_at == later
            assert not queue(session, now=later)["detail_failures"]["items"][0]["escalated"]
        elif restaging == "continuing":
            assert pending.failure_count == 4 and pending.first_failure_at == NOW
        else:
            assert pending.failure_count == 0


@pytest.mark.parametrize("restaging", ["processed", "changed", "unchanged", "reverted"])
def test_legacy_feed_restage_clears_obsolete_detail_failures(database, restaging):
    observed = NOW + timedelta(hours=13)
    notices = parse_complete("php", feed(), now=NOW)
    with Session(database.engine) as session, session.begin():
        store.stage(session, "php", notices, now=NOW, baseline=NOW - timedelta(days=14))
        if restaging == "reverted":
            store.drain(session, "php", now=NOW, process=lambda *args, **kwargs: True)
        pending = session.scalar(select(OfficialNoticePending))
        # Model retained diagnostic state from an older work slot/path.
        pending.qualification_required = True
        pending.processed_at = NOW if restaging == "processed" else None
        for hour in (0, 6, 12):
            record_failure(session, pending, now=NOW + timedelta(hours=hour), category="timeout")
        session.flush()
        failures = [row.document for row in session.scalars(select(BulletinMaintenanceReceipt))]
        if restaging == "changed":
            notices = parse_complete(
                "php", feed(entry(content="A corrected official security notice.")), now=observed
            )
        store.stage(session, "php", notices, now=observed, baseline=NOW - timedelta(days=14))

    with Session(database.engine) as session:
        pending = session.scalar(select(OfficialNoticePending))
        assert pending.failure_count == 0 and pending.failure_category is None
        assert pending.first_failure_at is None and pending.last_failure_at is None
        assert not pending.qualification_required and pending.next_attempt_at is None
        assert queue(session, now=observed)["detail_failures"]["pending"] == 0
        assert [r.document for r in session.scalars(select(BulletinMaintenanceReceipt))] == failures


def test_reversion_to_accepted_facts_cannot_drain_old_unqualified_evidence(database):
    run(
        database,
        source="mozilla-mfsa",
        fetch=lambda source, **kw: fetcher(MOZILLA_DETAIL if kw.get("url") else MOZILLA_INDEX)(),
    )
    observed = NOW + timedelta(hours=1)
    candidate = parse_index("mozilla-mfsa", MOZILLA_INDEX, now=observed)[0]
    changed = replace(
        candidate, facts={**candidate.facts, "index_hash": sha256_id(b"changed index")}
    )
    with Session(database.engine) as session, session.begin():
        automation.stage(
            session,
            "mozilla-mfsa",
            [changed],
            now=observed,
            baseline=NOW - timedelta(days=14),
        )
        pending = session.scalar(select(OfficialNoticePending))
        old_evidence_id = pending.evidence_id
        old_document = session.get(OfficialNoticeEvidence, old_evidence_id).document
        assert old_document["document"]["needs_detail"] is True
        record_failure(session, pending, now=observed, category="timeout")
        accepted = publisher_detail(candidate, MOZILLA_DETAIL, now=observed)
        automation.stage(
            session,
            "mozilla-mfsa",
            [accepted],
            now=observed,
            baseline=NOW - timedelta(days=14),
        )

    def unexpected(*args, **kwargs):
        pytest.fail("completed reverted work must not be fetched or published")

    with database.engine.connect() as connection:
        result = automation.qualify_details(
            connection,
            "mozilla-mfsa",
            now=observed + timedelta(hours=6),
            fetch=unexpected,
            registry=REGISTRY,
            enabled=lambda: True,
        )
    assert result["attempted"] == 0
    with Session(database.engine) as session, session.begin():
        assert automation.drain_qualified(
            session, "mozilla-mfsa", now=observed, process=unexpected
        ) == {"new": 0, "corrected": 0, "withdrawn": 0, "recheck": 0}
        pending = session.scalar(select(OfficialNoticePending))
        assert pending.processed_at == observed
        assert pending.failure_count == 0 and pending.first_failure_at is None
        assert pending.evidence_id == old_evidence_id
        assert session.get(OfficialNoticeEvidence, old_evidence_id).document == old_document
        current = session.scalar(select(OfficialNoticeCurrent))
        assert current.document["document"]["needs_detail"] is False
        assert session.scalar(select(BulletinCurrent)).revision == 1
