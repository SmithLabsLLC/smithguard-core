from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

import smithguard.official_notice_coordinator as m
from smithguard.db.models import JobRecord
from smithguard.official_notice_fetch import FetchResult
from smithguard.official_notice_store import QUEUE

ROOT = Path(__file__).parent / "fixtures" / "social-security"
NOW = datetime(2026, 10, 21, 6, tzinfo=UTC)
BODIES = {
    "php": (ROOT / "php-feed.xml").read_bytes(),
    "mozilla": (ROOT / "mozilla-feed.xml").read_bytes(),
}


def options(at=NOW):
    def project(session, lead, withdrawn, now):
        assert lead["provenance_kind"] == "official_announcement"
        assert lead["artifact_applicability"] == "unknown"
        return {"state": "test_projection_only"}

    return {
        "enabled": lambda: True,
        "now": at,
        "observe_clock": lambda: at + timedelta(seconds=1),
        "project_lead": project,
        "artifact_commit": "a" * 40,
        "invocation_id": "b" * 32,
    }


def test_hour_consumed_after_success_no_repeated_fetch(database):
    calls = []

    def fetch(source, **kwargs):
        calls.append(source)
        return FetchResult(200, BODIES[source], '"cursor"', None, "a" * 64)

    result = m.run(database.engine, fetch=fetch, **options())
    assert result["status"] == "complete" and result["network_attempts"] == 2
    assert set(calls) == {"php", "mozilla"}
    assert (
        m.run(
            database.engine,
            fetch=lambda *a, **k: pytest.fail("repeat"),
            **{**options(NOW + timedelta(minutes=2)), "invocation_id": "c" * 32},
        )["status"]
        == "hour_consumed"
    )
    with Session(database.engine) as session:
        rows = list(session.scalars(select(JobRecord).where(JobRecord.queue == QUEUE)))
        assert [row for row in rows if row.payload["kind"] == "available"]
        assert len([row for row in rows if row.payload["kind"] == "notice"]) == 2
        assert (
            session.scalar(
                select(func.count())
                .select_from(JobRecord)
                .where(JobRecord.queue != "official-notice-receipts")
            )
            == 0
        )


def test_one_source_failure_keeps_other_source(database):
    def fetch(source, **kwargs):
        if source == "php":
            raise OSError("private diagnostic must not be retained")
        return FetchResult(200, BODIES[source], None, None, "b" * 64)

    result = m.run(database.engine, fetch=fetch, **options())
    assert result["status"] == "degraded" and result["network_attempts"] == 2
    assert [r["outcome"] for r in result["sources"]] == ["failed", "success"]
    assert result["sources"][0]["reason"] == "OSError"


def test_interrupted_projection_cannot_replay_same_hour(database):
    calls = []

    def fetch(source, **kwargs):
        calls.append(source)
        return FetchResult(200, BODIES[source], None, None, "a" * 64)

    values = options()

    def fail(*a, **k):
        raise RuntimeError("projection transaction fails")

    values["project_lead"] = fail
    with pytest.raises(RuntimeError, match="projection transaction"):
        m.run(database.engine, fetch=fetch, **values)
    assert calls == ["php"]
    assert (
        m.run(database.engine, fetch=lambda *a, **k: pytest.fail("repeat"), **options())["status"]
        == "hour_consumed"
    )
    with Session(database.engine) as session:
        rows = list(session.scalars(select(JobRecord).where(JobRecord.queue == QUEUE)))
        assert len(rows) == 1 and rows[0].payload["kind"] == "started"


def test_paused_and_capacity_paths_do_not_fetch(database, monkeypatch):
    values = options()
    values["enabled"] = lambda: False
    assert (
        m.run(database.engine, fetch=lambda *a, **k: pytest.fail("fetch"), **values)["status"]
        == "paused"
    )
    monkeypatch.setattr(m, "all_count", lambda s: m.MAX_RECORDS)
    assert (
        m.run(database.engine, fetch=lambda *a, **k: pytest.fail("fetch"), **options())["status"]
        == "storage_budget_paused"
    )


def test_advisory_lock_serializes_manual_and_scheduled_runs(database):
    with database.engine.connect() as connection:
        connection.execute(select(func.pg_advisory_lock(func.hashtextextended(m.LOCK_NAME, 0))))
        connection.commit()
        try:
            assert (
                m.run(database.engine, fetch=lambda *a, **k: pytest.fail("fetch"), **options())[
                    "status"
                ]
                == "busy"
            )
        finally:
            connection.execute(
                select(func.pg_advisory_unlock(func.hashtextextended(m.LOCK_NAME, 0)))
            )
            connection.commit()


def test_three_failures_back_off_without_losing_failure_history(database):
    def fail(*a, **k):
        raise OSError()

    for hour in range(3):
        result = m.run(database.engine, fetch=fail, **options(NOW + timedelta(hours=hour)))
        assert result["network_attempts"] == 2
    for hour in (3, 4, 5, 6, 7):
        result = m.run(
            database.engine,
            fetch=lambda *a, **k: pytest.fail("cooldown fetch"),
            **options(NOW + timedelta(hours=hour)),
        )
        assert result["network_attempts"] == 0 and all(
            r["outcome"] == "cooldown" for r in result["sources"]
        )
    # Six full hours after the last failed completion; no immediate retry.
    result = m.run(database.engine, fetch=fail, **options(NOW + timedelta(hours=9)))
    assert result["network_attempts"] == 2


def test_explicit_stop_between_sources_blocks_second_fetch(database):
    calls = []

    def enabled():
        return len(calls) == 0

    def fetch(source, **kwargs):
        calls.append(source)
        return FetchResult(200, BODIES[source], None, None, "a" * 64)

    values = options()
    values["enabled"] = enabled
    result = m.run(database.engine, fetch=fetch, **values)
    assert result["network_attempts"] == 1 and result["sources"][1]["outcome"] == "paused"


def test_global_cap_defers_cursor_and_rotating_order_does_not_lose_tail(database):
    from smithguard.official_notice_store import cursor, known_notices
    from tests.test_official_notice_parser import entry, feed

    php = feed(
        "".join(
            entry(url=f"https://www.php.net/archive/2026.php#2026-10-20-{n}") for n in range(1, 6)
        )
    )
    calls = []

    def fetch(source, **kwargs):
        calls.append((source, kwargs))
        return FetchResult(
            200, php if source == "php" else BODIES["mozilla"], '"etag"', None, "a" * 64
        )

    first = m.run(database.engine, fetch=fetch, **options())
    assert first["status"] == "degraded"
    assert sum(sum(row["accepted"].values()) for row in first["sources"]) == 4
    with Session(database.engine) as session:
        assert cursor(session, "php")["etag"] is None
        assert cursor(session, "mozilla")["etag"] is None
        assert len(known_notices(session, "php")) == 4
    second = m.run(database.engine, fetch=fetch, **options(NOW + timedelta(hours=1)))
    assert second["status"] == "complete"
    assert [row["source"] for row in second["sources"]] == ["mozilla", "php"]
    assert sum(sum(row["accepted"].values()) for row in second["sources"]) == 2
    with Session(database.engine) as session:
        assert len(known_notices(session, "php")) == 5
        assert cursor(session, "php")["etag"] == '"etag"'
        assert cursor(session, "mozilla")["etag"] == '"etag"'
    assert all(kwargs["etag"] is None for _, kwargs in calls)


def test_not_modified_keeps_no_new_notice_or_availability_claims(database):
    first = m.run(
        database.engine,
        fetch=lambda source, **kw: FetchResult(200, BODIES[source], '"etag"', None, "a" * 64),
        **options(),
    )
    assert first["status"] == "complete"

    def unchanged(source, **kw):
        assert kw["etag"] == '"etag"'
        return FetchResult(304, b"", kw["etag"], None, None)

    second = m.run(database.engine, fetch=unchanged, **options(NOW + timedelta(hours=1)))
    assert second["status"] == "complete"
    assert all(
        row["outcome"] == "not_modified" and sum(row["accepted"].values()) == 0
        for row in second["sources"]
    )
    with Session(database.engine) as session:
        assert (
            session.scalar(
                select(func.count())
                .select_from(JobRecord)
                .where(JobRecord.queue == QUEUE, JobRecord.payload["kind"].as_string() == "notice")
            )
            == 2
        )
        from smithguard.official_notice_store import status

        current = status(session, now=NOW + timedelta(hours=1, seconds=2))
        assert current["sources"]["php"]["parser"]["feed_entries"] > 0
        assert current["sources"]["php"]["observation_gap_seconds"] == 3600


def test_last_identity_slot_is_used_without_counting_a_fetch_failure(database, monkeypatch):
    from smithguard.official_notice_store import known_notices, status
    from tests.test_official_notice_parser import entry, feed

    monkeypatch.setattr(m, "MAX_KNOWN", 1)
    php = feed(entry() + entry(url="https://www.php.net/archive/2026.php#2026-10-20-2"))
    result = m.run(
        database.engine,
        fetch=lambda source, **kw: FetchResult(
            200, php if source == "php" else BODIES[source], '"etag"', None, "a" * 64
        ),
        **options(),
    )
    assert result["status"] == "degraded"
    assert [row["outcome"] for row in result["sources"]] == ["identity_budget", "identity_budget"]
    with Session(database.engine) as session:
        assert len(known_notices(session, "php")) == 1
        assert len(known_notices(session, "mozilla")) == 0
        assert not m.cooling_down(session, "php", NOW)
        measured = status(session, now=NOW + timedelta(seconds=2))
        assert measured["sources"]["php"]["degradation_reason"] == "identity_budget"
