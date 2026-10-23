"""Exact joins, corrections, atomicity and stale-context behavior."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from smithguard.db.models import SupplementalFactRecord, SupplementalSnapshotRecord
from smithguard.supplemental_store import (
    EPSS_SOURCE,
    KEV_SOURCE,
    SupplementalStoreError,
    append_snapshot,
    cve_context,
)

NOW = datetime(2026, 10, 6, 23, tzinfo=UTC)
CVE = "CVE-2021-44228"


def add(
    session, source=EPSS_SOURCE, *, facts=None, now=NOW, mode="public", state="complete", as_of=NOW
):
    return append_snapshot(
        session,
        source_id=source,
        mode=mode,
        state=state,
        observed_at=now,
        source_as_of=as_of,
        document={"source_url": "https://www.first.org/epss/"},
        facts=facts
        if facts is not None
        else {
            CVE: {
                "epss": "0.9",
                "percentile": "0.99",
                "score_date": "2026-10-06",
                "model_version": None,
            }
        },
    )


def test_exact_join_missing_is_not_zero_and_shadow_is_not_public(database):
    with Session(database.engine) as session, session.begin():
        add(session, mode="shadow")
        context, _ = cve_context(session, [CVE], now=NOW)
        assert context[0]["epss"]["state"] == "missing"
        assert context[0]["epss"]["value"] is None
        add(session)
        add(session, KEV_SOURCE, facts={CVE: {"date_added": "2021-12-10"}})
        context, _ = cve_context(session, [CVE, "CVE-2021-44229", "CVE-2021-44228-extra"], now=NOW)
        assert [x["cve"] for x in context] == [CVE, "CVE-2021-44229"]
        assert context[0]["epss"]["value"]["epss"] == "0.9"
        assert context[0]["kev"]["listed"] is True
        assert context[1]["kev"]["listed"] is False
        assert context[1]["epss"]["value"] is None


def test_new_complete_snapshot_removes_old_membership_and_changes_fingerprint(database):
    with Session(database.engine) as session, session.begin():
        first = add(session, KEV_SOURCE, facts={CVE: {"date_added": "2021-12-10"}})
        _, before = cve_context(session, [CVE], now=NOW)
        add(session, KEV_SOURCE, facts={}, now=NOW + timedelta(minutes=1))
        result, after = cve_context(session, [CVE], now=NOW + timedelta(minutes=1))
        assert result[0]["kev"]["listed"] is False
        assert before != after
        assert session.get(SupplementalFactRecord, (first.snapshot_id, CVE)) is not None


def test_failed_attempt_preserves_last_good_with_failed_label(database):
    with Session(database.engine) as session, session.begin():
        add(session)
        _, before = cve_context(session, [CVE], now=NOW)
        add(session, facts={}, state="failed", now=NOW + timedelta(minutes=1), as_of=None)
        result, after = cve_context(session, [CVE], now=NOW + timedelta(minutes=1))
        assert result[0]["epss"]["state"] == "failed"
        assert result[0]["epss"]["value"]["epss"] == "0.9"
        assert before != after


def test_old_score_cannot_be_refreshed_by_new_download(database):
    with Session(database.engine) as session, session.begin():
        add(session, as_of=NOW - timedelta(days=3))
        result, _ = cve_context(session, [CVE], now=NOW)
        assert result[0]["epss"]["state"] == "stale"


def test_stale_fetch_and_backwards_clock_are_not_fresh(database):
    with Session(database.engine) as session, session.begin():
        add(session)
        for now in (NOW + timedelta(hours=31), NOW - timedelta(seconds=1)):
            result, _ = cve_context(session, [CVE], now=now)
            assert result[0]["epss"]["state"] == "stale"


def test_rollback_does_not_leave_partial_snapshot(database):
    with Session(database.engine) as session:
        add(session)
        session.rollback()
        assert list(session.scalars(select(SupplementalSnapshotRecord))) == []
        assert list(session.scalars(select(SupplementalFactRecord))) == []


@pytest.mark.parametrize(
    "changes",
    [
        {"facts": {"CVE-2021-1": {}}},
        {"state": "failed"},
        {"as_of": NOW + timedelta(hours=1)},
        {"mode": "unknown"},
    ],
)
def test_invalid_snapshot_refused_before_append(database, changes):
    with Session(database.engine) as session, session.begin():
        with pytest.raises(SupplementalStoreError):
            add(session, **changes)
        assert list(session.scalars(select(SupplementalSnapshotRecord))) == []


def test_batched_receipts_keep_latest_attempt_and_complete_in_one_statement(database):
    from sqlalchemy import event

    from smithguard.supplemental_store import (
        GO_SOURCE,
        RUST_SOURCE,
        SOURCE_NAMES,
        load_latest_receipts,
        source_state,
    )

    with Session(database.engine) as session, session.begin():
        initial = add(session)
        failed = add(session, state="failed", facts={}, now=NOW + timedelta(minutes=1), as_of=None)
        recovered = add(session, KEV_SOURCE, facts={}, now=NOW + timedelta(minutes=2))
        add(session, KEV_SOURCE, facts={}, state="failed", now=NOW + timedelta(minutes=3))
        newest = add(session, KEV_SOURCE, facts={}, now=NOW + timedelta(minutes=4))
        add(session, RUST_SOURCE, facts={}, mode="shadow", now=NOW + timedelta(minutes=5))
        statements = []

        def count(*args):
            statements.append(args[2])

        event.listen(database.engine, "before_cursor_execute", count)
        try:
            receipts = load_latest_receipts(session)
            for source in SOURCE_NAMES:
                source_state(session, source, now=NOW + timedelta(minutes=5), receipts=receipts)
        finally:
            event.remove(database.engine, "before_cursor_execute", count)
        assert len(statements) == 1
        assert receipts[EPSS_SOURCE].attempt.snapshot_id == failed.snapshot_id
        assert receipts[EPSS_SOURCE].complete.snapshot_id == initial.snapshot_id
        assert source_state(session, EPSS_SOURCE, now=NOW, receipts=receipts)[0] == "failed"
        assert receipts[KEV_SOURCE].attempt.snapshot_id == newest.snapshot_id
        assert receipts[KEV_SOURCE].complete.snapshot_id == newest.snapshot_id
        assert receipts[KEV_SOURCE].complete.snapshot_id != recovered.snapshot_id
        assert receipts[RUST_SOURCE].attempt is None
        assert receipts[GO_SOURCE].complete is None
        assert source_state(session, RUST_SOURCE, now=NOW, receipts=receipts) == ("missing", None)
        with pytest.raises(SupplementalStoreError, match="absent"):
            source_state(session, EPSS_SOURCE, now=NOW, receipts={})
        with pytest.raises(SupplementalStoreError, match="identity"):
            load_latest_receipts(session, ["gbsec:source:unknown"])


def test_batched_context_keeps_fingerprint_and_sees_committed_failure_immediately(database):
    from sqlalchemy import event

    from smithguard.identifiers import stable_id
    from smithguard.supplemental_store import load_latest_receipts

    with Session(database.engine) as session, session.begin():
        good_hash = add(session).record_hash
    with Session(database.engine) as session:
        before, fingerprint = cve_context(session, [CVE], now=NOW)
        receipts = load_latest_receipts(session)
        expected = stable_id(
            "cve-context",
            [
                (EPSS_SOURCE, "fresh", good_hash, good_hash),
                (KEV_SOURCE, "missing", None, None),
            ],
        )
        assert fingerprint == expected
        assert receipts[EPSS_SOURCE].complete.record_hash == good_hash
    with Session(database.engine) as session, session.begin():
        bad_hash = add(
            session, state="failed", facts={}, now=NOW + timedelta(minutes=1), as_of=None
        ).record_hash
    statements = []

    def count(*args):
        statements.append(args[2])

    event.listen(database.engine, "before_cursor_execute", count)
    try:
        with Session(database.engine) as session:
            after, fingerprint = cve_context(session, [CVE], now=NOW + timedelta(minutes=1))
    finally:
        event.remove(database.engine, "before_cursor_execute", count)
    assert len(statements) == 2  # One receipt batch and the exact last-good EPSS facts.
    assert after[0]["epss"]["state"] == "failed"
    assert after[0]["epss"]["value"] == before[0]["epss"]["value"]
    assert fingerprint == stable_id(
        "cve-context",
        [
            (EPSS_SOURCE, "failed", bad_hash, good_hash),
            (KEV_SOURCE, "missing", None, None),
        ],
    )


def test_supplemental_coverage_is_one_query_and_appended_after_legacy_lanes(database):
    from sqlalchemy import event

    from smithguard.coverage import _build_coverage_report, _supplemental_coverage_lanes
    from smithguard.supplemental_store import SOURCE_NAMES

    with Session(database.engine) as session:
        statements = []

        def count(*args):
            statements.append(args[2])

        event.listen(database.engine, "before_cursor_execute", count)
        try:
            lanes = _supplemental_coverage_lanes(session, measured_at=NOW)
        finally:
            event.remove(database.engine, "before_cursor_execute", count)
        assert len(statements) == 1
        assert [lane.source_id for lane in lanes] == list(SOURCE_NAMES)
        report = _build_coverage_report(session, measured_at=NOW)
        assert all(lane.source_id not in SOURCE_NAMES for lane in report.source_lanes[:7])
        assert [lane.source_id for lane in report.source_lanes[7:]] == list(SOURCE_NAMES)


@pytest.mark.parametrize("fault", ["failed", "shadow", "other-source", "absent"])
def test_missing_score_inspection_refuses_wrong_snapshot(database, fault):
    from smithguard.source_accounting import epss_missing

    with Session(database.engine) as session, session.begin():
        snapshot = add(
            session,
            source=KEV_SOURCE if fault == "other-source" else EPSS_SOURCE,
            state="failed" if fault == "failed" else "complete",
            mode="shadow" if fault == "shadow" else "public",
            facts={},
        )
        selected = (
            snapshot.snapshot_id if fault != "absent" else "gbsec:supplemental-snapshot:" + "f" * 40
        )
        with pytest.raises(ValueError, match="unavailable"):
            epss_missing(session, snapshot_id=selected)


def test_missing_score_inspection_does_not_claim_legacy_subject_inventory(database):
    from smithguard.source_accounting import epss_missing

    with Session(database.engine) as session, session.begin():
        snapshot = add(session)
        report = epss_missing(session, snapshot_id=snapshot.snapshot_id)
        assert report["identity_accounting"] == "unavailable_legacy_receipt"
        assert report["subjects"] == []
        assert report["missing_count"] is None
