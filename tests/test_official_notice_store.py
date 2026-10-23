from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

import smithguard.official_notice_store as m
from smithguard.official_notice_parser import Notice

NOW = datetime(2026, 10, 21, 6, tzinfo=UTC)
URL = "https://www.php.net/archive/2026.php#2026-10-20-1"
N = Notice(
    "php",
    URL,
    "Security advance notice",
    "Two vulnerabilities will be fixed.",
    NOW - timedelta(hours=10),
    NOW - timedelta(hours=10),
    False,
    "a" * 64,
)


def test_receipts_append_without_payload_changes(database):
    with Session(database.engine) as session, session.begin():
        r = m.receipt(
            session,
            identity="hour-start",
            kind="started",
            now=NOW,
            data={"run_id": "2026-10-21T06"},
        )
        before = r.payload_hash
        repeated = m.receipt(
            session,
            identity="hour-start",
            kind="started",
            now=NOW,
            data={"run_id": "2026-10-21T06"},
        )
        assert repeated.job_id == r.job_id and repeated.payload_hash == before
        assert m.all_count(session) == 1 and m.started_hour(session, "2026-10-21T06")


def test_failed_fetch_does_not_advance_cursor(database):
    with Session(database.engine) as session, session.begin():
        m.receipt(
            session,
            identity="success",
            kind="fetch",
            now=NOW,
            data={"source": "php", "cursor_committed": True, "etag": "old", "modified": None},
        )
        m.receipt(
            session,
            identity="failure",
            kind="fetch",
            now=NOW + timedelta(hours=1),
            data={"source": "php", "cursor_committed": False, "etag": "new", "modified": None},
        )
        assert m.cursor(session, "php") == {"etag": "old", "modified": None}
        assert len(m.latest_fetches(session, "php")) == 2


def test_changed_entry_history_and_latest_view(database):
    a = m.notice_document(N)
    b = m.notice_document(replace(N, context="Publisher correction.", entry_sha256="b" * 64))
    with Session(database.engine) as session, session.begin():
        old = m.receipt(
            session,
            identity="n1",
            kind="notice",
            now=NOW,
            data={**a, "semantic_sha256": m.semantic_hash(a)},
        )
        before = dict(old.payload)
        m.receipt(
            session,
            identity="n2",
            kind="notice",
            now=NOW + timedelta(hours=1),
            data={**b, "semantic_sha256": m.semantic_hash(b)},
        )
        known = m.known_notices(session, "php")
        assert len(known) == 1 and known[URL]["context"] == "Publisher correction."
        assert old.payload == before and m.all_count(session) == 2


def test_notice_identity_does_not_depend_on_corrected_wording():
    a = m.candidate(m.notice_document(N), NOW)
    b = m.candidate(m.notice_document(replace(N, title="Correction to security notice")), NOW)
    c = m.candidate(m.notice_document(replace(N, url=URL[:-1] + "2")), NOW)
    assert a["lead_id"] == b["lead_id"] and a["lead_id"] != c["lead_id"]
    assert a["provenance_kind"] == "official_announcement"
    assert a["artifact_applicability"] == "unknown"


def test_hash_change_without_semantic_change_is_duplicate():
    a = m.notice_document(N)
    known = {URL: {**a, "semantic_sha256": m.semantic_hash(a)}}
    plan = m.notice_changes([replace(N, entry_sha256="b" * 64)], known, 4)
    assert plan["changes"] == [] and plan["unchanged"] == 1 and not plan["overflow"]


def test_four_change_cap_reports_pending_tail():
    notices = [replace(N, url=URL[:-1] + str(i)) for i in range(1, 7)]
    plan = m.notice_changes(notices, {}, 4)
    assert len(plan["changes"]) == 4 and plan["overflow"] and plan["unprocessed"] == 2


def test_receipt_body_bound(database):
    with Session(database.engine) as session, session.begin():
        with pytest.raises(ValueError, match="official_receipt_bytes"):
            m.receipt(
                session,
                identity="large",
                kind="notice",
                now=NOW,
                data={"context": "x" * m.MAX_RECORD_BYTES},
            )
        assert m.all_count(session) == 0
