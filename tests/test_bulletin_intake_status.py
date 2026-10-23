"""Deployment proves actual compact closures, never a successful unit exit alone."""

import json
from copy import deepcopy
from datetime import timedelta

import pytest
from sqlalchemy import text

from smithguard import bulletin_intake as intake
from smithguard.bulletin_contract import BulletinError
from smithguard.bulletin_intake_status import STATUS_SQL, verified_result
from tests.test_bulletin_intake import NOW, fetcher, options, seed


def test_health_distinguishes_never_activated_from_publication_pause(database):
    from sqlalchemy.orm import Session

    from smithguard.bulletin_intake_status import health
    from smithguard.db.bulletin_models import BulletinStream

    with Session(database.engine) as session, session.begin():
        assert health(session, now=NOW) == "paused"
        stream = BulletinStream(stream_id="v1", mode="paused", sequence=0, created_at=NOW)
        session.add(stream)
        session.flush()
        assert health(session, now=NOW) == "paused"
        stream.grant_hash = "sha256:" + "a" * 64
        assert health(session, now=NOW) == "publication_paused"


def test_selected_source_is_bound_and_excluded_feed_is_never_fetched(database, monkeypatch):
    from sqlalchemy.orm import Session

    from smithguard.db.bulletin_models import BulletinSourceStatus

    seed(database)
    calls = []
    monkeypatch.setattr(intake, "clock", lambda: NOW + timedelta(seconds=1))
    outcome = intake.run(
        database.engine, fetch=fetcher(calls=calls), source_keys=("php",), **options()
    )
    assert [call[0] for call in calls] == ["php"]
    with database.engine.connect() as conn:
        rows = json.loads(conn.scalar(text(STATUS_SQL)))
    result = verified_result(
        outcome,
        rows,
        now=NOW + timedelta(seconds=2),
        invocation_id="b" * 32,
        artifact_commit="a" * 40,
        source_keys=("php",),
    )
    assert result["status"] == "complete" and len(result["sources"]) == 1
    with pytest.raises(BulletinError):
        verified_result(
            outcome,
            rows,
            now=NOW + timedelta(seconds=2),
            invocation_id="b" * 32,
            artifact_commit="a" * 40,
        )
    with Session(database.engine) as session:
        excluded = session.get(BulletinSourceStatus, "mozilla")
        assert excluded.state == "paused" and excluded.reason == "source_not_selected"
        assert excluded.last_success_at is None


def closed(database, monkeypatch):
    seed(database)
    monkeypatch.setattr(intake, "clock", lambda: NOW + timedelta(seconds=1))
    outcome = intake.run(database.engine, fetch=fetcher(), **options())
    with database.engine.connect() as conn:
        rows = json.loads(conn.scalar(text(STATUS_SQL)))
    return outcome, rows


def test_real_compact_closure_binds_invocation_and_consumed_hour(database, monkeypatch):
    outcome, rows = closed(database, monkeypatch)
    result = verified_result(
        outcome,
        rows,
        now=NOW + timedelta(seconds=2),
        invocation_id="b" * 32,
        artifact_commit="a" * 40,
    )
    assert result["intake_version"] == 2 and not result["reused"]
    assert len(result["sources"]) == 2
    consumed = {"status": "hour_consumed", "run_id": outcome["run_id"], "network_attempts": 0}
    result = verified_result(
        consumed,
        rows,
        now=NOW + timedelta(seconds=2),
        invocation_id="c" * 32,
        artifact_commit="d" * 40,
    )
    assert result["reused"] and result["source_artifact_commit"] == "a" * 40


@pytest.mark.parametrize(
    "fault", ["missing", "gap", "source_failure", "invocation", "release", "time", "busy"]
)
def test_invalid_or_unfinished_compact_evidence_refuses(database, monkeypatch, fault):
    outcome, rows = closed(database, monkeypatch)
    rows = deepcopy(rows)
    closure = next(r for r in rows if r["kind"] == "closure")
    intent = next(r for r in rows if r["kind"] == "intent")
    if fault == "missing":
        rows.remove(closure)
    elif fault == "gap":
        closure["document"]["sources"][0].update(state="incomplete", reason="finite_feed_gap")
    elif fault == "source_failure":
        closure["document"]["sources"][0]["http_status"] = None
    elif fault == "invocation":
        intent["document"]["invocation_id"] = "c" * 32
    elif fault == "release":
        intent["document"]["artifact_commit"] = "c" * 40
    elif fault == "time":
        closure["created_at"] = (NOW + timedelta(hours=1)).isoformat()
    else:
        outcome["status"] = "busy"
    with pytest.raises(BulletinError):
        verified_result(
            outcome,
            rows,
            now=NOW + timedelta(seconds=2),
            invocation_id="b" * 32,
            artifact_commit="a" * 40,
        )
