"""Root operator authority, fixed peer connection and real publication transactions."""

import json
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from smithguard import bulletin_runtime as runtime
from smithguard import bulletin_store as store
from smithguard.bulletin_contract import BulletinError, content_id
from smithguard.db.bulletin_models import BulletinDecision
from smithguard.identifiers import canonical_json_bytes, sha256_id

from .test_bulletins import GRANT, NOW, content


@pytest.mark.parametrize("failed", [False, True])
def test_operator_peer_connection_restores_root_on_success_and_failure(monkeypatch, failed):
    state = {"uid": 0, "transitions": []}

    def change(uid):
        state["uid"] = uid
        state["transitions"].append(uid)

    monkeypatch.setattr(runtime.os, "geteuid", lambda: state["uid"])
    monkeypatch.setattr(runtime.os, "seteuid", change)
    monkeypatch.setattr(runtime.threading, "active_count", lambda: 1)

    def identity(name):
        assert name == "smithguard-maintenance"
        return SimpleNamespace(pw_uid=969)

    monkeypatch.setattr(runtime.pwd, "getpwnam", identity)
    result = object()

    def connect(**kwargs):
        assert state["uid"] == 969
        assert kwargs == {
            "dbname": "smithguard",
            "user": "smithguard-maintenance",
            "host": "/run/postgresql",
            "port": 5432,
            "connect_timeout": 5,
            "options": "-c statement_timeout=10000 -c lock_timeout=5000",
        }
        if failed:
            raise RuntimeError("synthetic connection refusal")
        return result

    monkeypatch.setattr(runtime.psycopg, "connect", connect)
    if failed:
        with pytest.raises(RuntimeError, match="synthetic connection refusal"):
            runtime.operator_connection()
    else:
        assert runtime.operator_connection() is result
    assert state == {"uid": 0, "transitions": [969, 0]}


@pytest.mark.parametrize("uid,threads,maintenance_uid", [(1000, 1, 969), (0, 2, 969), (0, 1, 0)])
def test_operator_peer_connection_refuses_unsafe_identity(
    monkeypatch, uid, threads, maintenance_uid
):
    monkeypatch.setattr(runtime.os, "geteuid", lambda: uid)
    monkeypatch.setattr(runtime.threading, "active_count", lambda: threads)
    monkeypatch.setattr(runtime.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=maintenance_uid))
    monkeypatch.setattr(runtime.os, "seteuid", lambda _: pytest.fail("must not change identity"))
    monkeypatch.setattr(runtime.psycopg, "connect", lambda **_: pytest.fail("must not connect"))
    with pytest.raises(BulletinError, match="bulletin_operator_"):
        runtime.operator_connection()


def test_operator_cli_transactions_use_fixed_connection_and_locked_authority(
    database, tmp_path, monkeypatch, capsys
):
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW

    locks = []

    @contextmanager
    def lock(enabled, *, now):
        assert enabled and now == NOW
        locks.append(True)
        yield

    def engine(url, **kwargs):
        assert url == "postgresql+psycopg://"
        assert kwargs["creator"] is runtime.operator_connection
        assert kwargs["poolclass"] is NullPool and kwargs["hide_parameters"]
        # Exercise real SQL with the disposable test database. Peer identity is
        # tested separately and qualified by a read-only production socket probe.
        return create_engine(database.engine.url, poolclass=NullPool)

    monkeypatch.setattr(runtime, "datetime", Clock)
    monkeypatch.setattr(runtime, "create_engine", engine)
    monkeypatch.setattr(runtime, "operator_lock", lock)
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 0)
    monkeypatch.setattr(runtime, "current_grant", lambda **_: GRANT)
    monkeypatch.setattr(
        runtime,
        "rights_registry_path",
        lambda: Path(__file__).resolve().parents[1] / "contracts/v1/source-rights-register.json",
    )
    monkeypatch.delenv("SMITHGUARD_DATABASE_URL", raising=False)
    document = content()
    draft = tmp_path / "draft.json"
    draft.write_text(json.dumps(document))
    draft.chmod(0o600)
    identity = content_id(document)
    assert (
        runtime.main(["--publish", str(draft), "--approval-id", "1" * 64, "--expect-absent"]) == 0
    )
    baseline = sha256_id(canonical_json_bytes(document))
    document["summary"] = "Corrected synthetic operator evidence."
    draft.write_text(json.dumps(document))
    assert (
        runtime.main(["--publish", str(draft), "--approval-id", "2" * 64, "--expect-absent"]) == 1
    )
    options = [
        "--publish",
        str(draft),
        "--approval-id",
        "2" * 64,
        "--expected-content-hash",
        baseline,
    ]
    assert runtime.main([*options, "--expected-revision", "2"]) == 1
    assert runtime.main([*options, "--expected-revision", "1"]) == 0
    # Matching revision, wrong hash: a fresh approval and changed content isolate CAS.
    stale_draft = {
        **document,
        "summary": "A later synthetic edit must not overwrite this revision.",
    }
    draft.write_text(json.dumps(stale_draft))
    assert (
        runtime.main(
            [
                "--publish",
                str(draft),
                "--approval-id",
                "4" * 64,
                "--expected-content-hash",
                baseline,
                "--expected-revision",
                "2",
            ]
        )
        == 1
    )
    with Session(database.engine) as session:
        assert (
            session.scalar(
                select(BulletinDecision).where(BulletinDecision.manual_approval_id == "4" * 64)
            )
            is None
        )
        unchanged = store.detail(session, identity, now=NOW)
        assert unchanged["revision"] == 2 and unchanged["content"] == document
    draft.write_text(json.dumps(document))
    digest = sha256_id(canonical_json_bytes(document))
    assert (
        runtime.main(["--verify", identity, "--content-hash", digest, "--approval-id", "3" * 64])
        == 0
    )
    with Session(database.engine) as session:
        record = store.detail(session, identity, now=NOW)
        assert record["revision"] == 2 and record["content"] == document
    assert runtime.main(["--takedown", identity]) == 0
    with Session(database.engine) as session:
        for revision in (None, 1, 2):
            assert store.detail(session, identity, now=NOW, revision=revision)["content"] is None
    assert len(locks) == 7
    capsys.readouterr()
    assert runtime.main(["--observe"]) == 0
    observation = json.loads(capsys.readouterr().out)
    assert observation["hours"]["expected_elapsed_hours"] == 0
    assert not observation["hours"]["complete"]
    assert observation["event_counts"] == {}
    assert len(locks) == 8


def test_operator_cli_rejects_unprivileged_mutation_before_connection(monkeypatch):
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(runtime, "create_engine", lambda *_, **__: pytest.fail("must not connect"))
    assert runtime.main(["--takedown", "a" * 64]) == 1
    assert runtime.main(["--observe"]) == 1


@pytest.mark.parametrize(
    "options",
    [
        ["--status", "--expect-absent"],
        ["--publish", "/unused", "--approval-id", "1" * 64, "--expected-revision", "1"],
        [
            "--publish",
            "/unused",
            "--approval-id",
            "1" * 64,
            "--expected-content-hash",
            "bad",
            "--expected-revision",
            "1",
        ],
    ],
)
def test_operator_refuses_invalid_expected_state_before_connection(monkeypatch, options):
    monkeypatch.setattr(runtime, "create_engine", lambda *_, **__: pytest.fail("must not connect"))
    assert runtime.main(options) == 1
