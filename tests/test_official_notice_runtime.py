"""Runtime controls fail closed and status never performs network work."""

import json
import os
from datetime import timedelta

import pytest
from sqlalchemy.orm import Session

from smithguard import official_notice_runtime as m
from smithguard.official_notice_store import receipt, status
from smithguard.runtime import DEFAULT_RIGHTS_REGISTER
from tests.test_official_notice_store import NOW


@pytest.fixture
def control(tmp_path, monkeypatch):
    directory = tmp_path / "policies"
    directory.mkdir(mode=0o755)
    path = directory / "official-notices.json"
    monkeypatch.setattr(m, "CONTROL_DIRECTORY", directory)
    monkeypatch.setattr(m, "CONTROL_PATH", path)
    monkeypatch.setattr(m, "CONTROL_UID", os.getuid())
    monkeypatch.setattr(m, "running_release", lambda: "a" * 40)
    monkeypatch.setattr(m, "rights_registry_path", lambda: DEFAULT_RIGHTS_REGISTER)
    path.write_bytes(
        m.control_bytes(operation_id="20261021-" + "1" * 32, artifact_commit="a" * 40, enabled=True)
    )
    path.chmod(0o644)
    return path


@pytest.mark.parametrize(
    "fault", ["missing", "symlink", "mode", "directory", "release", "extra", "bool_version"]
)
def test_control_damage_never_enables_work(control, monkeypatch, fault):
    assert m.enabled()
    if fault == "missing":
        control.unlink()
    elif fault == "symlink":
        control.rename(control.with_suffix(".target"))
        control.symlink_to(control.with_suffix(".target"))
    elif fault == "mode":
        control.chmod(0o666)
    elif fault == "directory":
        control.parent.chmod(0o777)
    elif fault == "release":
        monkeypatch.setattr(m, "running_release", lambda: "b" * 40)
    else:
        document = json.loads(control.read_bytes())
        document["extra" if fault == "extra" else "schema_version"] = True
        control.write_text(json.dumps(document))
    assert not m.enabled() and m.control_state()["state"] == "unavailable"


def test_paused_worker_requires_neither_database_nor_network(control, monkeypatch, capsys):
    control.write_bytes(
        m.control_bytes(operation_id="20261021-" + "1" * 32, artifact_commit="a" * 40)
    )
    monkeypatch.delenv("SMITHGUARD_DATABASE_URL", raising=False)
    monkeypatch.setattr(m, "create_engine", lambda *a, **k: pytest.fail("database access"))
    monkeypatch.setattr(m, "run", lambda *a, **k: pytest.fail("network work"))
    assert m.main(["--run"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "paused"


def test_release_bound_source_selection_is_closed(control):
    value = json.loads(control.read_bytes())
    value["source_keys"] = ["php"]
    control.write_text(json.dumps(value))
    assert m.read_control()["source_keys"] == ["php"]
    for invalid in ([], ["php", "php"], ["unknown"], "php", [True]):
        value["source_keys"] = invalid
        control.write_text(json.dumps(value))
        assert not m.enabled()


def test_status_reports_incomplete_and_unknown_times(database):
    with Session(database.engine) as session, session.begin():
        before = status(session, now=NOW)
        assert before["status"] == "never_run" and before["retrieval_recall"] is None
        assert before["internal_available_upper_bound"] is None
        receipt(session, identity="start", kind="started", now=NOW, data={"run_id": "hour"})
        result = status(session, now=NOW + timedelta(seconds=1))
        assert result["status"] == "incomplete" and result["receipt_count"] == 1
        assert result["sources"]["php"]["last_success_observed_at"] is None
        assert result["publication"] == "ineligible"
        receipt(
            session,
            identity="done",
            kind="completed",
            now=NOW + timedelta(seconds=2),
            data={"run_id": "hour", "status": "degraded"},
        )
        result = status(session, now=NOW + timedelta(seconds=3))
        assert result["status"] == "degraded" and result["internal_available_upper_bound"] is None
        receipt(
            session,
            identity="available",
            kind="available",
            now=NOW + timedelta(seconds=4),
            data={"run_id": "hour"},
        )
        assert status(session, now=NOW + timedelta(seconds=5))["internal_available_upper_bound"]


@pytest.mark.parametrize(
    "outcome", ["degraded", "storage_budget_paused", "identity_budget_paused", "complete"]
)
def test_expected_feed_outcomes_are_successful_unit_execution(
    control, database, monkeypatch, capsys, outcome
):
    monkeypatch.setenv("SMITHGUARD_DATABASE_URL", "synthetic")
    monkeypatch.setenv("INVOCATION_ID", "b" * 32)
    monkeypatch.setattr(m, "_validate_database_url", lambda url: url)
    monkeypatch.setattr(m, "create_engine", lambda *a, **kw: database.engine)

    def run(engine, **kwargs):
        assert kwargs["artifact_commit"] == "a" * 40
        assert kwargs["invocation_id"] == "b" * 32
        return {"status": outcome}

    monkeypatch.setattr(m, "run", run)
    assert m.main(["--run"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == outcome


def test_disabled_control_can_close_authority_without_a_release_identity(control, monkeypatch):
    control.write_bytes(m.control_bytes(operation_id="20261021-" + "1" * 32, artifact_commit=None))
    monkeypatch.setattr(m, "running_release", lambda: pytest.fail("unreadable release"))
    assert m.control_state()["state"] == "paused"
    with pytest.raises(ValueError):
        m.control_bytes(operation_id="20261021-" + "1" * 32, artifact_commit=None, enabled=True)


def test_control_transition_timestamps_are_state_bound():
    arguments = dict(operation_id="20261021-" + "1" * 32, artifact_commit="a" * 40)
    assert json.loads(m.control_bytes(**arguments, draining_at=NOW))["draining_at"]
    assert json.loads(m.control_bytes(**arguments, enabled=True, enabled_at=NOW))["enabled_at"]
    with pytest.raises(ValueError, match="drain_time"):
        m.control_bytes(**arguments, enabled=True, draining_at=NOW)
    with pytest.raises(ValueError, match="enabled_time"):
        m.control_bytes(**arguments, enabled_at=NOW)
