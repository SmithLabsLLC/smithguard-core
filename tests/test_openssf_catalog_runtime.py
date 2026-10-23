"""OpenSSF catalog process-lock behavior."""

from __future__ import annotations

from typing import Any

import pytest

from smithguard import openssf_catalog
from smithguard.openssf_shadow import OpenSSFStateBusy, _exclusive_lock


class _LockConnection:
    """One explicit connection: the advisory lock lives and dies on it."""

    def __init__(self, acquired: bool) -> None:
        self.acquired = acquired
        self.execute_count = 0
        self.commit_count = 0
        self.closed = False

    def scalar(self, _statement: object) -> bool:
        return self.acquired

    def execute(self, _statement: object) -> None:
        self.execute_count += 1

    def commit(self) -> None:
        self.commit_count += 1

    def close(self) -> None:
        self.closed = True


class _LockEngine:
    def __init__(self, connection: _LockConnection) -> None:
        self.disposed = False
        self.connection = connection
        self.connect_count = 0

    def connect(self) -> _LockConnection:
        self.connect_count += 1
        return self.connection

    def dispose(self) -> None:
        self.disposed = True


def _runtime(
    monkeypatch,
    tmp_path,
    *,
    acquired: bool,
) -> tuple[_LockConnection, _LockEngine, list[str]]:
    monkeypatch.setenv("SMITHGUARD_OPENSSF_CATALOG_ROOT", str(tmp_path / "catalog"))
    session = _LockConnection(acquired)
    engine = _LockEngine(session)
    collections: list[str] = []
    monkeypatch.setattr(openssf_catalog, "load_runtime_config", lambda **_kwargs: object())
    monkeypatch.setattr(openssf_catalog, "_engine", lambda _config: engine)

    def collect() -> dict[str, Any]:
        with pytest.raises(OpenSSFStateBusy), _exclusive_lock(tmp_path / "catalog/run.lock"):
            pytest.fail("catalog filesystem lock was not held")
        collections.append("called")
        return {"status": "complete"}

    monkeypatch.setattr(openssf_catalog, "collect_openssf_catalog", collect)
    return session, engine, collections


def test_openssf_catalog_main_exits_distinctly_when_run_lock_is_held(
    monkeypatch,
    capsys,
    tmp_path,
) -> None:
    session, engine, collections = _runtime(monkeypatch, tmp_path, acquired=False)

    assert openssf_catalog.main() == openssf_catalog.OPENSSF_CATALOG_ALREADY_RUNNING
    assert capsys.readouterr().err == "openssf_catalog_already_running\n"
    assert collections == []
    assert session.execute_count == 0
    assert session.commit_count == 1
    assert session.closed
    assert engine.disposed and engine.connect_count == 1


def test_openssf_catalog_validation_timeout_has_fixed_diagnostic(
    monkeypatch, capsys, tmp_path
) -> None:
    session, engine, _collections = _runtime(monkeypatch, tmp_path, acquired=True)

    def fail():
        raise openssf_catalog.OpenSSFCatalogValidationTimeout("private failure detail")

    monkeypatch.setattr(openssf_catalog, "collect_openssf_catalog", fail)
    assert openssf_catalog.main() == 3
    assert capsys.readouterr().err == (
        "collection_diagnostic:validation_time_budget\nruntime_error:openssf_catalog_failed\n"
    )
    assert session.closed and engine.disposed
    assert session.execute_count == 1


def test_openssf_catalog_main_releases_the_session_lock_after_success(
    monkeypatch,
    capsys,
    tmp_path,
) -> None:
    session, engine, collections = _runtime(monkeypatch, tmp_path, acquired=True)

    assert openssf_catalog.main() == 0
    assert "openssf_catalog_complete" in capsys.readouterr().out
    assert collections == ["called"]
    with _exclusive_lock(tmp_path / "catalog/run.lock"):
        pass  # The real filesystem lock is released after the completed run.
    # One connection: the lock is taken, the transaction ended, the unlock issued and
    # committed on that same connection, then it is closed.
    assert session.execute_count == 1
    assert session.commit_count == 2
    assert session.closed
    assert engine.disposed and engine.connect_count == 1


def test_openssf_catalog_unexpected_failure_reports_its_cause_before_the_token(
    monkeypatch, capsys, tmp_path
) -> None:
    _session, _engine, _collections = _runtime(monkeypatch, tmp_path, acquired=True)

    def fail():
        raise RuntimeError("private cause")

    monkeypatch.setattr(openssf_catalog, "collect_openssf_catalog", fail)
    assert openssf_catalog.main() == 3
    assert capsys.readouterr().err.splitlines() == [
        "error_class=RuntimeError",
        "error_message=private cause",
        "runtime_error:openssf_catalog_failed",
    ]


def test_provisional_deferral_is_a_failed_exit_with_exact_candidate_and_released_locks(
    monkeypatch, capsys, tmp_path
) -> None:
    session, engine, _collections = _runtime(monkeypatch, tmp_path, acquired=True)
    commit = "a" * 40

    def defer():
        raise openssf_catalog.OpenSSFCatalogDeferred(commit)

    monkeypatch.setattr(openssf_catalog, "collect_openssf_catalog", defer)
    assert openssf_catalog.main() == 75
    captured = capsys.readouterr()
    assert "openssf_catalog_complete" not in captured.out
    assert captured.err == (
        "runtime_error:openssf_catalog_deferred reason=provisional_upstream_ids "
        f"commit={commit} provisional_ids_at_least=1\n"
    )
    assert session.closed and engine.disposed and session.execute_count == 1
    with _exclusive_lock(tmp_path / "catalog/run.lock"):
        pass
