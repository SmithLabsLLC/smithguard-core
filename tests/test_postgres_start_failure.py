"""GPT review round 11: a failed test-database start stops its exact cluster, keeps the
logs in the outer task folder and removes the cluster only once the stop is verified."""

import subprocess
from pathlib import Path

import pytest

from tests import support


class FakeTools:
    """Stands in for initdb and pg_ctl; records every call against the cluster."""

    def __init__(self, *, fail, status):
        self.fail, self.status, self.calls = fail, status, []

    def __call__(self, args, stdout=None, stderr=None, check=False, **_ignored):
        name = Path(args[0]).name
        action = args[-1]
        self.calls.append((name, action))
        stdout.write(f"{name} {action} output\n".encode())
        if name == "initdb":
            data = Path(args[args.index("-D") + 1])
            data.mkdir()
            return subprocess.CompletedProcess(args, 1 if self.fail == "initdb" else 0)
        if action == "start":
            data = Path(args[args.index("-D") + 1])
            (data / "postmaster.pid").write_text("123\n")
            log = Path(args[args.index("-l") + 1])
            log.write_text("FATAL: could not start in time\n")
            return subprocess.CompletedProcess(args, 1 if self.fail == "pg_ctl" else 0)
        if action == "status":
            return subprocess.CompletedProcess(args, self.status)
        return subprocess.CompletedProcess(args, 0)


@pytest.fixture
def outer(tmp_path, monkeypatch):
    folder = tmp_path / "task"
    folder.mkdir()
    monkeypatch.setenv("TMPDIR", str(folder))
    return folder


def run(monkeypatch, tools):
    monkeypatch.setattr(support, "postgres_tool", lambda name: f"/fake/bin/{name}")
    monkeypatch.setattr(support.subprocess, "run", tools)
    cluster = support.LocalPostgres()
    with pytest.raises(RuntimeError) as raised:
        cluster.start()
    return cluster, str(raised.value)


def test_timed_out_start_is_stopped_logs_kept_cluster_removed(outer, monkeypatch):
    tools = FakeTools(fail="pg_ctl", status=3)
    cluster, message = run(monkeypatch, tools)
    assert ("pg_ctl", "stop") in tools.calls and ("pg_ctl", "status") in tools.calls
    assert "stopped and removed" in message and "FATAL: could not start in time" in message
    assert not cluster.root.exists()
    (kept,) = outer.glob("postgres-start-failure-*")
    assert {p.name for p in kept.iterdir()} >= {"pg_ctl.log", "postgres.log", "initdb.log"}
    assert str(kept) in message


def test_unverified_shutdown_keeps_the_cluster_and_says_so(outer, monkeypatch):
    tools = FakeTools(fail="pg_ctl", status=0)
    cluster, message = run(monkeypatch, tools)
    assert "shutdown could not be verified" in message and str(cluster.root) in message
    assert cluster.root.exists()
    assert list(outer.glob("postgres-start-failure-*"))


def test_failed_initdb_keeps_logs_and_removes_the_cluster(outer, monkeypatch):
    tools = FakeTools(fail="initdb", status=3)
    cluster, message = run(monkeypatch, tools)
    assert message.startswith("initdb exited 1")
    assert not cluster.root.exists()
    assert ("pg_ctl", "start") not in tools.calls
    (kept,) = outer.glob("postgres-start-failure-*")
    assert (kept / "initdb.log").read_text().startswith("initdb")


def test_folder_with_a_space_is_refused_before_any_tool_runs(tmp_path, monkeypatch):
    folder = tmp_path / "with space"
    folder.mkdir()
    monkeypatch.setenv("TMPDIR", str(folder))
    tools = FakeTools(fail=None, status=3)
    cluster, message = run(monkeypatch, tools)
    assert "unsupported characters" in message and tools.calls == []
    assert not cluster.root.exists()
