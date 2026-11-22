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
        if hasattr(stdout, "write"):  # DEVNULL when the log file could not be created
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


def test_no_free_file_slots_still_stops_the_server(outer, monkeypatch):
    """GPT review round 12: shutdown does not depend on creating its log file."""
    tools = FakeTools(fail="pg_ctl", status=3)
    real_open = Path.open

    def no_slots(self, mode="r", *args, **kwargs):
        if self.name in {"pg_ctl-stop.log", "pg_ctl-status.log"}:
            raise OSError(24, "Too many open files")
        return real_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", no_slots)
    cluster, message = run(monkeypatch, tools)
    assert ("pg_ctl", "stop") in tools.calls and ("pg_ctl", "status") in tools.calls
    assert message.startswith("pg_ctl exited 1") and "stopped and removed" in message


def test_failed_log_copy_keeps_the_logs_in_the_cluster(outer, monkeypatch):
    tools = FakeTools(fail="pg_ctl", status=3)

    def broken_copy(*_args, **_kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(support.shutil, "copy2", broken_copy)
    cluster, message = run(monkeypatch, tools)
    assert message.startswith("pg_ctl exited 1")
    assert "could not be copied (OSError)" in message and str(cluster.root) in message
    assert cluster.root.exists() and (cluster.root / "postgres.log").exists()
    assert "FATAL: could not start in time" in message


def test_unlaunchable_stop_still_checks_status_and_keeps_the_cluster(outer, monkeypatch):
    """GPT review round 13: a launch failure of pg_ctl stop does not skip the status
    check, and an unknown status keeps the cluster with the original error first."""
    tools = FakeTools(fail="pg_ctl", status=3)

    def flaky(args, **kwargs):
        if args[-1] == "stop":
            raise OSError(24, "Too many open files")
        if args[-1] == "status":
            tools.calls.append(("pg_ctl", "status"))
            raise OSError(24, "Too many open files")
        return tools(args, **kwargs)

    cluster, message = run(monkeypatch, flaky)
    assert ("pg_ctl", "status") in tools.calls
    assert message.startswith("pg_ctl exited 1")
    assert "pg_ctl stop could not be launched" in message
    assert "shutdown could not be verified" in message and cluster.root.exists()


def test_unreadable_log_does_not_hide_the_start_error(outer, monkeypatch):
    tools = FakeTools(fail="pg_ctl", status=3)
    real_read = Path.read_text

    def unreadable(self, *args, **kwargs):
        if self.name == "postgres.log":
            raise OSError(5, "I/O error")
        return real_read(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", unreadable)
    cluster, message = run(monkeypatch, tools)
    assert message.startswith("pg_ctl exited 1")
    assert "postgres.log --- (unreadable: OSError)" in message


@pytest.mark.parametrize("tool", ["initdb", "pg_ctl"])
def test_a_start_tool_that_cannot_launch_is_a_named_failure(outer, monkeypatch, tool):
    """GPT review round 14: only exit code 0 is success; a launch failure is reported."""
    tools = FakeTools(fail=None, status=3)

    def unlaunchable(args, **kwargs):
        name, action = Path(args[0]).name, args[-1]
        if name == tool and (tool == "initdb" or action == "start"):
            tools.calls.append((name, action))
            raise OSError(2, "No such file or directory")
        return tools(args, **kwargs)

    cluster, message = run(monkeypatch, unlaunchable)
    assert message.startswith(f"{tool} could not be launched")
    assert cluster._started is False
    if tool == "initdb":
        assert ("pg_ctl", "start") not in tools.calls


def test_a_missing_tool_creates_no_folder(outer, monkeypatch):
    """GPT review round 15: setup that fails leaves no abandoned cluster folder."""

    def missing(name):
        raise RuntimeError(f"{name} not found")

    monkeypatch.setattr(support, "postgres_tool", missing)
    with pytest.raises(RuntimeError, match="initdb not found"):
        support.LocalPostgres()
    assert list(outer.iterdir()) == []


def test_a_socket_folder_that_cannot_be_made_creates_no_folder(outer, monkeypatch):
    monkeypatch.setattr(support, "postgres_tool", lambda name: f"/fake/bin/{name}")
    real_mkdir = Path.mkdir

    def no_slots(self, *args, **kwargs):
        if self.name == "socket":
            raise OSError(28, "No space left on device")
        return real_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", no_slots)
    with pytest.raises(OSError, match="No space left"):
        support.LocalPostgres()
    assert list(outer.iterdir()) == []


@pytest.mark.parametrize("status,removed", [(3, True), (0, False)])
def test_teardown_stops_the_cluster_even_without_an_admin_connection(
    outer, monkeypatch, status, removed
):
    """GPT review round 16: SQL cleanup failing does not skip shutdown."""
    tools = FakeTools(fail=None, status=status)
    monkeypatch.setattr(support, "postgres_tool", lambda name: f"/fake/bin/{name}")
    monkeypatch.setattr(support.subprocess, "run", tools)
    cluster = support.LocalPostgres().start()

    def unavailable():
        raise OSError(111, "Connection refused")

    monkeypatch.setattr(cluster, "_admin_connection", unavailable)
    with pytest.raises(RuntimeError, match="ConnectionRefusedError during SQL cleanup") as raised:
        cluster.close()
    assert ("pg_ctl", "stop") in tools.calls and ("pg_ctl", "status") in tools.calls
    assert cluster.root.exists() is not removed
    assert ("stopped and removed" in str(raised.value)) is removed
