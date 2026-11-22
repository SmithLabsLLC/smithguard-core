"""Audit SG22-31: the contributor check refuses an insufficient temporary location clearly."""

import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

spec = importlib.util.spec_from_file_location(
    "check_tool", Path(__file__).resolve().parents[1] / "tools/check.py"
)
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def fake_statvfs(free_bytes, free_inodes, total_inodes=10**9):
    return lambda path: SimpleNamespace(
        f_bavail=free_bytes, f_frsize=1, f_favail=free_inodes, f_files=total_inodes
    )


def test_insufficient_location_is_rejected_with_guidance(monkeypatch):
    monkeypatch.setattr(os, "statvfs", fake_statvfs(10**12, 10))
    with pytest.raises(SystemExit, match="free file slots"):
        check.require_capacity("/somewhere", check.MINIMUM)
    monkeypatch.setattr(os, "statvfs", fake_statvfs(10, 10**7))
    with pytest.raises(SystemExit, match="SMITHGUARD_CHECK_TMP"):
        check.require_capacity("/somewhere", check.MINIMUM)


def test_sufficient_location_passes_and_task_folder_is_short(monkeypatch, tmp_path):
    # pytest's own tmp_path can exceed the socket budget; that check is tested below.
    monkeypatch.setattr(check, "SOCKET_PATH_MAX", 10**6)
    monkeypatch.setattr(os, "statvfs", fake_statvfs(10**12, 10**7))
    monkeypatch.setenv("SMITHGUARD_CHECK_TMP", str(tmp_path))
    folder = check.task_temp()
    assert Path(folder).parent == tmp_path and Path(folder).name.startswith("sgc-")
    assert len(Path(folder).name) < 16


def test_refusal_leaves_no_task_folder(monkeypatch, tmp_path):
    # pytest's own tmp_path can exceed the socket budget; that check is tested below.
    monkeypatch.setattr(check, "SOCKET_PATH_MAX", 10**6)
    monkeypatch.setattr(os, "statvfs", fake_statvfs(10, 10))
    monkeypatch.setenv("SMITHGUARD_CHECK_TMP", str(tmp_path))
    with pytest.raises(SystemExit, match="Insufficient temporary capacity"):
        check.task_temp()
    assert list(tmp_path.iterdir()) == []


def test_missing_base_is_refused_clearly(monkeypatch, tmp_path):
    monkeypatch.setenv("SMITHGUARD_CHECK_TMP", str(tmp_path / "absent"))
    with pytest.raises(SystemExit, match="does not exist"):
        check.task_temp()


def test_relative_base_gives_an_absolute_task_folder(monkeypatch, tmp_path):
    # pytest's own tmp_path can exceed the socket budget; that check is tested below.
    monkeypatch.setattr(check, "SOCKET_PATH_MAX", 10**6)
    monkeypatch.setattr(os, "statvfs", fake_statvfs(10**12, 10**7))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "rel").mkdir()
    monkeypatch.setenv("SMITHGUARD_CHECK_TMP", "rel")
    folder = check.task_temp()
    assert Path(folder).is_absolute() and Path(folder).parent == tmp_path / "rel"


def test_unreported_inode_totals_are_not_exhaustion(monkeypatch):
    """GPT review round 2: Btrfs reports f_files 0; only the byte check applies."""
    monkeypatch.setattr(os, "statvfs", fake_statvfs(10**12, 0, total_inodes=0))
    check.require_capacity("/somewhere", check.MINIMUM)
    monkeypatch.setattr(os, "statvfs", fake_statvfs(10, 0, total_inodes=0))
    with pytest.raises(SystemExit, match="Insufficient"):
        check.require_capacity("/somewhere", check.MINIMUM)


def test_tmp_shortage_names_tmp_not_the_task_setting(monkeypatch):
    """GPT review round 3: SMITHGUARD_CHECK_TMP cannot fix a full /tmp."""
    monkeypatch.setattr(os, "statvfs", fake_statvfs(10, 10**7))
    with pytest.raises(SystemExit, match="free space or file slots in /tmp") as raised:
        check.require_capacity("/tmp", check.MINIMUM_SYSTEM_TMP)
    assert "SMITHGUARD_CHECK_TMP" not in str(raised.value)


def test_base_too_long_for_the_database_socket_is_refused_first(monkeypatch, tmp_path):
    """GPT review round 10: PostgreSQL's socket path must stay under 108 bytes."""
    monkeypatch.setattr(os, "statvfs", fake_statvfs(10**12, 10**7))
    deep = tmp_path / ("d" * max(1, 108 - check.SOCKET_SUFFIX - len(str(tmp_path))))
    deep.mkdir()
    assert len(os.fsencode(str(deep))) + check.SOCKET_SUFFIX > check.SOCKET_PATH_MAX
    monkeypatch.setenv("SMITHGUARD_CHECK_TMP", str(deep))
    with pytest.raises(SystemExit, match="too long for the test database socket"):
        check.task_temp()
    assert list(deep.iterdir()) == []


def test_socket_suffix_matches_the_suite_layout():
    """The budget covers <base>/sgc-XXXXXXXX/sg-pg-XXXXXXXX/socket/.s.PGSQL.5432."""
    example = "/sgc-abcdefgh/sg-pg-abcdefgh/socket/.s.PGSQL.5432"
    assert len(example) == check.SOCKET_SUFFIX
    support = (Path(__file__).resolve().parent / "support.py").read_text()
    assert 'prefix="sg-pg-"' in support and 'self.root / "socket"' in support
    assert "self.port = 5432" in support
    check.require_socket_room("/var/tmp")


@pytest.mark.parametrize("name", ["with space", "with,comma", "quote'd", "semi;colon"])
def test_base_with_unsupported_characters_is_refused_first(monkeypatch, tmp_path, name):
    """GPT review round 11: PostgreSQL gets the socket folder unquoted."""
    monkeypatch.setattr(os, "statvfs", fake_statvfs(10**12, 10**7))
    base = Path("/tmp") / name if len(str(tmp_path)) > 40 else tmp_path / name
    monkeypatch.setenv("SMITHGUARD_CHECK_TMP", str(base))
    with pytest.raises(SystemExit, match="characters the test database cannot use"):
        check.require_socket_room(str(base))


def test_a_cancelled_step_is_stopped_before_the_wrapper_moves_on(tmp_path, monkeypatch):
    """GPT review round 17: a termination request interrupts the whole step, waits for
    its cleanup (pytest teardown) and only then lets the wrapper exit and drop its lock."""
    import signal
    import sys
    import threading
    import time

    marker = tmp_path / "cleaned"
    child = (
        "import signal, sys, time\n"
        "def stop(*_):\n"
        "    time.sleep(1.0)\n"
        f"    open({str(marker)!r}, 'w').write('done')\n"
        "    sys.exit(130)\n"
        "signal.signal(signal.SIGINT, stop)\n"
        "time.sleep(60)\n"
    )
    monkeypatch.setattr(check, "ROOT", tmp_path)
    previous = signal.signal(signal.SIGTERM, check._cancel)
    threading.Timer(0.5, lambda: os.kill(os.getpid(), signal.SIGTERM)).start()
    started = time.monotonic()
    try:
        with pytest.raises(check.Cancelled):
            check.run(sys.executable, "-c", child)
    finally:
        signal.signal(signal.SIGTERM, previous)
    assert marker.read_text() == "done"
    assert time.monotonic() - started >= 1.0


def test_a_step_ignoring_interrupts_is_terminated_within_bounds(tmp_path):
    import subprocess
    import sys

    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import signal, time; signal.signal(signal.SIGINT, signal.SIG_IGN); time.sleep(60)",
        ],
        start_new_session=True,
    )
    import signal

    check.stop_child(child, steps=((signal.SIGINT, 0.5), (signal.SIGTERM, 5), (signal.SIGKILL, 5)))
    assert child.poll() is not None


def test_cancel_waits_for_a_worker_that_outlives_its_launcher(tmp_path):
    """GPT review round 18: success requires the whole process group to be gone."""
    import signal
    import subprocess
    import sys
    import time

    marker = tmp_path / "worker-done"
    worker = (
        "import signal, time\n"
        "signal.signal(signal.SIGINT, signal.SIG_IGN)\n"
        "time.sleep(1.5)\n"
        f"open({str(marker)!r}, 'w').write('done')\n"
    )
    launcher = (
        "import subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, '-c', {worker!r}])\n"
        "time.sleep(60)\n"
    )
    child = subprocess.Popen([sys.executable, "-c", launcher], start_new_session=True)
    time.sleep(0.5)
    assert check.stop_child(
        child, steps=((signal.SIGINT, 5), (signal.SIGTERM, 5), (signal.SIGKILL, 5))
    )
    assert marker.read_text() == "done"
    assert not check.group_alive(child.pid)


def test_an_unstoppable_group_is_reported_and_blocks_the_next_check(tmp_path, monkeypatch):
    import signal
    import subprocess
    import sys

    monkeypatch.setattr(check, "CANCELLED_MARKER", tmp_path / ".check-cancelled.json")
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import signal, time; signal.signal(signal.SIGINT, signal.SIG_IGN); time.sleep(30)",
        ],
        start_new_session=True,
    )
    import time

    time.sleep(0.5)  # let the child install its handler first
    try:
        assert check.stop_child(child, steps=((signal.SIGINT, 0.3),)) is False
        with pytest.raises(SystemExit, match="still running"):
            check.refuse_if_cancelled_step_runs()
    finally:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait()
    check.refuse_if_cancelled_step_runs()  # the group is gone: the marker is cleared
    assert not (tmp_path / ".check-cancelled.json").exists()


def test_runner_stops_clusters_a_worker_left_behind(tmp_path, monkeypatch):
    """A cluster whose worker exited before teardown is stopped by the runner and verified."""
    calls = tmp_path / "calls"
    fake = tmp_path / "bin" / "pg_ctl"
    fake.parent.mkdir()
    fake.write_text(
        f'#!/bin/sh\necho "$@" >> {calls}\ncase "$*" in *status*) exit 3;; esac\nexit 0\n'
    )
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake.parent}:{os.environ['PATH']}")
    folder = tmp_path / "sgc-task"
    for name in ("sg-pg-aaaa", "sg-pg-bbbb"):
        data = folder / name / "data"
        data.mkdir(parents=True)
        (data / "postmaster.pid").write_text("1\n")
    (folder / "sg-pg-cccc" / "data").mkdir(parents=True)  # never started: no pid file
    assert check.stop_clusters(folder) == []
    lines = calls.read_text().splitlines()
    assert sum(line.endswith(" stop") for line in lines) == 2
    assert sum(line.endswith(" status") for line in lines) == 2
    assert all("sg-pg-cccc" not in line for line in lines)


def test_runner_ignores_test_files_and_stale_pid_files(tmp_path, monkeypatch):
    """Only live clusters directly under the task folder are the suite's; nested test
    fixtures and pid files of finished processes are left alone."""
    import subprocess
    import sys

    calls = tmp_path / "calls"
    fake = tmp_path / "bin" / "pg_ctl"
    fake.parent.mkdir()
    fake.write_text(f'#!/bin/sh\necho "$@" >> {calls}\nexit 3\n')
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake.parent}:{os.environ['PATH']}")
    folder = tmp_path / "sgc-task"
    nested = folder / "pytest-of-user" / "test_x0" / "task" / "sg-pg-nested" / "data"
    nested.mkdir(parents=True)
    (nested / "postmaster.pid").write_text("1\n")
    finished = subprocess.run(
        [sys.executable, "-c", "import os; print(os.getpid())"], capture_output=True, text=True
    ).stdout.strip()
    stale = folder / "sg-pg-stale" / "data"
    stale.mkdir(parents=True)
    (stale / "postmaster.pid").write_text(finished + "\n")
    assert check.stop_clusters(folder) == []
    assert not calls.exists()
