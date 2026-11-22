#!/usr/bin/env python3
"""Run the contributor checks from any working directory."""

import fcntl
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Audit SG22-31: the database suite and browser-style tests create many small files.
# Use a short, task-owned, disk-backed folder and check its free space and free file
# slots before starting, like the private gate.
MINIMUM = {"bytes": 4 * 1024**3, "inodes": 500_000}
MINIMUM_SYSTEM_TMP = {"bytes": 1024**3, "inodes": 100_000}
# GPT review round 10: PostgreSQL refuses a Unix socket path of 108 bytes or more. The
# suite's socket is <task folder>/sg-pg-XXXXXXXX/socket/.s.PGSQL.5432 (tests/support.py),
# with the task folder <base>/sgc-XXXXXXXX made here.
SOCKET_PATH_MAX = 107
SOCKET_SUFFIX = len("/sgc-") + 8 + len("/sg-pg-") + 8 + len("/socket/.s.PGSQL.5432")


def require_socket_room(base):
    # GPT review round 11: the socket folder is passed to PostgreSQL unquoted, inside a
    # comma-separated setting; only plain path characters are supported.
    if not re.fullmatch(r"[A-Za-z0-9/._-]+", base):
        raise SystemExit(
            f"Temporary base {base} has characters the test database cannot use (spaces, "
            "commas, quotes or others); set SMITHGUARD_CHECK_TMP to a folder whose path has "
            "only letters, digits, '/', '.', '_' or '-'."
        )
    need = len(os.fsencode(base)) + SOCKET_SUFFIX
    if need > SOCKET_PATH_MAX:
        raise SystemExit(
            f"Temporary base {base} is too long for the test database socket ({need} bytes; "
            f"PostgreSQL allows {SOCKET_PATH_MAX}); set SMITHGUARD_CHECK_TMP to a shorter "
            "folder such as /var/tmp."
        )


def require_capacity(path, minimum):
    stat = os.statvfs(path)
    free_bytes, free_inodes = stat.f_bavail * stat.f_frsize, stat.f_favail
    # GPT review round 2: some filesystems (Btrfs) report no inode totals (f_files 0);
    # that is "not reported", not exhaustion, so only the byte check applies there.
    reported = stat.f_files != 0
    print(
        f"Check capacity {path}: {free_bytes} bytes, "
        + (f"{free_inodes} inodes available" if reported else "inode count not reported"),
        flush=True,
    )
    if free_bytes < minimum["bytes"] or (reported and free_inodes < minimum["inodes"]):
        advice = (
            "free space or file slots in /tmp (it is used by tools outside the task folder)"
            if os.path.realpath(path) == os.path.realpath("/tmp")
            else "set SMITHGUARD_CHECK_TMP to a disk-backed folder with room"
        )
        raise SystemExit(
            f"Insufficient temporary capacity at {path} (need {minimum['bytes']} bytes and "
            f"{minimum['inodes']} free file slots); {advice}."
        )


def task_temp():
    base = os.environ.get("SMITHGUARD_CHECK_TMP") or (
        "/var/tmp" if Path("/var/tmp").is_dir() else tempfile.gettempdir()
    )
    # An absolute base: the task folder becomes TMPDIR for children started elsewhere.
    base = os.path.abspath(base)
    if not Path(base).is_dir():
        raise SystemExit(
            f"Temporary base {base} does not exist; create it or set SMITHGUARD_CHECK_TMP."
        )
    # Check room and capacity before creating anything, so a refusal leaves nothing behind.
    require_socket_room(base)
    require_capacity(base, MINIMUM)
    if Path("/tmp").is_dir():
        require_capacity("/tmp", MINIMUM_SYSTEM_TMP)
    # A short root: pytest adds worker and test folders before AF_UNIX socket names.
    return tempfile.mkdtemp(prefix="sgc-", dir=base)


class Cancelled(BaseException):
    """GPT review round 17: a termination request reached this wrapper."""


def _cancel(signum, _frame):
    raise Cancelled(signal.Signals(signum).name)


# Bounded shutdown of a cancelled step: interrupt (lets pytest run its teardown, which
# stops the disposable PostgreSQL clusters), then terminate, then kill.
STOP_STEPS = ((signal.SIGINT, 90), (signal.SIGTERM, 30), (signal.SIGKILL, 10))


CANCELLED_MARKER = ROOT / ".check-cancelled.json"


def group_alive(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def stop_child(child, steps=STOP_STEPS):
    """GPT review round 18: success means the whole process group is gone, not only the
    direct child (a launcher can exit before its workers)."""
    pgid = child.pid
    for signum, grace in steps:
        if not group_alive(pgid):
            break
        try:
            os.killpg(pgid, signum)
        except ProcessLookupError:
            break
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline and group_alive(pgid):
            child.poll()
            time.sleep(0.05)
    child.poll()
    if group_alive(pgid):
        # Keep the next check from overlapping with what could not be stopped.
        CANCELLED_MARKER.write_text(json.dumps({"pgid": pgid}) + "\n")
        print(
            f"Cancelled step NOT verified stopped (process group {pgid} remains); the "
            f"next check refuses to start while it runs.",
            flush=True,
        )
        return False
    print(f"Cancelled step stopped (process group {pgid} gone).", flush=True)
    return True


def refuse_if_cancelled_step_runs():
    if not CANCELLED_MARKER.exists():
        return
    try:
        pgid = int(json.loads(CANCELLED_MARKER.read_text())["pgid"])
    except (OSError, ValueError, KeyError, TypeError):
        pgid = None
    if pgid is not None and group_alive(pgid):
        raise SystemExit(
            f"A cancelled check's process group {pgid} is still running; stop it first."
        )
    CANCELLED_MARKER.unlink(missing_ok=True)


def pg_ctl():
    direct = shutil.which("pg_ctl")
    if direct:
        return direct
    config = shutil.which("pg_config")
    if config:
        bindir = subprocess.run([config, "--bindir"], capture_output=True, text=True).stdout.strip()
        candidate = Path(bindir) / "pg_ctl"
        if candidate.is_file():
            return str(candidate)
    return None


def stop_clusters(folder):
    """GPT review round 18: every disposable cluster of this run lives under its task folder
    (pg_ctl starts PostgreSQL in its own session, outside the step's process group), so the
    runner stops whatever a worker left behind and verifies it. Returns the clusters it could
    not verify stopped."""
    tool = pg_ctl()
    remaining = []
    # The suite's clusters are direct children of the task folder (tests/support.py uses
    # TMPDIR); deeper folders belong to tests' own temporary files. Only a pid file whose
    # process is alive means a server may still be running.
    for pid_file in sorted(Path(folder).glob("sg-pg-*/data/postmaster.pid")):
        data = pid_file.parent
        try:
            pid = int(pid_file.read_text().split()[0])
            os.kill(pid, 0)
        except ProcessLookupError:
            continue
        except (OSError, ValueError, IndexError):
            pass
        if tool is None:
            remaining.append(str(data))
            continue
        subprocess.run(
            [tool, "-D", str(data), "-m", "immediate", "-w", "-t", "30", "stop"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        status = subprocess.run(
            [tool, "-D", str(data), "status"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        if status != 3:
            remaining.append(str(data))
    for data in remaining:
        print(f"Test database NOT verified stopped: {data}", flush=True)
    return remaining


def run(*args):
    print("+", " ".join(args), flush=True)
    # Its own process group, so a cancellation can stop the whole step (and its workers)
    # before this wrapper exits and releases the check lock.
    child = subprocess.Popen(args, cwd=ROOT, start_new_session=True)
    try:
        code = child.wait()
    except BaseException:
        stop_child(child)
        raise
    if code:
        raise subprocess.CalledProcessError(code, args)


def main():
    if os.name != "posix" or hasattr(os, "geteuid") and os.geteuid() == 0:
        raise SystemExit("Use an unprivileged Linux/WSL account for contributor tests.")
    uv = shutil.which("uv")
    if not uv:
        raise SystemExit("Install uv 0.13.4 and put it on PATH; see README.md.")
    workers = os.environ.get("SMITHGUARD_TEST_WORKERS", str(min(os.cpu_count() or 1, 4)))
    if not workers.isdigit() or not 1 <= int(workers) <= 16:
        raise SystemExit("SMITHGUARD_TEST_WORKERS must be an integer from 1 to 16.")
    # One check at a time: concurrent database suites share local PostgreSQL resources.
    lock = open(ROOT / ".check.lock", "a")  # noqa: SIM115 (held for the whole run)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit("Another contributor check is running; wait for it to finish.") from None
    refuse_if_cancelled_step_runs()
    folder = task_temp()
    os.environ["TMPDIR"] = folder
    # The lock stays held until every cancelled step has been stopped (see run()).
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, _cancel)
    try:
        checks(uv, workers)
    except BaseException:
        stop_clusters(folder)
        print(f"Check temporary evidence retained at {folder}.", flush=True)
        raise
    if stop_clusters(folder):
        raise SystemExit(f"Test databases left running; evidence retained at {folder}.")
    shutil.rmtree(folder, ignore_errors=True)
    print("Contributor checks passed.")


def checks(uv, workers):
    python_version = (ROOT / ".python-version").read_text().strip()
    run(uv, "python", "install", python_version)
    managed_python = subprocess.check_output(
        [uv, "python", "find", "--managed-python", python_version], cwd=ROOT, text=True
    ).strip()
    run(managed_python, "tools/check_build_lock.py")
    run(uv, "sync", "--locked")
    for tool, extra in (
        ("generate_artifacts", ["--check"]),
        ("migration_journal", []),
        ("check_dependencies", []),
        ("check_public_tree", []),
    ):
        run(uv, "run", "--locked", "python", f"tools/{tool}.py", *extra)
    run(uv, "run", "--locked", "ruff", "check", "src", "tests", "tools", "migrations")
    run(uv, "run", "--locked", "ruff", "format", "--check", "src", "tests", "tools", "migrations")
    run(uv, "run", "--locked", "pytest", "-q", "-n", workers, "-p", "no:cacheprovider", "tests")
    run(uv, "audit", "--locked", "--preview-features", "audit-command")
    run(uv, "run", "--locked", "python", "tools/check_client.py")
    run("git", "diff", "--check")


if __name__ == "__main__":
    main()
