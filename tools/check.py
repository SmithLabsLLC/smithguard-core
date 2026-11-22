#!/usr/bin/env python3
"""Run the contributor checks from any working directory."""

import fcntl
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Audit SG22-31: the database suite and browser-style tests create many small files.
# Use a short, task-owned, disk-backed folder and check its free space and free file
# slots before starting, like the private gate.
MINIMUM = {"bytes": 4 * 1024**3, "inodes": 500_000}
MINIMUM_SYSTEM_TMP = {"bytes": 1024**3, "inodes": 100_000}


def require_capacity(path, minimum):
    stat = os.statvfs(path)
    free_bytes, free_inodes = stat.f_bavail * stat.f_frsize, stat.f_favail
    print(f"Check capacity {path}: {free_bytes} bytes, {free_inodes} inodes available", flush=True)
    if free_bytes < minimum["bytes"] or free_inodes < minimum["inodes"]:
        raise SystemExit(
            f"Insufficient temporary capacity at {path} (need {minimum['bytes']} bytes and "
            f"{minimum['inodes']} free file slots); "
            "set SMITHGUARD_CHECK_TMP to a disk-backed folder."
        )


def task_temp():
    base = os.environ.get("SMITHGUARD_CHECK_TMP") or (
        "/var/tmp" if Path("/var/tmp").is_dir() else tempfile.gettempdir()
    )
    if not Path(base).is_dir():
        raise SystemExit(
            f"Temporary base {base} does not exist; create it or set SMITHGUARD_CHECK_TMP."
        )
    # Check capacity before creating anything, so a refusal leaves nothing behind.
    require_capacity(base, MINIMUM)
    if Path("/tmp").is_dir():
        require_capacity("/tmp", MINIMUM_SYSTEM_TMP)
    # A short root: pytest adds worker and test folders before AF_UNIX socket names.
    return tempfile.mkdtemp(prefix="sgc-", dir=base)


def run(*args):
    print("+", " ".join(args), flush=True)
    subprocess.run(args, cwd=ROOT, check=True)


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
    folder = task_temp()
    os.environ["TMPDIR"] = folder
    try:
        checks(uv, workers)
    except BaseException:
        print(f"Check temporary evidence retained at {folder}.", flush=True)
        raise
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
