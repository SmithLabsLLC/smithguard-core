#!/usr/bin/env python3
"""Run the contributor checks from any working directory."""

import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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
    run("git", "diff", "--check")
    print("Contributor checks passed.")


if __name__ == "__main__":
    main()
