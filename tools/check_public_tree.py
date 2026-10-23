#!/usr/bin/env python3
"""Reject accidental private files and personal home paths in the public source tree.

This is a packaging/privacy guard, not a comprehensive secret or security scanner.
It checks tracked and unignored new files without reading ignored local state.
"""

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_PARTS = {".secrets", "operations-archive", "node_modules", ".venv", "__pycache__"}
FORBIDDEN_NAMES = {
    ".env",
    "credentials",
    "id_rsa",
    "id_ed25519",
    "AGENTS.override.md",
    "source-activation-status.json",
    "checkpoint-readiness.json",
    "current-runtime.json",
    "current-topology.json",
    "next-004-current-source-readiness-contract.json",
    "next-004-current-source-readiness-contract-v5.json",
}
PRIVATE_PATH = re.compile(
    rb"/(?:home|Users)/[A-Za-z0-9_.-]+/|[A-Za-z]:\\+Users\\+[A-Za-z0-9_.-]+\\+"
)
PRIVATE_KEY = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")


def main():
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        capture_output=True,
        check=True,
    )
    files = sorted(set(result.stdout.decode().strip("\0").split("\0")))
    if not files or files == [""]:
        raise SystemExit("No source files were found; run this in the public Git checkout.")
    issues = []
    for name in files:
        path = ROOT / name
        if (
            path.is_symlink()
            or FORBIDDEN_PARTS.intersection(path.relative_to(ROOT).parts)
            or path.name in FORBIDDEN_NAMES
        ):
            issues.append((name, "private path or symlink"))
            continue
        if not path.is_file():
            continue  # A staged deletion has no distributed content.
        body = path.read_bytes()
        if PRIVATE_PATH.search(body):
            issues.append((name, "personal absolute home path"))
        if PRIVATE_KEY.search(body):
            issues.append((name, "private-key material"))
    if issues:
        for name, reason in issues:
            print(f"{name}: {reason}")
        raise SystemExit(1)
    print(f"Public-tree privacy guard passed for {len(files)} files.")


if __name__ == "__main__":
    main()
