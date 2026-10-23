#!/usr/bin/env python3
"""Validate the complete locked backend before installing any project dependencies."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
PIN = re.compile(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9.!+_-]+)")
HASH = re.compile(r"sha256:[a-f0-9]{64}")


class BuildLockError(ValueError):
    """The declared backend cannot be prepared from complete locked artifacts."""


def _name(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_.-]+", value) is None:
        raise BuildLockError("invalid locked build package identity")
    return re.sub(r"[-_.]+", "-", value).lower()


def _artifact(record: object, name: str) -> None:
    if not isinstance(record, dict):
        raise BuildLockError(f"invalid build artifact: {name}")
    digest, size, url = (record.get(key) for key in ("hash", "size", "url"))
    if (
        not isinstance(digest, str)
        or HASH.fullmatch(digest) is None
        or type(size) is not int
        or size <= 0
        or not isinstance(url, str)
    ):
        raise BuildLockError(f"build artifact requires SHA-256, size and URL: {name}")
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "files.pythonhosted.org"
        or not parsed.path.startswith("/packages/")
        or parsed.query
        or parsed.fragment
    ):
        raise BuildLockError(f"build artifact is not on the reviewed public index: {name}")


def validate_build_lock(project: dict, lock: dict) -> set[str]:
    uv = project.get("tool", {}).get("uv", {})
    if (
        uv.get("no-build-isolation-package") != ["smithguard"]
        or uv.get("no-build-isolation", False)
        or uv.get("default-groups", ["dev"]) != ["dev"]
    ):
        raise BuildLockError(
            "setup must use the default dev group and project-only isolation override"
        )
    requirements = project.get("build-system", {}).get("requires")
    if not isinstance(requirements, list) or not requirements:
        raise BuildLockError("project build requirements are missing")
    dev = project.get("dependency-groups", {}).get("dev", [])
    roots: dict[str, str] = {}
    for requirement in requirements:
        match = PIN.fullmatch(requirement) if isinstance(requirement, str) else None
        if match is None or requirement not in dev:
            raise BuildLockError("each exact build root must be in the default development group")
        name, version = _name(match[1]), match[2]
        if name in roots:
            raise BuildLockError(f"duplicate build root: {name}")
        roots[name] = version
    packages = {}
    for package in lock.get("package", []):
        if not isinstance(package, dict):
            raise BuildLockError("invalid lock package record")
        name = _name(package.get("name"))
        if name in packages:
            raise BuildLockError(f"duplicate locked package: {name}")
        packages[name] = package
    for name, version in roots.items():
        if packages.get(name, {}).get("version") != version:
            raise BuildLockError(f"build root differs from the exact lock: {name}")

    pending = list(roots)
    selected: set[str] = set()
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        package = packages.get(name)
        if package is None:
            raise BuildLockError(f"build dependency is missing from the lock: {name}")
        if package.get("source") != {"registry": "https://pypi.org/simple"}:
            raise BuildLockError(f"build dependency has an unreviewed source: {name}")
        if not isinstance(package.get("version"), str):
            raise BuildLockError(f"build dependency version is missing: {name}")
        wheels = package.get("wheels")
        if not isinstance(wheels, list) or not wheels:
            raise BuildLockError(f"locked build wheels are missing: {name}")
        for wheel in wheels:
            _artifact(wheel, name)
        if "sdist" in package:
            _artifact(package["sdist"], name)
        selected.add(name)
        edges = package.get("dependencies", [])
        optional = package.get("optional-dependencies", {})
        if not isinstance(edges, list) or not isinstance(optional, dict):
            raise BuildLockError(f"invalid locked build dependency edges: {name}")
        # Conservatively validate every recorded platform/extra branch before uv
        # evaluates the actual environment. No third-party module is imported here.
        groups = [edges, *optional.values()]
        for group in groups:
            if not isinstance(group, list):
                raise BuildLockError(f"invalid locked build dependency group: {name}")
            for edge in group:
                if not isinstance(edge, dict):
                    raise BuildLockError(f"invalid locked build dependency edge: {name}")
                pending.append(_name(edge.get("name")))
    return selected


def main() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    try:
        selected = validate_build_lock(project, lock)
    except BuildLockError as error:
        raise SystemExit(f"build setup refused: {error}") from error
    print(f"build lock preflight passed: {len(selected)} packages with complete artifact hashes")


if __name__ == "__main__":
    main()
