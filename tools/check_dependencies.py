#!/usr/bin/env python3
"""Check exact dependency pins, lock coverage, and the scoped license register."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = PROJECT_ROOT / "pyproject.toml"
LOCKFILE = PROJECT_ROOT / "uv.lock"
REGISTER = PROJECT_ROOT / "dependency-license-register.json"
EXTRA_PIN = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)\[(?P<extras>[A-Za-z0-9,._-]+)\]==.*$")
EXACT_PIN = re.compile(
    r"^(?P<name>[A-Za-z0-9._-]+)(?:\[[A-Za-z0-9,._-]+\])?==(?P<version>[^;\s]+)$"
)


def _pins(values: list[str]) -> dict[str, str]:
    pins: dict[str, str] = {}
    for value in values:
        match = EXACT_PIN.fullmatch(value)
        if match is None:
            raise SystemExit(f"dependency is not exactly pinned: {value}")
        pins[match.group("name").lower().replace("_", "-")] = match.group("version")
    return pins


def _runtime_extras(project: dict, lock: dict) -> dict[str, str]:
    requested: dict[str, set[str]] = {}
    for value in project["project"]["dependencies"]:
        match = EXTRA_PIN.fullmatch(value)
        if match is not None:
            name = match.group("name").lower().replace("_", "-")
            requested[name] = set(match.group("extras").split(","))
    packages = {
        package["name"].lower().replace("_", "-"): package
        for package in lock["package"]
        if "version" in package
    }
    # The register covers exact direct pins plus the companion distributions an
    # extra pulls from the same project (psycopg[binary,pool] -> psycopg-binary,
    # psycopg-pool). Third-party packages an extra adds (jsonschema[format] ->
    # fqdn and friends) are ordinary transitive dependencies covered by the lock.
    extras: dict[str, str] = {}
    for name, names in requested.items():
        optional = packages.get(name, {}).get("optional-dependencies", {})
        for extra in sorted(names):
            for entry in optional.get(extra, ()):
                extra_name = entry["name"].lower().replace("_", "-")
                if extra_name not in packages:
                    raise SystemExit(f"runtime extra is not locked: {extra_name}")
                if extra_name.startswith(f"{name}-"):
                    extras[extra_name] = packages[extra_name]["version"]
    if not extras:
        raise SystemExit("no runtime companion extras were resolved from the lock")
    return extras


def main() -> None:
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    runtime = _pins(project["project"]["dependencies"])
    development = _pins(project["dependency-groups"]["dev"])
    build = _pins(project["build-system"]["requires"])
    expected = runtime | development | build
    expected_scopes = (
        {name: "runtime" for name in runtime}
        | {name: "development" for name in development}
        | {name: "build" for name in build}
    )
    lock_expected = expected

    lock = tomllib.loads(LOCKFILE.read_text(encoding="utf-8"))
    locked = {
        package["name"].lower().replace("_", "-"): package["version"]
        for package in lock["package"]
        if "version" in package
    }
    for name, version in lock_expected.items():
        if locked.get(name) != version:
            raise SystemExit(f"lockfile does not contain the exact {name} pin")

    register = json.loads(REGISTER.read_text(encoding="utf-8"))
    if register.get("schema_version") != "1.0.0":
        raise SystemExit("unsupported dependency license register")
    registered = {entry["name"]: entry for entry in register["packages"]}
    for name, version in expected.items():
        entry = registered.get(name)
        if entry is None or entry.get("version") != version:
            raise SystemExit(f"license register does not cover the exact {name} pin")
        if not entry.get("license") or not entry.get("source"):
            raise SystemExit(f"license register entry is incomplete: {name}")
        if entry.get("scope") != expected_scopes[name]:
            raise SystemExit(f"license register entry has the wrong scope: {name}")

    # Runtime extras are whatever the lock resolves for the extras pyproject requests;
    # they are never re-typed here, so a psycopg bump is a one-file change.
    extras = _runtime_extras(project, lock)
    for name, version in extras.items():
        entry = registered.get(name)
        if locked.get(name) != version or entry is None or entry.get("version") != version:
            raise SystemExit(f"runtime extra is not locked and registered: {name}")
        if entry.get("scope") != "runtime-extra":
            raise SystemExit(f"runtime extra has the wrong license scope: {name}")

    for name, entry in registered.items():
        normalized = name.lower().replace("_", "-")
        if normalized not in locked:
            raise SystemExit(f"license register entry is not a locked package: {name}")
        if entry.get("version") != locked[normalized]:
            raise SystemExit(f"license register entry does not match the lockfile: {name}")

    print(
        f"dependency pins, lock coverage, and {len(registered)} scoped license records are current"
    )


if __name__ == "__main__":
    main()
