"""Cold setup refuses incomplete backend records before importing build dependencies."""

from __future__ import annotations

import copy
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from tools import check_build_lock as checker

ROOT = Path(__file__).resolve().parents[1]


def _inputs() -> tuple[dict, dict]:
    return (
        tomllib.loads((ROOT / "pyproject.toml").read_text()),
        tomllib.loads((ROOT / "uv.lock").read_text()),
    )


@pytest.mark.audit_ids("AUD-BUILD-14")
def test_cold_preflight_rejects_missing_roots_and_transitive_packages() -> None:
    project, lock = _inputs()
    selected = checker.validate_build_lock(project, lock)
    assert {"hatchling", "editables", "packaging"} <= selected
    for name in selected:
        changed = {**lock, "package": [item for item in lock["package"] if item["name"] != name]}
        with pytest.raises(checker.BuildLockError, match="exact lock|missing from the lock"):
            checker.validate_build_lock(project, changed)


@pytest.mark.audit_ids("AUD-BUILD-14")
def test_cold_preflight_rejects_missing_hashes_and_invalid_artifact_records() -> None:
    project, lock = _inputs()
    selected = checker.validate_build_lock(project, lock)
    for name in selected:
        for field, value in (
            ("hash", None),
            ("hash", "sha256:invalid"),
            ("size", None),
            ("size", True),
            ("size", 0),
            ("url", "https://example.com/unreviewed.whl"),
            ("url", "https://files.pythonhosted.org/packages/example.whl?token=invalid"),
        ):
            changed = copy.deepcopy(lock)
            package = next(item for item in changed["package"] if item["name"] == name)
            package["wheels"][0][field] = value
            with pytest.raises(checker.BuildLockError, match="build artifact"):
                checker.validate_build_lock(project, changed)
        changed = copy.deepcopy(lock)
        package = next(item for item in changed["package"] if item["name"] == name)
        package["wheels"] = []
        with pytest.raises(checker.BuildLockError, match="wheels are missing"):
            checker.validate_build_lock(project, changed)
        if "sdist" in package:
            package["wheels"] = next(item for item in lock["package"] if item["name"] == name)[
                "wheels"
            ]
            package["sdist"].pop("hash", None)
            with pytest.raises(checker.BuildLockError, match="requires SHA-256"):
                checker.validate_build_lock(project, changed)


@pytest.mark.audit_ids("AUD-BUILD-14")
def test_cold_preflight_rejects_root_scope_and_source_drift() -> None:
    project, lock = _inputs()
    for key, value in (
        ("no-build-isolation-package", ["smithguard", "hatchling"]),
        ("no-build-isolation-package", []),
        ("no-build-isolation", True),
        ("default-groups", []),
    ):
        changed = copy.deepcopy(project)
        changed["tool"]["uv"][key] = value
        with pytest.raises(checker.BuildLockError, match="project-only isolation"):
            checker.validate_build_lock(changed, lock)
    for roots in (
        [],
        ["hatchling>=1"],
        ["hatchling==0.0.1"],
        [project["build-system"]["requires"][0]] * 2,
    ):
        changed = copy.deepcopy(project)
        changed["build-system"]["requires"] = roots
        with pytest.raises(checker.BuildLockError):
            checker.validate_build_lock(changed, lock)
    changed = copy.deepcopy(lock)
    backend = next(item for item in changed["package"] if item["name"] == "hatchling")
    original_version = backend["version"]
    backend["version"] = "0.0.1"
    with pytest.raises(checker.BuildLockError, match="exact lock"):
        checker.validate_build_lock(project, changed)
    backend["version"] = original_version
    backend["source"] = {"directory": "."}
    with pytest.raises(checker.BuildLockError, match="unreviewed source"):
        checker.validate_build_lock(project, changed)


@pytest.mark.audit_ids("AUD-BUILD-14")
def test_cold_preflight_runs_without_site_packages() -> None:
    result = subprocess.run(
        [sys.executable, "-I", "-S", str(ROOT / "tools/check_build_lock.py")],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    assert result.returncode == 0, result.stderr
    assert "complete artifact hashes" in result.stdout
