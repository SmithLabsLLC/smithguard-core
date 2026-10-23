"""Dependency and retired-product isolation checks."""

from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SCANNED_CODE = (
    PACKAGE_ROOT / "src",
    PACKAGE_ROOT / "migrations",
    PACKAGE_ROOT / "tools",
)

LIVE_REBRAND_ROOTS = (
    PACKAGE_ROOT / "src",
    PACKAGE_ROOT / "tools",
    PACKAGE_ROOT / "deploy",
)
LEGACY_CUTOVER_FILES = {
    PACKAGE_ROOT / "deploy/postgresql/prepare-migration-role.sql",
    PACKAGE_ROOT / "src/smithguard/db/journal.py",
}
SERVER_ONLY_SQLITE_FILES = {
    PACKAGE_ROOT / "src/smithguard/anonymous_quota.py",
}


def test_dependency_pins_lock_and_scoped_licenses_are_current() -> None:
    result = subprocess.run(
        [sys.executable, str(PACKAGE_ROOT / "tools/check_dependencies.py")],
        cwd=PACKAGE_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "scoped license records are current" in result.stdout

    lock = tomllib.loads((PACKAGE_ROOT / "uv.lock").read_text(encoding="utf-8"))
    for package in lock["package"]:
        source = package.get("source", {})
        if package["name"] == "smithguard":
            assert source == {"editable": "."}
        else:
            assert source.get("registry") == "https://pypi.org/simple"


def test_new_product_code_has_no_retired_namespace_or_unapproved_sqlite() -> None:
    banned_everywhere = (
        "goodboy." + "sec_",
        "pipelines/" + "sec",
        "goodboy-sec-" + "pilot",
    )
    sqlite_markers = (
        "sqlite" + "3",
        "sqlite:" + "//",
    )
    for root in SCANNED_CODE:
        for path in root.rglob("*"):
            if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            text = path.read_text(encoding="utf-8")
            for value in banned_everywhere:
                assert value not in text, f"{path.relative_to(PACKAGE_ROOT)} contains {value}"
            if path in SERVER_ONLY_SQLITE_FILES:
                continue
            for value in sqlite_markers:
                assert value not in text, f"{path.relative_to(PACKAGE_ROOT)} contains {value}"


def test_server_only_sqlite_exception_is_exact_and_present() -> None:
    assert {
        PACKAGE_ROOT / "src/smithguard/anonymous_quota.py",
    } == SERVER_ONLY_SQLITE_FILES
    assert all(path.is_file() for path in SERVER_ONLY_SQLITE_FILES)


def test_package_sources_and_configuration_are_ascii() -> None:
    roots = (
        *SCANNED_CODE,
        PACKAGE_ROOT / "tests",
    )
    standalone = (
        PACKAGE_ROOT / "README.md",
        PACKAGE_ROOT / "pyproject.toml",
        PACKAGE_ROOT / "alembic.ini",
        PACKAGE_ROOT / "dependency-license-register.json",
    )
    paths = list(standalone)
    for root in roots:
        paths.extend(
            path
            for path in root.rglob("*")
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
        )
    for path in paths:
        path.read_bytes().decode("ascii")


def test_live_package_surfaces_use_only_smithguard_product_identifiers() -> None:
    banned = (
        "SmithGuard " + "Security",
        "goodboy-" + "security",
        "goodboy_" + "security",
        "GOODBOY_" + "SECURITY",
        "security." + "smithlabs.ai",
        "Hosted " + "Watch",
        "hosted_" + "watch",
        "hosted-" + "watch",
        "goodboy_" + "hosted_watch",
    )
    standalone = (PACKAGE_ROOT / "README.md", PACKAGE_ROOT / "pyproject.toml")
    paths = list(standalone)
    for root in LIVE_REBRAND_ROOTS:
        paths.extend(
            path
            for path in root.rglob("*")
            if path.is_file()
            and path not in LEGACY_CUTOVER_FILES
            and "__pycache__" not in path.parts
            and path.suffix not in {".pyc", ".pyo"}
        )
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for value in banned:
            assert value not in text, f"{path.relative_to(PACKAGE_ROOT)} contains {value}"


def test_production_path_guard_sees_nested_creation_and_edits(tmp_path) -> None:
    from tests.support import tree_state

    root = tmp_path / "protected"
    (root / "a" / "b").mkdir(parents=True)
    existing = root / "a" / "b" / "state.json"
    existing.write_text("{}")
    absent = tmp_path / "absent"
    before = tree_state((root, absent))
    assert before[str(absent)] is None
    assert tree_state((root, absent)) == before

    existing.write_text('{"x": 1}')  # an edit to an existing file
    edited = tree_state((root, absent))
    assert edited != before

    (root / "a" / "b" / "new.json").write_text("{}")  # nested creation
    assert tree_state((root, absent)).keys() - edited.keys() == {str(root / "a" / "b" / "new.json")}
