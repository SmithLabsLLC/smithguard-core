"""Shared test fixtures use only disposable synthetic local state."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from smithguard import warning_dispatch
from smithguard.operational_health import EXPECTED_MIGRATION

from .support import DatabaseHandle, LocalPostgres, migrated_database, tree_state

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_EXAMPLES = REPO_ROOT / "contracts/v1/contract-examples.json"


@pytest.fixture
def enabled_warning_dispatch(tmp_path_factory, monkeypatch) -> Path:
    """Opt-in authority for synthetic provider tests, using the real file checks.

    No production paths or global guard bypass: tests can mutate this disposable
    controller file to exercise pause, invalid authority and release mismatches.
    """
    directory = tmp_path_factory.mktemp("warning-dispatch")
    directory.chmod(0o755)
    control = directory / "warning-dispatch.json"
    release = "a" * 40
    control.write_bytes(
        warning_dispatch.control_bytes(
            operation_id="20261002-" + "1" * 32,
            artifact_commit=release,
            discovery=True,
            recheck=True,
        )
    )
    control.chmod(0o644)
    monkeypatch.setattr(warning_dispatch, "CONTROL_DIRECTORY", directory)
    monkeypatch.setattr(warning_dispatch, "CONTROL_PATH", control)
    monkeypatch.setattr(warning_dispatch, "CONTROL_UID", os.getuid())
    monkeypatch.setattr(warning_dispatch, "_running_release", lambda: release)
    monkeypatch.setenv(warning_dispatch.DISPATCH_FLAG, "1")
    return control


@pytest.fixture(autouse=True)
def _ordinary_process_umask():
    """Run every test under the ordinary 022 umask, whatever the caller's shell uses.

    A few permission tests intentionally create group-readable directories; this keeps
    the suite independent of the operator's umask instead of documenting a rule.
    """
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


PRODUCTION_PATHS = (
    Path("/var/lib/smithguard"),
    Path("/etc/SmithGuard"),
    Path("/opt/SmithGuard"),
    Path("/var/lib/smithguard-subscription"),
)


@pytest.fixture(scope="session", autouse=True)
def _never_touch_production_paths():
    """Fail the run if a test (or a subprocess it starts) creates, edits or removes
    anything under a production path on this machine (audit item 125: an overnight
    run once wrote under /var/lib/smithguard)."""
    before = tree_state(PRODUCTION_PATHS)
    yield
    after = tree_state(PRODUCTION_PATHS)
    changed = sorted(
        path for path in before.keys() | after.keys() if before.get(path) != after.get(path)
    )
    assert not changed, f"tests changed production paths: {changed[:20]}"


@pytest.fixture(scope="session")
def postgres_cluster() -> LocalPostgres:
    cluster = LocalPostgres().start()
    try:
        yield cluster
    finally:
        cluster.close()


@pytest.fixture
def database(postgres_cluster: LocalPostgres) -> DatabaseHandle:
    handle = migrated_database(postgres_cluster)
    try:
        yield handle
    finally:
        handle.engine.dispose()


@pytest.fixture
def public_runtime_database(postgres_cluster: LocalPostgres) -> DatabaseHandle:
    """Disposable database at the exact reviewed public-runtime migration."""
    handle = migrated_database(postgres_cluster, revision=EXPECTED_MIGRATION)
    try:
        yield handle
    finally:
        handle.engine.dispose()


@pytest.fixture(scope="session")
def contract_examples() -> list[dict[str, Any]]:
    return json.loads(CONTRACT_EXAMPLES.read_text(encoding="utf-8"))["examples"]
