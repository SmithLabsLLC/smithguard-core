#!/usr/bin/env python3
"""Build, verify, install, and activate a closed SmithGuard runtime release."""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import gzip
import hashlib
import importlib.metadata
import io
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.request
import uuid
import zipfile
from collections import defaultdict, deque
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit

from smithguard.deploy import site as product_site
from smithguard.deploy.mutation import MutationError, current_owner, release_mutation
from smithguard.fsio import fsync_directory, write_exclusive
from smithguard.identifiers import SHA1_HEX, SHA256_HEX, canonical_json_bytes, canonical_json_line

REPO_ROOT = Path(__file__).resolve().parents[3]
PACKAGE_ROOT = REPO_ROOT
BUILDER_PATH = "tools/runtime_release.py"
PROJECT_PATH = "pyproject.toml"
LOCK_PATH = "uv.lock"
ARCHIVE_APP_ROOT = "app"
SOURCE_RIGHTS_PATH = "contracts/v1/source-rights-register.json"
# Git history before BRAND-001 records the same append-only register at this path.
# It is lookup-only history and is never packaged as a live policy surface.
LEGACY_SOURCE_RIGHTS_PATH = "packages/security-contracts/v1/source-rights-register.json"
SOURCE_RIGHTS_HISTORY_PATHS = (SOURCE_RIGHTS_PATH, LEGACY_SOURCE_RIGHTS_PATH)
BUILDER_ID = "smithguard:runtime-release-builder:v1"
MANIFEST_NAME = "RELEASE-MANIFEST.json"
SBOM_NAME = "SBOM.cdx.json"
PROVENANCE_NAME = "PROVENANCE.intoto.json"
RUNTIME_LOCK_NAME = "RUNTIME-LOCK.json"
REQUIREMENTS_NAME = "requirements.txt"
MAX_ARCHIVE_BYTES = 536_870_912
MAX_ARCHIVE_MEMBERS = 512
MAX_UNCOMPRESSED_BYTES = 1_073_741_824
MAX_MEMBER_BYTES = 134_217_728
SHA256_PATTERN = SHA256_HEX
COMMIT_PATTERN = SHA1_HEX
UV_VERSION_PATTERN = re.compile(r"^uv [0-9]+\.[0-9]+\.[0-9]+(?: \([A-Za-z0-9_.-]+\))?$")
REQUIREMENT_LINE = re.compile(
    r"^(?P<requirement>[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[^ ]+) "
    r"--hash=sha256:(?P<sha256>[a-f0-9]{64})$"
)
EXACT_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9_.-]+)"
    r"(?:\[(?P<extras>[A-Za-z0-9_,.-]+)\])?"
    r"==(?P<version>[^;\s]+)$"
)

SCRIPT_NAME = re.compile(r"^smithguard-[a-z0-9-]+$")
SCRIPT_TARGET = re.compile(r"^smithguard(?:\.[a-z_][a-z0-9_]*)+:[a-z_][a-z0-9_]*$")


@dataclass(frozen=True)
class ProjectBoundary:
    """The reviewed project surface, read from pyproject at the release commit.

    pyproject.toml is the single source for runtime dependencies, build requirements
    and console scripts; this type carries them through the build and install steps
    so no copy of those lists lives in the builder.
    """

    version: str
    runtime_requirements: tuple[str, ...]
    build_requirements: tuple[str, ...]
    scripts: Mapping[str, str]

    @property
    def script_names(self) -> tuple[str, ...]:
        return tuple(self.scripts)


# Tracked files under src/smithguard that never ship. The whole tracked tree ships
# otherwise, so a new module cannot be dropped silently; every entry here must exist
# at the release commit so a stale exclusion is caught. Empty means the tree ships
# whole.
EXCLUDED_RUNTIME_FILES: tuple[str, ...] = ()
RUNTIME_POLICY_PATHS = (
    "contracts/v1/malware-authority-policy.json",
    "contracts/v1/source-governance-policy.json",
    SOURCE_RIGHTS_PATH,
    "contracts/v1/xai-spend-policy.json",
)
RUNTIME_RECORD_PATHS = (
    "docs/operations/STATUS.md",
    "docs/operations/current-runtime.json",
    "docs/operations/current-topology.json",
)
RUNTIME_DEPLOY_DIRECTORIES = (
    "deploy/systemd",
    "deploy/env",
    "deploy/nginx",
    "deploy/postgresql",
    "deploy/sysusers.d",
    "deploy/tmpfiles.d",
    "deploy/aws",
    "deploy/cloudflare",
)
# Trial operators/units ship inert, outside controller-managed systemd units.
RUNTIME_TRIAL_UNIT_PATHS = (
    "deploy/warning-trial/smithguard-warning-trial-broker.service",
    "deploy/warning-trial/smithguard-warning-trial-monitor.service",
    "deploy/warning-trial/smithguard-warning-trial-emergency.service",
)
RUNTIME_TRIAL_INSTALL_PATHS = (
    "deploy/warning-trial/sysusers.conf",
    "deploy/warning-trial/tmpfiles.conf",
)
RUNTIME_TRIAL_TOOLS = (
    "tools/observe_warning_timers.py",
    "tools/warning_trial_engine.py",
    "tools/warning_trial_host.py",
    "tools/supervise_warning_trial.py",
)
# Wheel members that must never appear, checked again after the build.
FORBIDDEN_WHEEL_FILES = tuple(f"smithguard/{path}" for path in EXCLUDED_RUNTIME_FILES)
# Packaged units the controller never stops, starts, installs or drains. The tunnel
# runs as the host's cloudflared identity from a host-managed credential and must
# keep serving the public origin across every activation and rollback; only the
# owner's provisioning touches it. Any other packaged unit must appear in
# SYSTEMD_UNITS, which build_release checks against the tracked deploy/systemd
# tree so a new unit file can never ship unlisted.
HOST_MANAGED_UNITS = ("smithguard-cloudflared.service",)
# Retired one-shots are no longer packaged. A host may still have the old unit file
# (inert, nothing wants it); the drain still waits if someone started one by hand.
RETIRED_ONESHOT_SERVICES = ("smithguard-github-catalog-backfill.service",)
SYSTEMD_UNITS = (
    "smithguard-bulletin-status.service",
    "smithguard-bulletin-status.timer",
    "smithguard-api.service",
    "smithguard-collect.service",
    "smithguard-collect.timer",
    "smithguard-discovery.service",
    "smithguard-discovery.timer",
    "smithguard-health.service",
    "smithguard-health.timer",
    "smithguard-metrics-publisher.service",
    "smithguard-metrics-publisher.timer",
    "smithguard-migrate.service",
    "smithguard-official-notices.service",
    "smithguard-official-notices.timer",
    "smithguard-openssf-catalog.service",
    "smithguard-openssf-catalog.timer",
    "smithguard-openssf-shadow.service",
    "smithguard-openssf-shadow.timer",
    "smithguard-signals.service",
    "smithguard-signals.timer",
    "smithguard-supplemental.service",
    "smithguard-supplemental.timer",
    "smithguard-warning-recheck.service",
    "smithguard-warning-recheck.timer",
)


class ReleaseError(RuntimeError):
    """The release cannot be built, verified, installed, or activated safely."""


def packaged_systemd_units(paths: Iterable[str]) -> tuple[str, ...]:
    """Return the controller-managed unit names among packaged deploy/systemd paths."""
    names = sorted(
        PurePosixPath(path).name for path in paths if path.endswith((".service", ".timer"))
    )
    return tuple(name for name in names if name not in HOST_MANAGED_UNITS)


def _verify_systemd_unit_inventory(commit: str) -> None:
    """Refuse a build whose packaged units differ from the controller's inventory."""
    packaged = set(packaged_systemd_units(_tracked_files(commit, "deploy/systemd")))
    listed = set(SYSTEMD_UNITS)
    if packaged != listed:
        raise ReleaseError(
            "packaged systemd units differ from the controller inventory: "
            f"unlisted={sorted(packaged - listed)} missing={sorted(listed - packaged)}"
        )


IDENTITY_PATTERN = re.compile(r"^smithguard-[a-z]+$")
SYSUSERS_PATH = "deploy/sysusers.d/smithguard.conf"


def packaged_identities(body: bytes) -> tuple[str, ...]:
    """Return the service identities a packaged sysusers.d file declares, in file order."""
    try:
        text = body.decode("ascii")
    except UnicodeDecodeError as error:
        raise ReleaseError("release sysusers inventory is not ASCII") from error
    identities: list[str] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0] != "u":
            continue
        name = parts[1]
        if IDENTITY_PATTERN.fullmatch(name) is None or name in identities:
            raise ReleaseError("release sysusers inventory is invalid")
        identities.append(name)
    if not identities:
        raise ReleaseError("release sysusers inventory declares no identity")
    return tuple(identities)


SUPPORTED_PYTHON_TARGETS = ("3.12", "3.14")


def _assert_python_target(
    *,
    python_target: str = "3.12",
    implementation: str | None = None,
    version: tuple[int, int] | None = None,
) -> None:
    actual_implementation = implementation or platform.python_implementation()
    actual_version = version or (sys.version_info.major, sys.version_info.minor)
    if (
        python_target not in SUPPORTED_PYTHON_TARGETS
        or actual_implementation != "CPython"
        or actual_version != tuple(map(int, python_target.split(".")))
    ):
        raise ReleaseError(f"the reviewed runtime artifact requires CPython {python_target}")


def _project_python_target(project: Mapping[str, Any]) -> str:
    metadata = project.get("project")
    requirement = metadata.get("requires-python") if isinstance(metadata, Mapping) else None
    for target in SUPPORTED_PYTHON_TARGETS:
        if requirement == f"=={target}.*":
            return target
    raise ReleaseError("source project Python target is unsupported")


def _manifest_python_target(manifest: Mapping[str, Any]) -> str:
    target = manifest.get("target")
    if not isinstance(target, Mapping):
        raise ReleaseError("release manifest Python target is invalid")
    minor = target.get("python")
    if (
        minor not in SUPPORTED_PYTHON_TARGETS
        or target.get("implementation") != "CPython"
        or target.get("platform") != "linux_x86_64"
    ):
        raise ReleaseError("release manifest Python target is invalid")
    return str(minor)


def _probe_python_target(python: Path, python_target: str) -> None:
    if python_target not in SUPPORTED_PYTHON_TARGETS:
        raise ReleaseError("interpreter target is unsupported")
    script = (
        "import json,platform,struct,sys,sysconfig; "
        "print(json.dumps({'implementation':platform.python_implementation(),"
        "'python':'.'.join(map(str,sys.version_info[:2])),"
        "'platform':sys.platform,'machine':platform.machine(),"
        "'bits':struct.calcsize('P')*8,'soabi':sysconfig.get_config_var('SOABI'),"
        "'free_threaded':bool(sysconfig.get_config_var('Py_GIL_DISABLED'))}))"
    )
    try:
        result = subprocess.run(
            (str(python), "-I", "-S", "-B", "-c", script),
            cwd="/",
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        actual = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, UnicodeDecodeError, ValueError) as error:
        raise ReleaseError("release interpreter target probe failed") from error
    expected = {
        "implementation": "CPython",
        "python": python_target,
        "platform": "linux",
        "machine": "x86_64",
        "bits": 64,
        "soabi": f"cpython-{python_target.replace('.', '')}-x86_64-linux-gnu",
        "free_threaded": False,
    }
    if actual != expected:
        raise ReleaseError("release interpreter ABI differs from its declared target")


def _installer_python(python_target: str) -> Path:
    if python_target not in SUPPORTED_PYTHON_TARGETS:
        raise ReleaseError("installer Python target is unsupported")
    current = f"{sys.version_info.major}.{sys.version_info.minor}"
    python = (
        Path(sys.executable)
        if platform.python_implementation() == "CPython" and current == python_target
        else Path(f"/usr/bin/python{python_target}")
    )
    _probe_python_target(python, python_target)
    return python


def _canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _exact_requirement(value: str) -> tuple[str, tuple[str, ...], str]:
    match = EXACT_REQUIREMENT.fullmatch(value)
    if match is None:
        raise ReleaseError(f"runtime requirement is not one exact pin: {value}")
    extras = tuple(sorted(filter(None, (match.group("extras") or "").split(","))))
    return _canonical_name(match.group("name")), extras, match.group("version")


@dataclass(frozen=True, slots=True)
class SelectedWheel:
    name: str
    version: str
    filename: str
    url: str
    sha256: str
    size: int
    extras: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class VerifiedRelease:
    commit: str
    root: str
    manifest: Mapping[str, Any]
    files: Mapping[str, bytes]
    archive_sha256: str


def _canonical_json(value: Any) -> bytes:
    return canonical_json_line(value)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_private_output(path: Path, body: bytes) -> None:
    # An exclusive private create; the commit step asserts the final mode is 0o600.
    write_exclusive(path, body, mode=0o600, fsync_dir=False)


def _fsync_directory(path: Path) -> None:
    fsync_directory(path)


def _commit_private_output(temporary: Path, final: Path) -> None:
    os.link(temporary, final, follow_symlinks=False)
    try:
        temporary.unlink()
        metadata = os.lstat(final)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ReleaseError("release output permissions are not private")
    except BaseException:
        with suppress(OSError):
            final.unlink()
        raise


def _write_release_outputs(output: Path, archive: bytes, digest: str) -> Path:
    sidecar = output.with_name(output.name + ".sha256")
    if output.exists() or output.is_symlink():
        raise ReleaseError("release output already exists")
    if sidecar.exists() or sidecar.is_symlink():
        raise ReleaseError("release digest sidecar already exists")
    nonce = uuid.uuid4().hex
    temporary_output = output.with_name(f".{output.name}.{nonce}.tmp")
    temporary_sidecar = sidecar.with_name(f".{sidecar.name}.{nonce}.tmp")
    created_finals: list[Path] = []
    try:
        _write_private_output(temporary_output, archive)
        _write_private_output(
            temporary_sidecar,
            f"{digest}  {output.name}\n".encode("ascii"),
        )
        _commit_private_output(temporary_output, output)
        created_finals.append(output)
        _commit_private_output(temporary_sidecar, sidecar)
        created_finals.append(sidecar)
        _fsync_directory(output.parent)
    except BaseException:
        for path in (temporary_output, temporary_sidecar, *reversed(created_finals)):
            with suppress(OSError):
                path.unlink()
        with suppress(OSError):
            _fsync_directory(output.parent)
        raise
    return sidecar


def _tree_sha256(payload: Mapping[str, bytes]) -> str:
    entries = [
        {"path": path, "size": len(body), "sha256": _sha256(body)}
        for path, body in sorted(payload.items())
    ]
    return _sha256(_canonical_json(entries))


def _run(
    command: Sequence[str],
    *,
    cwd: Path = REPO_ROOT,
    env: Mapping[str, str] | None = None,
) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=dict(env) if env is not None else None,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode:
        detail = (completed.stderr or completed.stdout).strip()
        detail = detail[-2000:] if detail else "no command output"
        raise ReleaseError(f"command failed: {command[0]}: {detail}")
    return completed.stdout.strip()


def _git(*arguments: str) -> str:
    return _run(("git", *arguments))


def _resolve_commit(value: str) -> str:
    commit = _git("rev-parse", "--verify", f"{value}^{{commit}}")
    if not COMMIT_PATTERN.fullmatch(commit):
        raise ReleaseError("Git did not resolve one full commit")
    return commit


def _git_blob(commit: str, path: str) -> bytes:
    completed = subprocess.run(
        ("git", "show", f"{commit}:{path}"),
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
    )
    if completed.returncode:
        raise ReleaseError(f"required source path is absent from the release commit: {path}")
    return completed.stdout


def _source_revision_maps(
    document: Mapping[str, Any],
    *,
    allow_missing_history: bool = False,
) -> tuple[dict[str, Mapping[str, Any]], dict[str, tuple[Mapping[str, Any], ...]]]:
    raw_profiles = document.get("source_profiles")
    raw_histories = document.get("source_revisions")
    if not isinstance(raw_profiles, list) or (
        not isinstance(raw_histories, list)
        and not (allow_missing_history and raw_histories is None)
    ):
        raise ReleaseError("source rights revision boundary is invalid")
    profiles: dict[str, Mapping[str, Any]] = {}
    for profile in raw_profiles:
        if not isinstance(profile, Mapping) or not isinstance(profile.get("source"), Mapping):
            raise ReleaseError("source rights revision boundary is invalid")
        source = profile["source"]
        source_id = source.get("id")
        if not isinstance(source_id, str) or source_id in profiles:
            raise ReleaseError("source rights revision boundary is invalid")
        profiles[source_id] = source
    histories: dict[str, tuple[Mapping[str, Any], ...]] = {}
    for history in raw_histories or ():
        if not isinstance(history, Mapping):
            raise ReleaseError("source rights revision boundary is invalid")
        source_id = history.get("source_id")
        revisions = history.get("revisions")
        if (
            not isinstance(source_id, str)
            or source_id in histories
            or not isinstance(revisions, list)
            or not revisions
            or not all(isinstance(entry, Mapping) for entry in revisions)
        ):
            raise ReleaseError("source rights revision boundary is invalid")
        histories[source_id] = tuple(revisions)
    if histories and set(profiles) != set(histories):
        raise ReleaseError("source rights revision boundary is incomplete")
    for source_id, revisions in histories.items():
        source = profiles[source_id]
        for expected_revision, entry in enumerate(revisions, start=1):
            if entry.get("revision") != expected_revision:
                raise ReleaseError("source rights revision history is not contiguous")
        source_revision = source.get("revision")
        if not isinstance(source_revision, int) or isinstance(source_revision, bool):
            raise ReleaseError("source rights revision boundary is invalid")
        canonical = canonical_json_bytes(source)
        if revisions[-1].get("revision") != source_revision or revisions[-1].get(
            "source_sha256"
        ) != "sha256:" + _sha256(canonical):
            raise ReleaseError("source rights revision head differs from current content")
    return profiles, histories


def _validate_source_revision_transition(
    previous: Mapping[str, Any],
    current: Mapping[str, Any],
) -> None:
    previous_profiles, previous_histories = _source_revision_maps(
        previous,
        allow_missing_history=True,
    )
    current_profiles, current_histories = _source_revision_maps(current)
    if not set(previous_profiles).issubset(current_profiles):
        raise ReleaseError("a reviewed source or its immutable history was removed")
    if not previous_histories:
        for source_id, previous_source in previous_profiles.items():
            current_source = current_profiles[source_id]
            current_history = current_histories[source_id]
            previous_revision = previous_source.get("revision")
            current_revision = current_source.get("revision")
            if (
                not isinstance(previous_revision, int)
                or isinstance(previous_revision, bool)
                or not isinstance(current_revision, int)
                or isinstance(current_revision, bool)
                or current_revision not in {previous_revision, previous_revision + 1}
                or len(current_history) != current_revision
                or current_history[-1].get("revision") != current_revision
            ):
                raise ReleaseError("initial source history does not match its source revisions")
        for source_id in set(current_profiles) - set(previous_profiles):
            source = current_profiles[source_id]
            history = current_histories[source_id]
            if source.get("revision") != 1 or len(history) != 1:
                raise ReleaseError("a new source did not begin with revision one")
        return
    for source_id, previous_source in previous_profiles.items():
        current_source = current_profiles[source_id]
        previous_history = previous_histories[source_id]
        current_history = current_histories[source_id]
        if current_history[: len(previous_history)] != previous_history:
            raise ReleaseError("a prior source revision history entry changed")
        if current_source == previous_source:
            if current_history != previous_history:
                raise ReleaseError("source revision history advanced without source content")
            continue
        # One release may contain several reviewed revisions (including a failed
        # pre-release attempt). Preserve every entry; Git commit boundaries must
        # not force their immutable history to be collapsed. The maps above verify
        # contiguous numbering/current hashes, and the prefix check forbids edits.
        previous_revision = previous_source.get("revision")
        current_revision = current_source.get("revision")
        if (
            not isinstance(previous_revision, int)
            or isinstance(previous_revision, bool)
            or not isinstance(current_revision, int)
            or isinstance(current_revision, bool)
            or current_revision <= previous_revision
            or len(current_history) - len(previous_history) != current_revision - previous_revision
            or current_history[-1].get("revision") != current_revision
        ):
            raise ReleaseError("changed source content did not append contiguous revisions")
        previous_content = {
            key: value for key, value in previous_source.items() if key != "revision"
        }
        current_content = {key: value for key, value in current_source.items() if key != "revision"}
        if previous_content == current_content:
            raise ReleaseError("source revision advanced without a content change")
    for source_id in set(current_profiles) - set(previous_profiles):
        source = current_profiles[source_id]
        history = current_histories[source_id]
        if source.get("revision") != 1 or len(history) != 1 or history[0].get("revision") != 1:
            raise ReleaseError("a new source did not begin with revision one")


def _assert_source_revision_transition(commit: str) -> None:
    try:
        current_blob = _git_blob(commit, SOURCE_RIGHTS_PATH)
        current = json.loads(current_blob)
        previous = None
        prior_register_found = False
        visited: set[tuple[str, str]] = set()
        for history_path in SOURCE_RIGHTS_HISTORY_PATHS:
            ancestors = _git(
                "log",
                "--format=%H",
                f"{commit}^",
                "--",
                history_path,
            ).splitlines()
            for ancestor in ancestors:
                lookup = (ancestor, history_path)
                if lookup in visited:
                    continue
                visited.add(lookup)
                try:
                    previous_blob = _git_blob(ancestor, history_path)
                except ReleaseError:
                    # A rename/deletion commit may appear in the old-path history even
                    # though that commit no longer contains the old path.
                    continue
                prior_register_found = True
                if previous_blob != current_blob:
                    previous = json.loads(previous_blob)
                    break
            if previous is not None:
                break
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseError("source rights revision boundary is not valid JSON") from error
    if previous is None:
        if not prior_register_found:
            raise ReleaseError("no prior source rights register baseline is available")
        if not isinstance(current, Mapping):
            raise ReleaseError("source rights revision boundary is invalid")
        # A newly extracted repository can carry one unchanged, already versioned
        # register from its first import through its first release. Its prior Git copy
        # is the immutable baseline; the register must still pass the complete internal
        # history checks before the release may proceed.
        _source_revision_maps(current)
        return
    if not isinstance(previous, Mapping) or not isinstance(current, Mapping):
        raise ReleaseError("source rights revision boundary is invalid")
    _validate_source_revision_transition(previous, current)


def _tracked_files(commit: str, prefix: str) -> tuple[str, ...]:
    output = _git("ls-tree", "-r", "--name-only", commit, "--", prefix)
    paths = tuple(line for line in output.splitlines() if line)
    if not paths:
        raise ReleaseError(f"release input directory is empty: {prefix}")
    return paths


def _assert_release_commit(commit: str) -> None:
    if _resolve_commit("HEAD") != commit:
        raise ReleaseError("the release commit must be the checked-out HEAD")
    if os.environ.get("CI") == "true":
        if _git("status", "--porcelain"):
            raise ReleaseError("the worktree must be clean before a CI runtime release build")
        try:
            _git("merge-base", "--is-ancestor", commit, "refs/remotes/origin/main")
        except ReleaseError as error:
            raise ReleaseError(
                "the CI release commit must be an ancestor of origin/main"
            ) from error
        return
    if _git("branch", "--show-current") != "main":
        raise ReleaseError("runtime releases may be built only from main")
    status = _git("status", "--porcelain", "--untracked-files=no")
    if status:
        raise ReleaseError("tracked files must be clean before a runtime release build")
    try:
        remote = _resolve_commit("refs/remotes/origin/main")
    except ReleaseError as error:
        raise ReleaseError("refreshed origin/main is required before a release build") from error
    if remote != commit:
        raise ReleaseError("the release commit must match refreshed origin/main")


def _project_at_commit(commit: str) -> Mapping[str, Any]:
    return tomllib.loads(_git_blob(commit, PROJECT_PATH).decode("utf-8"))


def _runtime_pyproject(boundary: ProjectBoundary, python_target: str = "3.12") -> bytes:
    dependency_lines = "\n".join(f'  "{value}",' for value in boundary.runtime_requirements)
    build_requirements = json.dumps(list(boundary.build_requirements))
    script_lines = "\n".join(f'{name} = "{target}"' for name, target in boundary.scripts.items())
    content = f"""[project]
name = "smithguard"
version = "{boundary.version}"
description = "Evidence-first SmithGuard production runtime"
requires-python = "=={python_target}.*"
dependencies = [
{dependency_lines}
]

[project.scripts]
{script_lines}

[build-system]
requires = {build_requirements}
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/smithguard"]
"""
    return content.encode("ascii")


def _validate_project_boundary(project: Mapping[str, Any]) -> ProjectBoundary:
    """Read and shape-check the project surface at the release commit."""
    build_system = project.get("build-system")
    if (
        not isinstance(build_system, Mapping)
        or not isinstance(build_system.get("requires"), list)
        or not build_system["requires"]
        or build_system.get("build-backend") != "hatchling.build"
        or "backend-path" in build_system
    ):
        raise ReleaseError("project build requirements differ from the reviewed build root")
    build_requirements = tuple(build_system["requires"])
    build_names = [_exact_requirement(value)[0] for value in build_requirements]
    if "hatchling" not in build_names or len(build_names) != len(set(build_names)):
        raise ReleaseError("project build requirements differ from the reviewed build root")
    metadata = project.get("project")
    if not isinstance(metadata, Mapping):
        raise ReleaseError("project metadata is missing")
    version = metadata.get("version")
    dependencies = metadata.get("dependencies")
    if not isinstance(version, str) or not isinstance(dependencies, list) or not dependencies:
        raise ReleaseError("project version or dependencies are invalid")
    runtime_requirements = tuple(dependencies)
    runtime_names = [_exact_requirement(value)[0] for value in runtime_requirements]
    if len(runtime_names) != len(set(runtime_names)):
        raise ReleaseError("project dependencies duplicate a package")
    scripts = metadata.get("scripts")
    if not isinstance(scripts, Mapping) or not scripts:
        raise ReleaseError("project scripts are missing")
    for name, target in scripts.items():
        if (
            not isinstance(name, str)
            or not isinstance(target, str)
            or SCRIPT_NAME.fullmatch(name) is None
            or SCRIPT_TARGET.fullmatch(target) is None
        ):
            raise ReleaseError(f"project console script is outside the package boundary: {name}")
    return ProjectBoundary(
        version=version,
        runtime_requirements=runtime_requirements,
        build_requirements=build_requirements,
        scripts=dict(scripts),
    )


def archive_console_scripts(files: Mapping[str, bytes]) -> tuple[str, ...]:
    """Console scripts the installer must relocate, read from the archive's own wheel.

    The application wheel's console_scripts entry points are generated from the same
    pyproject boundary the builder read, and every archive, old or new, carries that
    wheel. Reading them there keeps the archive path set identical for the
    controllers already installed on the host.
    """
    wheels = [
        path
        for path in files
        if path.startswith(f"{ARCHIVE_APP_ROOT}/wheelhouse/smithguard-") and path.endswith(".whl")
    ]
    if len(wheels) != 1:
        raise ReleaseError("release archive has no single application wheel")
    return _wheel_console_scripts(files[wheels[0]])


def installed_tree_console_scripts(release: Path) -> tuple[str, ...]:
    """The same console-script authority, read from an installed release directory."""
    wheelhouse = release / ARCHIVE_APP_ROOT / "wheelhouse"
    try:
        wheels = sorted(
            entry
            for entry in wheelhouse.iterdir()
            if entry.name.startswith("smithguard-")
            and entry.name.endswith(".whl")
            and entry.is_file()
            and not entry.is_symlink()
        )
        if len(wheels) != 1:
            raise ReleaseError("installed release has no single application wheel")
        return _wheel_console_scripts(wheels[0].read_bytes())
    except OSError as error:
        raise ReleaseError("installed release wheelhouse is unavailable") from error


def _wheel_console_scripts(wheel: bytes) -> tuple[str, ...]:
    try:
        with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
            names = [
                name for name in archive.namelist() if name.endswith(".dist-info/entry_points.txt")
            ]
            if len(names) != 1:
                raise ReleaseError("application wheel entry points are missing or duplicated")
            text = archive.read(names[0]).decode("utf-8")
    except (OSError, UnicodeDecodeError, zipfile.BadZipFile) as error:
        raise ReleaseError("application wheel entry points are unreadable") from error
    scripts: dict[str, str] = {}
    section = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip()
            continue
        if section != "console_scripts" or "=" not in stripped:
            continue
        name, target = (part.strip() for part in stripped.split("=", 1))
        if SCRIPT_NAME.fullmatch(name) is None or SCRIPT_TARGET.fullmatch(target) is None:
            raise ReleaseError(f"application wheel console script is outside the package: {name}")
        scripts[name] = target
    if not scripts:
        raise ReleaseError("application wheel declares no console scripts")
    return tuple(scripts)


def _runtime_source_files(commit: str) -> tuple[str, ...]:
    """Select the tracked runtime source tree minus the explicit exclusions.

    Selection is the tracked tree itself, so a module nothing imports still ships and
    a dynamic import cannot hide a drop. A stale exclusion fails the build.
    """
    prefix = "src/smithguard/"
    tracked = {
        path.removeprefix(prefix)
        for path in _tracked_files(commit, prefix.removesuffix("/"))
        if not path.endswith((".pyc", ".pyo")) and "__pycache__" not in PurePosixPath(path).parts
    }
    stale = set(EXCLUDED_RUNTIME_FILES) - tracked
    if stale:
        raise ReleaseError(f"runtime exclusions name untracked files: {sorted(stale)}")
    selected = tracked - set(EXCLUDED_RUNTIME_FILES)
    if "__init__.py" not in selected:
        raise ReleaseError("runtime source tree is missing its package root")
    return tuple(sorted(selected))


def _stage_runtime_source(
    commit: str, target: Path, boundary: ProjectBoundary, python_target: str = "3.12"
) -> None:
    (target / "src/smithguard").mkdir(parents=True)
    (target / "pyproject.toml").write_bytes(_runtime_pyproject(boundary, python_target))
    prefix = "src/smithguard/"
    for relative in _runtime_source_files(commit):
        destination = target / "src/smithguard" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(_git_blob(commit, prefix + relative))


def _lock_packages(lock: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    packages: dict[str, Mapping[str, Any]] = {}
    for package in lock.get("package", []):
        if not isinstance(package, Mapping) or not isinstance(package.get("name"), str):
            raise ReleaseError("lockfile contains an invalid package")
        name = _canonical_name(package["name"])
        if name in packages:
            raise ReleaseError(f"lockfile contains duplicate package identities: {name}")
        packages[name] = package
    return packages


def _marker_applies(value: object) -> bool:
    if value is None:
        return True
    if not isinstance(value, str):
        raise ReleaseError("lockfile marker is invalid")
    try:
        from packaging.markers import Marker, default_environment

        return Marker(value).evaluate(default_environment())
    except Exception as error:
        raise ReleaseError(f"lockfile marker cannot be evaluated: {value}") from error


def _resolve_graph(
    lock: Mapping[str, Any],
    requirements: Sequence[str],
) -> tuple[dict[str, Mapping[str, Any]], dict[str, set[str]], dict[str, set[str]]]:
    # Builder-only validation: the archive verifier stays standard-library-only.
    from packaging.version import InvalidVersion, Version

    packages = _lock_packages(lock)
    selected: dict[str, Mapping[str, Any]] = {}
    graph: dict[str, set[str]] = defaultdict(set)
    requested_extras: dict[str, set[str]] = defaultdict(set)
    processed_extras: dict[str, set[str]] = {}
    queue: deque[tuple[str, set[str]]] = deque()
    root_versions: dict[str, str] = {}
    for value in requirements:
        if not isinstance(value, str):
            raise ReleaseError("exact root requirement is invalid")
        name, extras, version = _exact_requirement(value)
        try:
            Version(version)
        except InvalidVersion as error:
            raise ReleaseError(f"exact root version is invalid: {name}") from error
        if name in root_versions and root_versions[name] != version:
            raise ReleaseError(f"exact root requirements conflict: {name}")
        root_versions[name] = version
        queue.append((name, set(extras)))

    for name, version in root_versions.items():
        package = packages.get(name)
        if package is None or not isinstance(package.get("version"), str):
            raise ReleaseError(f"root dependency is absent from the exact lock: {name}")
        if package["version"] != version:
            raise ReleaseError(f"exact root version differs from the lock: {name}")

    while queue:
        name, extras = queue.popleft()
        requested_extras[name].update(extras)
        if name in processed_extras and requested_extras[name] <= processed_extras[name]:
            continue
        package = packages.get(name)
        if package is None or "version" not in package:
            raise ReleaseError(f"runtime dependency is absent from the exact lock: {name}")
        selected[name] = package
        processed_extras[name] = set(requested_extras[name])
        dependencies = package.get("dependencies", [])
        if not isinstance(dependencies, list):
            raise ReleaseError(f"lock dependency list is invalid: {name}")
        for dependency in dependencies:
            if not isinstance(dependency, Mapping) or not isinstance(dependency.get("name"), str):
                raise ReleaseError(f"lock dependency edge is invalid: {name}")
            if not _marker_applies(dependency.get("marker")):
                continue
            child = _canonical_name(dependency["name"])
            child_extras = set(dependency.get("extra", []))
            graph[name].add(child)
            queue.append((child, child_extras))
        optional = package.get("optional-dependencies", {})
        if optional and not isinstance(optional, Mapping):
            raise ReleaseError(f"lock optional dependencies are invalid: {name}")
        for extra in sorted(requested_extras[name]):
            edges = optional.get(extra)
            if not isinstance(edges, list):
                raise ReleaseError(
                    f"requested extra is absent from the exact lock: {name}[{extra}]"
                )
            for dependency in edges:
                if not isinstance(dependency, Mapping) or not isinstance(
                    dependency.get("name"), str
                ):
                    raise ReleaseError(f"lock optional dependency edge is invalid: {name}[{extra}]")
                if not _marker_applies(dependency.get("marker")):
                    continue
                child = _canonical_name(dependency["name"])
                child_extras = set(dependency.get("extra", []))
                graph[name].add(child)
                queue.append((child, child_extras))
    return selected, graph, requested_extras


def _select_wheel(
    name: str,
    package: Mapping[str, Any],
    *,
    extras: Iterable[str] = (),
    python_target: str = "3.12",
) -> SelectedWheel:
    _assert_python_target(python_target=python_target)
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        raise ReleaseError("the reviewed runtime artifact target is Linux x86_64")
    try:
        from packaging.tags import sys_tags
        from packaging.utils import parse_wheel_filename
    except ImportError as error:
        raise ReleaseError("release building requires the locked packaging dependency") from error
    tags = list(sys_tags())
    tag_rank = {tag: index for index, tag in enumerate(tags)}
    candidates: list[tuple[int, Mapping[str, Any], str]] = []
    for wheel in package.get("wheels", []):
        if not isinstance(wheel, Mapping) or not isinstance(wheel.get("url"), str):
            raise ReleaseError(f"lockfile wheel record is invalid: {name}")
        filename = unquote(PurePosixPath(urlsplit(wheel["url"]).path).name)
        try:
            distribution, version, _build, wheel_tags = parse_wheel_filename(filename)
        except Exception as error:
            raise ReleaseError(f"lockfile wheel filename is invalid: {filename}") from error
        if _canonical_name(distribution) != name or str(version) != str(package["version"]):
            raise ReleaseError(f"lockfile wheel identity differs from its package: {filename}")
        ranks = [tag_rank[tag] for tag in wheel_tags if tag in tag_rank]
        if ranks:
            candidates.append((min(ranks), wheel, filename))
    if not candidates:
        raise ReleaseError(f"no exact locked wheel supports this production platform: {name}")
    _, wheel, filename = min(candidates, key=lambda item: (item[0], item[2]))
    digest = str(wheel.get("hash", "")).removeprefix("sha256:")
    size = wheel.get("size")
    parsed = urlsplit(str(wheel["url"]))
    if (
        parsed.scheme != "https"
        or parsed.hostname != "files.pythonhosted.org"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in {None, 443}
        or parsed.query
        or parsed.fragment
        or not SHA256_PATTERN.fullmatch(digest)
        or not isinstance(size, int)
        or size <= 0
        or size > MAX_MEMBER_BYTES
        or not filename.isascii()
        or Path(filename).name != filename
    ):
        raise ReleaseError(f"locked wheel origin, digest, size, or name is unsafe: {name}")
    return SelectedWheel(
        name=name,
        version=str(package["version"]),
        filename=filename,
        url=str(wheel["url"]),
        sha256=digest,
        size=size,
        extras=tuple(sorted(extras)),
    )


def _download_wheel(wheel: SelectedWheel) -> bytes:
    request = urllib.request.Request(
        wheel.url,
        headers={"User-Agent": f"{BUILDER_ID} smithguard"},
        method="GET",
    )
    digest = hashlib.sha256()
    body = bytearray()
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            final = urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname != "files.pythonhosted.org":
                raise ReleaseError(
                    f"locked wheel redirected outside its approved host: {wheel.name}"
                )
            while True:
                chunk = response.read(1_048_576)
                if not chunk:
                    break
                body.extend(chunk)
                digest.update(chunk)
                if len(body) > wheel.size:
                    raise ReleaseError(f"locked wheel exceeds its recorded size: {wheel.name}")
    except ReleaseError:
        raise
    except Exception as error:
        raise ReleaseError(f"locked wheel download failed: {wheel.name}") from error
    if len(body) != wheel.size or digest.hexdigest() != wheel.sha256:
        raise ReleaseError(f"locked wheel does not match its size and SHA-256: {wheel.name}")
    return bytes(body)


def _build_environment(
    lock: Mapping[str, Any], build_requirements: Sequence[str]
) -> tuple[Mapping[str, Any], ...]:
    selected, _graph, _extras = _resolve_graph(lock, build_requirements)
    records = []
    for name in sorted(selected):
        package = selected[name]
        installed = importlib.metadata.version(name)
        if installed != str(package["version"]):
            raise ReleaseError(f"build environment differs from the exact lock: {name}")
        records.append({"name": name, "version": installed})
    return tuple(records)


def _build_wheel_once(source: Path, epoch: int) -> bytes:
    environment = dict(os.environ)
    environment.update(
        {
            "PYTHONHASHSEED": "0",
            "SOURCE_DATE_EPOCH": str(epoch),
            "TZ": "UTC",
        }
    )
    _run(
        (sys.executable, "-m", "hatchling", "build", "-t", "wheel"),
        cwd=source,
        env=environment,
    )
    wheels = sorted((source / "dist").glob("*.whl"))
    if len(wheels) != 1:
        raise ReleaseError("the runtime build did not produce exactly one wheel")
    return wheels[0].read_bytes()


def _safe_zip_path(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        bool(name)
        and name.isascii()
        and "\\" not in name
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _validate_application_wheel(
    data: bytes,
    version: str,
    *,
    expected_requirements: Sequence[str] | None = None,
    expected_package_files: Collection[str] | None = None,
    python_target: str,
) -> tuple[str, frozenset[str]]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)) or len(names) > 256:
                raise ReleaseError("application wheel contains duplicate or excessive members")
            for info in archive.infolist():
                if (
                    not _safe_zip_path(info.filename)
                    or info.file_size > MAX_MEMBER_BYTES
                    or stat.S_ISLNK((info.external_attr >> 16) & 0xFFFF)
                ):
                    raise ReleaseError("application wheel contains an unsafe member")
            record_names = [name for name in names if name.endswith(".dist-info/RECORD")]
            if len(record_names) != 1:
                raise ReleaseError("application wheel RECORD is missing or duplicated")
            try:
                record_rows = tuple(
                    csv.reader(io.StringIO(archive.read(record_names[0]).decode("utf-8")))
                )
            except (UnicodeDecodeError, csv.Error) as error:
                raise ReleaseError("application wheel RECORD is invalid") from error
            if any(len(row) != 3 or not _safe_zip_path(row[0]) for row in record_rows):
                raise ReleaseError("application wheel RECORD contains an invalid entry")
            recorded_files = {row[0] for row in record_rows}
            if len(recorded_files) != len(record_rows) or recorded_files != set(names):
                raise ReleaseError("application wheel members differ from RECORD")
            package_files = {name for name in names if name.startswith("smithguard/")}
            if "smithguard/__init__.py" not in package_files:
                raise ReleaseError("application wheel package root is missing")
            if any(path in names for path in FORBIDDEN_WHEEL_FILES):
                raise ReleaseError("application wheel contains an excluded runtime module")
            if expected_package_files is not None:
                expected = {f"smithguard/{path}" for path in expected_package_files}
                if package_files != expected:
                    missing = sorted(expected - package_files)
                    extra = sorted(package_files - expected)
                    raise ReleaseError(
                        "application wheel members differ from the selected source tree: "
                        f"missing={missing} extra={extra}"
                    )
            metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
            if len(metadata_names) != 1:
                raise ReleaseError("application wheel metadata is missing or duplicated")
            metadata = archive.read(metadata_names[0]).decode("utf-8")
    except ReleaseError:
        raise
    except (OSError, UnicodeDecodeError, zipfile.BadZipFile) as error:
        raise ReleaseError("application wheel is not a valid bounded ZIP archive") from error
    if f"Version: {version}\n" not in metadata:
        raise ReleaseError("application wheel version differs from the source project")
    python_requirements = [
        line.removeprefix("Requires-Python: ").strip()
        for line in metadata.splitlines()
        if line.startswith("Requires-Python: ")
    ]
    if python_requirements != [f"=={python_target}.*"]:
        raise ReleaseError("application wheel Python target differs from the manifest")
    requirement_lines = [
        line.removeprefix("Requires-Dist: ").strip()
        for line in metadata.splitlines()
        if line.startswith("Requires-Dist: ")
    ]
    requirements = frozenset(requirement_lines)
    if not requirements or len(requirement_lines) != len(requirements):
        raise ReleaseError("application wheel dependency metadata is empty or duplicated")
    parsed_names = [_exact_requirement(requirement)[0] for requirement in requirements]
    if len(parsed_names) != len(set(parsed_names)):
        raise ReleaseError("application wheel dependency metadata duplicates a package")
    if expected_requirements is not None and requirements != frozenset(expected_requirements):
        raise ReleaseError("application wheel dependency metadata differs from the runtime split")
    identity = metadata_names[0].split("/", 1)[0].removesuffix(".dist-info")
    return identity, requirements


def _make_requirements(wheels: Sequence[SelectedWheel], app_version: str, app_sha256: str) -> bytes:
    lines = []
    for wheel in sorted(wheels, key=lambda item: item.name):
        extras = f"[{','.join(wheel.extras)}]" if wheel.extras else ""
        lines.append(f"{wheel.name}{extras}=={wheel.version} --hash=sha256:{wheel.sha256}")
    lines.append(f"smithguard=={app_version} --hash=sha256:{app_sha256}")
    return ("\n".join(lines) + "\n").encode("ascii")


def _runtime_lock(
    wheels: Sequence[SelectedWheel],
    graph: Mapping[str, set[str]],
    commit: str,
    python_target: str = "3.12",
    *,
    root_requirements: Sequence[str],
) -> bytes:
    document = {
        "schema_version": "1.1.0",
        "release_commit": commit,
        "target": {
            "implementation": "CPython",
            "python": python_target,
            "platform": "linux_x86_64",
        },
        "root_requirements": list(root_requirements),
        "packages": [
            {
                "name": wheel.name,
                "version": wheel.version,
                "extras": list(wheel.extras),
                "filename": wheel.filename,
                "sha256": wheel.sha256,
                "size": wheel.size,
                "dependencies": sorted(graph.get(wheel.name, set())),
            }
            for wheel in sorted(wheels, key=lambda item: item.name)
        ],
    }
    return _canonical_json(document)


def _sbom(
    wheels: Sequence[SelectedWheel],
    graph: Mapping[str, set[str]],
    *,
    commit: str,
    version: str,
    app_filename: str,
    app_sha256: str,
    timestamp: str,
    root_requirements: Sequence[str],
) -> bytes:
    app_ref = f"pkg:pypi/smithguard@{version}"
    components = [
        {
            "type": "application",
            "bom-ref": app_ref,
            "name": "smithguard",
            "version": version,
            "purl": app_ref,
            "hashes": [{"alg": "SHA-256", "content": app_sha256}],
            "properties": [
                {"name": "smithguard:release-commit", "value": commit},
                {"name": "smithguard:wheel-filename", "value": app_filename},
            ],
        }
    ]
    dependencies = [
        {
            "ref": app_ref,
            "dependsOn": [
                f"pkg:pypi/{name}@{version}"
                for name, _extras, version in map(_exact_requirement, root_requirements)
            ],
        }
    ]
    for wheel in sorted(wheels, key=lambda item: item.name):
        reference = f"pkg:pypi/{wheel.name}@{wheel.version}"
        components.append(
            {
                "type": "library",
                "bom-ref": reference,
                "name": wheel.name,
                "version": wheel.version,
                "purl": reference,
                "hashes": [{"alg": "SHA-256", "content": wheel.sha256}],
                "properties": [
                    {"name": "smithguard:wheel-filename", "value": wheel.filename},
                    {"name": "smithguard:wheel-size", "value": str(wheel.size)},
                ],
            }
        )
        dependencies.append(
            {
                "ref": reference,
                "dependsOn": [
                    (
                        f"pkg:pypi/{child}@"
                        f"{next(item.version for item in wheels if item.name == child)}"
                    )
                    for child in sorted(graph.get(wheel.name, set()))
                ],
            }
        )
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, commit + ':runtime-sbom')}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "component": components[0],
            "tools": {"components": [{"type": "application", "name": BUILDER_ID, "version": "1"}]},
        },
        "components": components[1:],
        "dependencies": dependencies,
    }
    return _canonical_json(document)


def _provenance(
    *,
    commit: str,
    version: str,
    app_filename: str,
    app_sha256: str,
    builder_sha256: str,
    project_sha256: str,
    runtime_project_sha256: str,
    lock_sha256: str,
    payload_tree_sha256: str,
    source_migration_head: str,
    source_migration_journal_sha256: str,
    build_environment: Sequence[Mapping[str, Any]],
    uv_version: str,
    python_target: str = "3.12",
) -> bytes:
    document = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": app_filename, "digest": {"sha256": app_sha256}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": BUILDER_ID,
                "externalParameters": {
                    "releaseCommit": commit,
                    "projectVersion": version,
                    "target": f"cpython-{python_target}-linux-x86_64",
                },
                "internalParameters": {
                    "builderPath": BUILDER_PATH,
                    "builderSha256": builder_sha256,
                    "projectSha256": project_sha256,
                    "runtimeProjectSha256": runtime_project_sha256,
                    "lockSha256": lock_sha256,
                    "payloadTreeSha256": payload_tree_sha256,
                    "packagedMigrationHead": source_migration_head,
                    "sourceMigrationHead": source_migration_head,
                    "sourceMigrationJournalSha256": source_migration_journal_sha256,
                    "uvVersion": uv_version,
                },
                "resolvedDependencies": [
                    {
                        "uri": "git+https://github.com/SmithLabsLLC/SmithGuard.git",
                        "digest": {"gitCommit": commit},
                    },
                    *[
                        {
                            "uri": f"pkg:pypi/{item['name']}@{item['version']}",
                            "digest": {},
                        }
                        for item in build_environment
                    ],
                ],
            },
            "runDetails": {
                "builder": {"id": BUILDER_ID, "version": {"runtime": "1"}},
                "metadata": {"invocationId": f"urn:smithguard:runtime-release:{commit}"},
            },
        },
    }
    return _canonical_json(document)


def _payload_files(commit: str) -> tuple[str, ...]:
    selected = [
        "alembic.ini",
        "deploy/README.md",
        *(
            path
            for directory in RUNTIME_DEPLOY_DIRECTORIES
            for path in _tracked_files(commit, directory)
        ),
        *RUNTIME_POLICY_PATHS,
        *RUNTIME_RECORD_PATHS,
        *RUNTIME_TRIAL_TOOLS,
        *RUNTIME_TRIAL_UNIT_PATHS,
        *RUNTIME_TRIAL_INSTALL_PATHS,
    ]
    result = []
    for path in selected:
        if "__pycache__" in PurePosixPath(path).parts or path.endswith((".pyc", ".pyo")):
            continue
        result.append(path)
    if len(result) != len(set(result)):
        raise ReleaseError("runtime payload source paths are duplicated")
    return tuple(sorted(result))


def _site_payload(commit: str) -> dict[str, bytes]:
    # The bridge release contains no site/ tree. Only a later reviewed commit,
    # after this verifier is installed and selected, adds the product payload.
    listing = _git("ls-tree", "-r", "-z", commit, "--", "site", product_site.PROVENANCE_PATH)
    if not listing:
        return {}
    if not listing.endswith("\0"):
        raise ReleaseError("product Git tree listing is malformed")
    rows = listing.split("\0")[:-1]
    if len(rows) > product_site.MAX_SITE_FILES:
        raise ReleaseError("product source exceeds its closed file boundary")
    paths = []
    for row in rows:
        metadata, separator, path = row.partition("\t")
        fields = metadata.split(" ")
        if (
            not separator
            or len(fields) != 3
            or fields[:2] != ["100644", "blob"]
            or COMMIT_PATTERN.fullmatch(fields[2]) is None
            or not product_site.allowed_site_path(path)
            or path in paths
        ):
            raise ReleaseError(
                "product source must contain only approved regular non-executable files"
            )
        paths.append(path)
    payload = {path: _git_blob(commit, path) for path in paths}
    try:
        product_site.verify_site_files(
            payload, contract_bytes=_git_blob(commit, "src/" + product_site.WHEEL_CONTRACT_PATH)
        )
    except product_site.SiteError as error:
        raise ReleaseError(str(error)) from error
    return payload


def _verify_product_site(files: Mapping[str, bytes]) -> None:
    if not any(path.startswith("site/") or path == product_site.PROVENANCE_PATH for path in files):
        return
    wheels = [
        body
        for path, body in files.items()
        if path.startswith("app/wheelhouse/smithguard-") and path.endswith(".whl")
    ]
    if len(wheels) != 1:
        raise ReleaseError("product payload requires one manifest-bound application wheel")
    try:
        with zipfile.ZipFile(io.BytesIO(wheels[0])) as wheel:
            if (
                wheel.getinfo(product_site.WHEEL_CONTRACT_PATH).file_size
                > product_site.MAX_SITE_MEMBER_BYTES
            ):
                raise ReleaseError("packaged product contract exceeds its byte limit")
            contract = wheel.read(product_site.WHEEL_CONTRACT_PATH)
        product_site.verify_site_files(files, contract_bytes=contract)
    except (KeyError, zipfile.BadZipFile, product_site.SiteError) as error:
        raise ReleaseError("product payload or packaged API-contract binding is invalid") from error


def _runtime_migration_payload(commit: str) -> tuple[dict[str, bytes], str, str]:
    source_prefix = "migrations/"
    archive_prefix = f"{ARCHIVE_APP_ROOT}/migrations/"
    journal_path = source_prefix + "journal.json"
    support_paths = {
        source_prefix + "env.py",
        source_prefix + "script.py.mako",
        journal_path,
    }
    try:
        journal_bytes = _git_blob(commit, journal_path)
        journal = json.loads(journal_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseError("source migration journal is invalid JSON") from error
    if not isinstance(journal, Mapping) or set(journal) != {"schema_version", "migrations"}:
        raise ReleaseError("source migration journal shape is invalid")
    entries = journal.get("migrations")
    if journal.get("schema_version") != "1.0.0" or not isinstance(entries, list):
        raise ReleaseError("source migration journal is invalid")

    selected_entries: list[Mapping[str, Any]] = []
    source_payload: dict[str, bytes] = {}
    journal_source_paths: set[str] = set()
    previous: str | None = None
    seen: set[str] = set()
    expected_fields = {
        "revision",
        "down_revision",
        "file",
        "source_sha256",
        "description",
        "rollback_mode",
    }
    for entry in entries:
        if not isinstance(entry, Mapping) or set(entry) != expected_fields:
            raise ReleaseError("source migration journal entry is invalid")
        revision = entry.get("revision")
        relative = entry.get("file")
        digest = entry.get("source_sha256")
        if (
            not isinstance(revision, str)
            or not revision
            or revision in seen
            or entry.get("down_revision") != previous
            or not isinstance(relative, str)
            or not _safe_relative_path(relative)
            or PurePosixPath(relative).parts[0] != "versions"
            or PurePosixPath(relative).suffix != ".py"
            or not isinstance(digest, str)
            or not digest.startswith("sha256:")
            or not isinstance(entry.get("description"), str)
            or not entry["description"]
            or entry.get("rollback_mode") not in {"safe_to_zero", "forward_only"}
        ):
            raise ReleaseError("source migration journal chain is invalid")
        source_path = source_prefix + relative
        source = _git_blob(commit, source_path)
        if f"sha256:{_sha256(source)}" != digest:
            raise ReleaseError("source migration differs from its journal")
        seen.add(revision)
        previous = revision
        journal_source_paths.add(source_path)
        selected_entries.append(entry)
        source_payload[archive_prefix + relative] = source
    tracked = set(_tracked_files(commit, source_prefix.removesuffix("/")))
    if tracked != support_paths | journal_source_paths:
        raise ReleaseError("tracked migration files differ from the source journal boundary")

    payload = {
        archive_prefix + "env.py": _git_blob(commit, source_prefix + "env.py"),
        archive_prefix + "script.py.mako": _git_blob(commit, source_prefix + "script.py.mako"),
        archive_prefix + "journal.json": _canonical_json(
            {
                "schema_version": "1.0.0",
                "migrations": selected_entries,
            }
        ),
    }
    payload.update(source_payload)
    if previous is None:
        raise ReleaseError("source migration journal is empty")
    return payload, previous, _sha256(journal_bytes)


def _manifest(
    commit: str, payload: Mapping[str, bytes], *, uv_version: str, python_target: str = "3.12"
) -> bytes:
    entries = [
        {
            "path": path,
            "size": len(data),
            "sha256": _sha256(data),
            "mode": "0644",
        }
        for path, data in sorted(payload.items())
    ]
    document = {
        "schema_version": "1.0.0",
        "release_commit": commit,
        "builder": {
            "id": BUILDER_ID,
            "path": BUILDER_PATH,
            "sha256": _sha256(_git_blob(commit, BUILDER_PATH)),
        },
        "target": {
            "implementation": "CPython",
            "python": python_target,
            "platform": "linux_x86_64",
            "uv_version": uv_version,
        },
        "files": entries,
    }
    return _canonical_json(document)


def _archive_directories(root: str, paths: Iterable[str]) -> tuple[str, ...]:
    directories = {root}
    for path in paths:
        parent = PurePosixPath(root, path).parent
        while str(parent) not in {".", root}:
            directories.add(str(parent))
            parent = parent.parent
    return tuple(sorted(directories, key=lambda item: (item.count("/"), item)))


def create_archive(root: str, payload: Mapping[str, bytes], *, epoch: int) -> bytes:
    if not root.isascii() or "/" in root or root in {"", ".", ".."}:
        raise ReleaseError("archive root is invalid")
    output = io.BytesIO()
    with (
        gzip.GzipFile(
            fileobj=output,
            mode="wb",
            filename="",
            mtime=epoch,
            compresslevel=9,
        ) as gzip_stream,
        tarfile.open(fileobj=gzip_stream, mode="w", format=tarfile.PAX_FORMAT) as archive,
    ):
        for directory in _archive_directories(root, payload):
            info = tarfile.TarInfo(directory + "/")
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            info.mtime = epoch
            info.size = 0
            archive.addfile(info)
        for path, data in sorted(payload.items()):
            if not _safe_relative_path(path):
                raise ReleaseError(f"payload path is unsafe: {path}")
            info = tarfile.TarInfo(f"{root}/{path}")
            info.type = tarfile.REGTYPE
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            info.mtime = epoch
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return output.getvalue()


def _safe_relative_path(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        bool(value)
        and value.isascii()
        and "\\" not in value
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _allowed_release_path(path: str) -> bool:
    exact = {
        MANIFEST_NAME,
        SBOM_NAME,
        PROVENANCE_NAME,
        RUNTIME_LOCK_NAME,
        "runtime-release.py",
        "app/alembic.ini",
        f"app/{REQUIREMENTS_NAME}",
        *RUNTIME_POLICY_PATHS,
        *RUNTIME_RECORD_PATHS,
    }
    prefixes = (
        "app/deploy/",
        "app/migrations/",
        "app/wheelhouse/",
    )
    return path in exact or path.startswith(prefixes) or product_site.allowed_site_path(path)


def _read_archive(data: bytes, *, expected_root: str) -> dict[str, bytes]:
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ReleaseError("release archive exceeds the compressed byte limit")
    files: dict[str, bytes] = {}
    directories: set[str] = set()
    names: set[str] = set()
    total = 0
    member_count = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r|gz") as archive:
            for member in archive:
                member_count += 1
                if member_count > MAX_ARCHIVE_MEMBERS:
                    raise ReleaseError("release archive exceeds the member limit")
                name = member.name.removesuffix("/") if member.isdir() else member.name
                if (
                    not name
                    or not name.isascii()
                    or "\\" in name
                    or name.startswith("/")
                    or name in names
                    or any(part in {"", ".", ".."} for part in PurePosixPath(name).parts)
                ):
                    raise ReleaseError("release archive contains an unsafe or duplicate path")
                names.add(name)
                if name != expected_root and not name.startswith(expected_root + "/"):
                    raise ReleaseError("release archive has more than one root")
                if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                    raise ReleaseError("release archive contains a link or special member")
                if member.uid != 0 or member.gid != 0:
                    raise ReleaseError("release archive ownership metadata is invalid")
                if member.isdir():
                    if stat.S_IMODE(member.mode) != 0o755:
                        raise ReleaseError("release archive directory mode is invalid")
                    directories.add(name)
                    continue
                if stat.S_IMODE(member.mode) != 0o644 or member.size > MAX_MEMBER_BYTES:
                    raise ReleaseError("release archive file mode or size is invalid")
                prefix = expected_root + "/"
                if not member.name.startswith(prefix):
                    raise ReleaseError("release archive has more than one root")
                relative = member.name.removeprefix(prefix)
                if not _safe_relative_path(relative) or not _allowed_release_path(relative):
                    raise ReleaseError(
                        f"release archive path is outside the closed manifest: {relative}"
                    )
                if (
                    product_site.allowed_site_path(relative)
                    and member.size > product_site.MAX_SITE_MEMBER_BYTES
                ):
                    raise ReleaseError("product archive member exceeds its byte limit")
                total += member.size
                if total > MAX_UNCOMPRESSED_BYTES:
                    raise ReleaseError("release archive exceeds the uncompressed byte limit")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ReleaseError("release archive member cannot be read")
                body = extracted.read(member.size + 1)
                if len(body) != member.size:
                    raise ReleaseError("release archive member size differs from its header")
                files[relative] = body
    except ReleaseError:
        raise
    except (OSError, EOFError, tarfile.TarError) as error:
        raise ReleaseError("release archive is not a valid bounded tar.gz") from error
    expected_directories = {expected_root}
    for relative in files:
        parent = PurePosixPath(expected_root, relative).parent
        while str(parent) not in {".", expected_root}:
            expected_directories.add(str(parent))
            parent = parent.parent
    if directories != expected_directories:
        raise ReleaseError("release archive directory set differs from its file tree")
    return files


def _verify_migration_journal(files: Mapping[str, bytes]) -> str:
    prefix = "app/migrations/"
    journal = _parse_json_file(files, prefix + "journal.json")
    migrations = journal.get("migrations")
    if journal.get("schema_version") != "1.0.0" or not isinstance(migrations, list):
        raise ReleaseError("release migration journal is invalid")
    previous = None
    seen = set()
    for entry in migrations:
        if not isinstance(entry, Mapping):
            raise ReleaseError("release migration journal entry is invalid")
        revision = entry.get("revision")
        relative = entry.get("file")
        digest = entry.get("source_sha256")
        if (
            not isinstance(revision, str)
            or revision in seen
            or entry.get("down_revision") != previous
            or not isinstance(relative, str)
            or not _safe_relative_path(relative)
            or not isinstance(digest, str)
            or not digest.startswith("sha256:")
        ):
            raise ReleaseError("release migration chain is invalid")
        source = files.get(prefix + relative)
        if source is None or f"sha256:{_sha256(source)}" != digest:
            raise ReleaseError("release migration differs from its journal")
        seen.add(revision)
        previous = revision
    if not migrations or previous is None:
        raise ReleaseError("release migration journal is empty")
    migration_sources = {
        path.removeprefix(prefix)
        for path in files
        if path.startswith(prefix + "versions/") and path.endswith(".py")
    }
    if migration_sources != {entry["file"] for entry in migrations}:
        raise ReleaseError("release migration files and journal differ")
    return previous


def _parse_json_file(files: Mapping[str, bytes], name: str) -> Mapping[str, Any]:
    body = files.get(name)
    if body is None or len(body) > 4_194_304:
        raise ReleaseError(f"release metadata is missing or oversized: {name}")
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseError(f"release metadata is invalid JSON: {name}") from error
    if not isinstance(value, Mapping):
        raise ReleaseError(f"release metadata root is invalid: {name}")
    return value


def _verify_requirements(files: Mapping[str, bytes], version: str) -> None:
    path = f"app/{REQUIREMENTS_NAME}"
    try:
        lines = files[path].decode("ascii").splitlines()
    except (KeyError, UnicodeDecodeError) as error:
        raise ReleaseError("runtime requirements are missing or non-ASCII") from error
    expected_wheels = {
        PurePosixPath(name).name: _sha256(body)
        for name, body in files.items()
        if name.startswith("app/wheelhouse/")
    }
    requirement_hashes = set()
    app_count = 0
    for line in lines:
        match = REQUIREMENT_LINE.fullmatch(line)
        if match is None:
            raise ReleaseError("runtime requirements contain an invalid line")
        name, _extras, required_version = _exact_requirement(match.group("requirement"))
        requirement_hashes.add(match.group("sha256"))
        if name == "smithguard":
            app_count += 1
            if required_version != version:
                raise ReleaseError("runtime requirements contain the wrong application version")
    if app_count != 1 or requirement_hashes != set(expected_wheels.values()):
        raise ReleaseError("runtime requirements and wheelhouse digests differ")


def _verify_runtime_dependency_boundary(
    runtime_lock: Mapping[str, Any],
    sbom: Mapping[str, Any],
    wheel_requirements: frozenset[str],
) -> None:
    schema_version = runtime_lock.get("schema_version")
    if schema_version not in {"1.0.0", "1.1.0"}:
        raise ReleaseError("runtime lock schema is unsupported")
    packages = runtime_lock.get("packages")
    if not isinstance(packages, list) or not packages or len(packages) > 128:
        raise ReleaseError("runtime lock package inventory is invalid")
    package_index: dict[str, tuple[str, frozenset[str]]] = {}
    for package in packages:
        if not isinstance(package, Mapping):
            raise ReleaseError("runtime lock package inventory is invalid")
        name = package.get("name")
        version = package.get("version")
        extras = package.get("extras", [])
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(version, str)
            or not version
            or not isinstance(extras, list)
            or not all(isinstance(extra, str) and extra for extra in extras)
            or len(extras) != len(set(extras))
        ):
            raise ReleaseError("runtime lock package inventory is invalid")
        canonical_name = _canonical_name(name)
        if canonical_name in package_index:
            raise ReleaseError("runtime lock package inventory contains a duplicate")
        package_index[canonical_name] = (version, frozenset(extras))

    if schema_version == "1.1.0":
        roots = runtime_lock.get("root_requirements")
        if (
            not isinstance(roots, list)
            or not roots
            or len(roots) > 64
            or not all(isinstance(requirement, str) for requirement in roots)
            or len(roots) != len(set(roots))
        ):
            raise ReleaseError("runtime lock root requirements are invalid")
        if frozenset(roots) != wheel_requirements:
            raise ReleaseError("application wheel dependencies differ from the runtime lock roots")
        root_requirements = tuple(roots)
    else:
        if "root_requirements" in runtime_lock:
            raise ReleaseError("legacy runtime lock contains unsupported root requirements")
        root_requirements = tuple(wheel_requirements)

    root_packages: dict[str, tuple[tuple[str, ...], str]] = {}
    for requirement in root_requirements:
        name, extras, version = _exact_requirement(requirement)
        if name in root_packages:
            raise ReleaseError("runtime lock roots contain a duplicate package")
        root_packages[name] = (extras, version)
        locked = package_index.get(name)
        if locked is None or locked[0] != version or not set(extras) <= locked[1]:
            raise ReleaseError("runtime lock roots differ from the package inventory")

    metadata = sbom.get("metadata")
    app_component = metadata.get("component") if isinstance(metadata, Mapping) else None
    app_ref = app_component.get("bom-ref") if isinstance(app_component, Mapping) else None
    dependency_graph = sbom.get("dependencies")
    if not isinstance(app_ref, str) or not isinstance(dependency_graph, list):
        raise ReleaseError("release SBOM application dependency boundary is invalid")
    app_edges = [
        entry
        for entry in dependency_graph
        if isinstance(entry, Mapping) and entry.get("ref") == app_ref
    ]
    if len(app_edges) != 1:
        raise ReleaseError("release SBOM application dependency boundary is invalid")
    depends_on = app_edges[0].get("dependsOn")
    if (
        not isinstance(depends_on, list)
        or not all(isinstance(reference, str) for reference in depends_on)
        or len(depends_on) != len(set(depends_on))
    ):
        raise ReleaseError("release SBOM application dependency boundary is invalid")
    expected_references = {
        f"pkg:pypi/{name}@{version}" for name, (_extras, version) in root_packages.items()
    }
    if set(depends_on) != expected_references:
        raise ReleaseError("release SBOM dependencies differ from the runtime lock roots")


def _verify_wheel_python_tags(files: Mapping[str, bytes], python_target: str) -> None:
    """Reject wrong Python ABIs without importing the builder's packaging dependency.

    Platform/libc eligibility still belongs to builder sys_tags and offline uv sync.
    abi3 is a minimum CPython minor, not a requirement for an identical minor tag.
    """
    if python_target not in SUPPORTED_PYTHON_TARGETS:
        raise ReleaseError("wheel Python target is unsupported")
    minor = int(python_target.split(".")[1])
    interpreter = f"cp3{minor}"
    compatible = {(interpreter, abi) for abi in (interpreter, "none", "abi3")}
    compatible.update((f"cp3{minimum}", "abi3") for minimum in range(2, minor))
    compatible.update((f"py3{minimum}", "none") for minimum in range(minor + 1))
    compatible.add(("py3", "none"))
    for path in files:
        if not path.startswith("app/wheelhouse/"):
            continue
        filename = PurePosixPath(path).name
        parts = filename.removesuffix(".whl").split("-")
        if not filename.endswith(".whl") or len(parts) not in {5, 6}:
            raise ReleaseError("wheelhouse filename has invalid compatibility tags")
        python_tags, abi_tags, _platform_tags = parts[-3:]
        if not any(
            (python_tag, abi_tag) in compatible
            for python_tag in python_tags.split(".")
            for abi_tag in abi_tags.split(".")
        ):
            raise ReleaseError("wheelhouse Python ABI differs from the manifest target")


def verify_release_bytes(
    data: bytes,
    *,
    expected_commit: str,
    expected_sha256: str,
) -> VerifiedRelease:
    if not COMMIT_PATTERN.fullmatch(expected_commit):
        raise ReleaseError("expected release commit is invalid")
    if not SHA256_PATTERN.fullmatch(expected_sha256):
        raise ReleaseError("expected release SHA-256 is invalid")
    archive_sha256 = _sha256(data)
    if archive_sha256 != expected_sha256:
        raise ReleaseError("release archive SHA-256 does not match the approved digest")
    root = f"smithguard-release-{expected_commit}"
    files = _read_archive(data, expected_root=root)
    manifest = _parse_json_file(files, MANIFEST_NAME)
    python_target = _manifest_python_target(manifest)
    target = manifest.get("target")
    if (
        manifest.get("schema_version") != "1.0.0"
        or manifest.get("release_commit") != expected_commit
        or not isinstance(manifest.get("files"), list)
        or not isinstance(target, Mapping)
        or target
        != {
            "implementation": "CPython",
            "python": python_target,
            "platform": "linux_x86_64",
            "uv_version": target.get("uv_version") if isinstance(target, Mapping) else None,
        }
        or not isinstance(target.get("uv_version"), str)
        or not UV_VERSION_PATTERN.fullmatch(target["uv_version"])
    ):
        raise ReleaseError("release manifest identity is invalid")
    expected_entries: dict[str, Mapping[str, Any]] = {}
    for entry in manifest["files"]:
        if not isinstance(entry, Mapping) or set(entry) != {"path", "size", "sha256", "mode"}:
            raise ReleaseError("release manifest file entry is invalid")
        path = entry["path"]
        if (
            not isinstance(path, str)
            or path == MANIFEST_NAME
            or path in expected_entries
            or not _allowed_release_path(path)
            or entry["mode"] != "0644"
            or not isinstance(entry["size"], int)
            or not isinstance(entry["sha256"], str)
            or not SHA256_PATTERN.fullmatch(entry["sha256"])
        ):
            raise ReleaseError("release manifest contains an unsafe file entry")
        expected_entries[path] = entry
    actual_paths = set(files) - {MANIFEST_NAME}
    if actual_paths != set(expected_entries):
        raise ReleaseError("release archive and manifest file sets differ")
    for path, entry in expected_entries.items():
        body = files[path]
        if len(body) != entry["size"] or _sha256(body) != entry["sha256"]:
            raise ReleaseError(f"release file does not match its manifest: {path}")
    sbom = _parse_json_file(files, SBOM_NAME)
    provenance = _parse_json_file(files, PROVENANCE_NAME)
    runtime_lock = _parse_json_file(files, RUNTIME_LOCK_NAME)
    if (
        sbom.get("bomFormat") != "CycloneDX"
        or provenance.get("_type") != "https://in-toto.io/Statement/v1"
        or runtime_lock.get("release_commit") != expected_commit
    ):
        raise ReleaseError("release SBOM, provenance, or runtime lock identity is invalid")
    sbom_metadata = sbom.get("metadata")
    app_component = sbom_metadata.get("component") if isinstance(sbom_metadata, Mapping) else None
    if not isinstance(app_component, Mapping):
        raise ReleaseError("release SBOM application component is invalid")
    version = app_component.get("version")
    if not isinstance(version, str):
        raise ReleaseError("release SBOM application version is invalid")
    _verify_requirements(files, version)
    _verify_wheel_python_tags(files, python_target)
    packaged_migration_head = _verify_migration_journal(files)
    predicate = provenance.get("predicate")
    build_definition = predicate.get("buildDefinition") if isinstance(predicate, Mapping) else None
    internal_parameters = (
        build_definition.get("internalParameters")
        if isinstance(build_definition, Mapping)
        else None
    )
    if not isinstance(internal_parameters, Mapping):
        raise ReleaseError("release migration provenance is invalid")
    source_migration_head = internal_parameters.get("sourceMigrationHead")
    source_journal_sha256 = internal_parameters.get("sourceMigrationJournalSha256")
    if (
        internal_parameters.get("packagedMigrationHead") != packaged_migration_head
        or not isinstance(source_migration_head, str)
        or re.fullmatch(r"[A-Za-z0-9_]{1,128}", source_migration_head) is None
        or source_migration_head != packaged_migration_head
        or not isinstance(source_journal_sha256, str)
        or SHA256_PATTERN.fullmatch(source_journal_sha256) is None
    ):
        raise ReleaseError("release migration provenance is invalid")
    external = build_definition.get("externalParameters")
    if (
        runtime_lock.get("target")
        != {"implementation": "CPython", "python": python_target, "platform": "linux_x86_64"}
        or not isinstance(external, Mapping)
        or external.get("target") != f"cpython-{python_target}-linux-x86_64"
    ):
        raise ReleaseError("release metadata Python targets disagree")
    app_wheels = [
        (path, body)
        for path, body in files.items()
        if path.startswith("app/wheelhouse/smithguard-")
    ]
    if len(app_wheels) != 1:
        raise ReleaseError("release wheelhouse must contain one application wheel")
    _wheel_identity, wheel_requirements = _validate_application_wheel(
        app_wheels[0][1], version, python_target=python_target
    )
    _verify_runtime_dependency_boundary(runtime_lock, sbom, wheel_requirements)
    _verify_product_site(files)
    return VerifiedRelease(
        commit=expected_commit,
        root=root,
        manifest=manifest,
        files=files,
        archive_sha256=archive_sha256,
    )


def build_release(commit_value: str, output: Path) -> Mapping[str, Any]:
    commit = _resolve_commit(commit_value)
    _assert_release_commit(commit)
    _assert_source_revision_transition(commit)
    if output.exists() or output.is_symlink():
        raise ReleaseError("release output already exists")
    if not output.parent.is_dir() or output.parent.is_symlink():
        raise ReleaseError("release output parent must be an existing real directory")
    project = _project_at_commit(commit)
    boundary = _validate_project_boundary(project)
    version = boundary.version
    python_target = _project_python_target(project)
    _assert_python_target(python_target=python_target)
    _probe_python_target(Path(sys.executable), python_target)
    lock_bytes = _git_blob(commit, LOCK_PATH)
    lock = tomllib.loads(lock_bytes.decode("utf-8"))
    if lock.get("requires-python") != f"=={python_target}.*":
        raise ReleaseError("source lock Python target differs from the project")
    build_environment = _build_environment(lock, boundary.build_requirements)
    epoch = int(_git("show", "-s", "--format=%ct", commit))
    timestamp = (
        datetime.fromtimestamp(epoch, tz=UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    uv_version = _run(("uv", "--version"))
    if not UV_VERSION_PATTERN.fullmatch(uv_version):
        raise ReleaseError("uv version identity is invalid")

    with tempfile.TemporaryDirectory(prefix="smithguard-runtime-build-") as temporary:
        temporary_root = Path(temporary)
        source = temporary_root / "source"
        _stage_runtime_source(commit, source, boundary, python_target)
        wheel_bytes = _build_wheel_once(source, epoch)
        wheel_identity, _wheel_requirements = _validate_application_wheel(
            wheel_bytes,
            version,
            expected_package_files=_runtime_source_files(commit),
            expected_requirements=boundary.runtime_requirements,
            python_target=python_target,
        )
        app_filename = f"{wheel_identity}-py3-none-any.whl"
        app_sha256 = _sha256(wheel_bytes)

        selected, graph, extras = _resolve_graph(lock, boundary.runtime_requirements)
        wheels = [
            _select_wheel(name, selected[name], extras=extras[name], python_target=python_target)
            for name in sorted(selected)
        ]
        payload: dict[str, bytes] = {
            "runtime-release.py": _git_blob(commit, BUILDER_PATH),
            f"app/wheelhouse/{app_filename}": wheel_bytes,
        }
        for wheel in wheels:
            payload[f"app/wheelhouse/{wheel.filename}"] = _download_wheel(wheel)
        payload[f"app/{REQUIREMENTS_NAME}"] = _make_requirements(wheels, version, app_sha256)
        payload[RUNTIME_LOCK_NAME] = _runtime_lock(
            wheels, graph, commit, python_target, root_requirements=boundary.runtime_requirements
        )
        _verify_systemd_unit_inventory(commit)
        for path in _payload_files(commit):
            destination = (
                f"{ARCHIVE_APP_ROOT}/deploy/warning-trial/{path}"
                if path in RUNTIME_TRIAL_TOOLS
                else f"{ARCHIVE_APP_ROOT}/{path}"
                if path == "alembic.ini" or path.startswith("deploy/")
                else path
            )
            payload[destination] = _git_blob(commit, path)
        payload.update(_site_payload(commit))
        migration_payload, source_migration_head, source_migration_journal_sha256 = (
            _runtime_migration_payload(commit)
        )
        payload.update(migration_payload)
        payload[SBOM_NAME] = _sbom(
            wheels,
            graph,
            commit=commit,
            version=version,
            app_filename=app_filename,
            app_sha256=app_sha256,
            timestamp=timestamp,
            root_requirements=boundary.runtime_requirements,
        )
        payload[PROVENANCE_NAME] = _provenance(
            commit=commit,
            version=version,
            app_filename=app_filename,
            app_sha256=app_sha256,
            builder_sha256=_sha256(_git_blob(commit, BUILDER_PATH)),
            project_sha256=_sha256(_git_blob(commit, PROJECT_PATH)),
            runtime_project_sha256=_sha256(_runtime_pyproject(boundary, python_target)),
            lock_sha256=_sha256(lock_bytes),
            payload_tree_sha256=_tree_sha256(payload),
            source_migration_head=source_migration_head,
            source_migration_journal_sha256=source_migration_journal_sha256,
            build_environment=build_environment,
            uv_version=uv_version,
            python_target=python_target,
        )
        payload[MANIFEST_NAME] = _manifest(
            commit, payload, uv_version=uv_version, python_target=python_target
        )
        root = f"smithguard-release-{commit}"
        archive = create_archive(root, payload, epoch=epoch)
        digest = _sha256(archive)
        verify_release_bytes(archive, expected_commit=commit, expected_sha256=digest)
        _write_release_outputs(output, archive, digest)
    return {
        "release_commit": commit,
        "version": version,
        "archive": str(output),
        "archive_sha256": digest,
        "compressed_bytes": output.stat().st_size,
        "manifest_files": len(payload) - 1,
        "runtime_wheels": len(wheels) + 1,
    }


def _load_verified_archive(path: Path, commit: str, digest: str) -> VerifiedRelease:
    if not path.is_file() or path.is_symlink():
        raise ReleaseError("release archive must be one real regular file")
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ReleaseError("release archive exceeds the compressed byte limit")
    return verify_release_bytes(path.read_bytes(), expected_commit=commit, expected_sha256=digest)


def _read_sha256_sidecar(path: Path, expected_filename: str) -> str:
    try:
        body = path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as error:
        raise ReleaseError("release digest sidecar is unavailable") from error
    match = re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9._-]+)\n?", body)
    if match is None or match.group(2) != expected_filename:
        raise ReleaseError("release digest sidecar is invalid")
    return match.group(1)


def _uv_version(path: Path) -> str:
    if not path.is_file() or path.is_symlink() or not os.access(path, os.X_OK):
        raise ReleaseError("uv installer must be one executable regular file")
    return _run((str(path), "--version"))


def _expected_versions(files: Mapping[str, bytes]) -> dict[str, str]:
    sbom = _parse_json_file(files, SBOM_NAME)
    components = [sbom["metadata"]["component"], *sbom.get("components", [])]
    result = {}
    for component in components:
        name = component.get("name")
        version = component.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise ReleaseError("release SBOM contains an invalid component")
        result[_canonical_name(name)] = version
    return result


def _installed_versions(python: Path) -> dict[str, str]:
    code = (
        "import importlib.metadata,json,os;"
        "print(json.dumps([[d.metadata['Name'],d.version,os.path.realpath(str(d._path))] "
        "for d in importlib.metadata.distributions()]))"
    )
    try:
        value = json.loads(_run((str(python), "-c", code)))
    except json.JSONDecodeError as error:
        raise ReleaseError("installed environment inventory is invalid") from error
    if not isinstance(value, list):
        raise ReleaseError("installed environment inventory has an invalid shape")
    result: dict[str, str] = {}
    seen_records: set[tuple[str, str, str]] = set()
    for component in value:
        if (
            not isinstance(component, list)
            or len(component) != 3
            or not all(isinstance(item, str) and item for item in component)
        ):
            raise ReleaseError("installed environment inventory has an invalid component")
        name = _canonical_name(component[0])
        record = (name, component[1], component[2])
        if record in seen_records:
            continue
        seen_records.add(record)
        if name in result:
            raise ReleaseError("installed environment inventory contains a duplicate component")
        result[name] = component[1]
    return result


def _installed_site_root(release: Path, sites: object) -> Path:
    if (
        not isinstance(sites, list)
        or not sites
        or len(sites) > 8
        or not all(isinstance(value, str) for value in sites)
    ):
        raise ReleaseError("installed environment has an unexpected site-packages layout")
    environment_root = (release / "app/.venv").resolve()
    existing: set[Path] = set()
    for value in sites:
        candidate = Path(value)
        if not candidate.is_absolute():
            raise ReleaseError("installed site-packages path is invalid")
        resolved = candidate.resolve()
        if not resolved.is_relative_to(environment_root):
            raise ReleaseError("installed site-packages escapes the release")
        if candidate.is_dir():
            existing.add(resolved)
    if len(existing) != 1:
        raise ReleaseError("installed environment has an unexpected site-packages layout")
    return existing.pop()


def _verify_installed_records(release: Path) -> None:
    python = release / "app/.venv/bin/python"
    output = _run(
        (
            str(python),
            "-c",
            "import json,site; print(json.dumps(site.getsitepackages()))",
        )
    )
    try:
        sites = json.loads(output)
    except json.JSONDecodeError as error:
        raise ReleaseError("installed site-packages path is invalid") from error
    site_root = _installed_site_root(release, sites)
    environment_root = (release / "app/.venv").resolve()
    records = sorted(site_root.glob("*.dist-info/RECORD"))
    if not records:
        raise ReleaseError("installed environment has no wheel RECORD files")
    for record in records:
        with record.open(newline="", encoding="utf-8") as stream:
            for row in csv.reader(stream):
                if len(row) != 3 or not row[1]:
                    continue
                try:
                    algorithm, encoded = row[1].split("=", 1)
                except ValueError as error:
                    raise ReleaseError("installed wheel RECORD digest is malformed") from error
                if algorithm != "sha256":
                    raise ReleaseError("installed wheel RECORD uses an unexpected digest")
                candidate = (site_root / row[0]).resolve()
                if not candidate.is_relative_to(environment_root) or not candidate.is_file():
                    raise ReleaseError("installed wheel RECORD path is missing or escapes")
                try:
                    decoded = base64.b64decode(
                        encoded + "=" * (-len(encoded) % 4),
                        altchars=b"-_",
                        validate=True,
                    )
                except (binascii.Error, ValueError) as error:
                    raise ReleaseError("installed wheel RECORD digest is malformed") from error
                if len(decoded) != 32:
                    raise ReleaseError("installed wheel RECORD digest is malformed")
                expected = decoded.hex()
                if _sha256(candidate.read_bytes()) != expected:
                    raise ReleaseError(f"installed wheel file drifted: {candidate.name}")


def _normalize_release_permissions(release: Path) -> None:
    for root, directories, files in os.walk(release, followlinks=False):
        current = Path(root)
        if not current.is_symlink():
            current.chmod(0o755)
        for name in directories:
            candidate = current / name
            if not candidate.is_symlink():
                candidate.chmod(0o755)
        for name in files:
            candidate = current / name
            if candidate.is_symlink():
                continue
            current_mode = stat.S_IMODE(candidate.stat().st_mode)
            candidate.chmod(0o755 if current_mode & 0o111 else 0o644)


def _launcher_parts(body: bytes, name: str) -> tuple[str, bytes]:
    lines = body.splitlines(keepends=True)
    if not lines:
        raise ReleaseError(f"installed runtime entry point has an invalid shebang: {name}")
    if lines[0].rstrip(b"\r\n") == b"#!/bin/sh":
        if len(lines) < 4 or lines[2].rstrip(b"\r\n") != b"' '''":
            raise ReleaseError(f"installed runtime entry point has an invalid shebang: {name}")
        match = re.fullmatch(
            rb"'''exec' '([^'\r\n]+)' \"\$0\" \"\$@\"\r?\n?",
            lines[1],
        )
        if match is None:
            raise ReleaseError(f"installed runtime entry point has an invalid shebang: {name}")
        encoded_interpreter = match.group(1)
        remainder = b"".join(lines[3:])
    elif lines[0].startswith(b"#!"):
        encoded_interpreter = lines[0][2:].rstrip(b"\r\n")
        remainder = b"".join(lines[1:])
    else:
        raise ReleaseError(f"installed runtime entry point has an invalid shebang: {name}")
    try:
        interpreter = encoded_interpreter.decode("ascii")
    except UnicodeDecodeError as error:
        raise ReleaseError(
            f"installed runtime entry point has an invalid shebang: {name}"
        ) from error
    return interpreter, remainder


def _launcher_body(interpreter: str, remainder: bytes, name: str) -> bytes:
    try:
        encoded = interpreter.encode("ascii")
    except UnicodeEncodeError as error:
        raise ReleaseError(f"installed runtime entry point path is unsafe: {name}") from error
    if not interpreter.startswith("/") or any(value in interpreter for value in ("'", "\r", "\n")):
        raise ReleaseError(f"installed runtime entry point path is unsafe: {name}")
    direct = b"#!" + encoded + b"\n"
    if len(direct) <= 127:
        return direct + remainder
    return b"#!/bin/sh\n'''exec' '" + encoded + b"' \"$0\" \"$@\"\n' '''\n" + remainder


def _verify_runtime_entry_points(
    release: Path,
    *,
    scripts: Sequence[str],
    target_release: Path | None = None,
    python_target: str = "3.12",
) -> None:
    venv = release / "app/.venv"
    target_venv = (target_release or release) / "app/.venv"
    allowed_interpreters = {
        str(target_venv / "bin/python"),
        str(target_venv / "bin/python3"),
        str(target_venv / f"bin/python{python_target}"),
    }
    for name in scripts:
        entry_point = venv / "bin" / name
        if (
            not entry_point.is_file()
            or entry_point.is_symlink()
            or not os.access(entry_point, os.X_OK)
        ):
            raise ReleaseError(f"installed runtime entry point is missing: {name}")
        try:
            interpreter, _remainder = _launcher_parts(entry_point.read_bytes(), name)
        except OSError as error:
            raise ReleaseError(f"installed runtime entry point cannot be read: {name}") from error
        if interpreter not in allowed_interpreters:
            raise ReleaseError(f"installed runtime entry point targets another release: {name}")


def _normalize_runtime_entry_points(
    release: Path,
    *,
    scripts: Sequence[str],
    target_release: Path | None = None,
    python_target: str = "3.12",
) -> None:
    venv = release / "app/.venv"
    interpreter = str((target_release or release) / "app/.venv/bin/python")
    for name in scripts:
        entry_point = venv / "bin" / name
        if not entry_point.is_file() or entry_point.is_symlink():
            raise ReleaseError(f"installed runtime entry point is missing: {name}")
        try:
            body = entry_point.read_bytes()
        except OSError as error:
            raise ReleaseError(f"installed runtime entry point cannot be read: {name}") from error
        old_interpreter, remainder = _launcher_parts(body, name)
        if PurePosixPath(old_interpreter).name not in {
            "python",
            "python3",
            f"python{python_target}",
        }:
            raise ReleaseError(f"installed runtime entry point has an invalid interpreter: {name}")
        temporary = entry_point.with_name(f".{name}.normalize.tmp")
        if temporary.exists() or temporary.is_symlink():
            raise ReleaseError(f"installed runtime entry point temporary path exists: {name}")
        temporary.write_bytes(_launcher_body(interpreter, remainder, name))
        temporary.chmod(0o755)
        os.replace(temporary, entry_point)


def _refresh_runtime_entry_point_records(release: Path, scripts: Sequence[str]) -> None:
    environment_root = (release / "app/.venv").resolve()
    site_roots = {
        candidate.resolve()
        for candidate in environment_root.glob("lib*/python*/site-packages")
        if candidate.is_dir()
    }
    if len(site_roots) != 1:
        raise ReleaseError("installed environment has an unexpected site-packages layout")
    site_root = site_roots.pop()
    targets = {(environment_root / "bin" / name).resolve(): name for name in scripts}
    occurrences = dict.fromkeys(scripts, 0)
    records = sorted(site_root.glob("*.dist-info/RECORD"))
    if not records:
        raise ReleaseError("installed environment has no wheel RECORD files")
    for record in records:
        with record.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.reader(stream))
        changed = False
        for row in rows:
            if len(row) != 3:
                raise ReleaseError("installed wheel RECORD row is malformed")
            candidate = (site_root / row[0]).resolve()
            name = targets.get(candidate)
            if name is None:
                continue
            occurrences[name] += 1
            if occurrences[name] != 1:
                raise ReleaseError(f"installed runtime entry point has duplicate RECORDs: {name}")
            body = candidate.read_bytes()
            digest = base64.urlsafe_b64encode(bytes.fromhex(_sha256(body))).decode("ascii")
            row[1] = f"sha256={digest.rstrip('=')}"
            row[2] = str(len(body))
            changed = True
        if not changed:
            continue
        temporary = record.with_name(f".{record.name}.refresh.tmp")
        if temporary.exists() or temporary.is_symlink():
            raise ReleaseError("installed wheel RECORD temporary path exists")
        with temporary.open("w", newline="", encoding="utf-8") as stream:
            csv.writer(stream, lineterminator="\n").writerows(rows)
        temporary.chmod(stat.S_IMODE(record.stat().st_mode))
        os.replace(temporary, record)
    missing = sorted(name for name, count in occurrences.items() if count != 1)
    if missing:
        raise ReleaseError(f"installed runtime entry point RECORD is missing: {missing[0]}")


def _verified_release_root(release_root: Path) -> Path:
    if not release_root.is_absolute() or release_root.is_symlink():
        raise ReleaseError("release root must be an existing absolute real directory")
    try:
        metadata = os.lstat(release_root)
        resolved = release_root.resolve(strict=True)
    except OSError as error:
        raise ReleaseError("release root is unavailable") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or resolved != release_root
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o755
    ):
        raise ReleaseError("release root must be owned by the installer with exact mode 0755")
    return resolved


def _default_identity_preflight(release: Path, identity: str) -> bool:
    entry_point = release / "app/.venv/bin/smithguard-runtime-preflight"
    try:
        completed = subprocess.run(
            (
                "/usr/sbin/runuser",
                "--user",
                identity,
                "--",
                str(entry_point),
            ),
            check=False,
            cwd="/",
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


def verify_install_preconditions(
    verified: VerifiedRelease,
    *,
    release_root: Path,
    uv_path: Path,
) -> str:
    """Refuse an install before any mutation marker when the host cannot complete it.

    Returns the builder uv version the installer must match. Every check here is
    read-only, so a refusal leaves no pending ownership behind.
    """
    python_target = _manifest_python_target(verified.manifest)
    _installer_python(python_target)
    release_root = _verified_release_root(release_root)
    destination = release_root / verified.commit
    if destination.exists() or destination.is_symlink():
        raise ReleaseError("commit-named release destination already exists")
    expected_uv = verified.manifest["target"]["uv_version"]
    if not isinstance(expected_uv, str) or not UV_VERSION_PATTERN.fullmatch(expected_uv):
        raise ReleaseError("release manifest uv version is invalid")
    if _uv_version(uv_path) != expected_uv:
        raise ReleaseError("installer uv version differs from the reviewed builder version")
    return expected_uv


def install_staging_present(release_root: Path, commit: str) -> bool:
    """Report whether an interrupted install left a staging tree for this commit."""
    if not COMMIT_PATTERN.fullmatch(commit):
        raise ReleaseError("release commit is invalid")
    prefix = f".{commit}."
    try:
        entries = list(os.scandir(release_root))
    except OSError as error:
        raise ReleaseError("release root is unavailable") from error
    # The commit-named entry itself counts as release bytes whatever its type.
    return any(entry.name == commit or entry.name.startswith(prefix) for entry in entries)


@release_mutation("release_install")
def install_release(
    verified: VerifiedRelease,
    *,
    release_root: Path,
    uv_path: Path,
) -> Path:
    python_target = _manifest_python_target(verified.manifest)
    installer_python = _installer_python(python_target)
    expected_uv = verify_install_preconditions(verified, release_root=release_root, uv_path=uv_path)
    release_root = _verified_release_root(release_root)
    destination = release_root / verified.commit
    current_owner().start()
    staging = Path(tempfile.mkdtemp(prefix=f".{verified.commit}.", dir=release_root))
    try:
        for relative, body in sorted(verified.files.items()):
            destination_file = staging / relative
            destination_file.parent.mkdir(parents=True, exist_ok=True)
            destination_file.write_bytes(body)
            destination_file.chmod(0o644)
        _normalize_release_permissions(staging)
        package = staging / "app"
        venv = package / ".venv"
        _run((str(installer_python), "-I", "-m", "venv", "--without-pip", str(venv)), cwd=staging)
        _probe_python_target(venv / "bin/python", python_target)
        environment = dict(os.environ)
        environment.update(
            {
                "UV_NO_CACHE": "1",
                "UV_NO_PROGRESS": "1",
                "UV_PYTHON_DOWNLOADS": "never",
            }
        )
        _run(
            (
                str(uv_path),
                "pip",
                "sync",
                "--python",
                str(venv / "bin/python"),
                "--offline",
                "--no-index",
                "--find-links",
                str(package / "wheelhouse"),
                "--require-hashes",
                "--only-binary",
                ":all:",
                "--strict",
                "--link-mode",
                "copy",
                "--compile-bytecode",
                str(package / REQUIREMENTS_NAME),
            ),
            cwd=staging,
            env=environment,
        )
        python = venv / "bin/python"
        expected_versions = _expected_versions(verified.files)
        if _installed_versions(python) != expected_versions:
            raise ReleaseError("installed environment differs from the release SBOM")
        _verify_installed_records(staging)
        scripts = archive_console_scripts(verified.files)
        _normalize_runtime_entry_points(
            staging, scripts=scripts, target_release=destination, python_target=python_target
        )
        _refresh_runtime_entry_point_records(staging, scripts)
        _normalize_release_permissions(staging)
        _verify_runtime_entry_points(
            staging, scripts=scripts, target_release=destination, python_target=python_target
        )
        _run(
            (
                str(python),
                "-c",
                "import smithguard.runtime, "
                "smithguard.operational_health, "
                "smithguard.migration_runtime, "
                "smithguard.deployment_bootstrap",
            ),
            cwd=staging,
        )
        _run(
            (str(uv_path), "pip", "check", "--python", str(python)),
            cwd=staging,
            env=environment,
        )
        _verify_installed_records(staging)
        installation = {
            "schema_version": "1.0.0",
            "release_commit": verified.commit,
            "archive_sha256": verified.archive_sha256,
            "manifest_sha256": _sha256(verified.files[MANIFEST_NAME]),
            "uv_version": expected_uv,
        }
        installation_path = staging / "INSTALLATION.json"
        installation_path.write_bytes(_canonical_json(installation))
        installation_path.chmod(0o644)
        _normalize_release_permissions(staging)
        os.replace(staging, destination)
    except BaseException:
        if staging.exists() and staging.parent == release_root:
            shutil.rmtree(staging)
        raise
    return destination


def _default_unit_active(unit: str) -> bool:
    load = subprocess.run(
        ("systemctl", "show", unit, "--property=LoadState", "--value"),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if load.returncode == 0 and load.stdout.strip() == "not-found":
        return False  # a unit the host does not have cannot be running
    job = subprocess.run(
        ("systemctl", "show", unit, "--property=Job", "--value"),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    state = subprocess.run(
        ("systemctl", "is-active", unit),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return not (
        job.returncode == 0
        and job.stdout.strip() in {"", "0", "[0]"}
        and state.returncode in {0, 3}
        and state.stdout.strip() in {"inactive", "failed"}
    )


@release_mutation("release_activate")
def activate_release(
    commit: str,
    *,
    release_root: Path,
    current_link: Path,
    unit_active: Callable[[str], bool] = _default_unit_active,
    identity_preflight: Callable[[Path, str], bool] = _default_identity_preflight,
    post_switch_verify: Callable[[Path, Path], bool] | None = None,
) -> Path:
    if not COMMIT_PATTERN.fullmatch(commit):
        raise ReleaseError("activation commit is invalid")
    release_root = _verified_release_root(release_root)
    destination = release_root / commit
    if (
        not destination.is_dir()
        or destination.is_symlink()
        or not (destination / "INSTALLATION.json").is_file()
    ):
        raise ReleaseError("prepared commit-named release is missing")
    active = [unit for unit in (*SYSTEMD_UNITS, *RETIRED_ONESHOT_SERVICES) if unit_active(unit)]
    if active:
        raise ReleaseError(f"release activation requires stopped units: {', '.join(active)}")
    sysusers_path = destination / ARCHIVE_APP_ROOT / SYSUSERS_PATH
    if sysusers_path.is_symlink() or not sysusers_path.is_file():
        raise ReleaseError("release sysusers inventory is missing")
    identities = packaged_identities(sysusers_path.read_bytes())
    failed_identities = [
        identity for identity in identities if not identity_preflight(destination, identity)
    ]
    if failed_identities:
        raise ReleaseError(
            "release traversal preflight failed for: " + ", ".join(failed_identities)
        )
    if not current_link.is_absolute() or current_link.parent.is_symlink():
        raise ReleaseError("current release link path is unsafe")
    _verified_release_root(current_link.parent)
    if current_link.exists() and not current_link.is_symlink():
        raise ReleaseError("current release path exists and is not a symlink")
    previous_target = os.readlink(current_link) if current_link.is_symlink() else None
    if current_link.is_symlink() and current_link.resolve() == destination:
        raise ReleaseError("release activation is already applied")
    temporary = current_link.with_name(f".{current_link.name}.{os.getpid()}.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise ReleaseError("temporary activation link already exists")
    current_owner().start()
    temporary.symlink_to(destination)
    try:
        os.replace(temporary, current_link)
    finally:
        if temporary.is_symlink():
            temporary.unlink()
    verifier = post_switch_verify or (lambda link, selected: link.resolve() == selected.resolve())
    try:
        if not verifier(current_link, destination):
            raise ReleaseError("atomic release activation did not select the intended commit")
    except BaseException as switch_error:
        if previous_target is None:
            current_link.unlink(missing_ok=True)
        else:
            rollback = current_link.with_name(f".{current_link.name}.{os.getpid()}.rollback.tmp")
            if rollback.exists() or rollback.is_symlink():
                raise ReleaseError(
                    "temporary activation rollback link already exists"
                ) from switch_error
            rollback.symlink_to(previous_target)
            try:
                os.replace(rollback, current_link)
            finally:
                if rollback.is_symlink():
                    rollback.unlink()
        raise
    return destination


def verify_installed_release(
    commit: str,
    *,
    release_root: Path,
) -> Mapping[str, Any]:
    if not COMMIT_PATTERN.fullmatch(commit):
        raise ReleaseError("drift-check commit is invalid")
    release_root = _verified_release_root(release_root)
    release = release_root / commit
    installation_path = release / "INSTALLATION.json"
    manifest_path = release / MANIFEST_NAME
    if (
        not release.is_dir()
        or release.is_symlink()
        or not installation_path.is_file()
        or installation_path.is_symlink()
        or not manifest_path.is_file()
        or manifest_path.is_symlink()
    ):
        raise ReleaseError("installed release metadata is missing")
    try:
        installation = json.loads(installation_path.read_text(encoding="ascii"))
        manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseError("installed release metadata is invalid") from error
    if (
        not isinstance(installation, Mapping)
        or not isinstance(manifest, Mapping)
        or set(installation)
        != {
            "schema_version",
            "release_commit",
            "archive_sha256",
            "manifest_sha256",
            "uv_version",
        }
        or installation.get("schema_version") != "1.0.0"
        or installation.get("release_commit") != commit
        or not isinstance(installation.get("archive_sha256"), str)
        or not SHA256_PATTERN.fullmatch(installation["archive_sha256"])
        or not isinstance(installation.get("manifest_sha256"), str)
        or not SHA256_PATTERN.fullmatch(installation["manifest_sha256"])
        or not isinstance(installation.get("uv_version"), str)
        or manifest.get("release_commit") != commit
        or installation.get("manifest_sha256") != _sha256(manifest_path.read_bytes())
    ):
        raise ReleaseError("installed release identity metadata differs")
    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise ReleaseError("installed release manifest has an invalid file list")
    try:
        site_files = product_site.installed_site_files(release)
    except (OSError, product_site.SiteError) as error:
        raise ReleaseError("installed product tree is unsafe") from error
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, Mapping) or set(entry) != {"path", "size", "sha256", "mode"}:
            raise ReleaseError("installed release manifest file entry is invalid")
        relative = entry["path"]
        if (
            not isinstance(relative, str)
            or relative == MANIFEST_NAME
            or relative in seen
            or not _safe_relative_path(relative)
            or not _allowed_release_path(relative)
            or entry["mode"] != "0644"
            or not isinstance(entry["size"], int)
            or not isinstance(entry["sha256"], str)
            or not SHA256_PATTERN.fullmatch(entry["sha256"])
        ):
            raise ReleaseError("installed release manifest contains an unsafe file entry")
        seen.add(relative)
        path = release / relative
        if (
            not path.is_file()
            or path.is_symlink()
            or path.stat().st_size != entry["size"]
            or _sha256(path.read_bytes()) != entry["sha256"]
        ):
            raise ReleaseError(f"installed release payload drifted: {relative}")
    site_paths = {
        path for path in seen if path.startswith("site/") or path == product_site.PROVENANCE_PATH
    }
    if set(site_files) != site_paths:
        raise ReleaseError("installed product and release manifest file sets differ")
    if site_files:
        wheel_files = {
            path: (release / path).read_bytes()
            for path in seen
            if path.startswith("app/wheelhouse/smithguard-") and path.endswith(".whl")
        }
        _verify_product_site({**site_files, **wheel_files})
    python = release / "app/.venv/bin/python"
    expected = _expected_versions(
        {
            SBOM_NAME: (release / SBOM_NAME).read_bytes(),
        }
    )
    python_target = _manifest_python_target(manifest)
    _probe_python_target(python, python_target)
    if _installed_versions(python) != expected:
        raise ReleaseError("installed package versions differ from the release SBOM")
    _verify_runtime_entry_points(
        release, scripts=installed_tree_console_scripts(release), python_target=python_target
    )
    _verify_installed_records(release)
    return {
        "release_commit": commit,
        "archive_sha256": installation["archive_sha256"],
        "manifest_files": len(manifest["files"]),
        "installed_packages": len(expected),
        "drift": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="build one exact pushed runtime release")
    build.add_argument("--commit", required=True)
    build.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify", help="verify a runtime archive without extracting it")
    verify.add_argument("archive", type=Path)
    verify.add_argument("--commit", required=True)
    verify.add_argument("--sha256", required=True)
    install = commands.add_parser("install", help="verify and prepare a commit-named release")
    install.add_argument("archive", type=Path)
    install.add_argument("--commit", required=True)
    install.add_argument("--sha256", required=True)
    install.add_argument(
        "--release-root",
        type=Path,
        default=Path("/opt/SmithGuard/releases"),
    )
    install.add_argument("--uv", type=Path, default=Path("/usr/local/bin/uv"))
    activate = commands.add_parser("activate", help="atomically select a prepared stopped release")
    activate.add_argument("--commit", required=True)
    activate.add_argument(
        "--release-root",
        type=Path,
        default=Path("/opt/SmithGuard/releases"),
    )
    activate.add_argument(
        "--current-link",
        type=Path,
        default=Path("/opt/SmithGuard/current"),
    )
    drift = commands.add_parser("drift", help="verify an installed release and its wheels")
    drift.add_argument("--commit", required=True)
    drift.add_argument(
        "--release-root",
        type=Path,
        default=Path("/opt/SmithGuard/releases"),
    )
    return parser


def main() -> None:
    arguments = _parser().parse_args()
    if arguments.command == "build":
        result = build_release(arguments.commit, arguments.output.resolve())
    elif arguments.command == "verify":
        verified = _load_verified_archive(
            arguments.archive.resolve(), arguments.commit, arguments.sha256
        )
        result = {
            "release_commit": verified.commit,
            "archive_sha256": verified.archive_sha256,
            "manifest_files": len(verified.manifest["files"]),
            "uv_version": verified.manifest["target"]["uv_version"],
            "verified": True,
        }
    elif arguments.command == "install":
        verified = _load_verified_archive(
            arguments.archive.resolve(), arguments.commit, arguments.sha256
        )
        destination = install_release(
            verified,
            release_root=arguments.release_root.resolve(),
            uv_path=arguments.uv.resolve(),
        )
        result = {
            "release_commit": verified.commit,
            "installed": str(destination),
            "activated": False,
        }
    elif arguments.command == "activate":
        destination = activate_release(
            arguments.commit,
            release_root=arguments.release_root.resolve(),
            current_link=arguments.current_link,
        )
        result = {"release_commit": arguments.commit, "activated": str(destination)}
    else:
        result = verify_installed_release(
            arguments.commit,
            release_root=arguments.release_root.resolve(),
        )
    print(canonical_json_bytes(result).decode("ascii"))


if __name__ == "__main__":
    try:
        main()
    except (ReleaseError, MutationError) as error:
        raise SystemExit(f"runtime release refused: {error}") from error
