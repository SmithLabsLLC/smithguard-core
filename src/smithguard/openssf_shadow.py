"""Isolated, disabled-by-default OpenSSF Malicious Packages shadow runtime."""

from __future__ import annotations

import argparse
import contextlib
import errno
import fcntl
import gzip
import hashlib
import io
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any, BinaryIO

from smithguard.fsio import (
    FsioError,
    atomic_write,
    fsync_directory,
    read_private_file,
    write_exclusive,
)
from smithguard.identifiers import SHA256, canonical_json_line, parse_timestamp
from smithguard.openssf_budget import bounded_timeout
from smithguard.openssf_git import (
    COMMIT,
    MAX_PAGE_SIZE,
    OPENSSF_LICENSE_SHA256,
    OPENSSF_MALICIOUS,
    OPENSSF_REPOSITORY_URL,
    LocalOpenSSFGitRepository,
    OpenSSFChange,
    OpenSSFGitEntry,
    OpenSSFGitError,
    OpenSSFProvisionalIDError,
    OpenSSFSnapshot,
    raw_batches,
)
from smithguard.source_rights import RightsRegistry, SourceRightsError

DEFAULT_STATE_ROOT = Path("/var/lib/smithguard/openssf-shadow")
DEFAULT_RIGHTS_REGISTER = Path("/opt/SmithGuard/current/contracts/v1/source-rights-register.json")
GIT_EXECUTABLE = "/usr/bin/git"
ENABLED_VARIABLE = "SMITHGUARD_OPENSSF_SHADOW_ENABLED"
RIGHTS_VARIABLE = "SMITHGUARD_RIGHTS_REGISTER_PATH"
OFFICIAL_BRANCH = "main"
BOOTSTRAP_COMMIT = "7ee8a3f50a5721235b26c9085540cf069599a77c"
FETCH_DEPTH = 512
FETCH_DEEPEN_STEPS = (2_048, 8_192)
FETCH_TIMEOUT_SECONDS = 1_200
FULL_VALIDATION_INTERVAL = timedelta(hours=24)
HEALTH_MAX_AGE = timedelta(hours=3)
MAX_CLOCK_FUTURE = timedelta(minutes=5)
MAX_CHECKPOINT_BYTES = 16_384
MAX_COMPRESSED_MANIFEST_BYTES = 536_870_912
MAX_MANIFEST_BYTES = 536_870_912
MAX_QUARANTINE_SAMPLES = 100
MAX_RECEIPT_BYTES = 1_048_576
MAX_STATE_ENTRIES = 2_000_000
MAX_STATE_APPARENT_BYTES = 5 * 1024**3
MIN_FILESYSTEM_AVAILABLE_BYTES = 20 * 1024**3
MAX_FILESYSTEM_USED_PERCENT = 75
PROVISIONAL_SETTLE_INTERVAL_SECONDS = 90
PROVISIONAL_SETTLE_MAX_OBSERVATIONS = 3
MONITOR_RECEIPT_VARIABLE = "SMITHGUARD_OPENSSF_MONITOR_RECEIPT_PATH"
MONITOR_SCHEMA_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0.0"


class OpenSSFShadowError(RuntimeError):
    """The isolated shadow lane could not produce a trustworthy checkpoint."""


@dataclass(frozen=True, slots=True)
class ShadowCapacityLimits:
    maximum_state_apparent_bytes: int
    minimum_filesystem_available_bytes: int
    maximum_filesystem_used_percent: int


@dataclass(frozen=True, slots=True)
class ShadowCapacityMeasurement:
    state_apparent_bytes: int
    state_entry_count: int
    filesystem_available_bytes: int
    filesystem_used_percent: int
    capacity_exceeded: bool = False


PRODUCTION_CAPACITY_LIMITS = ShadowCapacityLimits(
    maximum_state_apparent_bytes=MAX_STATE_APPARENT_BYTES,
    minimum_filesystem_available_bytes=MIN_FILESYSTEM_AVAILABLE_BYTES,
    maximum_filesystem_used_percent=MAX_FILESYSTEM_USED_PERCENT,
)


@dataclass(frozen=True, slots=True)
class ShadowPaths:
    root: Path
    repository: Path
    manifests: Path
    runs: Path
    checkpoint: Path
    latest: Path
    lock: Path

    @classmethod
    def from_root(cls, root: Path) -> ShadowPaths:
        return cls(
            root=root,
            repository=root / "repository",
            manifests=root / "manifests",
            runs=root / "runs",
            checkpoint=root / "checkpoint.json",
            latest=root / "latest.json",
            lock=root / "run.lock",
        )


def _canonical_json(document: Mapping[str, Any]) -> bytes:
    # Layout 2: the canonical hash encoder plus one newline; non-finite numbers now raise.
    return canonical_json_line(document)


def _sha256(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise OpenSSFShadowError("shadow time must include a timezone")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _clock_value(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if value.tzinfo is None or value.utcoffset() is None:
        raise OpenSSFShadowError("shadow clock must include a timezone")
    return value.astimezone(UTC)


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str) or not value.isascii():
        raise OpenSSFShadowError("shadow receipt time is invalid")
    try:
        return parse_timestamp(value, maximum=40)
    except ValueError as error:
        raise OpenSSFShadowError("shadow receipt time is invalid") from error


def _ensure_private_directory(path: Path) -> None:
    if not path.is_absolute():
        raise OpenSSFShadowError("shadow state root must be absolute")
    with suppress(FileExistsError):
        path.mkdir(mode=0o700)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise OpenSSFShadowError("shadow state directory is unavailable") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
    ):
        raise OpenSSFShadowError("shadow state directory is unsafe")
    path.chmod(0o700)
    if path.resolve(strict=True) != path:
        raise OpenSSFShadowError("shadow state directory must not traverse a symlink")


def _prepare_paths(root: Path) -> ShadowPaths:
    paths = ShadowPaths.from_root(root)
    _ensure_private_directory(paths.root)
    _ensure_private_directory(paths.manifests)
    _ensure_private_directory(paths.runs)
    return paths


class OpenSSFStateBusy(OpenSSFShadowError):
    """An existing collector or reviewed maintenance operation holds the state lock."""


def measure_state_capacity(
    root: Path,
    *,
    maximum_state_apparent_bytes: int = MAX_STATE_APPARENT_BYTES,
    maximum_state_entries: int = MAX_STATE_ENTRIES,
    clamp_overflow: bool = False,
    allow_group_read: bool = False,
) -> ShadowCapacityMeasurement:
    """Measure the complete private tree and its containing filesystem without mutation."""
    if (
        isinstance(maximum_state_apparent_bytes, bool)
        or not isinstance(maximum_state_apparent_bytes, int)
        or not 1 <= maximum_state_apparent_bytes <= MAX_STATE_APPARENT_BYTES
        or isinstance(maximum_state_entries, bool)
        or not isinstance(maximum_state_entries, int)
        or not 1 <= maximum_state_entries <= MAX_STATE_ENTRIES
    ):
        raise OpenSSFShadowError("shadow state capacity limit is invalid")
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise OpenSSFShadowError(
            "shadow state root is unavailable for capacity measurement"
        ) from error
    if (
        stat.S_ISLNK(root_metadata.st_mode)
        or not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
        or root.resolve(strict=True) != root
    ):
        raise OpenSSFShadowError("shadow state root is unsafe for capacity measurement")
    apparent_bytes = root_metadata.st_size
    entry_count = 0
    seen_files: set[tuple[int, int]] = set()
    pending = [root]
    capacity_exceeded = False
    while pending:
        directory = pending.pop()
        try:
            children = list(os.scandir(directory))
        except OSError as error:
            raise OpenSSFShadowError("shadow state capacity cannot be enumerated") from error
        for child in children:
            try:
                metadata = child.stat(follow_symlinks=False)
            except OSError as error:
                raise OpenSSFShadowError("shadow state capacity metadata is unavailable") from error
            if metadata.st_dev != root_metadata.st_dev:
                raise OpenSSFShadowError("shadow state crosses a filesystem boundary")
            if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & (
                0o027 if allow_group_read else 0o077
            ):
                raise OpenSSFShadowError("shadow state capacity boundary is unsafe")
            entry_count += 1
            if entry_count > maximum_state_entries:
                if not clamp_overflow:
                    raise OpenSSFShadowError(
                        "shadow state entry count exceeds its reviewed boundary"
                    )
                entry_count = maximum_state_entries
                capacity_exceeded = True
                pending.clear()
                break
            if stat.S_ISDIR(metadata.st_mode):
                apparent_bytes += metadata.st_size
                pending.append(Path(child.path))
            elif stat.S_ISREG(metadata.st_mode):
                identity = (metadata.st_dev, metadata.st_ino)
                if identity not in seen_files:
                    seen_files.add(identity)
                    apparent_bytes += metadata.st_size
            else:
                raise OpenSSFShadowError("shadow state contains a non-regular entry")
            if apparent_bytes > maximum_state_apparent_bytes:
                if not clamp_overflow:
                    raise OpenSSFShadowError("shadow state exceeds the cumulative capacity limit")
                apparent_bytes = maximum_state_apparent_bytes
                capacity_exceeded = True
                pending.clear()
                break
    try:
        filesystem = os.statvfs(root)
    except OSError as error:
        raise OpenSSFShadowError("shadow state filesystem cannot be measured") from error
    block_size = filesystem.f_frsize or filesystem.f_bsize
    available = filesystem.f_bavail * block_size
    used = (filesystem.f_blocks - filesystem.f_bfree) * block_size
    usable = used + available
    if block_size <= 0 or filesystem.f_blocks <= 0 or usable <= 0:
        raise OpenSSFShadowError("shadow state filesystem measurement is invalid")
    used_percent = (used * 100 + usable - 1) // usable
    return ShadowCapacityMeasurement(
        state_apparent_bytes=apparent_bytes,
        state_entry_count=entry_count,
        filesystem_available_bytes=available,
        filesystem_used_percent=used_percent,
        capacity_exceeded=capacity_exceeded,
    )


def require_state_capacity(
    root: Path,
    *,
    limits: ShadowCapacityLimits = PRODUCTION_CAPACITY_LIMITS,
) -> ShadowCapacityMeasurement:
    measurement = measure_state_capacity(
        root,
        maximum_state_apparent_bytes=limits.maximum_state_apparent_bytes,
    )
    if measurement.filesystem_available_bytes < limits.minimum_filesystem_available_bytes:
        raise OpenSSFShadowError("shadow state filesystem has insufficient available capacity")
    if measurement.filesystem_used_percent >= limits.maximum_filesystem_used_percent:
        raise OpenSSFShadowError("shadow state filesystem use reached its capacity limit")
    return measurement


def _private_file(path: Path, *, maximum: int) -> bytes:
    """Read a private state file: exactly mode 0o600, owned by this process, bounded.

    The check now happens on the opened descriptor (fstat after open) rather than an
    lstat before a separate read, which closes the former swap window.
    """
    try:
        return read_private_file(
            path, maximum=maximum, mode_mask=None, exact_mode=0o600, uid=os.geteuid(), minimum=0
        )
    except FsioError as error:
        # A symlink (ELOOP under O_NOFOLLOW) is a boundary problem as before; any other
        # open failure is unavailability, as the former lstat failure was.
        if error.code == "missing" or (error.code == "unsafe" and error.errno != errno.ELOOP):
            raise OpenSSFShadowError("shadow state file is unavailable") from error
        raise OpenSSFShadowError("shadow state file has an unsafe boundary") from error
    except OSError as error:
        raise OpenSSFShadowError("shadow state file cannot be read") from error


def _fsync_directory(path: Path) -> None:
    fsync_directory(path)


def _write_exclusive(path: Path, body: bytes) -> None:
    write_exclusive(path, body, mode=0o600)


def _write_atomic(path: Path, body: bytes) -> None:
    if path.exists() or path.is_symlink():
        _private_file(path, maximum=MAX_RECEIPT_BYTES)
    atomic_write(path, body, mode=0o600)


@contextmanager
def _exclusive_lock(path: Path):
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    stream: BinaryIO | None = None
    try:
        stream = os.fdopen(descriptor, "r+b")
        metadata = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise OpenSSFShadowError("shadow lock has an unsafe boundary")
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise OpenSSFStateBusy("another OpenSSF state operation is active") from error
        yield
    finally:
        if stream is not None:
            stream.close()
        else:
            os.close(descriptor)


def _git_environment(home: Path) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_ASKPASS": "/bin/false",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }


def _network_git(home: Path, arguments: Sequence[str]) -> bytes:
    command = (
        GIT_EXECUTABLE,
        "--no-replace-objects",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "credential.helper=",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "http.lowSpeedLimit=1024",
        "-c",
        "http.lowSpeedTime=60",
        "-c",
        "fetch.unpackLimit=1",
        "-c",
        "gc.auto=0",
        "-c",
        "maintenance.auto=false",
        *arguments,
    )
    try:
        completed = subprocess.run(  # noqa: S603 - fixed Git command, no shell
            command,
            check=False,
            capture_output=True,
            env=_git_environment(home),
            timeout=bounded_timeout(FETCH_TIMEOUT_SECONDS),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise OpenSSFShadowError("bounded official OpenSSF Git retrieval failed") from error
    if (
        completed.returncode != 0
        or len(completed.stdout) > 16_384
        or len(completed.stderr) > 65_536
    ):
        raise OpenSSFShadowError("official OpenSSF Git retrieval was rejected")
    return completed.stdout


def _local_git(repository: Path, *arguments: str, maximum: int = 512) -> str:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed Git command, no shell
            (
                GIT_EXECUTABLE,
                "-c",
                "core.hooksPath=/dev/null",
                "--no-replace-objects",
                "-C",
                str(repository),
                *arguments,
            ),
            check=False,
            capture_output=True,
            env=_git_environment(repository),
            timeout=bounded_timeout(120),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise OpenSSFShadowError("bounded shadow Git command failed") from error
    if completed.returncode != 0 or len(completed.stdout) > maximum or len(completed.stderr) > 4096:
        raise OpenSSFShadowError("shadow Git repository rejected its reviewed operation")
    try:
        return completed.stdout.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise OpenSSFShadowError("shadow Git metadata is not ASCII") from error


GIT_MAINTENANCE_STOP_GRACE_SECONDS = 10
# Lock files Git itself creates during maintenance. The catalog run lock guarantees no
# other Git process uses this repository, so leftovers can only be from the stopped run.
STALE_GIT_LOCKS = (
    "shallow.lock",
    "gc.pid",
    "gc.log.lock",
    "packed-refs.lock",
    "config.lock",
    "HEAD.lock",
    "index.lock",
    "objects/info/commit-graphs/commit-graph-chain.lock",
)


def _group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _stop_process_group(process: subprocess.Popen) -> bool:
    """Stop every process in the group (Git's repack and prune children included).

    Sends SIGTERM, waits for the leader, then SIGKILLs any member still alive and waits
    until the group is empty. Returns False if members survive the bounded wait.
    """
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=GIT_MAINTENANCE_STOP_GRACE_SECONDS)
    deadline = time.monotonic() + GIT_MAINTENANCE_STOP_GRACE_SECONDS
    while _group_alive(process.pid):
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        if process.poll() is None:
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=0.2)
        else:
            time.sleep(0.05)
        if time.monotonic() >= deadline:
            return not _group_alive(process.pid)
    return True


def _remove_stale_git_locks(repository: Path) -> list[str]:
    git_dir = repository / ".git" if (repository / ".git").is_dir() else repository
    removed = []
    for relative in STALE_GIT_LOCKS:
        path = git_dir / relative
        if path.is_file() and not path.is_symlink():
            path.unlink()
            removed.append(relative)
    if removed:
        sys.stderr.write(
            "collection_diagnostic:git_maintenance_locks_removed " + ",".join(removed) + "\n"
        )
    return removed


def maintain_repository(repository: Path, *, auto_pack_limit: int | None = None) -> bool:
    """Let Git consolidate the mirror after a successful run (``git gc --auto``).

    Fetches deliberately disable automatic maintenance so objects never change while a
    run inspects them. The caller runs this last, still holding the catalog lock; Git's
    own thresholds decide whether to repack and prune history below the shallow
    boundary, replacing the former hand-operated compaction. Detaching is disabled so
    the work finishes (or is killed with its whole process group at the deadline)
    before the lock is released. Returns False on any failure; the caller only logs.
    """
    command = [
        GIT_EXECUTABLE,
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "gc.autoDetach=false",
        "-c",
        "maintenance.autoDetach=false",
    ]
    if auto_pack_limit is not None:
        command += ["-c", f"gc.autoPackLimit={int(auto_pack_limit)}"]
    command += ["-C", str(repository), "gc", "--auto", "--quiet"]
    # The remaining catalog budget is computed before anything starts; an exhausted
    # budget raises here and nothing is left running.
    timeout = bounded_timeout(300)
    try:
        process = subprocess.Popen(  # noqa: S603 - fixed Git command, no shell
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=_git_environment(repository),
            start_new_session=True,
        )
    except OSError:
        return False
    finished = False
    try:
        returncode = process.wait(timeout=timeout)
        finished = True
        return returncode == 0
    except subprocess.TimeoutExpired:
        return False
    finally:
        # Any exit other than normal completion (timeout, a stop signal, an exception)
        # stops and reaps the whole Git process group before the run lock is released:
        # first a graceful SIGTERM, then SIGKILL, then removal of Git's own lock files.
        if not finished:
            # Locks are removed only once no Git process from this run can still write.
            if _stop_process_group(process):
                _remove_stale_git_locks(repository)
            else:
                sys.stderr.write("collection_diagnostic:git_maintenance_group_survived\n")


def _forward_transition_present(repository: Path, before: str, after: str) -> bool:
    if COMMIT.fullmatch(before) is None or COMMIT.fullmatch(after) is None:
        raise OpenSSFShadowError("shadow transition commits are invalid")
    try:
        completed = subprocess.run(  # noqa: S603 - fixed Git command, no shell
            (
                GIT_EXECUTABLE,
                "-c",
                "core.hooksPath=/dev/null",
                "--no-replace-objects",
                "-C",
                str(repository),
                "merge-base",
                "--is-ancestor",
                before,
                after,
            ),
            check=False,
            capture_output=True,
            env=_git_environment(repository),
            timeout=bounded_timeout(120),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise OpenSSFShadowError("bounded shadow ancestry check failed") from error
    if completed.returncode not in {0, 1, 128} or completed.stdout or len(completed.stderr) > 4096:
        raise OpenSSFShadowError("shadow ancestry check crossed its reviewed boundary")
    return completed.returncode == 0


def _commit_present(repository: Path, commit: str) -> bool:
    if COMMIT.fullmatch(commit) is None:
        raise OpenSSFShadowError("shadow commit is invalid")
    try:
        completed = subprocess.run(  # noqa: S603 - fixed Git command, no shell
            (
                GIT_EXECUTABLE,
                "-c",
                "core.hooksPath=/dev/null",
                "--no-replace-objects",
                "-C",
                str(repository),
                "cat-file",
                "-e",
                f"{commit}^{{commit}}",
            ),
            check=False,
            capture_output=True,
            env=_git_environment(repository),
            timeout=bounded_timeout(120),
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise OpenSSFShadowError("shadow commit presence check failed") from error
    return completed.returncode == 0


def ensure_commit_available(
    paths: ShadowPaths, commit: str, *, allow_bootstrap_fetch: bool = False
) -> None:
    """Recover history, with one exact fetch allowed only for the trusted bootstrap."""
    if _commit_present(paths.repository, commit):
        return
    for deepen_by in FETCH_DEEPEN_STEPS:
        if (
            _local_git(paths.repository, "rev-parse", "--is-shallow-repository", maximum=16)
            != "true"
        ):
            break
        _network_git(
            paths.root,
            (
                "-C",
                str(paths.repository),
                "fetch",
                "--no-tags",
                "--prune",
                f"--deepen={deepen_by}",
                OPENSSF_REPOSITORY_URL,
                f"+refs/heads/{OFFICIAL_BRANCH}:refs/remotes/origin/{OFFICIAL_BRANCH}",
            ),
        )
        if _commit_present(paths.repository, commit):
            return
    if allow_bootstrap_fetch and commit == BOOTSTRAP_COMMIT:
        # This only acquires the fixed initial catalog tree. FETCH_HEAD is not a
        # checkpoint or a branch update, and checkpoint ancestry never uses this path.
        _network_git(
            paths.root,
            (
                "-C",
                str(paths.repository),
                "fetch",
                "--no-tags",
                "--depth=1",
                OPENSSF_REPOSITORY_URL,
                BOOTSTRAP_COMMIT,
            ),
        )
        if _commit_present(paths.repository, commit):
            return
    raise OpenSSFShadowError("fixed OpenSSF commit is unavailable after bounded history recovery")


def _deepen_for_checkpoint(paths: ShadowPaths, observed_commit: str) -> None:
    checkpoint = _checkpoint(paths)
    if checkpoint is None:
        return
    previous_commit = checkpoint["commit"]
    if _forward_transition_present(paths.repository, previous_commit, observed_commit):
        return
    for deepen_by in FETCH_DEEPEN_STEPS:
        if (
            _local_git(
                paths.repository,
                "rev-parse",
                "--is-shallow-repository",
                maximum=16,
            )
            != "true"
        ):
            break
        _network_git(
            paths.root,
            (
                "-C",
                str(paths.repository),
                "fetch",
                "--no-tags",
                "--prune",
                f"--deepen={deepen_by}",
                OPENSSF_REPOSITORY_URL,
                f"+refs/heads/{OFFICIAL_BRANCH}:refs/remotes/origin/{OFFICIAL_BRANCH}",
            ),
        )
        if _forward_transition_present(paths.repository, previous_commit, observed_commit):
            return
    raise OpenSSFShadowError(
        "OpenSSF update is not a forward commit transition after bounded history recovery"
    )


def sync_official_repository(paths: ShadowPaths) -> tuple[Path, str]:
    """Retrieve only the fixed official HTTPS main branch into private state."""
    if not paths.repository.exists() and not paths.repository.is_symlink():
        temporary = paths.root / f".repository.{uuid.uuid4().hex}.tmp"
        try:
            _network_git(
                paths.root,
                (
                    "clone",
                    "--no-checkout",
                    f"--depth={FETCH_DEPTH}",
                    "--single-branch",
                    "--branch",
                    OFFICIAL_BRANCH,
                    "--no-tags",
                    OPENSSF_REPOSITORY_URL,
                    str(temporary),
                ),
            )
            temporary.chmod(0o700)
            os.replace(temporary, paths.repository)
        finally:
            if temporary.exists() and temporary.parent == paths.root:
                shutil.rmtree(temporary)
    else:
        try:
            metadata = paths.repository.lstat()
        except OSError as error:
            raise OpenSSFShadowError("OpenSSF shadow repository is unavailable") from error
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or paths.repository.resolve(strict=True) != paths.repository
        ):
            raise OpenSSFShadowError("OpenSSF shadow repository is unsafe")
        paths.repository.chmod(0o700)
        _network_git(
            paths.root,
            (
                "-C",
                str(paths.repository),
                "fetch",
                "--no-tags",
                "--prune",
                f"--depth={FETCH_DEPTH}",
                OPENSSF_REPOSITORY_URL,
                f"+refs/heads/{OFFICIAL_BRANCH}:refs/remotes/origin/{OFFICIAL_BRANCH}",
            ),
        )
    commit = _local_git(
        paths.repository,
        "rev-parse",
        "--verify",
        f"refs/remotes/origin/{OFFICIAL_BRANCH}^{{commit}}",
        maximum=128,
    )
    if COMMIT.fullmatch(commit) is None:
        raise OpenSSFShadowError("official OpenSSF branch did not resolve to a full commit")
    _deepen_for_checkpoint(paths, commit)
    return paths.repository, commit


def _entry_row(entry: OpenSSFGitEntry) -> dict[str, object]:
    return {
        "advisory_id": entry.advisory_id,
        "blob_oid": entry.blob_oid,
        "byte_count": entry.byte_count,
        "ecosystem": entry.ecosystem,
        "package_path": entry.package_path,
        "path": entry.path,
        "source_state": entry.source_state,
    }


def _gunzip_bounded(body: bytes) -> bytes:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(body), mode="rb") as stream:
            expanded = stream.read(MAX_MANIFEST_BYTES + 1)
    except OSError as error:
        raise OpenSSFShadowError("stored shadow manifest is invalid") from error
    if len(expanded) > MAX_MANIFEST_BYTES:
        raise OpenSSFShadowError("stored shadow manifest exceeds its reviewed boundary")
    return expanded


def _manifest(snapshot: OpenSSFSnapshot) -> tuple[bytes, dict[str, dict[str, object]]]:
    rows = [_entry_row(entry) for entry in snapshot.entries]
    document = {"commit": snapshot.commit, "entries": rows, "schema_version": SCHEMA_VERSION}
    return _canonical_json(document), {str(row["path"]): row for row in rows}


def _load_manifest(path: Path, *, commit: str, digest: str) -> dict[str, dict[str, object]]:
    if not SHA256.fullmatch(digest):
        raise OpenSSFShadowError("prior manifest digest is invalid")
    try:
        body = _gunzip_bounded(_private_file(path, maximum=MAX_COMPRESSED_MANIFEST_BYTES))
        document = json.loads(body.decode("ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OpenSSFShadowError("prior shadow manifest is invalid") from error
    if _sha256(body) != digest or not isinstance(document, Mapping):
        raise OpenSSFShadowError("prior shadow manifest digest differs")
    if document.get("schema_version") != SCHEMA_VERSION or document.get("commit") != commit:
        raise OpenSSFShadowError("prior shadow manifest identity differs")
    rows = document.get("entries")
    if not isinstance(rows, list):
        raise OpenSSFShadowError("prior shadow manifest entries are invalid")
    result: dict[str, dict[str, object]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            raise OpenSSFShadowError("prior shadow manifest row is invalid")
        path_value = row["path"]
        if path_value in result:
            raise OpenSSFShadowError("prior shadow manifest path is duplicated")
        result[path_value] = row
    return result


def _write_manifest(paths: ShadowPaths, commit: str, body: bytes) -> tuple[str, Path]:
    if len(body) > MAX_MANIFEST_BYTES:
        raise OpenSSFShadowError("shadow manifest exceeds its reviewed boundary")
    digest = _sha256(body)
    destination = paths.manifests / f"{commit}.json.gz"
    compressed = gzip.compress(body, compresslevel=6, mtime=0)
    if len(compressed) > MAX_COMPRESSED_MANIFEST_BYTES:
        raise OpenSSFShadowError("compressed shadow manifest exceeds its reviewed boundary")
    if destination.exists() or destination.is_symlink():
        try:
            existing = _gunzip_bounded(
                _private_file(destination, maximum=MAX_COMPRESSED_MANIFEST_BYTES)
            )
        except OSError as error:
            raise OpenSSFShadowError("stored shadow manifest is invalid") from error
        if existing != body:
            raise OpenSSFShadowError("stored shadow manifest differs for one commit")
    else:
        _write_exclusive(destination, compressed)
    return digest, destination


def _checkpoint(paths: ShadowPaths) -> dict[str, Any] | None:
    if not paths.checkpoint.exists() and not paths.checkpoint.is_symlink():
        return None
    try:
        document = json.loads(
            _private_file(paths.checkpoint, maximum=MAX_CHECKPOINT_BYTES).decode("ascii")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OpenSSFShadowError("shadow checkpoint is invalid") from error
    required = {
        "commit",
        "last_full_validation_at",
        "manifest_path",
        "manifest_sha256",
        "schema_version",
        "successful_at",
    }
    if not isinstance(document, dict) or set(document) != required:
        raise OpenSSFShadowError("shadow checkpoint shape is invalid")
    if (
        document.get("schema_version") != SCHEMA_VERSION
        or COMMIT.fullmatch(str(document.get("commit", ""))) is None
    ):
        raise OpenSSFShadowError("shadow checkpoint identity is invalid")
    if not SHA256.fullmatch(str(document.get("manifest_sha256", ""))):
        raise OpenSSFShadowError("shadow checkpoint digest is invalid")
    expected_path = f"manifests/{document['commit']}.json.gz"
    if document.get("manifest_path") != expected_path:
        raise OpenSSFShadowError("shadow checkpoint manifest path is invalid")
    _parse_time(document["last_full_validation_at"])
    _parse_time(document["successful_at"])
    return document


def _apply_diff(
    previous: dict[str, dict[str, object]], changes: Sequence[OpenSSFChange]
) -> dict[str, dict[str, object]]:
    reconciled = dict(previous)
    for change in changes:
        if change.before is not None:
            old = reconciled.pop(change.before.path, None)
            if old != _entry_row(change.before):
                raise OpenSSFShadowError("incremental shadow input differs from prior manifest")
        if change.after is not None:
            if change.after.path in reconciled:
                raise OpenSSFShadowError("incremental shadow update duplicates a path")
            reconciled[change.after.path] = _entry_row(change.after)
    return reconciled


def _validate_entries(
    reader: LocalOpenSSFGitRepository,
    entries: Sequence[OpenSSFGitEntry],
) -> tuple[int, int, tuple[dict[str, object], ...]]:
    accepted = 0
    quarantined_count = 0
    quarantine_samples: list[dict[str, object]] = []
    for page in raw_batches(entries, maximum_records=MAX_PAGE_SIZE):
        bodies = reader.read_blobs(page)
        for entry, body in zip(page, bodies, strict=True):
            try:
                reader.parse_record(entry, body)
                accepted += 1
            except OpenSSFGitError as error:
                quarantined_count += 1
                if len(quarantine_samples) < MAX_QUARANTINE_SAMPLES:
                    quarantine_samples.append(
                        {
                            "advisory_id": entry.advisory_id,
                            "blob_sha256": _sha256(body),
                            "error": str(error),
                            "path": entry.path,
                        }
                    )
    return accepted, quarantined_count, tuple(quarantine_samples)


def _change_counts(changes: Sequence[OpenSSFChange]) -> dict[str, int]:
    counts = Counter(change.kind for change in changes)
    return {
        name: counts[name]
        for name in ("added", "modified", "removed", "renamed", "restored", "withdrawn")
    }


def _authorize_rights(path: Path, *, today: date) -> None:
    try:
        profile = RightsRegistry.from_path(path).get(OPENSSF_MALICIOUS)
        profile.authorize_collection(
            method="git",
            canonical_url=OPENSSF_REPOSITORY_URL,
            today=today,
        )
    except (OSError, ValueError, SourceRightsError) as error:
        raise OpenSSFShadowError("OpenSSF shadow rights authorization failed") from error


def _pin_checkpoint(repository: Path, commit: str) -> None:
    reference = f"refs/smithguard/checkpoints/{commit}"
    result = _local_git(repository, "update-ref", reference, commit, maximum=0)
    if result:
        raise OpenSSFShadowError("shadow checkpoint reference returned unexpected output")


def _pin_observation(repository: Path, commit: str) -> None:
    reference = f"refs/smithguard/observations/{commit}"
    result = _local_git(repository, "update-ref", reference, commit, maximum=0)
    if result:
        raise OpenSSFShadowError("shadow observation reference returned unexpected output")


def _record_receipt(paths: ShadowPaths, receipt: Mapping[str, Any], completed_at: datetime) -> None:
    body = _canonical_json(receipt)
    if len(body) > MAX_RECEIPT_BYTES:
        raise OpenSSFShadowError("shadow receipt exceeds its reviewed boundary")
    history = paths.runs / (
        completed_at.astimezone(UTC).strftime("%Y%m%dT%H%M%S.%fZ") + f"-{uuid.uuid4().hex}.json"
    )
    _write_exclusive(history, body)
    _write_atomic(paths.latest, body)


def _failure_receipt(
    *,
    attempted_at: datetime,
    completed_at: datetime,
    error: Exception,
    network_attempted: bool,
    provisional_observation_count: int,
    provisional_settle_wait_seconds: int,
) -> dict[str, Any]:
    return {
        "attempted_at": _utc_text(attempted_at),
        "completed_at": _utc_text(completed_at),
        "error_class": type(error).__name__,
        "error_message": str(error),
        "network_attempted": network_attempted,
        "provisional_observation_count": provisional_observation_count,
        "provisional_settle_wait_seconds": provisional_settle_wait_seconds,
        "public_effect": False,
        "schema_version": SCHEMA_VERSION,
        "source_id": OPENSSF_MALICIOUS,
        "status": "failure",
    }


def run_shadow(
    *,
    state_root: Path = DEFAULT_STATE_ROOT,
    rights_path: Path = DEFAULT_RIGHTS_REGISTER,
    enabled: bool,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    fetcher: Callable[[ShadowPaths], tuple[Path, str]] = sync_official_repository,
    sleeper: Callable[[float], None] = time.sleep,
    capacity_limits: ShadowCapacityLimits | None = None,
) -> dict[str, Any]:
    """Run one isolated shadow attempt and return its non-secret receipt."""
    paths = _prepare_paths(state_root)
    attempted_at = _clock_value(now)
    with _exclusive_lock(paths.lock):
        if capacity_limits is not None:
            require_state_capacity(paths.root, limits=capacity_limits)
        if not enabled:
            completed_at = _clock_value(now)
            receipt = {
                "attempted_at": _utc_text(attempted_at),
                "completed_at": _utc_text(completed_at),
                "network_attempted": False,
                "public_effect": False,
                "schema_version": SCHEMA_VERSION,
                "source_id": OPENSSF_MALICIOUS,
                "status": "disabled",
            }
            _record_receipt(paths, receipt, completed_at)
            if capacity_limits is not None:
                require_state_capacity(paths.root, limits=capacity_limits)
            return receipt
        network_attempted = False
        provisional_observation_count = 0
        provisional_settle_wait_seconds = 0
        try:
            _authorize_rights(rights_path, today=attempted_at.date())
            network_attempted = True
            previous_provisional_commit: str | None = None
            for observation_number in range(1, PROVISIONAL_SETTLE_MAX_OBSERVATIONS + 1):
                repository_path, observed_commit = fetcher(paths)
                _pin_observation(repository_path, observed_commit)
                if previous_provisional_commit is not None and not _forward_transition_present(
                    repository_path,
                    previous_provisional_commit,
                    observed_commit,
                ):
                    raise OpenSSFShadowError(
                        "OpenSSF provisional settle retry is not a forward commit transition"
                    )
                reader = LocalOpenSSFGitRepository(repository_path)
                try:
                    snapshot = reader.inspect(
                        observed_commit,
                        expected_license_sha256=OPENSSF_LICENSE_SHA256,
                    )
                except OpenSSFProvisionalIDError as error:
                    provisional_observation_count += 1
                    if observation_number == PROVISIONAL_SETTLE_MAX_OBSERVATIONS:
                        raise OpenSSFProvisionalIDError(
                            "OpenSSF tree retained a recognized provisional advisory identity "
                            f"after {PROVISIONAL_SETTLE_MAX_OBSERVATIONS} bounded observations"
                        ) from error
                    previous_provisional_commit = observed_commit
                    sleeper(PROVISIONAL_SETTLE_INTERVAL_SECONDS)
                    provisional_settle_wait_seconds += PROVISIONAL_SETTLE_INTERVAL_SECONDS
                    continue
                break
            manifest_body, current_rows = _manifest(snapshot)
            manifest_digest = _sha256(manifest_body)
            previous = _checkpoint(paths)
            changes: tuple[OpenSSFChange, ...]
            previous_commit: str | None
            last_full_validation_at: datetime | None
            if previous is None:
                previous_commit = None
                changes = tuple()
                entries_to_validate = snapshot.entries
                validation_scope = "full_initial"
                last_full_validation_at = None
            else:
                previous_commit = previous["commit"]
                before = reader.inspect(
                    previous_commit,
                    expected_license_sha256=OPENSSF_LICENSE_SHA256,
                )
                changes = reader.diff(before, snapshot).changes
                prior_manifest_path = paths.root / previous["manifest_path"]
                prior_rows = _load_manifest(
                    prior_manifest_path,
                    commit=previous_commit,
                    digest=previous["manifest_sha256"],
                )
                if _apply_diff(prior_rows, changes) != current_rows:
                    raise OpenSSFShadowError(
                        "incremental checkpoint does not reconcile to the full current tree"
                    )
                last_full_validation_at = _parse_time(previous["last_full_validation_at"])
                if attempted_at - last_full_validation_at >= FULL_VALIDATION_INTERVAL:
                    entries_to_validate = snapshot.entries
                    validation_scope = "full_periodic"
                else:
                    entries_to_validate = tuple(
                        change.after for change in changes if change.after is not None
                    )
                    if entries_to_validate:
                        validation_scope = "incremental"
                    elif changes:
                        validation_scope = "incremental_removals_only"
                    else:
                        validation_scope = "unchanged"
            accepted_count, quarantined_count, quarantine_samples = _validate_entries(
                reader, entries_to_validate
            )
            completed_at = _clock_value(now)
            change_counts = _change_counts(changes)
            commit_time = reader.commit_time(observed_commit)
            if commit_time - completed_at > MAX_CLOCK_FUTURE:
                raise OpenSSFShadowError("OpenSSF commit time is unacceptably far in the future")
            receipt = {
                "accepted_count": accepted_count,
                "attempted_at": _utc_text(attempted_at),
                "checkpoint": observed_commit,
                "commit_time": _utc_text(commit_time),
                "completed_at": _utc_text(completed_at),
                "correction_count": sum(
                    change_counts[name] for name in ("modified", "removed", "renamed", "restored")
                ),
                "current_withdrawal_count": snapshot.withdrawn_count,
                "full_tree_reconciliation": "passed",
                "ignored_nonrecord_count": snapshot.ignored_nonrecord_count,
                "lag_seconds": max(0, int((completed_at - commit_time).total_seconds())),
                "license_sha256": snapshot.license_sha256,
                "manifest_sha256": manifest_digest,
                "network_attempted": True,
                "previous_checkpoint": previous_commit,
                "provisional_observation_count": provisional_observation_count,
                "provisional_settle_wait_seconds": provisional_settle_wait_seconds,
                "public_effect": False,
                "quarantine_sample_truncated": quarantined_count > len(quarantine_samples),
                "quarantine_samples": list(quarantine_samples),
                "quarantined_count": quarantined_count,
                "raw_count": (
                    len(snapshot.entries)
                    + sum(value for _name, value in snapshot.unsupported_counts)
                    + snapshot.ignored_nonrecord_count
                ),
                "schema_version": SCHEMA_VERSION,
                "source_id": OPENSSF_MALICIOUS,
                "status": "quarantined" if quarantined_count else "success",
                "supported_count": len(snapshot.entries),
                "total_reviewed_bytes": snapshot.total_reviewed_bytes,
                "transition": change_counts,
                "unsupported_ecosystem_counts": dict(snapshot.unsupported_counts),
                "validated_count": len(entries_to_validate),
                "validation_scope": validation_scope,
                "withdrawal_count": change_counts["withdrawn"],
            }
            if quarantined_count:
                _record_receipt(paths, receipt, completed_at)
                if capacity_limits is not None:
                    require_state_capacity(paths.root, limits=capacity_limits)
                return receipt
            stored_digest, stored_path = _write_manifest(paths, observed_commit, manifest_body)
            if stored_digest != manifest_digest:
                raise OpenSSFShadowError("stored shadow manifest digest differs")
            _pin_checkpoint(repository_path, observed_commit)
            full_at = (
                completed_at
                if validation_scope in {"full_initial", "full_periodic"}
                else last_full_validation_at
            )
            if full_at is None:
                raise OpenSSFShadowError("shadow full validation time is missing")
            checkpoint = {
                "commit": observed_commit,
                "last_full_validation_at": _utc_text(full_at),
                "manifest_path": stored_path.relative_to(paths.root).as_posix(),
                "manifest_sha256": manifest_digest,
                "schema_version": SCHEMA_VERSION,
                "successful_at": _utc_text(completed_at),
            }
            _write_atomic(paths.checkpoint, _canonical_json(checkpoint))
            _record_receipt(paths, receipt, completed_at)
            if capacity_limits is not None:
                require_state_capacity(paths.root, limits=capacity_limits)
            return receipt
        except (OpenSSFShadowError, OpenSSFGitError, OSError, ValueError) as error:
            completed_at = _clock_value(now)
            receipt = _failure_receipt(
                attempted_at=attempted_at,
                completed_at=completed_at,
                error=error,
                network_attempted=network_attempted,
                provisional_observation_count=provisional_observation_count,
                provisional_settle_wait_seconds=provisional_settle_wait_seconds,
            )
            _record_receipt(paths, receipt, completed_at)
            if capacity_limits is not None:
                require_state_capacity(paths.root, limits=capacity_limits)
            return receipt


def check_health(
    *,
    state_root: Path = DEFAULT_STATE_ROOT,
    enabled: bool,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Check source-specific state without network or public-database access."""
    if not enabled:
        return {
            "healthy": True,
            "network_attempted": False,
            "source_id": OPENSSF_MALICIOUS,
            "status": "disabled",
        }
    paths = _prepare_paths(state_root)
    try:
        receipt = json.loads(_private_file(paths.latest, maximum=MAX_RECEIPT_BYTES).decode("ascii"))
        checkpoint = _checkpoint(paths)
        if not isinstance(receipt, dict):
            raise OpenSSFShadowError("shadow receipt shape is invalid")
        current_value = now or datetime.now(UTC)
        if current_value.tzinfo is None or current_value.utcoffset() is None:
            raise OpenSSFShadowError("shadow health time must include a timezone")
        current = current_value.astimezone(UTC)
        completed = _parse_time(receipt.get("completed_at"))
    except (UnicodeDecodeError, json.JSONDecodeError, OpenSSFShadowError) as error:
        return {
            "error": str(error),
            "healthy": False,
            "network_attempted": False,
            "source_id": OPENSSF_MALICIOUS,
            "status": "critical",
        }
    healthy = (
        receipt.get("status") == "success"
        and checkpoint is not None
        and receipt.get("checkpoint") == checkpoint.get("commit")
        and timedelta(0) <= current - completed <= HEALTH_MAX_AGE
    )
    return {
        "age_seconds": max(0, int((current - completed).total_seconds())),
        "checkpoint": receipt.get("checkpoint"),
        "healthy": healthy,
        "network_attempted": False,
        "source_id": OPENSSF_MALICIOUS,
        "status": "healthy" if healthy else "critical",
    }


def _enabled_from_environment(environment: Mapping[str, str]) -> bool:
    value = environment.get(ENABLED_VARIABLE)
    if value not in {"0", "1"}:
        raise OpenSSFShadowError(f"{ENABLED_VARIABLE} must be exactly 0 or 1")
    return value == "1"


def _write_monitor_receipt(path: Path, result: Mapping[str, Any], *, state_root: Path) -> None:
    if not path.is_absolute():
        raise OpenSSFShadowError("OpenSSF monitor receipt path must be absolute")
    parent = path.parent
    try:
        parent_metadata = parent.lstat()
    except OSError as error:
        raise OpenSSFShadowError("OpenSSF monitor receipt parent is unavailable") from error
    parent_mode = stat.S_IMODE(parent_metadata.st_mode)
    if (
        stat.S_ISLNK(parent_metadata.st_mode)
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.geteuid()
        or parent_mode & 0o027
        or parent.resolve(strict=True) != parent
    ):
        raise OpenSSFShadowError("OpenSSF monitor receipt parent is unsafe")
    if path.exists() or path.is_symlink():
        try:
            metadata = path.lstat()
        except OSError as error:
            raise OpenSSFShadowError("OpenSSF monitor receipt is unavailable") from error
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o027
            or metadata.st_size > MAX_RECEIPT_BYTES
        ):
            raise OpenSSFShadowError("OpenSSF monitor receipt boundary is unsafe")
    if result.get("status") == "disabled" and not state_root.exists():
        # A disabled lane never prepares its state root, so there is no private tree to
        # measure. Report the receipt's own filesystem instead of failing the run.
        usage = shutil.disk_usage(parent)
        measurement = ShadowCapacityMeasurement(
            state_apparent_bytes=0,
            state_entry_count=0,
            filesystem_available_bytes=usage.free,
            filesystem_used_percent=(100 * usage.used) // usage.total if usage.total else 0,
        )
    else:
        measurement = measure_state_capacity(state_root, clamp_overflow=True)
    measured_at = result.get("completed_at")
    if not isinstance(measured_at, str):
        measured_at = _utc_text(datetime.now(UTC))
    else:
        _parse_time(measured_at)
    status = result.get("status")
    if not isinstance(status, str) or status not in {
        "critical",
        "disabled",
        "failure",
        "healthy",
        "quarantined",
        "success",
    }:
        status = "failure"
    if measurement.capacity_exceeded:
        status = "failure"
    document = {
        "checkpoint": result.get("checkpoint")
        if COMMIT.fullmatch(str(result.get("checkpoint", "")))
        else None,
        "filesystem_available_bytes": measurement.filesystem_available_bytes,
        "filesystem_used_percent": measurement.filesystem_used_percent,
        "healthy": status in {"healthy", "success"},
        "measured_at": measured_at,
        "schema_version": MONITOR_SCHEMA_VERSION,
        "source_id": OPENSSF_MALICIOUS,
        "state_apparent_bytes": measurement.state_apparent_bytes,
        "state_entry_count": measurement.state_entry_count,
        "status": status,
    }
    body = _canonical_json(document)
    if len(body) > MAX_RECEIPT_BYTES:
        raise OpenSSFShadowError("OpenSSF monitor receipt exceeds its boundary")
    # The temporary file is created at 0o640 and replaced atomically, so a reader in
    # the monitoring group never observes a partial receipt or a different mode.
    atomic_write(path, body, mode=0o640)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the isolated OpenSSF shadow lane")
    parser.add_argument("--check-health", action="store_true")
    arguments = parser.parse_args(argv)
    state_root = Path(os.environ.get("SMITHGUARD_OPENSSF_STATE_ROOT", str(DEFAULT_STATE_ROOT)))
    try:
        enabled = _enabled_from_environment(os.environ)
        if arguments.check_health:
            result = check_health(state_root=state_root, enabled=enabled)
        else:
            rights_path = Path(os.environ.get(RIGHTS_VARIABLE, str(DEFAULT_RIGHTS_REGISTER)))
            result = run_shadow(
                state_root=state_root,
                enabled=enabled,
                rights_path=rights_path,
                capacity_limits=PRODUCTION_CAPACITY_LIMITS,
            )
    except (OSError, OpenSSFShadowError) as error:
        result = {"error": str(error), "healthy": False, "status": "failure"}
    monitor_path = os.environ.get(MONITOR_RECEIPT_VARIABLE)
    if monitor_path is not None:
        try:
            _write_monitor_receipt(Path(monitor_path), result, state_root=state_root)
        except (OSError, OpenSSFShadowError) as error:
            # The run result and its checkpoint are already durable. Report the
            # monitor-receipt failure beside them instead of replacing them.
            result = {**result, "monitor_receipt_error": str(error)}
    print(_canonical_json(result).decode("ascii"), end="")
    if result.get("status") not in {"disabled", "healthy", "success"}:
        return 1
    return 1 if "monitor_receipt_error" in result else 0


if __name__ == "__main__":
    raise SystemExit(main())
