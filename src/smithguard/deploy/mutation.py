"""Exclusive release mutation ownership with durable, fail-closed crash state."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import threading
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from typing import Any

from smithguard.fsio import fsync_directory
from smithguard.identifiers import SHA256_HEX


class MutationError(RuntimeError):
    """Another mutation owns the host or a prior outcome needs reconciliation."""


@dataclass(frozen=True)
class MigrationRecovery:
    """Exact failed ownership selected for a separate matching-schema rollback."""

    operation_id: str
    pending_sha256: str


@dataclass(frozen=True)
class InstallRecovery:
    """Exact interrupted install ownership, cleared only after a read-only host check."""

    operation_id: str
    pending_sha256: str


@dataclass(frozen=True)
class SupplementalRecovery:
    """Exact failed initialization ownership for forward-only feed recovery."""

    operation_id: str
    pending_sha256: str


@dataclass(frozen=True)
class OfficialNoticeRecovery:
    """Exact pending official-intake mutation; recovery only closes authority."""

    operation_id: str
    pending_sha256: str


@dataclass(frozen=True)
class BulletinRecovery:
    """Exact failed publication-grant mutation; recovery only closes authority."""

    operation_id: str
    pending_sha256: str


RECOVERY_PHASES = {
    BulletinRecovery: (
        "recover_bulletins",
        "bulletin",
        frozenset({"activate_bulletins", "contain_bulletins", "recover_bulletins"}),
    ),
    OfficialNoticeRecovery: (
        "recover_official_notices",
        "official notice",
        frozenset(
            {"initialize_official_notices", "contain_official_notices", "recover_official_notices"}
        ),
    ),
    SupplementalRecovery: (
        "recover_supplemental",
        "supplemental",
        frozenset({"initialize_supplemental", "recover_supplemental"}),
    ),
    MigrationRecovery: ("recover_rollback", "migration", frozenset({"migrate"})),
    # A recover_install that died after archiving the original pending leaves its own
    # started marker; the same command can bind to it and finish the recovery.
    InstallRecovery: ("recover_install", "install", frozenset({"install", "recover_install"})),
}


def _sync_directory(path: Path) -> None:
    fsync_directory(path, nofollow=True)


def _private_directory(path: Path) -> None:
    if not path.is_absolute():
        raise MutationError("mutation directory must be absolute")
    for parent in (*reversed(path.parents), path):
        if parent.is_symlink():
            raise MutationError("mutation directory must not traverse a symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    _sync_directory(path.parent)
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise MutationError("mutation directory ownership or mode differs")


def _write_new(path: Path, document: Mapping[str, Any]) -> None:
    # The marker layout (sort_keys, default separators) is read back by older
    # controllers and is deliberately not the canonical hash layout.
    # The exclusive create happens before serialization and the directory fsync runs
    # only once the marker exists, as before: a marker that exists but is unreadable
    # (empty or partial) forces reconciliation, and a failed create fsyncs nothing.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        try:
            body = (json.dumps(document, sort_keys=True) + "\n").encode("ascii")
            stream = os.fdopen(descriptor, "wb")
        except BaseException:
            os.close(descriptor)
            raise
        with stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        _sync_directory(path.parent)


@dataclass
class MutationOwner:
    root: Path
    operation_id: str
    phase: str
    process_id: int
    thread_id: int
    started: bool = False
    reserved: bool = False
    read_only: bool = False
    recovery: (
        MigrationRecovery
        | InstallRecovery
        | SupplementalRecovery
        | OfficialNoticeRecovery
        | BulletinRecovery
        | None
    ) = None
    recovered_pending: bytes | None = None

    @property
    def pending_path(self) -> Path:
        return self.root / "pending.json"

    def _event(self, status: str) -> dict[str, Any]:
        document = {
            "schema_version": "1.0.0",
            "operation_id": self.operation_id,
            "phase": self.phase,
            "status": status,
            "at": datetime.now(UTC).isoformat(),
        }
        if self.recovery is not None:
            document["recovered_operation_id"] = self.recovery.operation_id
            document["recovered_pending_sha256"] = self.recovery.pending_sha256
        _write_new(self.root / f"event-{uuid.uuid4().hex}.json", document)
        return document

    def start(self) -> None:
        """Call immediately before the first mutation, while holding the lock."""
        if self.read_only:
            raise MutationError("read-only diagnosis cannot authorize mutation")
        if self.started:
            return
        if self.recovery is not None:
            self._archive_recovered_pending()
        document = self._event("started")
        if self.reserved:
            temporary = self.root / f".pending-{uuid.uuid4().hex}.json"
            _write_new(temporary, document)
            os.replace(temporary, self.pending_path)
            _sync_directory(self.root)
        else:
            _write_new(self.pending_path, document)
        self.started = True

    def _archive_recovered_pending(self) -> None:
        if self.recovery is None or self.recovered_pending is None:
            raise MutationError("diagnosed pending mutation is unavailable")
        try:
            if self.pending_path.read_bytes() != self.recovered_pending:
                raise MutationError("diagnosed pending mutation changed before recovery")
            archive = self.root / (
                f"recovered-{self.recovery.operation_id}-{self.recovery.pending_sha256}.json"
            )
            try:
                descriptor = os.open(
                    archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                )
            except FileExistsError:
                descriptor = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(descriptor, "rb") as stream:
                    metadata = os.fstat(stream.fileno())
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_uid != os.geteuid()
                        or stat.S_IMODE(metadata.st_mode) != 0o600
                        or metadata.st_nlink != 1
                        or metadata.st_size > 4096
                        or stream.read(4097) != self.recovered_pending
                    ):
                        raise MutationError(
                            "retained pending archive differs from diagnosed recovery"
                        ) from None
                    os.fsync(stream.fileno())
                _sync_directory(self.root)
                return
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(self.recovered_pending)
                stream.flush()
                os.fsync(stream.fileno())
            _sync_directory(self.root)
        except OSError as error:
            raise MutationError("diagnosed pending mutation archive is unavailable") from error

    def finish(self, status: str, *, next_phase: str | None = None) -> None:
        if not self.started:
            return
        document = self._event(status)
        if next_phase is not None:
            document["next_phase"] = next_phase
            temporary = self.root / f".pending-{uuid.uuid4().hex}.json"
            _write_new(temporary, document)
            os.replace(temporary, self.pending_path)
        else:
            self.pending_path.unlink()
        _sync_directory(self.root)
        self.started = False


_CURRENT: ContextVar[MutationOwner | None] = ContextVar("smithguard_mutation_owner", default=None)


def current_owner() -> MutationOwner:
    owner = _CURRENT.get()
    if owner is None or owner.process_id != os.getpid() or owner.thread_id != threading.get_ident():
        raise MutationError("mutation requires exclusive ownership")
    return owner


@contextmanager
def mutation_owner(
    root: Path,
    *,
    operation_id: str,
    phase: str,
    join: bool = False,
    read_only: bool = False,
    recovery: (
        MigrationRecovery
        | InstallRecovery
        | SupplementalRecovery
        | OfficialNoticeRecovery
        | BulletinRecovery
        | None
    ) = None,
) -> Iterator[MutationOwner]:
    """Nonblocking flock shared by controllers and compatibility release helpers.

    A pending marker survives process death. Only an explicitly retained transition
    to the same operation's next phase may proceed. A diagnosed migrate failure can
    transfer ownership only to the separately bound recovery phase.
    """
    root = root.absolute()
    recovery_phase, recovery_name, recovered_phases = (
        RECOVERY_PHASES[type(recovery)]
        if recovery is not None
        else ("recover_rollback", "migration", frozenset({"migrate"}))
    )
    if recovery is not None and (
        read_only
        or join
        or phase != recovery_phase
        or re.fullmatch(r"[0-9]{8}-[a-f0-9]{32}", recovery.operation_id) is None
        or re.fullmatch(r"[0-9]{8}-[a-f0-9]{32}", operation_id) is None
        or recovery.operation_id == operation_id
        or SHA256_HEX.fullmatch(recovery.pending_sha256) is None
    ):
        raise MutationError(f"{recovery_name} recovery ownership binding is invalid")
    existing = _CURRENT.get()
    if (
        join
        and existing is not None
        and existing.root == root
        and existing.process_id == os.getpid()
        and existing.thread_id == threading.get_ident()
    ):
        if existing.read_only:
            raise MutationError("read-only diagnosis cannot join a release mutation")
        yield existing
        return
    _private_directory(root)
    descriptor = os.open(root / "lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise MutationError("mutation lock ownership or mode differs")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise MutationError("another process owns the release mutation lock") from error
        owner = MutationOwner(root, operation_id, phase, os.getpid(), threading.get_ident())
        owner.read_only = read_only
        if owner.pending_path.exists() or owner.pending_path.is_symlink():
            metadata = owner.pending_path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size > 4096
            ):
                raise MutationError("pending mutation ownership is unsafe")
            try:
                pending_body = owner.pending_path.read_bytes()
                pending = json.loads(pending_body)
            except (ValueError, OSError) as error:
                raise MutationError("pending mutation ownership is invalid") from error
            if not isinstance(pending, dict) or pending.get("schema_version") != "1.0.0":
                raise MutationError("pending mutation ownership is invalid")
            if recovery is not None:
                if (
                    hashlib.sha256(pending_body).hexdigest() != recovery.pending_sha256
                    or pending.get("operation_id") != recovery.operation_id
                    or pending.get("phase") not in recovered_phases
                    or pending.get("status") != "started"
                    or "next_phase" in pending
                ):
                    raise MutationError(f"pending mutation differs from diagnosed {recovery_name}")
                owner.recovery = recovery
                owner.recovered_pending = pending_body
            elif not read_only and (
                not isinstance(pending, dict)
                or pending.get("schema_version") != "1.0.0"
                or pending.get("operation_id") != operation_id
                or pending.get("status") != "quiesced"
                or pending.get("next_phase") != "migrate"
                or phase not in {"migrate", "rollback"}
            ):
                raise MutationError("a prior mutation requires diagnosed recovery")
            owner.reserved = not read_only
        elif recovery is not None:
            raise MutationError(f"diagnosed {recovery_name} has no pending ownership")
        token = _CURRENT.set(owner)
        try:
            yield owner
        finally:
            _CURRENT.reset(token)
    finally:
        os.close(descriptor)


def release_mutation(phase: str) -> Callable:
    """Keep the low-level install/link entry points inside the same host lock."""

    def decorate(function: Callable) -> Callable:
        @wraps(function)
        def guarded(*args: Any, **kwargs: Any) -> Any:
            root = kwargs["release_root"].parent / ".deploy-mutations"
            with mutation_owner(
                root, operation_id="compat-" + uuid.uuid4().hex, phase=phase, join=True
            ) as owner:
                result = function(*args, **kwargs)
                if owner.phase == phase:
                    owner.finish("completed")
                return result

        return guarded

    return decorate
