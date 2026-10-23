"""Immutable content-addressed evidence storage with recoverable staging."""

from __future__ import annotations

import fcntl
import math
import os
import secrets
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from threading import Condition, Thread
from typing import Protocol

from smithguard.identifiers import SHA256, SHA256_HEX, SHARD

SHA256_PATTERN = SHA256
HEX_PATTERN = SHA256_HEX
SHARD_PATTERN = SHARD
DEFAULT_MAX_BYTES = 52_428_800
COLLECTION_LOCK_TIMEOUT_SECONDS = 300.0


class EvidenceIntegrityError(IOError):
    """Stored bytes, size, permissions, or digest are not trustworthy."""


class EvidenceMissingError(EvidenceIntegrityError):
    """The immutable object was never stored or is gone; nothing verified was violated."""


class UnsafeEvidencePath(ValueError):
    """The evidence root or a derived path is unsafe."""


class EvidenceCollectionBusy(TimeoutError):
    """Another evidence transaction exceeded the collector's bounded wait."""


@contextmanager
def _collection_flock(descriptor: int, *, deadline: float) -> Iterator[None]:
    """Own the descriptor, including cancellation of a kernel-queued waiter.

    A timed-out daemon waiter never enters collection. It retains sole ownership
    of its descriptor until the kernel grants/fails the lock, then closes it.
    This avoids closing a descriptor while flock still uses it, or permitting a
    late grant to run protected work. Production entrypoints exit on timeout.
    """
    condition = Condition()
    started = False
    finished = False
    abandoned = False
    failure: OSError | None = None

    def acquire() -> None:
        nonlocal finished, failure
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        except OSError as error:
            failure = error
        finally:
            with condition:
                finished = True
                if abandoned:
                    os.close(descriptor)
                condition.notify_all()

    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise EvidenceCollectionBusy("evidence collection lock wait exceeded") from None
            worker = Thread(target=acquire, daemon=True, name="smithguard-evidence-lock")
            started = True
            try:
                worker.start()
            except RuntimeError:
                # A refused Thread.start leaves descriptor ownership here. An
                # asynchronous interruption instead preserves worker ownership
                # when launch may already have occurred.
                started = False
                raise
            with condition:
                while not finished:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise EvidenceCollectionBusy(
                            "evidence collection lock wait exceeded"
                        ) from None
                    condition.wait(timeout=remaining)
                if time.monotonic() >= deadline:
                    raise EvidenceCollectionBusy("evidence collection lock wait exceeded") from None
                if failure is not None:
                    raise failure from None
        yield
    finally:
        with condition:
            if not started or finished:
                os.close(descriptor)
            else:
                abandoned = True


@dataclass(frozen=True, slots=True)
class EvidenceBlob:
    digest: str
    byte_count: int
    storage_key: str


@dataclass(frozen=True, slots=True)
class EvidenceStage:
    """One verified content-addressed object awaiting database commit."""

    digest: str
    byte_count: int
    storage_key: str
    staging_key: str


class EvidenceStore(Protocol):
    def put_bytes(self, data: bytes) -> EvidenceBlob: ...

    def stage_bytes(self, data: bytes) -> EvidenceStage: ...

    def finalize_stage(self, stage: EvidenceStage) -> EvidenceBlob: ...

    def discard_stage(self, stage: EvidenceStage) -> None: ...

    def pending_manifest(self) -> list[EvidenceBlob]: ...

    def read_bytes(self, digest: str) -> bytes: ...

    def verify(self, digest: str) -> EvidenceBlob: ...

    def manifest(self) -> list[EvidenceBlob]: ...


def _digest(data: bytes) -> str:
    return "sha256:" + sha256(data).hexdigest()


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        if written <= 0:
            raise OSError("unable to write immutable evidence")
        offset += written


class LocalImmutableEvidenceStore:
    """A local adapter whose paths are anchored below one verified root descriptor."""

    def __init__(
        self,
        root: Path,
        *,
        max_bytes: int = DEFAULT_MAX_BYTES,
        create: bool = True,
        allow_group_read: bool = False,
    ) -> None:
        if max_bytes <= 0 or max_bytes > DEFAULT_MAX_BYTES:
            raise ValueError(f"max_bytes must be between 1 and {DEFAULT_MAX_BYTES}")
        self.root = root.expanduser().absolute()
        self.max_bytes = max_bytes
        self.allow_group_read = allow_group_read
        self._directory_mode = 0o750 if allow_group_read else 0o700
        self._file_mode = 0o440 if allow_group_read else 0o400
        self._root_fd = self._prepare_root(create=create)

    def _assert_directory_mode(self, mode: int, *, label: str) -> None:
        forbidden = 0o027 if self.allow_group_read else 0o077
        if stat.S_IMODE(mode) & forbidden:
            raise PermissionError(
                f"{label} must not grant write access to the group or any access to others"
                if self.allow_group_read
                else f"{label} must not grant group or other access"
            )

    def _prepare_root(self, *, create: bool) -> int:
        if create:
            try:
                self.root.mkdir(mode=self._directory_mode, parents=True, exist_ok=True)
            except FileExistsError as error:
                raise UnsafeEvidencePath("evidence root is not a directory") from error
        try:
            root_stat = os.lstat(self.root)
        except FileNotFoundError as error:
            raise UnsafeEvidencePath("evidence root does not exist") from error
        if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
            raise UnsafeEvidencePath("evidence root must be a real directory")
        self._assert_directory_mode(root_stat.st_mode, label="evidence root")
        if self.root.resolve(strict=True) != self.root:
            raise UnsafeEvidencePath("evidence root cannot traverse a symbolic link")
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.root, flags)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_dev != root_stat.st_dev
                or metadata.st_ino != root_stat.st_ino
            ):
                raise UnsafeEvidencePath("evidence root changed during verification")
            self._assert_directory_mode(metadata.st_mode, label="evidence root")
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def _root_descriptor(self) -> int:
        if self._root_fd < 0:
            raise EvidenceIntegrityError("evidence store is closed")
        descriptor = os.dup(self._root_fd)
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(descriptor)
            raise UnsafeEvidencePath("evidence root must be a real directory")
        self._assert_directory_mode(metadata.st_mode, label="evidence root")
        return descriptor

    def close(self) -> None:
        """Release the store-owned root descriptor."""
        if self._root_fd >= 0:
            os.close(self._root_fd)
            self._root_fd = -1

    @contextmanager
    def collection_lock(
        self, *, timeout_seconds: float = COLLECTION_LOCK_TIMEOUT_SECONDS
    ) -> Iterator[None]:
        """Coordinate local collectors through commit/finalization or rollback.

        Every evidence-producing transaction and global recovery inspection must
        hold this lock. It is deliberately not reentrant: each acquisition opens
        an independent description, including calls on the same store instance.
        No lock file is created in the immutable evidence namespace.
        """
        if (
            isinstance(timeout_seconds, bool)
            or not math.isfinite(timeout_seconds)
            or not 0 <= timeout_seconds <= COLLECTION_LOCK_TIMEOUT_SECONDS
        ):
            raise ValueError("evidence collection lock timeout is outside its bound")
        if self._root_fd < 0:
            raise EvidenceIntegrityError("evidence store is closed")
        deadline = time.monotonic() + timeout_seconds
        descriptor = self._prepare_root(create=False)
        try:
            expected = os.fstat(self._root_fd)
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
                raise UnsafeEvidencePath("evidence root changed before collection")
        except BaseException:
            os.close(descriptor)
            raise
        with _collection_flock(descriptor, deadline=deadline):
            current = os.lstat(self.root)
            if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != (
                opened.st_dev,
                opened.st_ino,
            ):
                raise UnsafeEvidencePath("evidence root changed while waiting for collection")
            self._assert_directory_mode(current.st_mode, label="evidence root")
            yield

    def __del__(self) -> None:
        root_fd = getattr(self, "_root_fd", -1)
        if root_fd >= 0:
            with suppress(OSError):
                os.close(root_fd)
            self._root_fd = -1

    def _directory_descriptor(
        self,
        parent: int,
        name: str,
        *,
        label: str,
        create: bool,
    ) -> int:
        if "/" in name or name in {"", ".", ".."}:
            raise UnsafeEvidencePath("evidence directory name is unsafe")
        created = False
        if create:
            try:
                os.mkdir(name, self._directory_mode, dir_fd=parent)
                created = True
            except FileExistsError:
                pass
        if created:
            os.fsync(parent)
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(name, flags, dir_fd=parent)
        except FileNotFoundError:
            raise
        except OSError as error:
            raise UnsafeEvidencePath(f"{label} must be a real directory") from error
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(descriptor)
            raise UnsafeEvidencePath(f"{label} must be a real directory")
        self._assert_directory_mode(metadata.st_mode, label=label)
        return descriptor

    @staticmethod
    def _digest_parts(digest: str) -> tuple[str, str]:
        if not SHA256_PATTERN.fullmatch(digest):
            raise ValueError("invalid SHA-256 storage key")
        hexadecimal = digest.removeprefix("sha256:")
        return hexadecimal[:2], hexadecimal

    def _shard_descriptor(
        self,
        root_descriptor: int,
        digest: str,
        *,
        staging: bool,
        create: bool,
    ) -> tuple[int, int, int | None]:
        shard, _hexadecimal = self._digest_parts(digest)
        staging_descriptor: int | None = None
        parent = root_descriptor
        if staging:
            staging_descriptor = self._directory_descriptor(
                root_descriptor,
                ".staging",
                label="evidence staging namespace",
                create=create,
            )
            parent = staging_descriptor
        namespace_descriptor = self._directory_descriptor(
            parent,
            "sha256",
            label="evidence namespace",
            create=create,
        )
        try:
            shard_descriptor = self._directory_descriptor(
                namespace_descriptor,
                shard,
                label="evidence shard",
                create=create,
            )
        except Exception:
            os.close(namespace_descriptor)
            if staging_descriptor is not None:
                os.close(staging_descriptor)
            raise
        return shard_descriptor, namespace_descriptor, staging_descriptor

    @staticmethod
    def _close_shard(
        shard_descriptor: int,
        namespace_descriptor: int,
        staging_descriptor: int | None,
    ) -> None:
        os.close(shard_descriptor)
        os.close(namespace_descriptor)
        if staging_descriptor is not None:
            os.close(staging_descriptor)

    def _read_verified_descriptor(
        self,
        descriptor: int,
        *,
        digest: str,
    ) -> tuple[EvidenceBlob, bytes]:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceIntegrityError("immutable evidence must be a regular file")
        file_mode = stat.S_IMODE(metadata.st_mode)
        if file_mode & 0o222:
            raise EvidenceIntegrityError("immutable evidence remains writable")
        if file_mode != self._file_mode:
            raise EvidenceIntegrityError(
                "immutable evidence permissions exceed the selected read boundary"
            )
        if metadata.st_size > self.max_bytes:
            raise EvidenceIntegrityError("immutable evidence exceeds its byte limit")
        os.lseek(descriptor, 0, os.SEEK_SET)
        body = bytearray()
        while len(body) <= self.max_bytes:
            chunk = os.read(descriptor, min(1024 * 1024, self.max_bytes + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
        final = os.fstat(descriptor)
        if (
            final.st_dev != metadata.st_dev
            or final.st_ino != metadata.st_ino
            or final.st_size != metadata.st_size
            or stat.S_IMODE(final.st_mode) != self._file_mode
        ):
            raise EvidenceIntegrityError("immutable evidence changed during verification")
        if len(body) > self.max_bytes or len(body) != metadata.st_size:
            raise EvidenceIntegrityError("immutable evidence size changed during verification")
        verified_body = bytes(body)
        if _digest(verified_body) != digest:
            raise EvidenceIntegrityError("immutable evidence checksum mismatch")
        return (
            EvidenceBlob(digest=digest, byte_count=len(verified_body), storage_key=digest),
            verified_body,
        )

    def _read_at(
        self,
        shard_descriptor: int,
        *,
        digest: str,
    ) -> tuple[EvidenceBlob, bytes]:
        _shard, hexadecimal = self._digest_parts(digest)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(hexadecimal, flags, dir_fd=shard_descriptor)
        except FileNotFoundError as error:
            raise EvidenceMissingError("immutable evidence is missing") from error
        except OSError as error:
            raise EvidenceIntegrityError("immutable evidence must be a regular file") from error
        try:
            return self._read_verified_descriptor(descriptor, digest=digest)
        finally:
            os.close(descriptor)

    def _write_at(self, shard_descriptor: int, *, digest: str, data: bytes) -> EvidenceBlob:
        _shard, hexadecimal = self._digest_parts(digest)
        try:
            return self._read_at(shard_descriptor, digest=digest)[0]
        except EvidenceIntegrityError:
            try:
                os.stat(
                    hexadecimal,
                    dir_fd=shard_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                return self._read_at(shard_descriptor, digest=digest)[0]

        temporary = f".{hexadecimal}.{secrets.token_hex(16)}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            descriptor = os.open(temporary, flags, 0o600, dir_fd=shard_descriptor)
            _write_all(descriptor, data)
            os.fchmod(descriptor, self._file_mode)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            with suppress(FileExistsError):
                os.link(
                    temporary,
                    hexadecimal,
                    src_dir_fd=shard_descriptor,
                    dst_dir_fd=shard_descriptor,
                    follow_symlinks=False,
                )
            os.fsync(shard_descriptor)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            with suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=shard_descriptor)
            os.fsync(shard_descriptor)
        return self._read_at(shard_descriptor, digest=digest)[0]

    def stage_bytes(self, data: bytes) -> EvidenceStage:
        if not isinstance(data, bytes):
            raise TypeError("evidence must be bytes")
        if len(data) > self.max_bytes:
            raise ValueError("evidence exceeds its byte limit")
        digest = _digest(data)
        root_descriptor = self._root_descriptor()
        try:
            descriptors = self._shard_descriptor(
                root_descriptor,
                digest,
                staging=True,
                create=True,
            )
            try:
                try:
                    blob = self._write_at(descriptors[0], digest=digest, data=data)
                except EvidenceIntegrityError as error:
                    if not isinstance(error.__cause__, FileNotFoundError):
                        raise
                    try:
                        blob = self.verify(digest)
                    except EvidenceIntegrityError as final_error:
                        if not isinstance(final_error.__cause__, FileNotFoundError):
                            raise
                        blob = self._write_at(descriptors[0], digest=digest, data=data)
            finally:
                self._close_shard(*descriptors)
        finally:
            os.close(root_descriptor)
        return EvidenceStage(
            digest=blob.digest,
            byte_count=blob.byte_count,
            storage_key=blob.storage_key,
            staging_key=blob.digest,
        )

    def finalize_stage(self, stage: EvidenceStage) -> EvidenceBlob:
        if stage.staging_key != stage.digest or stage.storage_key != stage.digest:
            raise EvidenceIntegrityError("evidence stage metadata is inconsistent")
        root_descriptor = self._root_descriptor()
        stage_descriptors: tuple[int, int, int | None] | None = None
        final_descriptors: tuple[int, int, int | None] | None = None
        _shard, hexadecimal = self._digest_parts(stage.digest)
        try:
            final_descriptors = self._shard_descriptor(
                root_descriptor,
                stage.digest,
                staging=False,
                create=True,
            )
            fcntl.flock(final_descriptors[0], fcntl.LOCK_EX)
            try:
                stage_descriptors = self._shard_descriptor(
                    root_descriptor,
                    stage.digest,
                    staging=True,
                    create=False,
                )
                staged_blob = self._read_at(
                    stage_descriptors[0],
                    digest=stage.digest,
                )[0]
            except FileNotFoundError:
                staged_blob = None
            except EvidenceIntegrityError as error:
                if not isinstance(error.__cause__, FileNotFoundError):
                    raise
                try:
                    final_blob = self._read_at(
                        final_descriptors[0],
                        digest=stage.digest,
                    )[0]
                except EvidenceIntegrityError as final_error:
                    if not isinstance(final_error.__cause__, FileNotFoundError):
                        raise
                    staged_blob = None
                else:
                    if final_blob.byte_count != stage.byte_count:
                        raise EvidenceIntegrityError("evidence stage size is inconsistent")
                    return final_blob
            if staged_blob is not None:
                with suppress(FileExistsError, FileNotFoundError):
                    os.link(
                        hexadecimal,
                        hexadecimal,
                        src_dir_fd=stage_descriptors[0],
                        dst_dir_fd=final_descriptors[0],
                        follow_symlinks=False,
                    )
                os.fsync(final_descriptors[0])
            final_blob = self._read_at(final_descriptors[0], digest=stage.digest)[0]
            if final_blob.byte_count != stage.byte_count:
                raise EvidenceIntegrityError("evidence stage size is inconsistent")
            if stage_descriptors is not None:
                with suppress(FileNotFoundError):
                    os.unlink(hexadecimal, dir_fd=stage_descriptors[0])
                os.fsync(stage_descriptors[0])
            return final_blob
        finally:
            if final_descriptors is not None:
                with suppress(OSError):
                    fcntl.flock(final_descriptors[0], fcntl.LOCK_UN)
                self._close_shard(*final_descriptors)
            if stage_descriptors is not None:
                self._close_shard(*stage_descriptors)
            os.close(root_descriptor)

    def discard_stage(self, stage: EvidenceStage) -> None:
        if stage.staging_key != stage.digest:
            raise EvidenceIntegrityError("evidence stage metadata is inconsistent")
        root_descriptor = self._root_descriptor()
        descriptors: tuple[int, int, int | None] | None = None
        try:
            try:
                descriptors = self._shard_descriptor(
                    root_descriptor,
                    stage.digest,
                    staging=True,
                    create=False,
                )
            except FileNotFoundError:
                return
            _shard, hexadecimal = self._digest_parts(stage.digest)
            with suppress(FileNotFoundError):
                os.unlink(hexadecimal, dir_fd=descriptors[0])
            os.fsync(descriptors[0])
        finally:
            if descriptors is not None:
                self._close_shard(*descriptors)
            os.close(root_descriptor)

    def put_bytes(self, data: bytes) -> EvidenceBlob:
        return self.finalize_stage(self.stage_bytes(data))

    def _read_namespace(self, digest: str, *, staging: bool) -> tuple[EvidenceBlob, bytes]:
        root_descriptor = self._root_descriptor()
        descriptors: tuple[int, int, int | None] | None = None
        try:
            descriptors = self._shard_descriptor(
                root_descriptor,
                digest,
                staging=staging,
                create=False,
            )
            return self._read_at(descriptors[0], digest=digest)
        except FileNotFoundError as error:
            raise EvidenceMissingError("immutable evidence is missing") from error
        finally:
            if descriptors is not None:
                self._close_shard(*descriptors)
            os.close(root_descriptor)

    def read_bytes(self, digest: str) -> bytes:
        return self._read_namespace(digest, staging=False)[1]

    def verify(self, digest: str) -> EvidenceBlob:
        return self._read_namespace(digest, staging=False)[0]

    def _manifest(self, *, staging: bool, maximum_entries: int | None = None) -> list[EvidenceBlob]:
        root_descriptor = self._root_descriptor()
        staging_descriptor: int | None = None
        namespace_descriptor: int | None = None
        blobs: list[EvidenceBlob] = []
        try:
            parent = root_descriptor
            if staging:
                try:
                    staging_descriptor = self._directory_descriptor(
                        root_descriptor,
                        ".staging",
                        label="evidence staging namespace",
                        create=False,
                    )
                except FileNotFoundError:
                    return []
                parent = staging_descriptor
            try:
                namespace_descriptor = self._directory_descriptor(
                    parent,
                    "sha256",
                    label="evidence namespace",
                    create=False,
                )
            except FileNotFoundError:
                return []
            for shard in sorted(os.listdir(namespace_descriptor)):
                if not SHARD_PATTERN.fullmatch(shard):
                    raise UnsafeEvidencePath("evidence namespace contains an invalid shard")
                shard_descriptor = self._directory_descriptor(
                    namespace_descriptor,
                    shard,
                    label="evidence shard",
                    create=False,
                )
                try:
                    for name in sorted(os.listdir(shard_descriptor)):
                        if name.startswith("."):
                            continue
                        if not HEX_PATTERN.fullmatch(name) or not name.startswith(shard):
                            raise UnsafeEvidencePath(
                                "evidence shard contains an invalid object name"
                            )
                        if maximum_entries is not None and len(blobs) >= maximum_entries:
                            raise EvidenceIntegrityError(
                                "evidence manifest exceeds its entry bound"
                            )
                        blobs.append(
                            self._read_at(
                                shard_descriptor,
                                digest="sha256:" + name,
                            )[0]
                        )
                finally:
                    os.close(shard_descriptor)
            return blobs
        finally:
            if namespace_descriptor is not None:
                os.close(namespace_descriptor)
            if staging_descriptor is not None:
                os.close(staging_descriptor)
            os.close(root_descriptor)

    def manifest(self) -> list[EvidenceBlob]:
        return self._manifest(staging=False)

    def pending_manifest(self, *, maximum_entries: int | None = None) -> list[EvidenceBlob]:
        return self._manifest(staging=True, maximum_entries=maximum_entries)
