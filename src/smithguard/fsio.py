"""The one set of private file primitives.

Every routine raises ``FsioError`` (an ``OSError`` subclass); callers wrap it in their
own domain error. Mode assertions and size bounds are parameters because the sites
that these replace deliberately differ, and none of them may change silently.
"""

from __future__ import annotations

import os
import stat
import uuid
from contextlib import suppress
from pathlib import Path


class FsioError(OSError):
    """A private file could not be read or written safely.

    ``code`` names the failure class so callers branch on it, never on the message:
    missing, unsafe (could not be opened; ``errno`` says why), not_regular, mode,
    owner, group, size, changed, exists.
    """

    def __init__(self, code: str, message: str, *, errno: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.errno = errno


def fsync_directory(path: Path, *, nofollow: bool = False) -> None:
    """Flush a directory entry to disk; ``nofollow`` refuses a symlinked directory."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if nofollow:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_exclusive(
    path: Path,
    body: bytes,
    *,
    mode: int = 0o600,
    fsync_dir: bool = True,
    apply_mode: bool = True,
) -> None:
    """Create ``path`` (which must not exist), write, fsync, and fsync its directory.

    By default ``fchmod`` applies the mode exactly. ``apply_mode=False`` preserves
    the process umask for writers that historically used only ``os.open``. A partial
    file is removed on failure; the writers that must keep one (the deploy mutation
    markers, the host-run compaction tools) inline their own exclusive create.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        if apply_mode:
            os.fchmod(descriptor, mode)
        stream = os.fdopen(descriptor, "wb")
    except BaseException:
        os.close(descriptor)
        with suppress(OSError):
            path.unlink()
        raise
    try:
        with stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        if fsync_dir:
            fsync_directory(path.parent)
    except BaseException:
        with suppress(OSError):
            path.unlink()
        raise


def atomic_write(
    path: Path,
    body: bytes,
    *,
    mode: int = 0o600,
    fsync_dir: bool = True,
    random_suffix: bool = True,
    apply_mode: bool = True,
) -> None:
    """Replace ``path`` atomically through an exclusive temporary file in its directory.

    ``random_suffix`` names the temporary file by a fresh UUID; ``False`` uses the process
    id, which the older sites relied on together with an explicit pre-existence check.
    """
    suffix = uuid.uuid4().hex if random_suffix else str(os.getpid())
    temporary = path.with_name(f".{path.name}.{suffix}.tmp")
    if not random_suffix and (temporary.exists() or temporary.is_symlink()):
        raise FsioError("exists", f"temporary file already exists: {temporary}")
    write_exclusive(temporary, body, mode=mode, fsync_dir=False, apply_mode=apply_mode)
    try:
        os.replace(temporary, path)
        if fsync_dir:
            fsync_directory(path.parent)
    finally:
        with suppress(OSError):
            temporary.unlink()


def read_private_file(
    path: Path,
    *,
    maximum: int,
    mode_mask: int | None = 0o077,
    exact_mode: int | None = None,
    uid: int | None = None,
    gid: int | None = None,
    minimum: int = 1,
) -> bytes:
    """Read a regular, non-symlinked file after checking it on the open descriptor.

    ``mode_mask`` bits must be clear on the file mode; ``exact_mode`` requires the mode to
    equal it; ``uid``/``gid`` require ownership; the size must be within
    ``minimum..maximum`` and unchanged while reading.
    """
    # O_NONBLOCK makes a FIFO or device open return at once (it has no effect on a
    # regular file), so the fstat below refuses it instead of the open hanging.
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as error:
        raise FsioError("missing", f"private file is missing: {path}") from error
    except OSError as error:
        # The errno is kept so a caller can tell the O_NOFOLLOW symlink refusal (ELOOP)
        # from an access failure without parsing the message.
        raise FsioError(
            "unsafe", f"private file could not be opened safely: {path}", errno=error.errno
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise FsioError(
                "not_regular", f"private file must be a regular non-symlink file: {path}"
            )
        permissions = stat.S_IMODE(metadata.st_mode)
        if mode_mask is not None and permissions & mode_mask:
            raise FsioError("mode", f"private file grants excess permissions: {path}")
        if exact_mode is not None and permissions != exact_mode:
            raise FsioError("mode", f"private file mode differs from the required mode: {path}")
        if uid is not None and metadata.st_uid != uid:
            raise FsioError("owner", f"private file has the wrong owner: {path}")
        if gid is not None and metadata.st_gid != gid:
            raise FsioError("group", f"private file has the wrong group: {path}")
        if not minimum <= metadata.st_size <= maximum:
            raise FsioError("size", f"private file has an invalid size: {path}")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        body = b"".join(chunks)
        if len(body) != metadata.st_size:
            raise FsioError("changed", f"private file changed during reading: {path}")
        return body
    finally:
        os.close(descriptor)
