"""Private bounded output, with descriptor traversal and no replacement of other files."""

from __future__ import annotations

import os
import stat
from contextlib import suppress
from pathlib import PurePath

from .discovery import open_directory, read_regular
from .verification import canonical, strict_json

MAX_LOCAL_BYTES = 32 * 1024 * 1024


class PrivateDirectory:
    def __init__(self, path: str, *, create: bool = False):
        parts = PurePath(path)
        if create:
            parent = open_directory(str(parts.parent))
            try:
                os.mkdir(parts.name, 0o700, dir_fd=parent)
            finally:
                os.close(parent)
        self.fd = open_directory(path)
        info = os.fstat(self.fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            os.close(self.fd)
            raise ValueError("output directory must be owned by this user and mode 700")

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def write(self, name: str, body: bytes):
        if len(body) > MAX_LOCAL_BYTES or "/" in name or name in {"", ".", ".."}:
            raise ValueError("invalid output name or size")
        fd = os.open(
            name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd
        )
        try:
            with os.fdopen(fd, "wb", closefd=False) as handle:
                handle.write(body)
                handle.flush()
                os.fsync(fd)
        except BaseException:
            # Remove only our exclusively created file if writing it failed.
            with suppress(FileNotFoundError):
                os.unlink(name, dir_fd=self.fd)
            raise
        finally:
            os.close(fd)

    def write_json(self, name: str, value):
        self.write(name, canonical(value) + b"\n")

    def read_json(self, name: str):
        if "/" in name or name in {"", ".", ".."}:
            raise ValueError("one private file component required")
        info = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("private input must be owned by this user and mode 600")
        return strict_json(read_regular(self.fd, name, MAX_LOCAL_BYTES), limit=MAX_LOCAL_BYTES)

    def replace_own_json(self, name: str, value, *, previous_sha256: str | None):
        """Atomic progress replacement, bounded to exactly the caller's prior file."""
        import hashlib
        import uuid

        body = canonical(value) + b"\n"
        if "/" in name or name in {"", ".", ".."} or len(body) > MAX_LOCAL_BYTES:
            raise ValueError("invalid progress file")
        if previous_sha256 is not None:
            info = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077
                or hashlib.sha256(read_regular(self.fd, name, MAX_LOCAL_BYTES)).hexdigest()
                != previous_sha256
            ):
                raise ValueError("progress file changed; refusing to replace")
        else:
            try:
                os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise FileExistsError(name)
        temporary = ".progress-" + uuid.uuid4().hex
        self.write(temporary, body)
        try:
            if previous_sha256 is None:
                # link is exclusive and cannot replace an unrelated destination.
                os.link(
                    temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd, follow_symlinks=False
                )
                os.unlink(temporary, dir_fd=self.fd)
            else:
                os.replace(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            with suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=self.fd)
        return hashlib.sha256(body).hexdigest()
