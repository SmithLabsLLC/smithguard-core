"""Read-only access to the retained signed public snapshot key documents.

The archive is historical: nothing writes or prunes it since the signed-snapshot
producer (API-12) and the retention pass (September 18, 2026) were removed.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Any

PUBLIC_KEY_ID = re.compile(r"^gbsec:snapshot-public-key:[a-f0-9]{40}$")


class SnapshotArchiveError(ValueError):
    """The immutable signed-publication archive is unavailable or inconsistent."""


class SnapshotArchive:
    """Serve retained verification keys from the immutable archive directory."""

    def __init__(self, root: Path) -> None:
        if not root.is_absolute():
            raise SnapshotArchiveError("snapshot archive path must be absolute")
        metadata = root.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise SnapshotArchiveError("snapshot archive path must be a directory")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise SnapshotArchiveError("snapshot archive directory must not be writable by group")
        self.root = root

    @staticmethod
    def _read_immutable(path: Path, *, maximum: int) -> bytes | None:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise SnapshotArchiveError(
                "snapshot archive entry could not be opened safely"
            ) from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or not 1 <= metadata.st_size <= maximum:
                raise SnapshotArchiveError("snapshot archive entry has an invalid shape")
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
                raise SnapshotArchiveError("snapshot archive entry changed while reading")
            return body
        finally:
            os.close(descriptor)

    def public_key_document(self, public_key_id: str) -> dict[str, Any] | None:
        if PUBLIC_KEY_ID.fullmatch(public_key_id) is None:
            return None
        body = self._read_immutable(
            self.root / f"{public_key_id}.public-key.json",
            maximum=4096,
        )
        if body is None:
            return None
        value = json.loads(body.decode("ascii"))
        if not isinstance(value, dict) or value.get("public_key_id") != public_key_id:
            raise SnapshotArchiveError("archived public key document is invalid")
        return value
