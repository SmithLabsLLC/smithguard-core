"""Install the exact public Claude Code binary; no login or inference."""

from __future__ import annotations

import fcntl
import hashlib
import os
import stat
import tempfile
import urllib.request
from pathlib import Path

from smithguard.claude_build import CLAUDE_BINARY, CLAUDE_SHA256

URL = (
    "https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/"
    "claude-code-releases/2.1.309/linux-x64/claude"
)
BINARY_BYTES = 293_469_552


def install() -> None:
    if os.geteuid() != 0:
        raise PermissionError("root required for pinned tool installation")
    parent = CLAUDE_BINARY.parent
    parent.mkdir(mode=0o755, exist_ok=True)
    metadata = parent.stat()
    if parent.resolve() != parent or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise ValueError("tool directory is not trusted")
    descriptor = os.open(
        parent / ".claude-install.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "wb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if CLAUDE_BINARY.exists() or CLAUDE_BINARY.is_symlink():
            metadata = CLAUDE_BINARY.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != 0
                or stat.S_IMODE(metadata.st_mode) != 0o755
            ):
                raise ValueError("existing tool metadata differs; no replacement")
            with CLAUDE_BINARY.open("rb") as existing:
                if hashlib.file_digest(existing, "sha256").hexdigest() != CLAUDE_SHA256:
                    raise ValueError("existing tool hash differs; no replacement")
            return
        with tempfile.NamedTemporaryFile(
            dir=parent, prefix=".claude-download-", delete=False
        ) as output:
            temporary = Path(output.name)
            try:
                # Fixed public vendor URL; exact size and SHA-256 required before execution.
                with urllib.request.urlopen(URL, timeout=30) as response:  # noqa: S310
                    received = 0
                    digest = hashlib.sha256()
                    while chunk := response.read(1_048_576):
                        received += len(chunk)
                        if received > BINARY_BYTES:
                            raise ValueError("download size exceeded")
                        output.write(chunk)
                        digest.update(chunk)
                if received != BINARY_BYTES or digest.hexdigest() != CLAUDE_SHA256:
                    raise ValueError("download identity differs")
                output.flush()
                os.fsync(output.fileno())
                os.chmod(temporary, 0o755)  # noqa: S103 - verified public executable, root-owned
                # Exclusive link preserves an unexpected existing destination.
                os.link(temporary, CLAUDE_BINARY)
            finally:
                temporary.unlink()


if __name__ == "__main__":
    install()
    print("Pinned Claude Code 2.1.309 installation verified; no inference or login")
