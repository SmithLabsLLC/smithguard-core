"""Snapshot signer key handling."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from smithguard.feeds import SnapshotSigner


def test_snapshot_private_key_file_rejects_unsafe_paths(tmp_path: Path) -> None:
    key_path = tmp_path / "snapshot.key"
    key_path.write_bytes(SnapshotSigner.generate_private_key_bytes())
    os.chmod(key_path, 0o600)

    signer = SnapshotSigner.from_private_key_file(key_path)
    assert signer.public_key_id.startswith("gbsec:snapshot-public-key:")

    os.chmod(key_path, 0o640)
    with pytest.raises(PermissionError, match="group or world"):
        SnapshotSigner.from_private_key_file(key_path)

    os.chmod(key_path, 0o600)
    linked_path = tmp_path / "linked.key"
    linked_path.symlink_to(key_path)
    with pytest.raises((OSError, ValueError), match="regular file|symbolic link"):
        SnapshotSigner.from_private_key_file(linked_path)
