"""Retained signed-publication verification keys are served read-only."""

import json
import os
from pathlib import Path

import pytest

from smithguard.feeds import SnapshotSigner
from smithguard.snapshot_archive import SnapshotArchive, SnapshotArchiveError


def _write_key(root: Path, signer: SnapshotSigner) -> Path:
    path = root / f"{signer.public_key_id}.public-key.json"
    path.write_text(json.dumps(signer.public_key_document()), encoding="ascii")
    path.chmod(0o440)
    return path


@pytest.mark.audit_ids("DATA-02")
def test_snapshot_archive_rejects_symlinked_root_or_entry(tmp_path: Path) -> None:
    root = tmp_path / "snapshots"
    root.mkdir(mode=0o750)
    with pytest.raises(SnapshotArchiveError, match="absolute"):
        SnapshotArchive(Path("relative"))
    link = tmp_path / "linked"
    link.symlink_to(root, target_is_directory=True)
    with pytest.raises(SnapshotArchiveError, match="directory"):
        SnapshotArchive(link)
    writable = tmp_path / "writable"
    writable.mkdir()
    writable.chmod(0o770)
    with pytest.raises(SnapshotArchiveError, match="writable by group"):
        SnapshotArchive(writable)
    signer = SnapshotSigner.ephemeral()
    real = tmp_path / "real.json"
    real.write_text(json.dumps(signer.public_key_document()), encoding="ascii")
    os.symlink(real, root / f"{signer.public_key_id}.public-key.json")
    with pytest.raises(SnapshotArchiveError, match="opened safely"):
        SnapshotArchive(root).public_key_document(signer.public_key_id)


def test_snapshot_archive_serves_only_retained_matching_public_keys(tmp_path: Path) -> None:
    root = tmp_path / "snapshots"
    root.mkdir(mode=0o750)
    archive = SnapshotArchive(root)
    signer = SnapshotSigner.ephemeral()
    assert archive.public_key_document(signer.public_key_id) is None
    assert archive.public_key_document("not-a-key-id") is None
    _write_key(root, signer)
    assert archive.public_key_document(signer.public_key_id) == signer.public_key_document()
    assert not hasattr(archive, "put")
    assert not hasattr(archive, "prune_verified")

    other = SnapshotSigner.ephemeral()
    mismatched = root / f"{other.public_key_id}.public-key.json"
    mismatched.write_text(json.dumps(signer.public_key_document()), encoding="ascii")
    with pytest.raises(SnapshotArchiveError, match="invalid"):
        archive.public_key_document(other.public_key_id)
