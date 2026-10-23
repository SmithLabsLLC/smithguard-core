"""Immutable local evidence adapter checks."""

from __future__ import annotations

import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import smithguard.evidence as evidence_module
from smithguard.evidence import (
    EvidenceIntegrityError,
    LocalImmutableEvidenceStore,
    UnsafeEvidencePath,
)


def _blob_path(root: Path, digest: str) -> Path:
    hexadecimal = digest.removeprefix("sha256:")
    return root / "sha256" / hexadecimal[:2] / hexadecimal


def _staging_path(root: Path, digest: str) -> Path:
    hexadecimal = digest.removeprefix("sha256:")
    return root / ".staging" / "sha256" / hexadecimal[:2] / hexadecimal


def test_content_addressed_write_read_verify_and_manifest(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    store = LocalImmutableEvidenceStore(root)
    blob = store.put_bytes(b"synthetic evidence")
    duplicate = store.put_bytes(b"synthetic evidence")

    assert duplicate == blob
    assert store.read_bytes(blob.digest) == b"synthetic evidence"
    assert store.verify(blob.digest) == blob
    assert store.manifest() == [blob]
    assert stat.S_IMODE(os.lstat(root).st_mode) == 0o700
    assert stat.S_IMODE(os.lstat(_blob_path(root, blob.digest)).st_mode) == 0o400


def test_concurrent_identical_writes_are_idempotent(tmp_path: Path) -> None:
    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    with ThreadPoolExecutor(max_workers=4) as workers:
        results = list(workers.map(store.put_bytes, [b"same bytes"] * 8))
    assert len(set(results)) == 1
    assert store.manifest() == [results[0]]


def test_finalizer_accepts_verified_final_after_staged_missing_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "evidence"
    store = LocalImmutableEvidenceStore(root)
    body = b"concurrent final evidence"
    blob = store.put_bytes(body)
    stage = store.stage_bytes(body)
    staging_path = _staging_path(root, stage.digest)
    staging_shard = staging_path.parent.stat()
    original_read_at = store._read_at
    raced = False

    def race_read(shard_descriptor: int, *, digest: str):
        nonlocal raced
        descriptor = os.fstat(shard_descriptor)
        if not raced and (descriptor.st_dev, descriptor.st_ino) == (
            staging_shard.st_dev,
            staging_shard.st_ino,
        ):
            raced = True
            staging_path.unlink()
            staging_path.write_bytes(body)
            staging_path.chmod(0o400)
            try:
                raise FileNotFoundError(staging_path)
            except FileNotFoundError as error:
                raise EvidenceIntegrityError("immutable evidence is missing") from error
        return original_read_at(shard_descriptor, digest=digest)

    monkeypatch.setattr(store, "_read_at", race_read)

    assert store.finalize_stage(stage) == blob
    assert raced is True
    assert staging_path.exists()
    assert store.finalize_stage(stage) == blob
    assert store.pending_manifest() == []


def test_stager_accepts_verified_final_after_shared_stage_missing_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "evidence"
    store = LocalImmutableEvidenceStore(root)
    body = b"concurrent staged evidence"
    blob = store.put_bytes(body)
    original_write_at = store._write_at
    raced = False

    def race_write(shard_descriptor: int, *, digest: str, data: bytes):
        nonlocal raced
        if not raced:
            raced = True
            hexadecimal = digest.removeprefix("sha256:")
            staged_path = root / ".staging" / "sha256" / hexadecimal[:2] / hexadecimal
            staged_path.write_bytes(data)
            staged_path.chmod(0o400)
            try:
                raise FileNotFoundError(staged_path)
            except FileNotFoundError as error:
                raise EvidenceIntegrityError("immutable evidence is missing") from error
        return original_write_at(shard_descriptor, digest=digest, data=data)

    monkeypatch.setattr(store, "_write_at", race_write)

    stage = store.stage_bytes(body)
    assert stage.digest == blob.digest
    assert raced is True
    assert store.finalize_stage(stage) == blob
    assert store.pending_manifest() == []


def test_size_type_digest_and_permissions_fail_closed(tmp_path: Path) -> None:
    store = LocalImmutableEvidenceStore(tmp_path / "evidence", max_bytes=4)
    with pytest.raises(TypeError, match="must be bytes"):
        store.put_bytes("text")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="byte limit"):
        store.put_bytes(b"12345")
    with pytest.raises(ValueError, match="invalid SHA"):
        store.read_bytes("sha256:not-a-digest")

    blob = store.put_bytes(b"1234")
    path = _blob_path(store.root, blob.digest)
    os.chmod(path, 0o600)
    with pytest.raises(EvidenceIntegrityError, match="remains writable"):
        store.verify(blob.digest)
    os.chmod(path, 0o400)
    os.chmod(path, 0o600)
    path.write_bytes(b"4321")
    os.chmod(path, 0o400)
    with pytest.raises(EvidenceIntegrityError, match="checksum mismatch"):
        store.read_bytes(blob.digest)


def test_roots_and_shards_cannot_traverse_links(tmp_path: Path) -> None:
    real_root = tmp_path / "real"
    real_root.mkdir(mode=0o700)
    linked_root = tmp_path / "linked"
    linked_root.symlink_to(real_root, target_is_directory=True)
    with pytest.raises(UnsafeEvidencePath, match="real directory"):
        LocalImmutableEvidenceStore(linked_root)

    root = tmp_path / "evidence"
    store = LocalImmutableEvidenceStore(root)
    body = b"synthetic"
    digest = store.put_bytes(body).digest
    path = _blob_path(root, digest)
    path.unlink()
    path.symlink_to(tmp_path / "missing")
    with pytest.raises(EvidenceIntegrityError, match="regular file"):
        store.verify(digest)


def test_existing_group_access_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    root.mkdir(mode=0o750)
    with pytest.raises(PermissionError, match="group or other"):
        LocalImmutableEvidenceStore(root)


def test_collector_mode_allows_backup_group_reads_but_never_group_writes(
    tmp_path: Path,
) -> None:
    root = tmp_path / "evidence"
    store = LocalImmutableEvidenceStore(root, allow_group_read=True)
    blob = store.put_bytes(b"synthetic group-readable evidence")
    path = _blob_path(root, blob.digest)
    assert stat.S_IMODE(os.lstat(root).st_mode) == 0o750
    assert stat.S_IMODE(os.lstat(root / "sha256").st_mode) == 0o750
    assert stat.S_IMODE(os.lstat(path.parent).st_mode) == 0o750
    assert stat.S_IMODE(os.lstat(path).st_mode) == 0o440
    assert store.read_bytes(blob.digest) == b"synthetic group-readable evidence"

    os.chmod(path, 0o460)
    with pytest.raises(EvidenceIntegrityError, match="remains writable"):
        store.verify(blob.digest)


def test_private_mode_rejects_a_group_readable_existing_blob(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    store = LocalImmutableEvidenceStore(root)
    blob = store.put_bytes(b"synthetic private evidence")
    path = _blob_path(root, blob.digest)
    os.chmod(path, 0o440)
    with pytest.raises(EvidenceIntegrityError, match="read boundary"):
        store.verify(blob.digest)


def test_open_existing_mode_never_creates_a_missing_root(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    with pytest.raises(UnsafeEvidencePath, match="does not exist"):
        LocalImmutableEvidenceStore(missing, create=False)
    assert not missing.exists()


def test_stage_finalize_and_discard_are_explicit(tmp_path: Path) -> None:
    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    finalized = store.stage_bytes(b"finalized stage")
    discarded = store.stage_bytes(b"discarded stage")

    assert {blob.digest for blob in store.pending_manifest()} == {
        finalized.digest,
        discarded.digest,
    }
    assert store.manifest() == []

    blob = store.finalize_stage(finalized)
    store.discard_stage(discarded)
    assert blob.digest == finalized.digest
    assert store.pending_manifest() == []
    assert store.read_bytes(finalized.digest) == b"finalized stage"


def test_corrupted_stage_cannot_hide_behind_an_existing_final_object(
    tmp_path: Path,
) -> None:
    root = tmp_path / "evidence"
    store = LocalImmutableEvidenceStore(root)
    body = b"existing final evidence"
    blob = store.put_bytes(body)
    stage = store.stage_bytes(body)
    staging_path = _staging_path(root, stage.digest)
    os.chmod(staging_path, 0o600)
    staging_path.write_bytes(b"x" * len(body))
    os.chmod(staging_path, 0o400)

    with pytest.raises(EvidenceIntegrityError, match="checksum mismatch"):
        store.finalize_stage(stage)
    assert store.read_bytes(blob.digest) == body
    assert staging_path.exists()


def test_staging_namespace_cannot_traverse_a_symbolic_link(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    store = LocalImmutableEvidenceStore(root)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    (root / ".staging").symlink_to(outside, target_is_directory=True)

    with pytest.raises(UnsafeEvidencePath, match="staging namespace"):
        store.stage_bytes(b"must stay inside")
    assert not any(outside.iterdir())


def test_stage_write_failure_removes_its_temporary_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "evidence"
    store = LocalImmutableEvidenceStore(root)

    def fail_write(_descriptor: int, _data: bytes) -> None:
        raise OSError("synthetic write failure")

    monkeypatch.setattr(evidence_module, "_write_all", fail_write)
    with pytest.raises(OSError, match="synthetic write failure"):
        store.stage_bytes(b"interrupted stage")

    assert not tuple(root.rglob("*.tmp"))
    assert store.pending_manifest() == []


def test_open_root_descriptor_survives_path_replacement(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    moved = tmp_path / "verified-root"
    store = LocalImmutableEvidenceStore(root)
    root.rename(moved)
    root.mkdir(mode=0o700)

    blob = store.put_bytes(b"anchored to verified root")

    assert _blob_path(moved, blob.digest).is_file()
    assert not _blob_path(root, blob.digest).exists()
    assert store.read_bytes(blob.digest) == b"anchored to verified root"


def test_missing_immutable_object_raises_the_missing_subclass_with_its_cause(tmp_path) -> None:
    from smithguard.evidence import EvidenceMissingError, LocalImmutableEvidenceStore

    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    digest = "sha256:" + "a" * 64
    for reader in (store.read_bytes, store.verify):
        with pytest.raises(EvidenceMissingError, match="immutable evidence is missing") as caught:
            reader(digest)
        assert isinstance(caught.value.__cause__, FileNotFoundError)
