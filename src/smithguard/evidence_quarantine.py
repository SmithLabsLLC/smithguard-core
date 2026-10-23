"""Explicit operator-only quarantine for proven uncommitted evidence stages.

Never called by a collector. The operator holds deployment ownership and supplies
its repeated exact-target/all-producers-stopped check. Files are moved, not copied
or deleted. A consumed operation directory is never reused after any failure.
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Callable, Mapping
from pathlib import Path
from time import monotonic

from sqlalchemy import func, or_, select, text

from smithguard.db.models import EvidenceFinalizationRecord, EvidenceRecord
from smithguard.evidence import LocalImmutableEvidenceStore
from smithguard.evidence_finalization import reconcile_evidence_finalizations
from smithguard.fsio import fsync_directory, write_exclusive
from smithguard.identifiers import canonical_json_bytes


class EvidenceQuarantineError(RuntimeError):
    """An orphan stage has not been proved safe to remove from active staging."""


def quarantine_orphan_stages(
    factory,
    *,
    store: LocalImmutableEvidenceStore,
    parent: Path,
    operation_id: str,
    approved: Mapping[str, int],
    verify_quiescence: Callable[[], None],
) -> dict:
    """Quarantine the exact bounded allowlist after committed-state reconciliation."""
    if (
        re.fullmatch(r"[0-9]{8}-[0-9a-f]{32}", operation_id) is None
        or not 1 <= len(approved) <= 100
        or any(
            not isinstance(key, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", key) is None
            or type(size) is not int
            or not 0 <= size <= store.max_bytes
            for key, size in approved.items()
        )
        or sum(approved.values()) > 64 * 1024**2
    ):
        raise EvidenceQuarantineError("quarantine allowlist is invalid or exceeds its bound")
    metadata = parent.lstat()
    if (
        not parent.is_absolute()
        or parent.resolve(strict=True) != parent
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or parent == store.root
        or store.root in parent.parents
        or metadata.st_dev != store.root.stat().st_dev
    ):
        raise EvidenceQuarantineError(
            "quarantine parent must be private and outside active evidence on the same filesystem"
        )
    deadline = monotonic() + 240
    verify_quiescence()
    destination = parent / operation_id
    destination.mkdir(mode=0o700)
    fsync_directory(parent)
    write_exclusive(destination / "approved.json", canonical_json_bytes(dict(approved)), mode=0o600)
    moved = []
    try:
        with store.collection_lock(timeout_seconds=10):
            verify_quiescence()
            with factory() as session, session.begin():
                session.execute(text("SET LOCAL statement_timeout='10000ms'"))
                session.execute(text("SET LOCAL lock_timeout='5000ms'"))
                _finalized, failed = reconcile_evidence_finalizations(session, store=store)
                unresolved = session.scalar(
                    select(func.count())
                    .select_from(EvidenceFinalizationRecord)
                    .where(EvidenceFinalizationRecord.state != "finalized")
                )
            if failed or unresolved:
                raise EvidenceQuarantineError("committed finalizations remain unresolved")
            manifest = {
                item.digest: item.byte_count for item in store.pending_manifest(maximum_entries=100)
            }
            if manifest != dict(approved):
                raise EvidenceQuarantineError(
                    "pending stages differ from the exact approved allowlist"
                )
            with factory() as session, session.begin():
                session.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"))
                session.execute(text("SET LOCAL statement_timeout='10000ms'"))
                session.execute(text("SET LOCAL lock_timeout='5000ms'"))
                # All producers must remain stopped under the caller's root release
                # lock and this collection lock. The collector deliberately has no
                # table-wide mutation privileges; do not expand them for recovery.
                verify_quiescence()
                keys = list(approved)
                referenced = session.scalar(
                    select(func.count())
                    .select_from(EvidenceRecord)
                    .where(EvidenceRecord.sha256.in_(keys))
                )
                referenced += session.scalar(
                    select(func.count())
                    .select_from(EvidenceFinalizationRecord)
                    .where(
                        or_(
                            EvidenceFinalizationRecord.digest.in_(keys),
                            EvidenceFinalizationRecord.staging_key.in_(keys),
                        )
                    )
                )
                if referenced:
                    raise EvidenceQuarantineError(
                        "a staged digest is referenced by committed database state"
                    )
                root_fd = store._root_descriptor()
                target_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    for index, key in enumerate(sorted(approved)):
                        if monotonic() >= deadline:
                            raise EvidenceQuarantineError("quarantine work deadline exceeded")
                        verify_quiescence()
                        descriptors = store._shard_descriptor(
                            root_fd, key, staging=True, create=False
                        )
                        try:
                            hexadecimal = key.removeprefix("sha256:")
                            source_fd = os.open(
                                hexadecimal,
                                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                dir_fd=descriptors[0],
                            )
                            try:
                                observed = os.fstat(source_fd)
                                if (
                                    observed.st_uid != os.geteuid()
                                    or observed.st_nlink != 1
                                    or observed.st_dev != metadata.st_dev
                                ):
                                    raise EvidenceQuarantineError(
                                        "staged file owner/link/filesystem differs"
                                    )
                                blob, _body = store._read_verified_descriptor(source_fd, digest=key)
                                if blob.byte_count != approved[key]:
                                    raise EvidenceQuarantineError(
                                        "staged size differs from approval"
                                    )
                                current = os.stat(
                                    hexadecimal, dir_fd=descriptors[0], follow_symlinks=False
                                )
                                if (current.st_dev, current.st_ino) != (
                                    observed.st_dev,
                                    observed.st_ino,
                                ):
                                    raise EvidenceQuarantineError("stage changed before quarantine")
                                write_exclusive(
                                    destination / f"{index:03d}-move-started.json",
                                    canonical_json_bytes(
                                        {"digest": key, "byte_count": blob.byte_count}
                                    ),
                                    mode=0o600,
                                )
                                # Fresh exclusive operation directory; no destination
                                # filename exists and only its owner can create one.
                                os.rename(
                                    hexadecimal,
                                    hexadecimal,
                                    src_dir_fd=descriptors[0],
                                    dst_dir_fd=target_fd,
                                )
                                os.fsync(descriptors[0])
                                os.fsync(target_fd)
                                moved.append(key)
                                write_exclusive(
                                    destination / f"{index:03d}-moved.json",
                                    canonical_json_bytes({"digest": key}),
                                    mode=0o600,
                                )
                            finally:
                                os.close(source_fd)
                        finally:
                            store._close_shard(*descriptors)
                finally:
                    os.close(root_fd)
                    os.close(target_fd)
            if store.pending_manifest(maximum_entries=100):
                raise EvidenceQuarantineError("staging remained nonempty after quarantine")
        result = {"status": "quarantined", "operation_id": operation_id, "digests": moved}
        write_exclusive(destination / "result.json", canonical_json_bytes(result), mode=0o600)
        return result
    except BaseException as error:
        write_exclusive(
            destination / "failure.json",
            canonical_json_bytes(
                {"status": "failed", "error_class": type(error).__name__, "moved": moved}
            ),
            mode=0o600,
        )
        raise
