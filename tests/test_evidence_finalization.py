"""Database transaction checks for crash-recoverable evidence finalization."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import event, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from smithguard.db.models import EvidenceFinalizationRecord
from smithguard.evidence import (
    EvidenceBlob,
    EvidenceStage,
    LocalImmutableEvidenceStore,
)
from smithguard.evidence_finalization import (
    EvidenceFinalizationError,
    reconcile_evidence_finalizations,
    register_evidence_stage,
)
from smithguard.identifiers import stable_id

NOW = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)


@contextmanager
def server_failure(engine, statement_fragment, *, occurrence=1):
    """Raise an actual PostgreSQL53200 error during one matching SQL operation."""
    matches = 0
    injected = False

    def inject(connection, cursor, statement, parameters, context, executemany):
        nonlocal matches, injected
        if not injected and statement_fragment in statement.lower():
            matches += 1
            if matches == occurrence:
                injected = True
                return (
                    "DO $$ BEGIN RAISE EXCEPTION 'synthetic capacity exhaustion' "
                    "USING ERRCODE = '53200'; END $$",
                    {},
                )
        return statement, parameters

    event.listen(engine, "before_cursor_execute", inject, retval=True)
    try:
        yield
    finally:
        event.remove(engine, "before_cursor_execute", inject)
    assert injected, "the intended real database failure was not exercised"


class FailOnceEvidenceStore:
    """Delegate every operation except the first finalization attempt."""

    def __init__(self, delegate: LocalImmutableEvidenceStore) -> None:
        self.delegate = delegate
        self.remaining_failures = 1

    def put_bytes(self, data: bytes) -> EvidenceBlob:
        return self.delegate.put_bytes(data)

    def stage_bytes(self, data: bytes) -> EvidenceStage:
        return self.delegate.stage_bytes(data)

    def finalize_stage(self, stage: EvidenceStage) -> EvidenceBlob:
        if self.remaining_failures:
            self.remaining_failures -= 1
            raise OSError("synthetic finalization interruption")
        return self.delegate.finalize_stage(stage)

    def discard_stage(self, stage: EvidenceStage) -> None:
        self.delegate.discard_stage(stage)

    def pending_manifest(self) -> list[EvidenceBlob]:
        return self.delegate.pending_manifest()

    def read_bytes(self, digest: str) -> bytes:
        return self.delegate.read_bytes(digest)

    def verify(self, digest: str) -> EvidenceBlob:
        return self.delegate.verify(digest)

    def manifest(self) -> list[EvidenceBlob]:
        return self.delegate.manifest()


class FailFirstDiscardEvidenceStore:
    """Attempt every discard while one staged object remains unavailable."""

    def __init__(self, delegate: LocalImmutableEvidenceStore) -> None:
        self.delegate = delegate
        self.failed_digest: str | None = None
        self.discard_attempts: list[str] = []

    def stage_bytes(self, data: bytes) -> EvidenceStage:
        return self.delegate.stage_bytes(data)

    def discard_stage(self, stage: EvidenceStage) -> None:
        self.discard_attempts.append(stage.digest)
        if stage.digest == self.failed_digest:
            raise OSError("synthetic discard failure")
        self.delegate.discard_stage(stage)


def _register(
    session: Session,
    *,
    store: (LocalImmutableEvidenceStore | FailOnceEvidenceStore | FailFirstDiscardEvidenceStore),
    body: bytes,
) -> EvidenceStage:
    stage = store.stage_bytes(body)
    register_evidence_stage(
        session,
        store=store,
        stage=stage,
        evidence_id=stable_id("evidence", stage.digest),
        staged_at=NOW,
    )
    return stage


def test_commit_finalizes_stage_and_records_completion(database, tmp_path: Path) -> None:
    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    with Session(database.engine) as session, session.begin():
        stage = _register(session, store=store, body=b"committed evidence")
        assert store.pending_manifest()[0].digest == stage.digest
        assert store.manifest() == []

    assert store.pending_manifest() == []
    assert store.read_bytes(stage.digest) == b"committed evidence"
    with Session(database.engine) as session:
        record = session.scalar(
            select(EvidenceFinalizationRecord).where(
                EvidenceFinalizationRecord.digest == stage.digest
            )
        )
        assert record is not None
        assert record.state == "finalized"
        assert record.attempts == 1
        assert record.finalized_at is not None


def test_existing_legacy_finalization_id_is_updated_after_commit(
    database,
    tmp_path: Path,
) -> None:
    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    blob = store.put_bytes(b"legacy finalized evidence")
    legacy_id = "gbsec:evidence-finalization:legacy:" + blob.digest.removeprefix("sha256:")
    with Session(database.engine) as session, session.begin():
        session.add(
            EvidenceFinalizationRecord(
                finalization_id=legacy_id,
                evidence_id=stable_id("evidence", blob.digest),
                digest=blob.digest,
                staging_key=blob.digest,
                byte_count=blob.byte_count,
                state="finalized",
                attempts=0,
                last_error_code=None,
                staged_at=NOW,
                updated_at=NOW,
                finalized_at=NOW,
            )
        )

    with Session(database.engine) as session, session.begin():
        stage = store.stage_bytes(b"legacy finalized evidence")
        record = register_evidence_stage(
            session,
            store=store,
            stage=stage,
            evidence_id=stable_id("other-evidence", blob.digest),
            staged_at=NOW,
        )
        assert record.finalization_id == legacy_id

    assert store.pending_manifest() == []
    with Session(database.engine) as session:
        record = session.get(EvidenceFinalizationRecord, legacy_id)
        assert record is not None
        assert record.state == "finalized"
        assert record.attempts == 1


def test_root_rollback_discards_only_its_new_stage(database, tmp_path: Path) -> None:
    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    with (
        pytest.raises(RuntimeError, match="synthetic rollback"),
        Session(database.engine) as session,
        session.begin(),
    ):
        stage = _register(session, store=store, body=b"rolled back evidence")
        raise RuntimeError("synthetic rollback")

    assert store.pending_manifest() == []
    assert store.manifest() == []
    with Session(database.engine) as session:
        assert (
            session.scalar(
                select(EvidenceFinalizationRecord).where(
                    EvidenceFinalizationRecord.digest == stage.digest
                )
            )
            is None
        )


def test_flush_failure_discards_all_new_stages(database, tmp_path):
    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    with (
        server_failure(
            database.engine, "insert into smithguard.evidence_finalizations", occurrence=3
        ),
        pytest.raises(OperationalError),
        Session(database.engine) as session,
        session.begin(),
    ):
        for index in range(3):
            _register(session, store=store, body=f"new stage {index}".encode())
    assert store.pending_manifest() == store.manifest() == []
    with Session(database.engine) as session:
        assert session.scalar(select(EvidenceFinalizationRecord)) is None


def test_flush_failure_in_savepoint_preserves_outer_and_sibling_stages(database, tmp_path):
    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    with Session(database.engine) as session, session.begin():
        outer = _register(session, store=store, body=b"outer stage")
        with session.begin_nested():
            sibling = _register(session, store=store, body=b"committed sibling")
        with (
            server_failure(
                database.engine, "insert into smithguard.evidence_finalizations", occurrence=2
            ),
            pytest.raises(OperationalError),
            session.begin_nested(),
        ):
            _register(session, store=store, body=b"failed savepoint first")
            _register(session, store=store, body=b"failed savepoint second")
        assert {blob.digest for blob in store.pending_manifest()} == {
            outer.digest,
            sibling.digest,
        }
        assert store.manifest() == []
    assert store.pending_manifest() == []
    assert {blob.digest for blob in store.manifest()} == {outer.digest, sibling.digest}


def test_session_close_discards_new_stages_without_explicit_rollback(database, tmp_path):
    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    with Session(database.engine) as session:
        _register(session, store=store, body=b"implicit session close")
    assert store.pending_manifest() == store.manifest() == []
    with Session(database.engine) as session:
        assert session.scalar(select(EvidenceFinalizationRecord)) is None


@pytest.mark.parametrize("state", ["pending", "failed"])
def test_flush_failure_preserves_adopted_committed_stage_for_reconciliation(
    database, tmp_path, state
):
    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    stage = store.stage_bytes(b"committed recoverable bytes")
    finalization_id = stable_id("evidence-finalization", stage.digest)
    with Session(database.engine) as session, session.begin():
        session.add(
            EvidenceFinalizationRecord(
                finalization_id=finalization_id,
                evidence_id=stable_id("evidence", stage.digest),
                digest=stage.digest,
                staging_key=stage.staging_key,
                byte_count=stage.byte_count,
                state=state,
                attempts=1,
                last_error_code=None if state == "pending" else "evidence_finalization_failed",
                staged_at=NOW,
                updated_at=NOW,
                finalized_at=None,
            )
        )
    with (
        server_failure(
            database.engine, "insert into smithguard.evidence_finalizations", occurrence=2
        ),
        pytest.raises(OperationalError),
        Session(database.engine) as session,
        session.begin(),
    ):
        adopted = _register(session, store=store, body=b"committed recoverable bytes")
        assert adopted.digest == stage.digest
        _register(session, store=store, body=b"rolled-back new bytes first")
        _register(session, store=store, body=b"rolled-back new bytes second")
    assert [blob.digest for blob in store.pending_manifest()] == [stage.digest]
    with Session(database.engine) as session, session.begin():
        assert session.get(EvidenceFinalizationRecord, finalization_id).state == state
        assert reconcile_evidence_finalizations(session, store=store) == (1, 0)
    assert store.pending_manifest() == []
    assert store.read_bytes(stage.digest) == b"committed recoverable bytes"


@pytest.mark.parametrize("field", ["staging_key", "storage_key"])
def test_registration_rejects_wrong_keys_without_deleting_committed_recoverable_stage(
    database, tmp_path, field
):
    delegate = LocalImmutableEvidenceStore(tmp_path / "evidence")
    interrupted = FailOnceEvidenceStore(delegate)
    with Session(database.engine) as session, session.begin():
        stage = _register(session, store=interrupted, body=b"committed recoverable key check")
    wrong = replace(stage, **{field: "sha256:" + "a" * 64})
    with (
        pytest.raises(EvidenceFinalizationError, match="prepared metadata"),
        Session(database.engine) as session,
        session.begin(),
    ):
        register_evidence_stage(
            session,
            store=delegate,
            stage=wrong,
            evidence_id=stable_id("evidence", stage.digest),
            staged_at=NOW,
        )
    assert [blob.digest for blob in delegate.pending_manifest()] == [stage.digest]
    with Session(database.engine) as session, session.begin():
        record = session.scalar(select(EvidenceFinalizationRecord))
        assert record.state == "failed" and record.attempts == 1
        assert reconcile_evidence_finalizations(session, store=delegate) == (1, 0)
    assert delegate.pending_manifest() == []
    assert delegate.read_bytes(stage.digest) == b"committed recoverable key check"


def test_flush_cleanup_attempts_every_stage_once_when_one_discard_fails(database, tmp_path):
    delegate = LocalImmutableEvidenceStore(tmp_path / "evidence")
    store = FailFirstDiscardEvidenceStore(delegate)
    with (
        server_failure(
            database.engine, "insert into smithguard.evidence_finalizations", occurrence=3
        ),
        pytest.raises(EvidenceFinalizationError, match="rolled-back evidence cleanup failed"),
        Session(database.engine) as session,
        session.begin(),
    ):
        first = _register(session, store=store, body=b"temporarily unavailable stage")
        store.failed_digest = first.digest
        _register(session, store=store, body=b"cleanup first available stage")
        _register(session, store=store, body=b"cleanup second available stage")
    assert len(store.discard_attempts) == len(set(store.discard_attempts)) == 3
    assert [blob.digest for blob in delegate.pending_manifest()] == [first.digest]
    with Session(database.engine) as session:
        assert session.scalar(select(EvidenceFinalizationRecord)) is None


def test_rollback_attempts_every_discard_before_reporting_failures(
    database,
    tmp_path: Path,
) -> None:
    delegate = LocalImmutableEvidenceStore(tmp_path / "evidence")
    store = FailFirstDiscardEvidenceStore(delegate)
    with Session(database.engine) as session:
        transaction = session.begin()
        first = _register(session, store=store, body=b"first staged object")
        second = _register(session, store=store, body=b"second staged object")
        store.failed_digest = first.digest

        with pytest.raises(
            EvidenceFinalizationError,
            match="rolled-back evidence cleanup failed",
        ):
            transaction.rollback()

    assert store.discard_attempts == [first.digest, second.digest]
    assert [blob.digest for blob in delegate.pending_manifest()] == [first.digest]
    with Session(database.engine) as session:
        assert session.scalar(select(EvidenceFinalizationRecord)) is None


def test_nested_commit_waits_for_root_and_nested_rollback_discards(
    database,
    tmp_path: Path,
) -> None:
    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    with Session(database.engine) as session, session.begin():
        with session.begin_nested():
            committed = _register(session, store=store, body=b"nested commit")
        assert store.pending_manifest()[0].digest == committed.digest
        assert store.manifest() == []

        with (
            pytest.raises(RuntimeError, match="nested rollback"),
            session.begin_nested(),
        ):
            rolled_back = _register(session, store=store, body=b"nested rollback")
            raise RuntimeError("nested rollback")
        assert {blob.digest for blob in store.pending_manifest()} == {committed.digest}
        assert all(blob.digest != rolled_back.digest for blob in store.manifest())

    assert store.pending_manifest() == []
    assert store.read_bytes(committed.digest) == b"nested commit"


def test_parent_savepoint_rollback_discards_a_committed_child_stage(
    database,
    tmp_path: Path,
) -> None:
    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    with Session(database.engine) as session, session.begin():
        with (
            pytest.raises(RuntimeError, match="parent rollback"),
            session.begin_nested(),
        ):
            with session.begin_nested():
                stage = _register(session, store=store, body=b"child savepoint")
            assert store.pending_manifest()[0].digest == stage.digest
            raise RuntimeError("parent rollback")

        assert store.pending_manifest() == []
        assert store.manifest() == []

    with Session(database.engine) as session:
        assert (
            session.scalar(
                select(EvidenceFinalizationRecord).where(
                    EvidenceFinalizationRecord.digest == stage.digest
                )
            )
            is None
        )


def test_post_commit_failure_is_durable_and_reconciles(
    database, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    delegate = LocalImmutableEvidenceStore(tmp_path / "evidence")
    store = FailOnceEvidenceStore(delegate)
    # The rows are already committed when finalization runs, so the caller sees a
    # successful commit plus a stderr notice, never an exception for durable work.
    with Session(database.engine) as session, session.begin():
        stage = _register(session, store=store, body=b"recover after commit")
    notice = capsys.readouterr().err
    assert notice.startswith("evidence_finalization_pending count=1 ids=")

    assert delegate.pending_manifest()[0].digest == stage.digest
    assert delegate.manifest() == []
    with Session(database.engine) as session:
        record = session.scalar(
            select(EvidenceFinalizationRecord).where(
                EvidenceFinalizationRecord.digest == stage.digest
            )
        )
        assert record is not None
        assert record.state == "failed"
        assert record.attempts == 1

    with Session(database.engine) as session, session.begin():
        assert reconcile_evidence_finalizations(
            session,
            store=delegate,
            now=NOW,
        ) == (1, 0)

    assert delegate.pending_manifest() == []
    assert delegate.read_bytes(stage.digest) == b"recover after commit"


def test_rollback_does_not_delete_a_shared_committed_pending_stage(
    database,
    tmp_path: Path,
) -> None:
    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    stage = store.stage_bytes(b"shared pending evidence")
    with Session(database.engine) as session, session.begin():
        session.add(
            EvidenceFinalizationRecord(
                finalization_id=stable_id("evidence-finalization", stage.digest),
                evidence_id=stable_id("evidence", stage.digest),
                digest=stage.digest,
                staging_key=stage.staging_key,
                byte_count=stage.byte_count,
                state="pending",
                attempts=0,
                last_error_code=None,
                staged_at=NOW,
                updated_at=NOW,
                finalized_at=None,
            )
        )

    with (
        pytest.raises(RuntimeError, match="second transaction"),
        Session(database.engine) as session,
        session.begin(),
    ):
        register_evidence_stage(
            session,
            store=store,
            stage=stage,
            evidence_id=stable_id("other-evidence", stage.digest),
            staged_at=NOW,
        )
        raise RuntimeError("second transaction")

    assert store.pending_manifest()[0].digest == stage.digest
    with Session(database.engine) as session:
        assert (
            session.scalar(
                select(EvidenceFinalizationRecord.state).where(
                    EvidenceFinalizationRecord.digest == stage.digest
                )
            )
            == "pending"
        )


def test_reconciler_skips_exhausted_records(database, tmp_path: Path) -> None:
    store = LocalImmutableEvidenceStore(tmp_path / "evidence")
    stage = store.stage_bytes(b"exhausted evidence")
    with Session(database.engine) as session, session.begin():
        session.add(
            EvidenceFinalizationRecord(
                finalization_id=stable_id("evidence-finalization", stage.digest),
                evidence_id=stable_id("evidence", stage.digest),
                digest=stage.digest,
                staging_key=stage.staging_key,
                byte_count=stage.byte_count,
                state="failed",
                attempts=100,
                last_error_code="evidence_finalization_failed",
                staged_at=NOW,
                updated_at=NOW,
                finalized_at=None,
            )
        )

    with Session(database.engine) as session, session.begin():
        assert reconcile_evidence_finalizations(session, store=store) == (0, 0)
    assert store.pending_manifest()[0].digest == stage.digest
