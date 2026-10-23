"""Crash-recoverable evidence finalization bound to SQLAlchemy transactions."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import event, func, select, update
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Session

from smithguard.db.locks import advisory_xact_lock
from smithguard.db.models import EvidenceFinalizationRecord
from smithguard.evidence import EvidenceStage, EvidenceStore
from smithguard.identifiers import stable_id

PROCESSING_ERROR = "evidence_finalization_failed"
_FAILURES_KEY = "smithguard_evidence_finalization_failures"
_QUEUE_KEY = "smithguard_evidence_stages"


class EvidenceFinalizationError(RuntimeError):
    """Committed evidence could not reach its immutable final namespace."""


@dataclass(frozen=True, slots=True)
class _RegisteredStage:
    store: EvidenceStore
    stage: EvidenceStage
    finalization_id: str
    discard_on_rollback: bool
    transaction: Any


@dataclass(frozen=True, slots=True)
class _PreparedStageRegistration:
    session: Session
    transaction: Any
    digest: str
    byte_count: int
    existing: EvidenceFinalizationRecord | None
    discard_on_rollback: bool


def _now() -> datetime:
    return datetime.now(UTC)


def _engine_for(session: Session) -> Engine:
    bind = session.get_bind()
    if isinstance(bind, Engine):
        return bind
    if isinstance(bind, Connection):
        return bind.engine
    raise EvidenceFinalizationError("evidence finalization has no database engine")


def _mark_finalization(
    engine: Engine,
    *,
    finalization_id: str,
    finalized: bool,
    occurred_at: datetime,
) -> None:
    values: dict[str, Any] = {
        "state": "finalized" if finalized else "failed",
        "updated_at": occurred_at,
        "last_error_code": None if finalized else PROCESSING_ERROR,
        "finalized_at": occurred_at if finalized else None,
        "attempts": func.least(EvidenceFinalizationRecord.attempts + 1, 100),
    }
    with engine.begin() as connection:
        result = connection.execute(
            update(EvidenceFinalizationRecord)
            .where(EvidenceFinalizationRecord.finalization_id == finalization_id)
            .values(**values)
        )
        if result.rowcount != 1:
            raise EvidenceFinalizationError("committed evidence finalization record is missing")


@event.listens_for(Session, "after_commit")
def _finalize_committed_stages(session: Session) -> None:
    if session.in_nested_transaction():
        return
    registered = tuple(session.info.pop(_QUEUE_KEY, ()))
    if not registered:
        return
    engine = _engine_for(session)
    failures: list[str] = []
    for item in registered:
        occurred_at = _now()
        try:
            item.store.finalize_stage(item.stage)
        except Exception:
            _mark_finalization(
                engine,
                finalization_id=item.finalization_id,
                finalized=False,
                occurred_at=occurred_at,
            )
            failures.append(item.finalization_id)
        else:
            _mark_finalization(
                engine,
                finalization_id=item.finalization_id,
                finalized=True,
                occurred_at=occurred_at,
            )
    if failures:
        # The database rows are already durable, so raising here would tell the caller
        # that a committed transaction failed. The failed stages are recorded above and
        # reconcile_evidence_finalizations retries them. The owning runtime can read the
        # ids back with pop_finalization_failures and decide its own exit.
        session.info[_FAILURES_KEY] = tuple(
            (*session.info.get(_FAILURES_KEY, ()), *sorted(failures))
        )
        sys.stderr.write(
            "evidence_finalization_pending count="
            f"{len(failures)} ids={','.join(sorted(failures))}\n"
        )


def pop_finalization_failures(session: Session) -> tuple[str, ...]:
    """Return and clear the finalization ids that failed after this session's commits."""
    return tuple(session.info.pop(_FAILURES_KEY, ()))


def require_finalized(session: Session) -> None:
    """Fail the owning run, outside any transaction, when a committed stage did not finalize.

    Call this right after a transaction that may have registered evidence stages. The
    rows stay committed and the failed records stay durable for reconciliation; the run
    that produced them must not report completion over bytes that were never stored.
    """
    failed = pop_finalization_failures(session)
    if failed:
        raise EvidenceFinalizationError(
            "committed evidence objects require reconciliation: " + ",".join(failed)
        )


@event.listens_for(Session, "after_soft_rollback")
def _discard_rolled_back_stages(session: Session, previous_transaction: Any) -> None:
    # Flush rolls back a real root/SAVEPOINT but reports its internal child marker.
    boundary = previous_transaction
    while boundary.parent is not None and not boundary.nested:
        boundary = boundary.parent
    _discard_registered_stages(session, boundary)


@event.listens_for(Session, "after_transaction_end")
def _discard_closed_root_stages(session: Session, transaction: Any) -> None:
    # Inactive-root teardown and Session.close do not emit after_soft_rollback.
    # Successful root after_commit already consumed the queue; nested commits must
    # keep their stages until their root commits.
    if transaction.parent is None:
        _discard_registered_stages(session, transaction)


def _discard_registered_stages(session: Session, boundary: Any) -> None:
    registered = list(session.info.get(_QUEUE_KEY, ()))
    if boundary.parent is None:
        discarded = registered
        session.info.pop(_QUEUE_KEY, None)
    else:
        discarded = [
            item for item in registered if _transaction_descends_from(item.transaction, boundary)
        ]
        retained = [item for item in registered if item not in discarded]
        if retained:
            session.info[_QUEUE_KEY] = retained
        else:
            session.info.pop(_QUEUE_KEY, None)
    failures: list[str] = []
    for item in discarded:
        if item.discard_on_rollback:
            try:
                item.store.discard_stage(item.stage)
            except Exception:
                failures.append(item.stage.digest)
    if failures:
        raise EvidenceFinalizationError(
            "rolled-back evidence cleanup failed for " + ",".join(failures)
        )


def _transaction_descends_from(transaction: Any, ancestor: Any) -> bool:
    """Return whether a registered savepoint belongs to a rolled-back ancestor."""
    current = transaction
    while current is not None:
        if current is ancestor:
            return True
        current = current.parent
    return False


def _prepare_evidence_stage(
    session: Session,
    *,
    digest: str,
    byte_count: int,
) -> _PreparedStageRegistration:
    """Resolve ownership under the digest lock before creating a staged file."""
    with session.no_autoflush:
        advisory_xact_lock(session, f"evidence-finalization:{digest}")
        existing = session.scalar(
            select(EvidenceFinalizationRecord).where(EvidenceFinalizationRecord.digest == digest)
        )
    discard_on_rollback = existing is None or existing.state == "finalized"
    if existing is not None:
        if existing.byte_count != byte_count or existing.staging_key != digest:
            raise EvidenceFinalizationError("evidence finalization metadata conflicts")
        if existing.state != "finalized" and existing.attempts >= 100:
            raise EvidenceFinalizationError("evidence finalization retry budget is exhausted")
    transaction = session.get_nested_transaction() or session.get_transaction()
    if transaction is None:
        raise EvidenceFinalizationError("evidence finalization requires an active transaction")
    return _PreparedStageRegistration(
        session=session,
        transaction=transaction,
        digest=digest,
        byte_count=byte_count,
        existing=existing,
        discard_on_rollback=discard_on_rollback,
    )


def _register_prepared_evidence_stage(
    session: Session,
    *,
    preparation: _PreparedStageRegistration,
    store: EvidenceStore,
    stage: EvidenceStage,
    evidence_id: str,
    staged_at: datetime,
) -> EvidenceFinalizationRecord:
    """Queue the owned stage before any SQL can abort its accepting transaction."""
    transaction = session.get_nested_transaction() or session.get_transaction()
    if preparation.session is not session or preparation.transaction is not transaction:
        raise EvidenceFinalizationError("evidence stage preparation belongs to another transaction")
    if (
        stage.digest != preparation.digest
        or stage.byte_count != preparation.byte_count
        or stage.staging_key != preparation.digest
        or stage.storage_key != preparation.digest
    ):
        raise EvidenceFinalizationError("evidence stage differs from its prepared metadata")
    existing = preparation.existing
    if existing is not None:
        record = existing
    else:
        record = EvidenceFinalizationRecord(
            finalization_id=stable_id("evidence-finalization", stage.digest),
            evidence_id=evidence_id,
            digest=stage.digest,
            staging_key=stage.staging_key,
            byte_count=stage.byte_count,
            state="pending",
            attempts=0,
            last_error_code=None,
            staged_at=staged_at,
            updated_at=staged_at,
            finalized_at=None,
        )
    finalization_id = record.finalization_id

    queue: list[_RegisteredStage] = session.info.setdefault(_QUEUE_KEY, [])
    if not any(item.finalization_id == finalization_id for item in queue):
        queue.append(
            _RegisteredStage(
                store=store,
                stage=stage,
                finalization_id=finalization_id,
                discard_on_rollback=preparation.discard_on_rollback,
                transaction=transaction,
            )
        )
    if existing is None:
        session.add(record)
        session.flush()
    return record


def register_evidence_stage(
    session: Session,
    *,
    store: EvidenceStore,
    stage: EvidenceStage,
    evidence_id: str,
    staged_at: datetime,
) -> EvidenceFinalizationRecord:
    """Register an already-staged object; collectors prepare before staging instead."""
    preparation = _prepare_evidence_stage(session, digest=stage.digest, byte_count=stage.byte_count)
    return _register_prepared_evidence_stage(
        session,
        preparation=preparation,
        store=store,
        stage=stage,
        evidence_id=evidence_id,
        staged_at=staged_at,
    )


def reconcile_evidence_finalizations(
    session: Session,
    *,
    store: EvidenceStore,
    limit: int = 100,
    now: datetime | None = None,
) -> tuple[int, int]:
    """Resume a bounded set of committed pending or failed finalizations."""
    if not 1 <= limit <= 500:
        raise ValueError("evidence finalization reconciliation limit is invalid")
    occurred_at = now or _now()
    records = list(
        session.scalars(
            select(EvidenceFinalizationRecord)
            .where(
                EvidenceFinalizationRecord.state.in_(("pending", "failed")),
                EvidenceFinalizationRecord.attempts < 100,
            )
            .order_by(
                EvidenceFinalizationRecord.updated_at,
                EvidenceFinalizationRecord.finalization_id,
            )
            .with_for_update(skip_locked=True)
            .limit(limit)
        )
    )
    finalized = 0
    failed = 0
    for record in records:
        stage = EvidenceStage(
            digest=record.digest,
            byte_count=record.byte_count,
            storage_key=record.digest,
            staging_key=record.staging_key,
        )
        record.attempts += 1
        record.updated_at = occurred_at
        try:
            store.finalize_stage(stage)
        except Exception:
            record.state = "failed"
            record.last_error_code = PROCESSING_ERROR
            record.finalized_at = None
            failed += 1
        else:
            record.state = "finalized"
            record.last_error_code = None
            record.finalized_at = occurred_at
            finalized += 1
    session.flush()
    return finalized, failed
