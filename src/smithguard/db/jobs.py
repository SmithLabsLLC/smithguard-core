"""Durable PostgreSQL jobs with leases, retries, and idempotency."""

from __future__ import annotations

import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy import case, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from smithguard.identifiers import REASON_CODE_LONG, canonical_json_bytes, sha256_id

from .models import JobRecord

_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]+$")
_ERROR_PATTERN = REASON_CODE_LONG
_CLASSIFICATIONS = {"public", "restricted_source", "internal_control"}
EXPIRED_LEASE_RECLAIM_LIMIT = 100


class IdempotencyConflict(ValueError):
    """An idempotency key was reused for different work."""


class LeaseLost(RuntimeError):
    """A worker no longer owns a live lease."""


@dataclass(frozen=True, slots=True)
class LeasedJob:
    job_id: str
    queue: str
    job_type: str
    payload: dict[str, Any]
    payload_classification: str
    attempts: int
    max_attempts: int
    lease_token: str
    lease_expires_at: datetime


def _now() -> datetime:
    return datetime.now(UTC)


def _hash_bytes(value: bytes) -> str:
    return sha256_id(value)


def _canonical_payload(payload: dict[str, Any]) -> bytes:
    return canonical_json_bytes(payload)


def _validate_name(value: str, *, label: str, maximum: int) -> None:
    if len(value) > maximum or not _NAME_PATTERN.fullmatch(value):
        raise ValueError(f"{label} must be a bounded lowercase identifier")


def enqueue(
    session: Session,
    *,
    queue: str,
    job_type: str,
    idempotency_key: str,
    payload: dict[str, Any],
    payload_classification: str = "internal_control",
    max_attempts: int = 5,
    available_at: datetime | None = None,
    now: datetime | None = None,
) -> tuple[JobRecord, bool]:
    """Create work once or return the identical existing job."""
    _validate_name(queue, label="queue", maximum=80)
    _validate_name(job_type, label="job_type", maximum=120)
    if not (1 <= len(idempotency_key) <= 512):
        raise ValueError("idempotency_key must contain 1 to 512 characters")
    if payload_classification not in _CLASSIFICATIONS:
        raise ValueError("job payload classification is not allowed")
    if not 1 <= max_attempts <= 100:
        raise ValueError("max_attempts must be between 1 and 100")
    if not isinstance(payload, dict):
        raise TypeError("job payload must be an object")
    enqueued_at = now or _now()
    if enqueued_at.tzinfo is None or enqueued_at.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    when = available_at or enqueued_at
    if when.tzinfo is None or when.utcoffset() is None:
        raise ValueError("available_at must be timezone-aware")

    key_hash = _hash_bytes(idempotency_key.encode())
    payload_hash = _hash_bytes(_canonical_payload(payload))
    job_id = str(uuid4())
    statement = (
        insert(JobRecord)
        .values(
            job_id=job_id,
            queue=queue,
            job_type=job_type,
            idempotency_key_hash=key_hash,
            payload_hash=payload_hash,
            payload_classification=payload_classification,
            payload=payload,
            state="pending",
            attempts=0,
            max_attempts=max_attempts,
            available_at=when,
            created_at=enqueued_at,
            updated_at=enqueued_at,
        )
        .on_conflict_do_nothing(index_elements=["queue", "idempotency_key_hash"])
        .returning(JobRecord.job_id)
    )
    created_id = session.scalar(statement)
    if created_id is not None:
        return session.get_one(JobRecord, created_id), True

    existing = session.scalar(
        select(JobRecord)
        .where(
            JobRecord.queue == queue,
            JobRecord.idempotency_key_hash == key_hash,
        )
        .with_for_update()
    )
    if existing is None:
        raise RuntimeError("idempotent job disappeared during enqueue")
    if (
        existing.job_type != job_type
        or existing.payload_hash != payload_hash
        or existing.payload_classification != payload_classification
        or existing.max_attempts != max_attempts
    ):
        raise IdempotencyConflict("idempotency key already belongs to different work")
    return existing, False


def _expire_leases(session: Session, *, queue: str, now: datetime) -> None:
    expired_ids = tuple(
        session.scalars(
            select(JobRecord.job_id)
            .where(
                JobRecord.queue == queue,
                JobRecord.state == "running",
                JobRecord.lease_expires_at <= now,
            )
            .order_by(JobRecord.lease_expires_at, JobRecord.job_id)
            .with_for_update(skip_locked=True)
            .limit(EXPIRED_LEASE_RECLAIM_LIMIT)
        )
    )
    if not expired_ids:
        return
    terminal = JobRecord.attempts >= JobRecord.max_attempts
    session.execute(
        update(JobRecord)
        .where(
            JobRecord.job_id.in_(expired_ids),
        )
        .values(
            state=case((terminal, "dead_letter"), else_="retry_wait"),
            available_at=now,
            lease_owner=None,
            lease_token_hash=None,
            lease_expires_at=None,
            last_error_code="lease_expired",
            completed_at=case((terminal, now), else_=None),
            updated_at=now,
        )
    )


def lease_next(
    session: Session,
    *,
    queue: str,
    worker_id: str,
    lease_for: timedelta,
    now: datetime | None = None,
) -> LeasedJob | None:
    """Atomically lease one available job without blocking another worker."""
    _validate_name(queue, label="queue", maximum=80)
    if not 3 <= len(worker_id) <= 160:
        raise ValueError("worker_id must contain 3 to 160 characters")
    if lease_for <= timedelta(0) or lease_for > timedelta(hours=1):
        raise ValueError("lease duration must be greater than zero and at most one hour")
    current = now or _now()
    _expire_leases(session, queue=queue, now=current)

    record = session.scalar(
        select(JobRecord)
        .where(
            JobRecord.queue == queue,
            JobRecord.state.in_(("pending", "retry_wait")),
            JobRecord.available_at <= current,
            JobRecord.attempts < JobRecord.max_attempts,
        )
        .order_by(JobRecord.available_at, JobRecord.created_at, JobRecord.job_id)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if record is None:
        return None

    token = secrets.token_urlsafe(32)
    expires_at = current + lease_for
    record.state = "running"
    record.attempts += 1
    record.lease_owner = worker_id
    record.lease_token_hash = _hash_bytes(token.encode())
    record.lease_expires_at = expires_at
    record.updated_at = current
    session.flush()
    return LeasedJob(
        job_id=record.job_id,
        queue=record.queue,
        job_type=record.job_type,
        payload=dict(record.payload),
        payload_classification=record.payload_classification,
        attempts=record.attempts,
        max_attempts=record.max_attempts,
        lease_token=token,
        lease_expires_at=expires_at,
    )


def _owned_record(
    session: Session,
    *,
    job_id: str,
    lease_token: str,
    now: datetime,
) -> JobRecord:
    record = session.scalar(select(JobRecord).where(JobRecord.job_id == job_id).with_for_update())
    supplied_hash = _hash_bytes(lease_token.encode())
    if (
        record is None
        or record.state != "running"
        or record.lease_token_hash is None
        or not hmac.compare_digest(record.lease_token_hash, supplied_hash)
        or record.lease_expires_at is None
        or record.lease_expires_at <= now
    ):
        raise LeaseLost("job lease is absent, expired, or owned by another worker")
    return record


def complete(
    session: Session,
    *,
    job_id: str,
    lease_token: str,
    now: datetime | None = None,
) -> None:
    current = now or _now()
    record = _owned_record(
        session,
        job_id=job_id,
        lease_token=lease_token,
        now=current,
    )
    record.state = "succeeded"
    record.lease_owner = None
    record.lease_token_hash = None
    record.lease_expires_at = None
    record.last_error_code = None
    record.completed_at = current
    record.updated_at = current
    session.flush()


def fail(
    session: Session,
    *,
    job_id: str,
    lease_token: str,
    error_code: str,
    retry_after: timedelta,
    now: datetime | None = None,
) -> str:
    """Fail owned work and return its retry or dead-letter state."""
    if not _ERROR_PATTERN.fullmatch(error_code):
        raise ValueError("error_code must be a bounded machine-readable identifier")
    if retry_after < timedelta(0) or retry_after > timedelta(days=7):
        raise ValueError("retry delay must be between zero and seven days")
    current = now or _now()
    record = _owned_record(
        session,
        job_id=job_id,
        lease_token=lease_token,
        now=current,
    )
    terminal = record.attempts >= record.max_attempts
    record.state = "dead_letter" if terminal else "retry_wait"
    record.available_at = current + retry_after
    record.lease_owner = None
    record.lease_token_hash = None
    record.lease_expires_at = None
    record.last_error_code = error_code
    record.completed_at = current if terminal else None
    record.updated_at = current
    session.flush()
    return record.state


def dead_letter(
    session: Session,
    *,
    job_id: str,
    lease_token: str,
    error_code: str,
    now: datetime | None = None,
) -> None:
    """Permanently fail owned work without waiting for retry exhaustion."""
    if not _ERROR_PATTERN.fullmatch(error_code):
        raise ValueError("error_code must be a bounded machine-readable identifier")
    current = now or _now()
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    record = _owned_record(
        session,
        job_id=job_id,
        lease_token=lease_token,
        now=current,
    )
    record.state = "dead_letter"
    record.lease_owner = None
    record.lease_token_hash = None
    record.lease_expires_at = None
    record.last_error_code = error_code
    record.completed_at = current
    record.updated_at = current
    session.flush()


def acknowledge_dead_letter(
    session: Session,
    *,
    job_id: str,
    reason: str,
    now: datetime | None = None,
) -> JobRecord:
    """Acknowledge one warning-lane dead letter without deleting its history."""
    if not _ERROR_PATTERN.fullmatch(reason):
        raise ValueError("reason must be a bounded machine-readable identifier")
    current = now or _now()
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    current = current.astimezone(UTC)
    record = session.scalar(select(JobRecord).where(JobRecord.job_id == job_id).with_for_update())
    if record is None or record.state != "dead_letter":
        raise ValueError("job is not an unacknowledged dead letter")
    if record.queue not in {"ai-warning-discovery", "ai-warning-qualification"}:
        raise ValueError("only a warning-lane dead letter may be acknowledged")
    if record.completed_at is None or current < record.completed_at.astimezone(UTC):
        raise ValueError("acknowledgment cannot precede the dead letter")
    run_id = record.payload.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        run_id = record.job_id
    from smithguard.warning_lane_receipts import append_warning_lane_receipt

    append_warning_lane_receipt(
        session,
        receipt_type="dead_letter_acknowledged",
        reason_code=reason,
        run_id=run_id,
        job_id=record.job_id,
        occurred_at=current,
        public_metadata={
            "queue": record.queue,
            "dead_letter_error_code": record.last_error_code,
        },
    )
    record.state = "acknowledged"
    record.updated_at = current
    session.flush()
    return record
