"""Durable PostgreSQL job behavior checks."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from smithguard.db.jobs import (
    IdempotencyConflict,
    LeaseLost,
    acknowledge_dead_letter,
    complete,
    dead_letter,
    enqueue,
    fail,
    lease_next,
)
from smithguard.db.models import JobRecord

NOW = datetime(2026, 8, 5, tzinfo=UTC)


def test_enqueue_is_idempotent_without_storing_the_plaintext_key(database) -> None:
    scheduled_for = NOW + timedelta(days=1)
    with Session(database.engine) as session, session.begin():
        first, created = enqueue(
            session,
            queue="intake",
            job_type="synthetic_check",
            idempotency_key="private-once-key",
            payload={"artifact": "pkg:npm/example@1.0.0"},
            available_at=scheduled_for,
            now=NOW,
        )
        assert created
        second, created_again = enqueue(
            session,
            queue="intake",
            job_type="synthetic_check",
            idempotency_key="private-once-key",
            payload={"artifact": "pkg:npm/example@1.0.0"},
            available_at=scheduled_for,
            now=NOW,
        )
        assert not created_again
        assert second.job_id == first.job_id
        assert second.idempotency_key_hash != "private-once-key"
        assert second.idempotency_key_hash.startswith("sha256:")
        assert first.created_at == NOW
        assert first.available_at == scheduled_for

    with (
        Session(database.engine) as session,
        session.begin(),
        pytest.raises(IdempotencyConflict),
    ):
        enqueue(
            session,
            queue="intake",
            job_type="synthetic_check",
            idempotency_key="private-once-key",
            payload={"artifact": "pkg:npm/different@2.0.0"},
            available_at=scheduled_for,
            now=NOW,
        )


def test_lease_token_is_opaque_and_required_for_completion(database) -> None:
    with Session(database.engine) as session, session.begin():
        record, _created = enqueue(
            session,
            queue="intake",
            job_type="synthetic_check",
            idempotency_key="complete-once",
            payload={"case": 1},
            available_at=NOW,
            now=NOW,
        )
        job_id = record.job_id

    with Session(database.engine) as session, session.begin():
        leased = lease_next(
            session,
            queue="intake",
            worker_id="worker-one",
            lease_for=timedelta(minutes=5),
            now=NOW,
        )
        assert leased is not None
        assert leased.job_id == job_id
        stored = session.get_one(JobRecord, leased.job_id)
        assert stored.lease_token_hash != leased.lease_token
        with pytest.raises(LeaseLost):
            complete(
                session,
                job_id=leased.job_id,
                lease_token="wrong-token",
                now=NOW,
            )
        complete(
            session,
            job_id=leased.job_id,
            lease_token=leased.lease_token,
            now=NOW,
        )

    with Session(database.engine) as session:
        stored = session.get_one(JobRecord, job_id)
        assert stored.state == "succeeded"
        assert stored.completed_at == NOW
        assert stored.lease_token_hash is None


@pytest.mark.audit_ids("WL-19")
def test_retry_then_dead_letter_and_expired_lease(database) -> None:
    with Session(database.engine) as session, session.begin():
        retrying, _ = enqueue(
            session,
            queue="intake",
            job_type="synthetic_check",
            idempotency_key="retrying",
            payload={"case": 2},
            max_attempts=2,
            available_at=NOW,
            now=NOW,
        )
        expiring, _ = enqueue(
            session,
            queue="expiry",
            job_type="synthetic_check",
            idempotency_key="expiring",
            payload={"case": 3},
            max_attempts=1,
            available_at=NOW,
            now=NOW,
        )
        retrying_id = retrying.job_id
        expiring_id = expiring.job_id

    with Session(database.engine) as session, session.begin():
        first = lease_next(
            session,
            queue="intake",
            worker_id="worker-one",
            lease_for=timedelta(minutes=1),
            now=NOW,
        )
        assert first is not None
        assert (
            fail(
                session,
                job_id=first.job_id,
                lease_token=first.lease_token,
                error_code="temporary_failure",
                retry_after=timedelta(seconds=10),
                now=NOW,
            )
            == "retry_wait"
        )

    later = NOW + timedelta(seconds=10)
    with Session(database.engine) as session, session.begin():
        second = lease_next(
            session,
            queue="intake",
            worker_id="worker-two",
            lease_for=timedelta(minutes=1),
            now=later,
        )
        assert second is not None
        assert second.attempts == 2
        assert (
            fail(
                session,
                job_id=second.job_id,
                lease_token=second.lease_token,
                error_code="still_failing",
                retry_after=timedelta(0),
                now=later,
            )
            == "dead_letter"
        )

    with Session(database.engine) as session, session.begin():
        leased = lease_next(
            session,
            queue="expiry",
            worker_id="worker-one",
            lease_for=timedelta(seconds=1),
            now=NOW,
        )
        assert leased is not None
    with Session(database.engine) as session, session.begin():
        assert (
            lease_next(
                session,
                queue="expiry",
                worker_id="worker-two",
                lease_for=timedelta(seconds=1),
                now=NOW + timedelta(seconds=2),
            )
            is None
        )

    with Session(database.engine) as session:
        assert session.get_one(JobRecord, retrying_id).state == "dead_letter"
        expired = session.get_one(JobRecord, expiring_id)
        assert expired.state == "dead_letter"
        assert expired.last_error_code == "lease_expired"


def test_skip_locked_allows_two_workers_to_take_different_jobs(database) -> None:
    with Session(database.engine) as session, session.begin():
        for suffix in ("one", "two"):
            enqueue(
                session,
                queue="parallel",
                job_type="synthetic_check",
                idempotency_key=f"parallel-{suffix}",
                payload={"case": suffix},
                available_at=NOW,
                now=NOW,
            )

    with Session(database.engine) as first_session:
        first_transaction = first_session.begin()
        first = lease_next(
            first_session,
            queue="parallel",
            worker_id="worker-one",
            lease_for=timedelta(minutes=1),
            now=NOW,
        )
        assert first is not None

        with Session(database.engine) as second_session, second_session.begin():
            second_session.execute(text("SET LOCAL lock_timeout = '500ms'"))
            second = lease_next(
                second_session,
                queue="parallel",
                worker_id="worker-two",
                lease_for=timedelta(minutes=1),
                now=NOW,
            )
            assert second is not None
            assert second.job_id != first.job_id
        first_transaction.commit()

    with Session(database.engine) as session:
        assert session.scalars(
            select(JobRecord.state).where(JobRecord.queue == "parallel")
        ).all() == ["running", "running"]


def test_locked_expired_lease_does_not_block_an_unrelated_pending_job(database) -> None:
    with Session(database.engine) as session, session.begin():
        expired, _ = enqueue(
            session,
            queue="independent-reclaim",
            job_type="synthetic_check",
            idempotency_key="expired-first",
            payload={"case": "expired"},
            available_at=NOW,
            now=NOW,
        )
        pending, _ = enqueue(
            session,
            queue="independent-reclaim",
            job_type="synthetic_check",
            idempotency_key="pending-second",
            payload={"case": "pending"},
            available_at=NOW,
            now=NOW + timedelta(microseconds=1),
        )
        expired_id = expired.job_id
        pending_id = pending.job_id

    with Session(database.engine) as session, session.begin():
        leased = lease_next(
            session,
            queue="independent-reclaim",
            worker_id="first-worker",
            lease_for=timedelta(seconds=1),
            now=NOW,
        )
        assert leased is not None
        assert leased.job_id == expired_id

    with Session(database.engine) as lock_session:
        lock_transaction = lock_session.begin()
        lock_session.scalar(
            select(JobRecord).where(JobRecord.job_id == expired_id).with_for_update()
        )
        with Session(database.engine) as worker_session, worker_session.begin():
            worker_session.execute(text("SET LOCAL lock_timeout = '500ms'"))
            available = lease_next(
                worker_session,
                queue="independent-reclaim",
                worker_id="second-worker",
                lease_for=timedelta(minutes=1),
                now=NOW + timedelta(seconds=2),
            )
            assert available is not None
            assert available.job_id == pending_id
        lock_transaction.commit()


def test_dead_letter_helpers_reject_unsafe_times_before_database_lookup(database) -> None:
    naive = datetime(2026, 8, 5)
    with (
        Session(database.engine) as session,
        session.begin(),
        pytest.raises(ValueError, match="now must be timezone-aware"),
    ):
        dead_letter(
            session,
            job_id="missing-job",
            lease_token="missing-token",
            error_code="synthetic_failure",
            now=naive,
        )


@pytest.mark.audit_ids("WL-09", "WL-19")
def test_warning_dead_letter_acknowledgment_preserves_cause_and_writes_receipt(database) -> None:
    run_id = "gbsec:ai-warning-run:acknowledgment"
    with Session(database.engine) as session, session.begin():
        record, _created = enqueue(
            session,
            queue="ai-warning-discovery",
            job_type="scheduled_public_discovery",
            idempotency_key="warning-dead-letter-acknowledgment",
            payload={"run_id": run_id},
            max_attempts=1,
            available_at=NOW,
            now=NOW,
        )
        job_id = record.job_id
    with Session(database.engine) as session, session.begin():
        leased = lease_next(
            session,
            queue="ai-warning-discovery",
            worker_id="acknowledgment-worker",
            lease_for=timedelta(minutes=1),
            now=NOW,
        )
        assert leased is not None
        dead_letter(
            session,
            job_id=job_id,
            lease_token=leased.lease_token,
            error_code="provider_failure",
            now=NOW + timedelta(seconds=1),
        )
    with (
        Session(database.engine) as session,
        session.begin(),
        pytest.raises(ValueError, match="cannot precede"),
    ):
        acknowledge_dead_letter(
            session,
            job_id=job_id,
            reason="operator_reviewed",
            now=NOW,
        )
    with Session(database.engine) as session, session.begin():
        acknowledged = acknowledge_dead_letter(
            session,
            job_id=job_id,
            reason="operator_reviewed",
            now=NOW + timedelta(minutes=1),
        )
        assert acknowledged.state == "acknowledged"
        assert acknowledged.completed_at == NOW + timedelta(seconds=1)
        assert acknowledged.last_error_code == "provider_failure"
    with Session(database.engine) as session:
        receipt = session.scalar(
            select(JobRecord).where(
                JobRecord.queue == "ai-warning-receipts",
                JobRecord.payload["receipt_type"].as_string() == "dead_letter_acknowledged",
            )
        )
        assert receipt is not None
        assert receipt.payload["reason_code"] == "operator_reviewed"
        assert receipt.payload["run_id"] == run_id
        assert receipt.payload["public_metadata"]["dead_letter_error_code"] == ("provider_failure")


@pytest.mark.audit_ids("WL-17")
def test_warning_receipt_indexes_support_bounded_lookup_plans(database) -> None:
    with Session(database.engine) as session, session.begin():
        index_names = set(
            session.scalars(
                text(
                    "SELECT indexname FROM pg_indexes "
                    "WHERE schemaname = 'smithguard' AND tablename = 'jobs' "
                    "AND indexname IN "
                    "('ix_jobs_receipt_run_completed', 'ix_jobs_receipt_type_completed')"
                )
            )
        )
        assert index_names == {
            "ix_jobs_receipt_run_completed",
            "ix_jobs_receipt_type_completed",
        }
        session.execute(text("SET LOCAL enable_seqscan = off"))
        type_plan = "\n".join(
            str(row[0])
            for row in session.execute(
                text(
                    "EXPLAIN SELECT job_id FROM smithguard.jobs "
                    "WHERE (payload ->> 'receipt_type') = 'provider_cost_observed' "
                    "AND completed_at >= TIMESTAMPTZ '2026-08-04T00:00:00Z'"
                )
            )
        )
        run_plan = "\n".join(
            str(row[0])
            for row in session.execute(
                text(
                    "EXPLAIN SELECT job_id FROM smithguard.jobs "
                    "WHERE (payload ->> 'run_id') = 'gbsec:ai-warning-run:synthetic' "
                    "AND completed_at >= TIMESTAMPTZ '2026-08-04T00:00:00Z'"
                )
            )
        )
    assert "ix_jobs_receipt_type_completed" in type_plan
    assert "ix_jobs_receipt_run_completed" in run_plan
