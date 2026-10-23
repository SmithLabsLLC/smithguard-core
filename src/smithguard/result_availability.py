"""Prospective committed-result observations, separate from historical job clocks."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import text

from smithguard.db.models import JobRecord
from smithguard.identifiers import canonical_json_bytes, require_aware_utc, sha256_id
from smithguard.warning_lane_receipts import RECEIPT_QUEUE, append_warning_lane_receipt


def _utc_now() -> datetime:
    return datetime.now(UTC)


def observe_committed_result(
    factory, *, job_id, run_id, receipt_id, receipt_hash, stage, job_clock, provider_finished_at
) -> bool:
    """Best-effort upper bound after a new session reads the committed outcome.

    A crash or observer failure leaves availability unknown; it must never reopen
    an already completed provider job. This is not a public publication timestamp.
    """
    from smithguard.scheduled_discovery import _emit_failure_diagnostic

    try:
        expected = {"discovery": "discovery_completed", "qualification": "lead_decision"}[stage]
        with factory() as session, session.begin():
            session.execute(text("SET LOCAL statement_timeout = '3s'"))
            session.execute(text("SET LOCAL lock_timeout = '1s'"))
            receipt = session.get(JobRecord, receipt_id)
            job = session.get(JobRecord, job_id)
            if receipt is None or job is None:
                raise ValueError("committed result missing")
            payload = receipt.payload
            core = {key: value for key, value in payload.items() if key != "receipt_sha256"}
            if (
                job.state != "succeeded"
                or receipt.state != "succeeded"
                or receipt.queue != RECEIPT_QUEUE
                or payload.get("receipt_type") != expected
                or payload.get("run_id") != run_id
                or payload.get("job_id_sha256") != sha256_id(job_id.encode())
                or payload.get("receipt_sha256") != receipt_hash
                or sha256_id(canonical_json_bytes(core)) != receipt_hash
            ):
                raise ValueError("committed result binding invalid")
            observed = require_aware_utc(_utc_now())
            started = require_aware_utc(job_clock)
            finished = (
                require_aware_utc(provider_finished_at)
                if provider_finished_at is not None
                else None
            )
            if observed < started or (finished is not None and not started <= finished <= observed):
                raise ValueError("result observation clock order invalid")
            append_warning_lane_receipt(
                session,
                receipt_type="result_commit_observed",
                reason_code="committed_result_read_back",
                run_id=run_id,
                job_id=job_id,
                occurred_at=observed,
                public_metadata={
                    "schema_version": "1.0.0",
                    "stage": stage,
                    "completion_receipt_sha256": receipt_hash,
                    "job_clock_at": started.isoformat(timespec="microseconds"),
                    "provider_finished_at": finished.isoformat(timespec="microseconds")
                    if finished is not None
                    else None,
                    "availability_observed_at": observed.isoformat(timespec="microseconds"),
                    "availability_bound": "upper_bound_after_committed_read",
                    "timestamp_resolution": "microseconds",
                    "clock_accuracy": "unknown",
                    "publication_state": "not_observed",
                },
            )
        return True
    except Exception as error:
        _emit_failure_diagnostic(
            stage="result_availability_observation",
            error=error,
            reason_code="result_availability_unknown",
            job_id=job_id,
        )
        return False
