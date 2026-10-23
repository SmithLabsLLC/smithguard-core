"""Durable containment prevents attempts; real file/database locks order pauses."""

from __future__ import annotations

import fcntl
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from threading import Event

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from smithguard import warning_dispatch as dispatch
from smithguard.db.jobs import enqueue, lease_next
from smithguard.db.models import JobRecord
from smithguard.scheduled_discovery import enqueue_due_discovery, work_one
from smithguard.signals import get_preliminary_warning, recheck_warning
from smithguard.warning_lane_budget import (
    DISCOVERY_QUEUE,
    QUALIFICATION_QUEUE,
    WORKER_LOCK,
    calculate_dispatch_budget,
    collect_dispatch_budget,
)
from smithguard.warning_lane_receipts import RECEIPT_QUEUE, append_warning_lane_receipt

from .test_scheduled_discovery import NOW, SyntheticProvider, _active_policy, _discovery_result
from .test_signals import NOW as RECHECK_NOW
from .test_signals import _create


def _write_control(path, *, enabled=False, recheck=False, operation="1", release="a"):
    replacement = path.with_suffix(".pending")
    replacement.write_bytes(
        dispatch.control_bytes(
            operation_id="20261002-" + operation * 32,
            artifact_commit=release * 40,
            discovery=enabled,
            recheck=recheck,
        )
    )
    replacement.chmod(0o644)
    replacement.replace(path)


def _seed_failures(session, *, now=NOW):
    for index in range(2):
        at = now - timedelta(minutes=10 - index)
        for kind in ("provider_request_started", "provider_failure"):
            append_warning_lane_receipt(
                session,
                receipt_type=kind,
                reason_code="synthetic_failure",
                run_id=f"synthetic-failed-run-{index}",
                occurred_at=at,
                public_metadata={"error_class": "TimeoutError"},
            )


@pytest.mark.parametrize("flag", [None, "0", "true", "", "2"])
def test_environment_gate_requires_explicit_one(enabled_warning_dispatch, monkeypatch, flag):
    if flag is None:
        monkeypatch.delenv(dispatch.DISPATCH_FLAG)
    else:
        monkeypatch.setenv(dispatch.DISPATCH_FLAG, flag)
    with dispatch.dispatch_guard("discovery") as control:
        assert control is None


@pytest.mark.parametrize("stage", ["discovery", "recheck"])
def test_stale_enabled_environment_cannot_override_durable_pause(enabled_warning_dispatch, stage):
    _write_control(enabled_warning_dispatch)
    assert os.environ[dispatch.DISPATCH_FLAG] == "1"
    with dispatch.dispatch_guard(stage) as control:
        assert control is None


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "corrupt",
        "duplicate_json_key",
        "symlink",
        "hardlink",
        "mode",
        "owner",
        "directory_mode",
        "directory_symlink",
        "fifo",
        "oversized",
        "stale_release",
    ],
)
def test_invalid_authority_fails_closed(enabled_warning_dispatch, monkeypatch, fault):
    path = enabled_warning_dispatch
    if fault == "missing":
        path.unlink()
    elif fault == "corrupt":
        path.write_text("not-json")
    elif fault == "duplicate_json_key":
        path.write_text(
            path.read_text().replace(
                '"schema_version":', '"schema_version":"1.0.0", "schema_version":'
            )
        )
    elif fault in {"symlink", "fifo"}:
        data = path.read_bytes()
        path.unlink()
        if fault == "symlink":
            target = path.with_suffix(".target")
            target.write_bytes(data)
            path.symlink_to(target)
        else:
            os.mkfifo(path)
    elif fault == "hardlink":
        os.link(path, path.with_suffix(".link"))
    elif fault == "mode":
        path.chmod(0o666)
    elif fault == "owner":
        monkeypatch.setattr(dispatch, "CONTROL_UID", os.getuid() + 1)
    elif fault == "directory_mode":
        path.parent.chmod(0o777)
    elif fault == "directory_symlink":
        alias = path.parent.with_name(path.parent.name + "-alias")
        alias.symlink_to(path.parent, target_is_directory=True)
        monkeypatch.setattr(dispatch, "CONTROL_DIRECTORY", alias)
        monkeypatch.setattr(dispatch, "CONTROL_PATH", alias / path.name)
    elif fault == "oversized":
        path.write_bytes(b" " * 4097)
    else:
        monkeypatch.setattr(dispatch, "_running_release", lambda: "b" * 40)
    with dispatch.dispatch_guard("discovery") as control:
        assert control is None
    with pytest.raises(dispatch.DispatchControlError):
        dispatch.read_runtime_control()


@pytest.mark.parametrize(
    "document",
    [
        None,
        {},
        {"schema_version": "1.0.0"},
        {
            "schema_version": "1.0.0",
            "operation_id": "20261002-" + "1" * 32,
            "artifact_commit": "a" * 40,
            "discovery_enabled": 1,
            "recheck_enabled": False,
        },
        {
            "schema_version": "1.0.0",
            "operation_id": "20261002-" + "1" * 32,
            "artifact_commit": "a" * 40,
            "discovery_enabled": False,
            "recheck_enabled": True,
        },
    ],
)
def test_invalid_control_schema_never_enables_dispatch(document):
    with pytest.raises(dispatch.DispatchControlError):
        dispatch.parse_control(document)


def test_release_validation_requires_current_symlink_and_running_code(tmp_path, monkeypatch):
    release = tmp_path / ("a" * 40)
    release.mkdir()
    module = release / "warning_dispatch.py"
    module.write_text("synthetic module")
    current = tmp_path / "current"
    current.symlink_to(release, target_is_directory=True)
    monkeypatch.setattr(dispatch, "CURRENT_RELEASE", current)
    monkeypatch.setattr(dispatch, "__file__", str(module))
    assert dispatch._running_release() == "a" * 40
    monkeypatch.setattr(dispatch, "__file__", str(tmp_path / "outside.py"))
    with pytest.raises(dispatch.DispatchControlError):
        dispatch._running_release()
    current.unlink()
    with pytest.raises(dispatch.DispatchControlError):
        dispatch._running_release()
    current.mkdir()
    with pytest.raises(dispatch.DispatchControlError):
        dispatch._running_release()


@pytest.mark.parametrize("queue", [DISCOVERY_QUEUE, QUALIFICATION_QUEUE])
@pytest.mark.parametrize(("state", "attempts"), [("pending", 0), ("retry_wait", 1), ("running", 1)])
def test_pause_blocks_enqueue_and_leasing_without_consuming_attempts(
    database,
    enabled_warning_dispatch,
    queue,
    state,
    attempts,
):
    factory = sessionmaker(database.engine)
    with factory() as session, session.begin():
        job, _created = enqueue(
            session,
            queue=queue,
            job_type="synthetic_pending",
            idempotency_key="pending-before-pause",
            payload={},
            max_attempts=2,
            now=NOW,
        )
        if state == "running":
            assert (
                lease_next(
                    session,
                    queue=queue,
                    worker_id="synthetic-lease",
                    lease_for=timedelta(seconds=1),
                    now=NOW,
                )
                is not None
            )
            job.lease_expires_at = NOW - timedelta(seconds=1)
        else:
            job.state = state
            job.attempts = attempts
        job_id = job.job_id
    _write_control(enabled_warning_dispatch)
    with factory() as session, session.begin():
        assert enqueue_due_discovery(session, policy=_active_policy(), now=NOW) == ()
    provider = SyntheticProvider(_discovery_result())
    result = work_one(
        factory, policy=_active_policy(), provider=provider, worker_id="paused-worker", now=NOW
    )
    assert result.outcome == "dispatch_contained"
    assert provider.discovery_calls == provider.qualification_calls == 0
    with factory() as session:
        job = session.get_one(JobRecord, job_id)
        assert (job.state, job.attempts) == (state, attempts)
        assert session.scalar(select(func.count()).select_from(JobRecord)) == 1


@pytest.mark.parametrize("queue", [DISCOVERY_QUEUE, QUALIFICATION_QUEUE])
@pytest.mark.parametrize("trip", ["failures", "dead_letters", "technical"])
def test_budget_trip_latches_restart_identity_and_preserves_attempts(
    database,
    enabled_warning_dispatch,
    queue,
    trip,
):
    factory = sessionmaker(database.engine)
    with factory() as session, session.begin():
        pending, _created = enqueue(
            session,
            queue=queue,
            job_type="synthetic_pending",
            idempotency_key="pending-before-trip",
            payload={},
            max_attempts=2,
            now=NOW,
        )
        job_id = pending.job_id
        if trip == "failures":
            _seed_failures(session)
        elif trip == "dead_letters":
            for index in range(2):
                dead, _created = enqueue(
                    session,
                    queue=DISCOVERY_QUEUE,
                    job_type="synthetic_dead_letter",
                    idempotency_key=f"dead-{index}",
                    payload={},
                    max_attempts=2,
                    now=NOW - timedelta(minutes=2),
                )
                dead.state = "dead_letter"
                dead.completed_at = NOW - timedelta(minutes=1)
        else:
            append_warning_lane_receipt(
                session,
                receipt_type="policy_denial",
                reason_code="provider_token_usage_exceeded",
                run_id="synthetic-technical",
                occurred_at=NOW - timedelta(minutes=1),
                public_metadata={},
            )
    provider = SyntheticProvider(_discovery_result())
    for now in (NOW, NOW + timedelta(seconds=1), NOW + timedelta(hours=25)):
        result = work_one(
            factory, policy=_active_policy(), provider=provider, worker_id="budget-worker", now=now
        )
        assert result.outcome == "budget_contained"
    with factory() as session:
        job = session.get_one(JobRecord, job_id)
        assert (job.state, job.attempts) == ("pending", 0)
        pauses = list(
            session.scalars(
                select(JobRecord).where(
                    JobRecord.queue == RECEIPT_QUEUE,
                    JobRecord.payload["receipt_type"].as_string() == dispatch.PAUSE_RECEIPT,
                )
            )
        )
        assert len(pauses) == 1
        assert collect_dispatch_budget(session, now=NOW + timedelta(hours=25)).allowed
        assert dispatch.generation_paused(session, control=dispatch.read_control())
        next_generation = replace(dispatch.read_control(), operation_id="20261002-" + "2" * 32)
        assert dispatch.dispatch_budget_clear(
            session, control=next_generation, now=NOW + timedelta(hours=25), latch=False
        )
    assert provider.discovery_calls == provider.qualification_calls == 0


def test_budget_blocks_enqueue_with_one_control_receipt(database, enabled_warning_dispatch):
    with Session(database.engine) as session, session.begin():
        _seed_failures(session)
    for _ in range(2):
        with Session(database.engine) as session, session.begin():
            assert enqueue_due_discovery(session, policy=_active_policy(), now=NOW) == ()
    with Session(database.engine) as session:
        assert (
            session.scalar(
                select(func.count())
                .select_from(JobRecord)
                .where(
                    JobRecord.queue == DISCOVERY_QUEUE,
                )
            )
            == 0
        )
        assert (
            session.scalar(
                select(func.count())
                .select_from(JobRecord)
                .where(
                    JobRecord.payload["receipt_type"].as_string() == dispatch.PAUSE_RECEIPT,
                )
            )
            == 1
        )


@pytest.mark.parametrize("reason", ["pause", "budget", "worker_busy"])
def test_legacy_recheck_cannot_consume_sequence_under_containment(
    database,
    enabled_warning_dispatch,
    reason,
):
    warning_id = _create(database, "contained-recheck")
    factory = sessionmaker(database.engine)
    if reason == "pause":
        _write_control(enabled_warning_dispatch)
    elif reason == "budget":
        with factory() as session, session.begin():
            _seed_failures(session, now=RECHECK_NOW)
    with factory() as blocker:
        if reason == "worker_busy":
            assert (
                blocker.scalar(
                    select(
                        func.pg_try_advisory_lock(
                            func.hashtextextended(WORKER_LOCK, 0),
                        )
                    )
                )
                is True
            )
        try:
            result = recheck_warning(
                factory,
                warning_id=warning_id,
                policy=_active_policy(),
                provider=lambda *_: pytest.fail("provider dispatched"),
                now=RECHECK_NOW + timedelta(hours=1),
            )
        finally:
            if reason == "worker_busy":
                blocker.scalar(
                    select(func.pg_advisory_unlock(func.hashtextextended(WORKER_LOCK, 0)))
                )
    assert result.outcome == "dispatch_contained"
    assert result.revision == 1 and result.recheck_count == 0
    with factory() as session:
        current = get_preliminary_warning(session, warning_id)
        assert current.revision == 1 and current.recheck_count == 0
        assert (
            session.scalar(
                select(func.count())
                .select_from(JobRecord)
                .where(
                    JobRecord.payload["receipt_type"].as_string() == "provider_request_started",
                    JobRecord.payload["run_id"].as_string() == warning_id,
                )
            )
            == 0
        )


def test_controller_pause_waits_for_whole_attempt_then_blocks_qualification(
    database,
    enabled_warning_dispatch,
):
    factory = sessionmaker(database.engine)
    with factory() as session, session.begin():
        enqueue_due_discovery(session, policy=_active_policy(), now=NOW)
    entered, release, controller_waiting = Event(), Event(), Event()

    class BlockingProvider(SyntheticProvider):
        def discover(self, payload):
            entered.set()
            assert release.wait(timeout=5)
            return super().discover(payload)

    def pause():
        descriptor = os.open(enabled_warning_dispatch.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            controller_waiting.set()
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            with factory() as session:
                assert (
                    session.scalar(
                        select(func.count())
                        .select_from(JobRecord)
                        .where(
                            JobRecord.payload["receipt_type"].as_string()
                            == "provider_cost_observed",
                        )
                    )
                    == 1
                )
            _write_control(enabled_warning_dispatch)
        finally:
            os.close(descriptor)

    provider = BlockingProvider(_discovery_result())
    with ThreadPoolExecutor(max_workers=2) as executor:
        worker = executor.submit(
            work_one,
            factory,
            policy=_active_policy(),
            provider=provider,
            worker_id="pause-race-worker",
            now=NOW + timedelta(minutes=1),
            allow_reserved_hosts=True,
        )
        try:
            assert entered.wait(timeout=5)
            controller = executor.submit(pause)
            assert controller_waiting.wait(timeout=5)
        finally:
            release.set()
        assert worker.result(timeout=5).outcome == "succeeded"
        controller.result(timeout=5)
    assert (
        work_one(
            factory,
            policy=_active_policy(),
            provider=provider,
            worker_id="stale-queued-worker",
            now=NOW + timedelta(minutes=2),
        ).outcome
        == "dispatch_contained"
    )
    with factory() as session:
        qualification = session.scalar(
            select(JobRecord).where(JobRecord.queue == QUALIFICATION_QUEUE)
        )
        assert (qualification.state, qualification.attempts) == ("pending", 0)
    assert provider.discovery_calls == 1 and provider.qualification_calls == 0


def test_rolling_failure_threshold_and_technical_deduplication():
    receipts = [
        {
            "receipt_type": "provider_request_started",
            "run_id": str(index),
            "occurred_at": f"2026-10-02T00:{index:02d}:00Z",
        }
        for index in range(40)
    ]
    for index in (3, 20):
        receipts.append(
            {
                "receipt_type": "provider_failure",
                "run_id": str(index),
                "occurred_at": f"2026-10-02T00:{index:02d}:01Z",
            }
        )
    assert calculate_dispatch_budget(receipts, dead_letters=2).allowed
    assert not calculate_dispatch_budget(receipts, dead_letters=3).allowed
    for kind in ("provider_failure", "provider_cost_observed", "policy_denial"):
        receipts.append(
            {
                "receipt_type": kind,
                "run_id": "technical",
                "reason_code": "provider_token_usage_exceeded",
            }
        )
    budget = calculate_dispatch_budget(receipts, dead_letters=0)
    assert budget.technical_envelope_breaches_24h == 1
    assert not budget.allowed
