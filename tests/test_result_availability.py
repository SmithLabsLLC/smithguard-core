"""A result becomes available after commit; failures never replay accepted work."""

from copy import deepcopy
from datetime import timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from smithguard import result_availability as availability
from smithguard.db.models import EmergingLeadRecord, JobRecord
from smithguard.identifiers import canonical_json_bytes, sha256_id
from tests.test_emerging_leads import (
    POLICY_ID,
    PUBLICATION_ENV,
    LeadProvider,
    enqueue_search,
    output,
    raw_lead,
    work,
)
from tests.test_grok_build_continuation import _events
from tests.test_grok_build_continuation import adapter_factory as adapter_factory
from tests.test_scheduled_discovery import NOW

pytestmark = pytest.mark.usefixtures("enabled_warning_dispatch")


def _observations(database):
    with Session(database.engine) as session:
        return [
            deepcopy(row.payload)
            for row in session.scalars(select(JobRecord))
            if row.payload.get("receipt_type") == "result_commit_observed"
        ]


def test_distinct_committed_stages_preserve_historical_job_clock(database, monkeypatch):
    clock = [NOW + timedelta(seconds=30, microseconds=123456)]
    monkeypatch.setattr(availability, "_utc_now", lambda: clock[0])
    provider = LeadProvider()
    enqueue_search(database)
    assert work(database, provider).outcome == "succeeded"
    discovery = _observations(database)
    assert len(discovery) == 1
    observed = discovery[0]["public_metadata"]
    assert observed["stage"] == "discovery"
    assert observed["availability_observed_at"] == clock[0].isoformat(timespec="microseconds")
    assert observed["provider_finished_at"] is None
    assert observed["availability_bound"] == "upper_bound_after_committed_read"
    with Session(database.engine) as session:
        old = {
            row.job_id: canonical_json_bytes(row.payload)
            for row in session.scalars(select(JobRecord))
            if row.payload.get("receipt_type")
        }
        lead = session.scalar(select(EmergingLeadRecord))
        assert lead.first_seen_at == NOW and lead.observed_at == NOW
        completion = next(
            row
            for row in session.scalars(select(JobRecord))
            if row.payload.get("receipt_type") == "discovery_completed"
        )
        assert observed["completion_receipt_sha256"] == completion.payload["receipt_sha256"]
    clock[0] += timedelta(seconds=30)
    assert work(database, provider, NOW + timedelta(seconds=31)).outcome == "succeeded"
    observations = _observations(database)
    assert {row["public_metadata"]["stage"] for row in observations} == {
        "discovery",
        "qualification",
    }
    with Session(database.engine) as session:
        for job_id, payload_bytes in old.items():
            assert canonical_json_bytes(session.get(JobRecord, job_id).payload) == payload_bytes
        for row in observations:
            core = {k: v for k, v in row.items() if k != "receipt_sha256"}
            assert sha256_id(canonical_json_bytes(core)) == row["receipt_sha256"]


@pytest.mark.parametrize("failure", ["write", "clock", "read"])
def test_observer_failure_does_not_reopen_committed_job(database, monkeypatch, failure):
    provider = LeadProvider()
    if failure == "clock":
        monkeypatch.setattr(availability, "_utc_now", lambda: NOW - timedelta(seconds=1))
    elif failure == "write":

        def fail(*args, **kwargs):
            raise RuntimeError("private observer fault")

        monkeypatch.setattr(availability, "append_warning_lane_receipt", fail)
    else:
        original = availability.observe_committed_result

        def wrong_binding(factory, **kwargs):
            return original(factory, **{**kwargs, "receipt_hash": "sha256:" + "0" * 64})

        monkeypatch.setattr("smithguard.emerging_pipeline.observe_committed_result", wrong_binding)
    enqueue_search(database)
    assert work(database, provider).outcome == "succeeded"
    assert work(database, provider, NOW + timedelta(seconds=1)).outcome == "succeeded"
    assert work(database, provider, NOW + timedelta(seconds=2)).outcome == "idle"
    assert provider.discovery_calls == provider.qualification_calls == 1
    assert _observations(database) == []


def test_uncommitted_result_is_not_observed(database, monkeypatch):
    from smithguard.db.jobs import enqueue
    from smithguard.warning_lane_receipts import append_warning_lane_receipt

    monkeypatch.setattr(availability, "_utc_now", lambda: NOW + timedelta(seconds=1))
    factory = sessionmaker(database.engine)
    with factory() as session, session.begin():
        job, _ = enqueue(
            session,
            queue="synthetic",
            job_type="synthetic",
            idempotency_key="test",
            payload={},
            payload_classification="internal_control",
            now=NOW,
        )
        job.state = "succeeded"
        job.completed_at = NOW
        receipt = append_warning_lane_receipt(
            session,
            receipt_type="discovery_completed",
            reason_code="bounded_leads_processed",
            run_id="synthetic",
            job_id=job.job_id,
            occurred_at=NOW,
            public_metadata={},
        )
        assert not availability.observe_committed_result(
            factory,
            job_id=job.job_id,
            run_id="synthetic",
            receipt_id=receipt.job_id,
            receipt_hash=receipt.payload["receipt_sha256"],
            stage="discovery",
            job_clock=NOW,
            provider_finished_at=None,
        )
    assert _observations(database) == []


def test_failed_result_commit_cannot_create_availability_receipt(database, monkeypatch):
    from sqlalchemy import event

    from smithguard import scheduled_discovery as lane

    original = lane.append_receipt

    def append(session, **kwargs):
        record = original(session, **kwargs)
        if kwargs["receipt_type"] == "discovery_completed":

            def refuse_commit(_session):
                raise RuntimeError("synthetic result transaction failed")

            event.listen(session, "before_commit", refuse_commit, once=True)
        return record

    monkeypatch.setattr(lane, "append_receipt", append)
    provider = LeadProvider()
    enqueue_search(database)
    assert work(database, provider).outcome == "dead_letter"
    assert provider.discovery_calls == 1
    assert work(database, provider, NOW + timedelta(seconds=1)).outcome == "idle"
    assert _observations(database) == []
    with Session(database.engine) as session:
        assert not list(session.scalars(select(EmergingLeadRecord)))


@pytest.mark.parametrize("finish_seconds", [10, -1, 31])
def test_native_finish_preserves_precision_and_rejects_impossible_order(
    database, monkeypatch, adapter_factory, finish_seconds
):
    from smithguard import scheduled_discovery as lane

    finished = NOW + timedelta(seconds=finish_seconds, microseconds=123456)
    events = _events(ordinal=1)
    events[1]["data"] = output(raw_lead())
    provider, calls, _, _ = adapter_factory([{"events": events}])
    provider.utc_now = lambda: finished
    monkeypatch.setattr(availability, "_utc_now", lambda: NOW + timedelta(seconds=30))
    diagnostics = []
    monkeypatch.setattr(lane, "_emit_failure_diagnostic", lambda **kw: diagnostics.append(kw))
    enqueue_search(database)
    assert work(database, provider).outcome == "succeeded"
    assert len(calls) == 1
    observations = _observations(database)
    if finish_seconds == 10:
        assert len(observations) == 1
        assert observations[0]["public_metadata"]["provider_finished_at"] == finished.isoformat(
            timespec="microseconds"
        )
        assert diagnostics == []
    else:
        assert observations == []
        assert len(diagnostics) == 1
        assert diagnostics[0]["reason_code"] == "result_availability_unknown"
    with Session(database.engine) as session:
        jobs = [
            row
            for row in session.scalars(select(JobRecord))
            if row.job_type == lane.DISCOVERY_JOB_TYPE
        ]
        assert len(jobs) == 1 and jobs[0].state == "succeeded"


def test_public_eligibility_is_separate_from_availability_observation(database, monkeypatch):
    monkeypatch.setenv(PUBLICATION_ENV, POLICY_ID)
    monkeypatch.setattr(availability, "_utc_now", lambda: NOW + timedelta(seconds=30))
    provider = LeadProvider()
    enqueue_search(database)
    assert work(database, provider).outcome == "succeeded"
    assert work(database, provider, NOW + timedelta(seconds=1)).outcome == "succeeded"
    with Session(database.engine) as session:
        assert any(row.public_eligible for row in session.scalars(select(EmergingLeadRecord)))
    observations = _observations(database)
    assert len(observations) == 2
    for row in observations:
        assert row["public_metadata"]["publication_state"] == "not_observed"
        assert "public_publication" not in row["public_metadata"]
