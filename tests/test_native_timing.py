"""Content-free observations of real adapter paths using controlled clocks and I/O."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import timedelta

import pytest

from smithguard.native_timing import BUCKET_COUNT, NativeTimingRecorder
from smithguard.scheduled_discovery import ScheduledProviderError
from tests.test_grok_build_continuation import _events, _payload
from tests.test_grok_build_continuation import adapter_factory as adapter_factory
from tests.test_scheduled_discovery import NOW


def test_recent_buckets_are_fixed_size_and_do_not_keep_old_activity():
    clock = [0.0]
    recorder = NativeTimingRecorder(started=0, clock=lambda: clock[0], utc_now=lambda: NOW)
    recorder.start_invocation()
    for index in range(120):
        clock[0] = float(index)
        recorder.observe_bytes((index + 1) * 10)
        recorder.observe_event()
    clock[0] = 160
    recorder.failure("stream_read", "timeout")
    observed = recorder.snapshot()
    assert len(recorder.buckets) == BUCKET_COUNT
    assert len(observed.activity.buckets) == BUCKET_COUNT
    assert observed.activity.stream_bytes == 1200
    assert observed.activity.parsed_events == 120
    assert observed.activity.last_event_age_ms == 41000
    assert all(
        bucket.parsed_events == bucket.stream_bytes == 0 for bucket in observed.activity.buckets
    )
    with pytest.raises(ValueError, match="phases"):
        replace(observed, phase_elapsed_ms=(1,))
    with pytest.raises(ValueError, match="count"):
        replace(observed.activity, stream_bytes=True)


@pytest.mark.parametrize("active", [False, True])
def test_deadline_snapshot_distinguishes_quiet_and_active_streams_before_cleanup(
    adapter_factory,
    monkeypatch,
    active,
):
    provider, calls, processes, clock = adapter_factory([{"close_seconds": 2}])
    provider.utc_now = lambda: NOW + timedelta(seconds=122)
    original_start = provider._start
    steps = [10, *([5] * 21 if active else [])]

    def start(*args):
        process = original_start(*args)

        def line(deadline):
            assert deadline == 1120.0  # One original 120-second deadline.
            if not steps:
                clock[0] = deadline
                # Partial stderr/stdout bytes can arrive without a JSON event.
                process.bytes += 7
                process.on_bytes(process.bytes)
                raise TimeoutError("synthetic private text https://invalid.example/secret")
            clock[0] += steps.pop(0)
            event = (
                {"type": "available_commands", "tools": []}
                if len(steps) == (21 if active else 0)
                else {
                    "type": "thought",
                    "data": "synthetic private text",
                }
            )
            value = json.dumps(event).encode()
            process.bytes += len(value)
            process.on_bytes(process.bytes)
            process.on_pipe("stdout", len(value))
            return value

        monkeypatch.setattr(process, "line", line)
        return process

    monkeypatch.setattr(provider, "_start", start)
    payload = {**_payload(), "tools": []}
    with pytest.raises(ScheduledProviderError) as exc:
        provider.qualify(payload)
    error = exc.value
    assert error.usage_uncertain and error.exact_usage is None and not error.retryable
    timing = error.native_diagnostic.timing
    assert timing.observed_finished_at == NOW + timedelta(seconds=122)
    assert timing.first_failure.phase == "stream_read"
    assert timing.first_failure.activity.elapsed_ms == 120_000
    assert timing.first_failure.activity.last_event_age_ms == (5000 if active else 110000)
    assert timing.first_failure.activity.stream_bytes == processes[0].bytes
    assert timing.activity.elapsed_ms == 122_000
    assert timing.metadata()["phase_elapsed_ms"]["process_cleanup"] == 2000
    assert timing.invocations[0].elapsed_ms == 122_000
    assert len(calls) == 1 and processes[0].closed
    assert "synthetic private text" not in json.dumps(timing.metadata())
    assert "https://" not in json.dumps(timing.metadata())


def test_success_includes_all_invocation_and_cleanup_timing(adapter_factory, monkeypatch):
    provider, calls, processes, clock = adapter_factory(
        [
            {"events": _events(ordinal=1, boundary=True), "exit": 1, "close_seconds": 2},
            {"events": _events(ordinal=2), "close_seconds": 3},
        ]
    )
    provider.utc_now = lambda: NOW + timedelta(seconds=8)

    def inspect(*args):
        clock[0] += 1

    def bootstrap(*args):
        clock[0] += 2

    monkeypatch.setattr(provider, "_inspect", inspect)
    monkeypatch.setattr(provider, "_bootstrap", bootstrap)
    result = provider.discover(_payload())
    timing = result.native_timing
    assert timing.first_failure is None
    assert timing.observed_finished_at == NOW + timedelta(seconds=8)
    assert result.elapsed_milliseconds == timing.activity.elapsed_ms == 8000
    phases = timing.metadata()["phase_elapsed_ms"]
    assert phases["inspection"] == 1000 and phases["bootstrap"] == 2000
    assert phases["process_cleanup"] == 5000
    assert [x.elapsed_ms for x in timing.invocations] == [2000, 3000]
    assert [x.start_elapsed_ms for x in timing.invocations] == [3000, 5000]
    assert timing.activity.stream_bytes == sum(process.bytes for process in processes)
    assert len(calls) == 2 and all(process.closed for process in processes)


def test_partial_stdout_and_stderr_bytes_are_observed_without_a_json_event(tmp_path):
    import sys
    from time import monotonic

    from smithguard.grok_build import _Process

    started = monotonic()
    recorder = NativeTimingRecorder(started=started, clock=monotonic, utc_now=lambda: NOW)
    process = _Process(
        [sys.executable, "-c", 'import os; os.write(1,b"partial"); os.write(2,b"stderr")'],
        cwd=tmp_path,
        env={},
    )
    process.on_bytes = recorder.observe_bytes
    process.on_pipe = recorder.observe_pipe
    try:
        assert process.line(started + 5) == b"partial"
        assert process.line(started + 5) is None
        assert process.finish(started + 5) == 0
    finally:
        process.close()
    activity = recorder.snapshot().activity
    assert activity.stream_bytes == 13 and activity.parsed_events == 0
    assert activity.first_event_elapsed_ms is activity.last_event_age_ms is None
    assert sum(bucket.stream_bytes for bucket in activity.buckets) == 13


def test_timeout_then_cleanup_failure_keeps_primary_time_and_known_usage(adapter_factory):
    provider, calls, processes, clock = adapter_factory(
        [
            {"events": _events(ordinal=1, boundary=True), "exit": 1, "close_seconds": 1},
            {"timeout": True, "cleanup_failure": True, "close_seconds": 2},
        ]
    )
    with pytest.raises(ScheduledProviderError) as exc:
        provider.discover(_payload())
    error = exc.value
    timing = error.native_diagnostic.timing
    assert error.usage_uncertain and error.exact_usage is None and not error.retryable
    assert len(error.native_diagnostic.known_invocations) == 1
    assert error.native_diagnostic.phase == "process_cleanup"
    assert timing.first_failure.phase == "stream_read"
    assert timing.first_failure.exception_category == "timeout"
    assert timing.first_failure.activity.elapsed_ms == 1000
    assert timing.activity.elapsed_ms == 3000
    assert len(timing.invocations) == len(calls) == 2
    assert all(process.closed for process in processes)


def test_timing_document_is_bounded_at_counter_limits(database):
    from uuid import UUID

    from sqlalchemy.orm import Session

    from smithguard.identifiers import canonical_json_bytes
    from smithguard.native_event_observations import EVENT_TYPES, MAX_COUNT, EventObservation
    from smithguard.native_timing import MAX_MS, MAX_STREAM_BYTES
    from smithguard.native_usage import NativeInvocationUsage
    from smithguard.scheduled_discovery import NativeFailureDiagnostic
    from smithguard.warning_lane_receipts import MAX_RECEIPT_BYTES, append_warning_lane_receipt
    from smithguard.xai_settings import XAI_MAX_INPUT_TOKENS, XAI_MAX_TOTAL_TOKENS

    clock = [0.0]
    recorder = NativeTimingRecorder(started=0, clock=lambda: clock[0], utc_now=lambda: NOW)
    for _index in range(3):
        recorder.start_invocation()
        clock[0] += 5
        recorder.observe_bytes(MAX_STREAM_BYTES * 2)
        recorder.observe_event()
        recorder.finish_invocation()
    clock[0] = MAX_MS / 1000 + 100
    recorder.failure("stream_read", "timeout")
    timing = recorder.snapshot()
    assert timing.activity.elapsed_ms == MAX_MS
    assert timing.activity.stream_bytes == MAX_STREAM_BYTES
    assert len(timing.invocations) == 3
    # Conservative representation stress: maximum-width counters, including
    # mutually unreachable combinations, within each stored type's validation.
    observation = EventObservation(
        counts=(MAX_COUNT,) * len(EVENT_TYPES),
        serialized_bytes=(100_000,) * len(EVENT_TYPES),
        stdout_bytes=MAX_STREAM_BYTES - 1024,
        stderr_bytes=1024,
        framing_bytes=255,
        malformed_bytes=255,
        malformed_lines=MAX_COUNT,
        first_text_elapsed_ms=MAX_MS,
    )
    invocations = tuple(
        replace(item, start_elapsed_ms=MAX_MS, elapsed_ms=MAX_MS, events=observation)
        for item in timing.invocations
    )
    timing = replace(
        timing,
        invocations=invocations,
        first_failure=replace(timing.first_failure, invocations=invocations),
        phase_elapsed_ms=(MAX_MS,) * len(timing.phase_elapsed_ms),
    )
    known = tuple(
        NativeInvocationUsage(
            session_id=str(UUID(int=1)),
            request_id=str(UUID(int=index)),
            input_tokens=XAI_MAX_INPUT_TOKENS,
            cached_input_tokens=XAI_MAX_INPUT_TOKENS,
            output_tokens=XAI_MAX_TOTAL_TOKENS - XAI_MAX_INPUT_TOKENS,
            reasoning_tokens=XAI_MAX_TOTAL_TOKENS - XAI_MAX_INPUT_TOKENS,
            total_tokens=XAI_MAX_TOTAL_TOKENS,
            model_turns=1,
            tool_calls=2,
            stop_reason="cancelled",
            bounded_turn_limit=True,
        )
        for index in (2, 3)
    )
    diagnostic = NativeFailureDiagnostic(
        phase="process_cleanup",
        exception_category="contract_rejection",
        elapsed_ms=MAX_MS,
        observed_stream_events=MAX_COUNT,
        observed_model_turns=MAX_COUNT,
        observed_tool_calls=MAX_COUNT,
        prompt_bytes=65_536,
        stream_bytes=MAX_STREAM_BYTES,
        known_invocations=known,
        timing=timing,
    )
    with Session(database.engine) as session, session.begin():
        receipt = append_warning_lane_receipt(
            session,
            receipt_type="provider_failure",
            reason_code="native_contract_rejection",
            run_id="r" * 512,
            job_id="j" * 512,
            occurred_at=NOW,
            public_metadata={
                "error_class": "ScheduledProviderError",
                "queue": "warning_discovery",
                "attempt": 2,
                "failed_at": NOW.isoformat(),
                "elapsed_milliseconds": MAX_MS,
                "native_diagnostic": diagnostic.metadata(),
            },
        )
        assert len(canonical_json_bytes(receipt.payload)) <= MAX_RECEIPT_BYTES
        stored = receipt.payload["public_metadata"]["native_diagnostic"]["timing"]
        for item in stored["invocations"]:
            assert all(
                counter["count"] == MAX_COUNT for counter in item["events"]["event_types"].values()
            )


@pytest.mark.usefixtures("enabled_warning_dispatch")
@pytest.mark.parametrize("failure", [False, True])
def test_durable_timing_preserves_historical_times_and_health_budget_boundaries(
    adapter_factory, database, failure
):
    from copy import deepcopy

    from sqlalchemy import select
    from sqlalchemy.orm import sessionmaker

    from smithguard.db.models import JobRecord
    from smithguard.identifiers import canonical_json_bytes
    from smithguard.scheduled_discovery import append_receipt, enqueue_due_discovery, work_one
    from smithguard.warning_dispatch import collect_dispatch_budget
    from smithguard.warning_lane_health import collect_warning_lane_health
    from tests.test_scheduled_discovery import _active_policy, _receipts

    factory = sessionmaker(database.engine)
    policy = _active_policy()
    worker_time = NOW + timedelta(minutes=1)
    finished = worker_time + timedelta(seconds=122)
    from smithguard.discovery import DISCOVERY_PROMPT_VERSION

    events = _events(ordinal=1)
    events[1]["data"] = json.dumps(
        {
            "prompt_version": DISCOVERY_PROMPT_VERSION,
            "sampled_not_complete": True,
            "candidates": [],
        }
    )
    provider, _, _, _ = adapter_factory([{"timeout": True}] if failure else [{"events": events}])
    provider.utc_now = lambda: finished
    with factory() as session, session.begin():
        append_receipt(
            session,
            receipt_type="discovery_completed",
            reason_code="bounded_discovery_processed",
            run_id="gbsec:ai-warning-run:historical",
            occurred_at=NOW - timedelta(minutes=30),
            public_metadata={"accepted_candidates": 0, "rejected_candidates": 0},
        )
        old_records = {
            row.job_id: canonical_json_bytes(row.payload)
            for row in session.scalars(select(JobRecord))
        }
        enqueue_due_discovery(session, policy=policy, now=NOW)
    outcome = work_one(
        factory, policy=policy, provider=provider, worker_id="timing", now=worker_time
    )
    with factory() as session:
        assert outcome.outcome == ("dead_letter" if failure else "succeeded"), _receipts(session)

    def observations(session):
        return tuple(
            (
                collect_warning_lane_health(
                    session,
                    policy=policy,
                    measured_at=worker_time + offset,
                    expiry_job_success=True,
                    schedule_expected=True,
                ),
                collect_dispatch_budget(session, now=worker_time + offset),
            )
            for offset in (
                timedelta(minutes=45, microseconds=-1),
                timedelta(minutes=45, seconds=1),
                timedelta(hours=24, microseconds=-1),
                timedelta(hours=24, seconds=1),
            )
        )

    with factory() as session, session.begin():
        receipts = _receipts(session)
        matching = [
            item
            for item in receipts
            if item["receipt_type"] == ("provider_failure" if failure else "provider_cost_observed")
        ]
        assert len(matching) == 1
        metadata = matching[0]["public_metadata"]
        timing = metadata["native_diagnostic"]["timing"] if failure else metadata["native_timing"]
        assert timing["observed_finished_at"] == finished.isoformat().replace("+00:00", "Z")
        before = observations(session)
        row_times = {}
        for row in session.scalars(select(JobRecord)):
            row_times[row.job_id] = (
                row.created_at,
                row.completed_at,
                row.available_at,
                row.attempts,
            )
            if row.job_id in old_records:
                assert canonical_json_bytes(row.payload) == old_records[row.job_id]
            payload = deepcopy(row.payload)
            metadata = payload.get("public_metadata", {})
            metadata.pop("native_timing", None)
            metadata.get("native_diagnostic", {}).pop("timing", None)
            row.payload = payload
        session.flush()
        assert observations(session) == before
        assert {
            row.job_id: (row.created_at, row.completed_at, row.available_at, row.attempts)
            for row in session.scalars(select(JobRecord))
        } == row_times


def test_invocation_diagnostic_bound_matches_the_native_contract():
    from smithguard.grok_build import NATIVE_LIMITS
    from smithguard.native_timing import MAX_INVOCATIONS

    assert NATIVE_LIMITS["maximum_model_turns"] == MAX_INVOCATIONS


def test_failure_timing_rejects_unvalidated_metadata():
    from smithguard.scheduled_discovery import NativeFailureDiagnostic

    with pytest.raises(ValueError, match="native timing type invalid"):
        NativeFailureDiagnostic(
            phase="stream_read",
            exception_category="timeout",
            elapsed_ms=1,
            timing={"secret": "synthetic-private-content"},
        )


@pytest.mark.parametrize("bad_type", [False, True])
def test_usage_receipt_rejects_wrong_route_or_unvalidated_timing(bad_type):
    from smithguard.scheduled_discovery import ScheduledLaneError, _record_response
    from tests.test_scheduled_discovery import _active_policy, _discovery_result

    timing = NativeTimingRecorder(started=0, clock=lambda: 0, utc_now=lambda: NOW).snapshot()
    result = replace(
        _discovery_result(),
        native_timing={} if bad_type else timing,
        credential_route="grok_build_subscription" if bad_type else "api_key",
    )
    with pytest.raises(ScheduledLaneError, match="native timing provenance invalid"):
        _record_response(
            lambda: pytest.fail("invalid timing reached database"),
            policy=_active_policy(),
            job=None,
            provider_result=result,
            now=NOW,
        )


@pytest.mark.parametrize("phase", ["inspection", "bootstrap"])
def test_setup_process_bytes_are_not_inference_activity(tmp_path, monkeypatch, phase):
    from smithguard.grok_build import GrokBuildWarningProvider, _DiagnosticState
    from smithguard.grok_build_tools import search_profile
    from tests.test_grok_build import SID

    inspection = {
        key: [] for key in ("mcpServers", "skills", "projectInstructions", "hooks", "plugins")
    }
    events = (
        [inspection]
        if phase == "inspection"
        else [
            {"id": 1, "result": {}},
            {"id": 2, "result": {"sessionId": SID}},
            {"id": 3, "result": {"success": True}},
            {
                "method": "session/update",
                "params": {
                    "sessionId": SID,
                    "update": {
                        "sessionUpdate": "available_commands_update",
                        "_meta": {"tools": []},
                    },
                },
            },
        ]
    )

    class Process:
        bytes = 0
        on_bytes = None
        closed = False

        def line(self, _deadline):
            if not events:
                return None
            row = json.dumps(events.pop(0)).encode()
            self.bytes += len(row)
            if self.on_bytes is not None:
                self.on_bytes(self.bytes)
            return row

        def send(self, _value):
            pass

        def finish(self, _deadline):
            return 0

        def close_input(self):
            pass

        def close(self):
            self.closed = True

    process = Process()
    provider = GrokBuildWarningProvider()
    recorder = NativeTimingRecorder(started=0, clock=lambda: 0, utc_now=lambda: NOW)
    diagnostic = _DiagnosticState(started=0, timing=recorder)
    diagnostic.set_phase(phase)
    monkeypatch.setattr(provider, "_start", lambda *args: process)
    if phase == "inspection":
        provider._inspect(tmp_path, {}, 120, diagnostic)
    else:
        provider._bootstrap(
            tmp_path, {}, SID, 120, search_profile({"tools": []}, qualification=True), diagnostic
        )
    assert process.bytes > 0 and process.closed
    assert process.on_bytes is None
    assert (
        recorder.snapshot().activity.stream_bytes == recorder.snapshot().activity.parsed_events == 0
    )


def test_event_observations_keep_exact_bytes_and_fixed_vocabulary():
    clock = [10.0]
    recorder = NativeTimingRecorder(started=10, clock=lambda: clock[0], utc_now=lambda: NOW)
    recorder.start_invocation()
    lines = [
        ("thought", b'{"type":"thought","data":"private-reasoning"}', 1),
        ("text", b'{"type":"text","data":"private-answer"}', 1),
        ("secret-arbitrary-event-name", b'{"type":"secret-arbitrary-event-name"}', 0),
    ]
    for kind, line, framing in lines:
        clock[0] += 1
        recorder.observe_pipe("stdout", len(line) + framing)
        recorder.observe_line(kind, len(line), framing)
    recorder.observe_pipe("stderr", 7)
    recorder.observe_pipe("stdout", 9)  # Incomplete event bytes, never inferred.
    metadata = recorder.snapshot().invocations[0].events.metadata()
    assert metadata["event_types"]["thought"] == {"count": 1, "serialized_bytes": len(lines[0][1])}
    assert metadata["event_types"]["unknown"]["count"] == 1
    assert metadata["stderr_bytes"] == 7
    assert metadata["unparsed_stdout_bytes"] == 9
    assert metadata["framing_bytes"] == 2
    assert metadata["first_text_elapsed_ms"] == 2000
    assert not any(word in json.dumps(metadata) for word in ("private", "secret-arbitrary"))
    recorder.failure("stream_read", "timeout")
    recorder.observe_pipe("stdout", 10)
    assert recorder.first_failure.invocations[0].events.metadata()["unparsed_stdout_bytes"] == 9
    assert recorder.snapshot().invocations[0].events.metadata()["unparsed_stdout_bytes"] == 19


def test_oversized_pipe_is_counted_before_rejection_without_retaining_content(tmp_path):
    import sys
    from time import monotonic

    from smithguard.grok_build import _Process

    started = monotonic()
    recorder = NativeTimingRecorder(started=started, clock=monotonic, utc_now=lambda: NOW)
    recorder.start_invocation()
    process = _Process(
        [sys.executable, "-c", 'import os; os.write(1,b"secret-value"*1000)'], cwd=tmp_path, env={}
    )
    process.byte_limit = 1
    process.on_bytes = recorder.observe_bytes
    process.on_pipe = recorder.observe_pipe
    try:
        with pytest.raises(ValueError, match="stream exceeds bound"):
            process.line(started + 5)
        recorder.failure("stream_read", "invalid_data")
    finally:
        process.close()
        recorder.finish_invocation()
    observed = recorder.snapshot()
    assert observed.first_failure.invocations[0].events.stdout_bytes == process.bytes
    assert (
        observed.first_failure.invocations[0].events.metadata()["unparsed_stdout_bytes"]
        == process.bytes
    )
    assert "secret-value" not in json.dumps(observed.metadata())


def test_success_finish_clock_is_sampled_after_ram_directory_exit(adapter_factory, monkeypatch):
    from contextlib import contextmanager

    provider, _, _, clock = adapter_factory([{"events": _events(ordinal=1)}])
    original = provider._directory
    exited = []

    @contextmanager
    def directory(diagnostic):
        with original(diagnostic) as path:
            yield path
        clock[0] += 7
        exited.append(True)

    def utc_now():
        assert exited == [True]
        return NOW + timedelta(seconds=clock[0] - 1000)

    monkeypatch.setattr(provider, "_directory", directory)
    provider.utc_now = utc_now
    result = provider.discover(_payload())
    assert result.native_timing.observed_finished_at == NOW + timedelta(seconds=7)
    assert result.native_timing.activity.elapsed_ms == result.elapsed_milliseconds == 7000
