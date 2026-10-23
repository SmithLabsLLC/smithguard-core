"""Actual adapter orchestration and durable accounting with synthetic processes."""

from __future__ import annotations

import json
import tomllib
from contextlib import contextmanager
from dataclasses import fields, replace
from datetime import timedelta
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy.orm import Session, sessionmaker

from smithguard import grok_build as native
from smithguard.identifiers import canonical_json_bytes, sha256_id
from smithguard.scheduled_discovery import (
    ProviderUsageSnapshot,
    ScheduledProviderError,
    append_receipt,
    enqueue_due_discovery,
    work_one,
)
from smithguard.warning_lane_receipts import (
    ProviderUsage,
    WarningLaneReceiptError,
    _provider_document,
    append_warning_lane_receipt,
)
from tests.test_grok_build_sequence import SID, _end, _tool
from tests.test_scheduled_discovery import NOW, _active_policy, _receipts

pytestmark = pytest.mark.usefixtures("enabled_warning_dispatch")


def _events(*, ordinal, boundary=False, malformed=False, output=8):
    end = _end(
        stop="cancelled" if boundary else "end_turn",
        request_id=str(UUID(int=ordinal)),
        output=output,
    )
    events = [
        {"type": "available_commands", "tools": ["web_fetch"]},
        {"type": "text", "data": "discard preamble" if boundary else '{"leads":[]}'},
        {"type": "usage", "usage": {k: v for k, v in end["usage"].items() if k != "total_tokens"}},
    ]
    if boundary:
        events.extend(_tool(f"search-{ordinal}"))
        if not malformed:
            events.append({"type": "max_turns_reached"})
    return [*events, end]


@pytest.fixture
def adapter_factory(tmp_path, monkeypatch):
    """Stub only I/O; run the real adapter, parser, sequence and cleanup paths."""
    clock = [1000.0]
    monkeypatch.setattr(native, "monotonic", lambda: clock[0])
    monkeypatch.setattr(native, "uuid4", lambda: SID)
    monkeypatch.setattr(native, "_preflight", lambda *args: None)

    def factory(specifications):
        calls, processes = [], []
        provider = native.GrokBuildWarningProvider(ram=tmp_path)
        monkeypatch.setattr(provider, "_inspect", lambda *args: None)
        monkeypatch.setattr(provider, "_bootstrap", lambda *args: None)
        monkeypatch.setattr(provider, "_summary_clean", lambda *args: True)

        class Process:
            def __init__(self, spec):
                self.spec = spec
                self.rows = iter(spec.get("events", []))
                self.bytes = spec.get("bytes", 0)
                self.closed = False
                self.deadlines = []
                self.byte_limit = native.MAX_BYTES

            def line(self, deadline):
                self.deadlines.append(deadline)
                if self.bytes > self.byte_limit:
                    raise ValueError("synthetic aggregate stream bound")
                if self.spec.get("timeout"):
                    raise TimeoutError("synthetic content must not be retained")
                event = next(self.rows, None)
                if event is None:
                    return None
                row = json.dumps(event).encode()
                if not self.spec.get("bytes"):
                    self.bytes += len(row) + 1
                    self.on_pipe("stdout", len(row) + 1)
                    self.line_framing_bytes = 1
                return row

            def finish(self, deadline):
                self.deadlines.append(deadline)
                return self.spec.get("exit", 0)

            def close(self):
                self.closed = True
                clock[0] += self.spec.get("close_seconds", 0)
                if self.spec.get("cleanup_failure"):
                    raise OSError("synthetic cleanup failure")

        def start(args, work, env):
            index = len(calls)
            if index >= len(specifications):
                pytest.fail("adapter dispatched an unauthorized extra synthetic invocation")
            prompt = Path(args[args.index("--prompt-file") + 1])
            calls.append(
                {
                    "args": list(args),
                    "config": tomllib.loads((Path(env["GROK_HOME"]) / "config.toml").read_text()),
                    "prompt": prompt.read_bytes(),
                    "cwd": work,
                    "env_keys": set(env),
                }
            )
            process = Process(specifications[index])
            processes.append(process)
            return process

        monkeypatch.setattr(provider, "_start", start)
        return provider, calls, processes, clock

    return factory


def _payload():
    return {
        "model": "grok-4.7",
        "reasoning": {"effort": "high"},
        "instructions": "Synthetic public fixture.",
        "input": "Return the static terminal JSON.",
        "tools": [{"type": "web_search"}],
        "text": {"format": {"schema": {"type": "object"}}},
    }


def _three_steps():
    return [
        {"events": _events(ordinal=1, boundary=True), "exit": 1},
        {"events": _events(ordinal=2, boundary=True), "exit": 1},
        {"events": _events(ordinal=3)},
    ]


def test_three_steps_keep_one_session_config_and_complete_aggregate(adapter_factory, tmp_path):
    provider, calls, processes, _ = adapter_factory(_three_steps())
    result = provider.discover(_payload())
    assert len(calls) == 3 and all(process.closed for process in processes)
    for call in calls:
        args = call["args"]
        assert args[args.index("--max-turns") + 1] == "1"
        assert args[args.index("--model") + 1] == "grok-4.7"
        assert args[args.index("--reasoning-effort") + 1] == "high"
        assert args[args.index("--resume") + 1] == SID
        assert "max_completion_tokens" not in call["config"]["model"]["grok-4.7"]
        assert "max_completion_tokens" not in call["config"]["models"]
        assert "XAI_API_KEY" not in call["env_keys"]
    assert len({call["cwd"] for call in calls}) == 1
    assert calls[1]["prompt"] == calls[2]["prompt"] == native.NATIVE_CONTINUATION
    assert calls[0]["prompt"] != native.NATIVE_CONTINUATION
    assert result.request_bytes == sum(len(call["prompt"]) for call in calls)
    assert result.response_bytes == sum(process.bytes for process in processes)
    assert result.input_tokens == 45 and result.output_tokens == 24 and result.total_tokens == 69
    assert result.server_side_tool_calls == 2
    assert result.citation_urls == ("https://example.org/advisory",)
    assert result.output_text == '{"leads":[]}'
    assert len(result.native_invocations) == 3
    assert [item.bounded_turn_limit for item in result.native_invocations] == [True, True, False]
    assert len({item.request_id for item in result.native_invocations}) == 3
    assert not list(tmp_path.iterdir())


def test_second_timeout_is_uncertain_with_only_prior_known_subset(adapter_factory, tmp_path):
    provider, calls, processes, _ = adapter_factory(
        [{"events": _events(ordinal=1, boundary=True), "exit": 1}, {"timeout": True}]
    )
    with pytest.raises(ScheduledProviderError) as raised:
        provider.discover(_payload())
    error = raised.value
    assert error.code == "native_execution_uncertain" and error.usage_uncertain
    assert not error.retryable and error.exact_usage is None
    assert len(calls) == 2 and all(process.closed for process in processes)
    diagnostic = error.native_diagnostic
    assert diagnostic.exception_category == "timeout"
    assert len(diagnostic.known_invocations) == 1
    assert diagnostic.known_invocations[0].total_tokens == 23
    metadata = diagnostic.metadata()
    assert metadata["completed_native_usage_scope"] == "known_subset_not_attempt_total"
    assert "synthetic content" not in json.dumps(metadata)
    assert not list(tmp_path.iterdir())


def test_duplicate_failed_request_and_cleanup_error_preserve_only_prior_subset(
    adapter_factory, tmp_path
):
    duplicate = _events(ordinal=1)
    duplicate[-1]["stopReason"] = "max_tokens"
    provider, calls, processes, _ = adapter_factory(
        [
            {"events": _events(ordinal=1, boundary=True), "exit": 1},
            {"events": duplicate, "cleanup_failure": True},
        ]
    )
    with pytest.raises(ScheduledProviderError) as raised:
        provider.discover(_payload())
    error = raised.value
    assert error.code == "native_execution_uncertain" and error.usage_uncertain
    assert not error.retryable and error.exact_usage is None
    assert len(calls) == 2 and all(process.closed for process in processes)
    assert provider.cleanup_failed
    assert error.native_diagnostic.phase == "process_cleanup"
    assert len(error.native_diagnostic.known_invocations) == 1
    assert error.native_diagnostic.known_invocations[0].total_tokens == 23
    assert not list(tmp_path.iterdir())


def test_uncertain_second_step_dead_letters_without_paid_factory(adapter_factory, database):
    primary, calls, _, _ = adapter_factory(
        [{"events": _events(ordinal=1, boundary=True), "exit": 1}, {"timeout": True}]
    )
    paid_calls = []
    provider = native.SubscriptionFirstProvider(
        primary=primary, fallback_factory=lambda: paid_calls.append("forbidden_paid_factory")
    )
    factory = sessionmaker(database.engine)
    policy = _active_policy()
    with factory() as session, session.begin():
        enqueue_due_discovery(session, policy=policy, now=NOW)
    result = work_one(
        factory,
        policy=policy,
        provider=provider,
        worker_id="synthetic",
        now=NOW + timedelta(minutes=1),
    )
    assert result.outcome == "dead_letter" and len(calls) == 2 and paid_calls == []
    with factory() as session:
        receipts = _receipts(session)
    failures = [item for item in receipts if item["reason_code"] == "native_execution_uncertain"]
    assert len(failures) == 1 and failures[0]["provider"] is None
    diagnostic = failures[0]["public_metadata"]["native_diagnostic"]
    assert diagnostic["completed_native_usage_scope"] == "known_subset_not_attempt_total"
    assert len(diagnostic["completed_native_invocations"]) == 1
    assert not any(item["reason_code"] == "provider_http_error_uncharged" for item in receipts)


def test_cancelled_without_marker_never_resumes(adapter_factory):
    provider, calls, _, _ = adapter_factory(
        [{"events": _events(ordinal=1, boundary=True, malformed=True), "exit": 1}]
    )
    with pytest.raises(ScheduledProviderError) as raised:
        provider.discover(_payload())
    assert len(calls) == 1
    assert raised.value.code == "native_response_incomplete"
    assert not raised.value.usage_uncertain and raised.value.exact_usage.total_tokens == 23


def test_third_boundary_never_dispatches_fourth_step(adapter_factory):
    provider, calls, _, _ = adapter_factory(
        [{"events": _events(ordinal=i, boundary=True), "exit": 1} for i in (1, 2, 3)]
    )
    with pytest.raises(ScheduledProviderError) as raised:
        provider.discover(_payload())
    assert len(calls) == 3
    assert raised.value.code == "native_response_incomplete"
    assert raised.value.exact_usage.total_tokens == 69
    assert len(raised.value.exact_usage.native_invocations) == 3


def test_time_bound_is_shared_and_blocks_next_dispatch(adapter_factory):
    provider, calls, processes, _ = adapter_factory(
        [{"events": _events(ordinal=1, boundary=True), "exit": 1, "close_seconds": 121}]
    )
    with pytest.raises(ScheduledProviderError) as raised:
        provider.discover(_payload())
    assert len(calls) == 1 and processes[0].closed
    assert all(deadline == 1120.0 for deadline in processes[0].deadlines)
    assert not raised.value.retryable
    assert raised.value.exact_usage.total_tokens == 23


def test_stream_byte_allowance_is_reduced_between_processes(adapter_factory):
    specifications = _three_steps()
    specifications[0]["bytes"] = native.MAX_BYTES - 100
    specifications[1]["bytes"] = 101
    provider, calls, processes, _ = adapter_factory(specifications)
    with pytest.raises(ScheduledProviderError) as raised:
        provider.discover(_payload())
    assert len(calls) == 2 and processes[1].byte_limit == 100
    assert raised.value.usage_uncertain and raised.value.exact_usage is None
    assert len(raised.value.native_diagnostic.known_invocations) == 1


def test_prompt_byte_bound_blocks_resume_before_dispatch(adapter_factory, monkeypatch):
    monkeypatch.setattr(
        native,
        "_prompt",
        lambda *args, **kwargs: b"x" * (65536 - len(native.NATIVE_CONTINUATION) + 1),
    )
    provider, calls, processes, _ = adapter_factory(
        [{"events": _events(ordinal=1, boundary=True), "exit": 1}]
    )
    with pytest.raises(ScheduledProviderError) as raised:
        provider.discover(_payload())
    assert len(calls) == 1 and processes[0].closed
    assert not raised.value.retryable and not raised.value.usage_uncertain
    assert raised.value.exact_usage.total_tokens == 23
    assert len(raised.value.exact_usage.native_invocations) == 1


def _usage(result):
    return ProviderUsage(
        stage="discovery",
        model="grok-4.7",
        configured_maximum_turns=3,
        **{field.name: getattr(result, field.name) for field in fields(ProviderUsageSnapshot)},
    )


@pytest.mark.parametrize("output", [8, 2786, 8193, 600001])
def test_durable_sequence_receipt_sums_and_hashes_every_identity(adapter_factory, database, output):
    specs = [
        {"events": _events(ordinal=i, boundary=i < 3, output=output), "exit": 1 if i < 3 else 0}
        for i in (1, 2, 3)
    ]
    provider, calls, _, _ = adapter_factory(specs)
    result = provider.discover(_payload())
    with Session(database.engine) as session, session.begin():
        record = append_receipt(
            session,
            receipt_type="provider_cost_observed",
            reason_code="within_technical_envelope",
            run_id="synthetic-native-sequence",
            occurred_at=NOW,
            public_metadata={},
            provider_result=result,
            provider_stage="discovery",
        )
        payload = record.payload
        assert payload["schema_version"] == "3.1.0" and record.state == "succeeded"
        doc = payload["provider"]
        assert len(calls) == 3 and doc["output_tokens"] == 3 * output
        assert doc["identity_scope"] == "native_harness_session_and_ordered_requests"
        assert doc["request_bytes_scope"] == "input_prompts"
        assert doc["total_tokens"] == sum(
            item["total_tokens"] for item in doc["native_invocations"]
        )
        assert doc["tool_calls"] == sum(item["tool_calls"] for item in doc["native_invocations"])
        assert doc["response_id_sha256"] == sha256_id(result.response_id.encode("ascii"))
        for actual, stored in zip(
            result.native_invocations, doc["native_invocations"], strict=True
        ):
            assert stored["request_id_sha256"] == sha256_id(actual.request_id.encode("ascii"))
            assert stored["session_id_sha256"] == sha256_id(actual.session_id.encode("ascii"))
        serialized = canonical_json_bytes(payload).decode("ascii")
        assert SID not in serialized
        assert all(item.request_id not in serialized for item in result.native_invocations)
        assert result.output_text not in serialized


@pytest.mark.parametrize(
    "fault", ["tokens", "tools", "identity", "route", "duplicate", "mixed_session"]
)
def test_invalid_native_aggregate_is_rejected_before_receipt_write(
    adapter_factory, database, fault
):
    provider, _, _, _ = adapter_factory(_three_steps())
    usage = _usage(provider.discover(_payload()))
    if fault == "tokens":
        usage = replace(
            usage, input_tokens=usage.input_tokens + 1, total_tokens=usage.total_tokens + 1
        )
    elif fault == "tools":
        usage = replace(usage, server_side_tool_calls=usage.server_side_tool_calls + 1)
    elif fault == "identity":
        usage = replace(usage, response_id="grok-build:unrelated")
    elif fault == "route":
        usage = replace(usage, credential_route="api_key")
    elif fault == "duplicate":
        usage = replace(usage, native_invocations=(usage.native_invocations[0],) * 2)
    else:
        second = replace(usage.native_invocations[1], session_id=str(UUID(int=100)))
        usage = replace(usage, native_invocations=(usage.native_invocations[0], second))
    with Session(database.engine) as session, session.begin():
        with pytest.raises(WarningLaneReceiptError):
            append_warning_lane_receipt(
                session,
                receipt_type="provider_cost_observed",
                reason_code="within_technical_envelope",
                run_id="synthetic-invalid-sequence",
                occurred_at=NOW,
                public_metadata={},
                provider_usage=usage,
            )
        assert _receipts(session) == ()
    with pytest.raises(WarningLaneReceiptError):
        _provider_document(usage)


@pytest.mark.parametrize("fault", ["cleanup", "third_boundary", "input_overrun"])
def test_exact_failure_durable_receipt_has_no_partial_usage_label(adapter_factory, database, fault):
    if fault == "cleanup":
        specs = [{"events": _events(ordinal=1), "cleanup_failure": True}]
        code, total, invocations = "native_cleanup_failed", 23, 1
    elif fault == "third_boundary":
        specs = [{"events": _events(ordinal=i, boundary=True), "exit": 1} for i in (1, 2, 3)]
        code, total, invocations = "native_response_incomplete", 69, 3
    else:
        events = _events(ordinal=2)
        terminal = _end(input_tokens=500001, request_id=str(UUID(int=2)))
        events[-1] = terminal
        events[2]["usage"] = {k: v for k, v in terminal["usage"].items() if k != "total_tokens"}
        specs = [
            {"events": _events(ordinal=1, boundary=True), "exit": 1},
            {"events": events},
        ]
        code, total, invocations = "provider_token_usage_exceeded", 500032, 2
    provider, _, _, _ = adapter_factory(specs)
    factory = sessionmaker(database.engine)
    policy = _active_policy()
    with factory() as session, session.begin():
        enqueue_due_discovery(session, policy=policy, now=NOW)
    result = work_one(
        factory,
        policy=policy,
        provider=provider,
        worker_id="synthetic",
        now=NOW + timedelta(minutes=1),
    )
    assert result.outcome == "dead_letter"
    with factory() as session:
        receipts = _receipts(session)
    failures = [
        item
        for item in receipts
        if item["reason_code"] == code and item["receipt_type"] == "provider_failure"
    ]
    assert len(failures) == 1
    diagnostic = failures[0]["public_metadata"]["native_diagnostic"]
    assert "completed_native_usage_scope" not in diagnostic
    assert "completed_native_invocations" not in diagnostic
    usage = [item for item in receipts if item["receipt_type"] == "provider_cost_observed"]
    assert len(usage) == 1
    assert usage[0]["provider"]["total_tokens"] == total
    assert len(usage[0]["provider"]["native_invocations"]) == invocations


@pytest.mark.parametrize("qualification", [False, True])
def test_post_cleanup_deadline_is_neutral_for_single_invocation(
    adapter_factory, tmp_path, qualification
):
    events = _events(ordinal=1)
    payload = _payload()
    if qualification:
        events[0]["tools"] = []
        payload["tools"] = []
    provider, calls, processes, clock = adapter_factory([{"events": events}])
    original_directory = provider._directory

    @contextmanager
    def slow_ram_cleanup(diagnostic):
        with original_directory(diagnostic) as directory:
            yield directory
        clock[0] += 121

    provider._directory = slow_ram_cleanup
    with pytest.raises(ScheduledProviderError) as raised:
        (provider.qualify if qualification else provider.discover)(payload)
    error = raised.value
    assert len(calls) == 1 and processes[0].closed
    assert error.code == "native_deadline_exceeded"
    assert not error.retryable and not error.usage_uncertain
    assert error.exact_usage.total_tokens == 23
    assert "completed_native_usage_scope" not in error.native_diagnostic.metadata()
    assert not list(tmp_path.iterdir())
