"""Native administrative boundaries, shared budgets and exact partial ledgers."""

from __future__ import annotations

from dataclasses import replace
from uuid import uuid4

import pytest

from smithguard.grok_build_sequence import NativeSequence
from smithguard.grok_build_stream import NATIVE_MODEL, NativeStream
from smithguard.scheduled_discovery import ScheduledProviderError

SID = "11111111-1111-4111-8111-111111111111"


def _end(*, stop="end_turn", output=8, input_tokens=15, turns=1, request_id=None):
    return {
        "type": "end",
        "sessionId": SID,
        "requestId": request_id or str(uuid4()),
        "stopReason": stop,
        "usage": {
            "input_tokens": input_tokens - 5,
            "cache_read_input_tokens": 2,
            "cache_creation_input_tokens": 3,
            "output_tokens": output,
            "reasoning_tokens": min(output, 6),
            "total_tokens": input_tokens + output,
        },
        "num_turns": turns,
        "modelUsage": {
            NATIVE_MODEL: {
                "inputTokens": input_tokens - 5,
                "cacheReadInputTokens": 2,
                "cacheCreationInputTokens": 3,
                "outputTokens": output,
                "modelCalls": turns,
            }
        },
    }


def _tool(identity, *, url="https://example.org/advisory"):
    return {
        "type": "tool_call",
        "toolCallId": identity,
        "toolName": "web_search",
        "status": "pending",
        "rawInput": {"variant": "WebSearch", "backend": True},
    }, {
        "type": "tool_call_update",
        "toolCallId": identity,
        "status": "completed",
        "rawOutput": {
            "status": "completed",
            "action": {"type": "search", "sources": [{"url": url}]},
        },
    }


def _stream(
    sequence=None,
    *,
    boundary=False,
    tools=(),
    text="{}",
    output=8,
    input_tokens=15,
    request_id=None,
):
    stream = NativeStream(session_id=SID, qualification=False)
    if sequence:
        sequence.prepare(stream)
    accept = stream.accept if sequence is None else lambda event: sequence.accept(stream, event)
    accept({"type": "available_commands", "tools": ["web_fetch"]})
    accept({"type": "text", "data": text})
    terminal = _end(
        stop="cancelled" if boundary else "end_turn",
        output=output,
        input_tokens=input_tokens,
        request_id=request_id,
    )
    accept(
        {
            "type": "usage",
            "usage": {k: v for k, v in terminal["usage"].items() if k != "total_tokens"},
        }
    )
    for identity in tools:
        for event in _tool(identity):
            accept(event)
    if boundary:
        accept({"type": "max_turns_reached"})
    accept(terminal)
    return stream


def _result(stream, *, boundary=False, **kwargs):
    return stream.result(
        request_bytes=100,
        response_bytes=200,
        elapsed_ms=300,
        segmented=True,
        execution_failed=boundary,
        accept_turn_boundary=boundary,
        **kwargs,
    )


def test_explicit_administrative_stop_has_complete_usage_and_continuation_flag():
    stream = _stream(boundary=True, tools=("search-1",))
    result = _result(stream, boundary=True)
    assert stream.bounded_continuation
    assert result.output_text == ""
    invocation = result.native_invocations[0]
    assert invocation.bounded_turn_limit and invocation.stop_reason == "cancelled"
    assert invocation.model_turns == 1 and invocation.tool_calls == 1
    assert invocation.input_tokens == 15 and invocation.total_tokens == 23


@pytest.mark.parametrize(
    "fault",
    [
        "no_opt_in",
        "not_segmented",
        "clean_exit",
        "no_marker",
        "duplicate_marker",
        "no_tool",
        "wrong_stop",
        "invalid_output",
    ],
)
def test_cancelled_is_not_general_continuation_permission(fault):
    stream = _stream(boundary=True, tools=() if fault == "no_tool" else ("search",))
    if fault == "no_marker":
        stream.turn_limit_events = 0
    elif fault == "duplicate_marker":
        stream.turn_limit_events = 2
    elif fault == "wrong_stop":
        stream.end["stopReason"] = "max_tokens"
    elif fault == "invalid_output":
        stream.invalid_output = True
    with pytest.raises(ScheduledProviderError) as raised:
        stream.result(
            request_bytes=100,
            response_bytes=200,
            elapsed_ms=300,
            segmented=fault != "not_segmented",
            execution_failed=fault != "clean_exit",
            accept_turn_boundary=fault != "no_opt_in",
        )
    assert not raised.value.retryable and not raised.value.usage_uncertain
    assert raised.value.exact_usage.total_tokens == 23
    assert not stream.bounded_continuation


@pytest.mark.parametrize(
    "fault",
    [
        "missing_tool_pair",
        "error",
        "bad_ledger",
        "wrong_session",
        "no_usage_event",
        "usage_mismatch",
    ],
)
def test_uncertain_boundary_never_continues(fault):
    stream = _stream(boundary=True, tools=("search",))
    if fault == "missing_tool_pair":
        stream.tools["search"]["complete"] = False
    elif fault == "error":
        stream.saw_error = True
    elif fault == "bad_ledger":
        stream.end["usage"]["total_tokens"] += 1
    elif fault == "wrong_session":
        stream.end["sessionId"] = str(uuid4())
    elif fault == "no_usage_event":
        stream.observed_model_turns = 0
    else:
        stream.usage_counts = (10, 999, 2, 3, 6)
    with pytest.raises(ScheduledProviderError) as raised:
        _result(stream, boundary=True)
    assert raised.value.usage_uncertain and raised.value.exact_usage is None
    assert not stream.bounded_continuation


def test_three_segments_preserve_citations_ids_and_only_final_text():
    sequence = NativeSequence(session_id=SID)
    first = _stream(sequence, boundary=True, tools=("first",), text="discard preamble")
    sequence.add(first, _result(first, boundary=True))
    second = _stream(sequence, boundary=True, tools=("second",))
    sequence.add(second, _result(second, boundary=True))
    last = _stream(sequence, text='{"final":true}')
    sequence.add(last, _result(last))
    result = sequence.result(request_bytes=400, response_bytes=900, elapsed_ms=1200)
    assert result.output_text == '{"final":true}'
    assert result.citation_urls == ("https://example.org/advisory",)
    assert result.input_tokens == 45 and result.cached_input_tokens == 6
    assert result.output_tokens == 24 and result.total_tokens == 69
    assert result.server_side_tool_calls == 2 and len(result.native_invocations) == 3
    assert result.response_id == f"grok-build:{SID}:" + ",".join(
        item.request_id for item in sequence.known_invocations
    )
    assert result.request_bytes == 400 and result.response_bytes == 900
    assert result.elapsed_milliseconds == 1200
    assert sequence.observed_model_turns == 3 and sequence.observed_tool_calls == 2


@pytest.mark.parametrize("output,input_tokens", [(8, 500001)])
def test_later_overrun_keeps_previous_and_current_exact_usage(output, input_tokens):
    sequence = NativeSequence(session_id=SID)
    first = _stream(sequence, boundary=True, tools=("first",))
    sequence.add(first, _result(first, boundary=True))
    current = _stream(sequence, output=output, input_tokens=input_tokens)
    with pytest.raises(ScheduledProviderError) as raised:
        _result(current)
    assert raised.value.code == "provider_token_usage_exceeded"
    snapshot = sequence.add_failure(current, raised.value.exact_usage)
    assert snapshot.total_tokens == 23 + input_tokens + output
    assert len(snapshot.native_invocations) == 2
    assert snapshot.request_bytes == 100 and snapshot.response_bytes == 200
    assert snapshot.elapsed_milliseconds == 300
    with pytest.raises(ScheduledProviderError):
        sequence.prepare(NativeStream(session_id=SID, qualification=False))


def test_unrepresentable_aggregate_preserves_all_known_invocations():
    sequence = NativeSequence(session_id=SID)
    first = _stream(sequence, boundary=True, tools=("first",), input_tokens=500000)
    sequence.add(first, _result(first, boundary=True))
    current = _stream(sequence, input_tokens=2000000)
    with pytest.raises(ScheduledProviderError) as raised:
        _result(current)
    assert sequence.add_failure(current, raised.value.exact_usage) is None
    assert len(sequence.known_invocations) == 2
    assert sum(item.input_tokens for item in sequence.known_invocations) == 2500000


@pytest.mark.parametrize("duplicate", ["tool", "request"])
def test_cross_segment_duplicate_identities_fail_closed(duplicate):
    sequence = NativeSequence(session_id=SID)
    first = _stream(sequence, boundary=True, tools=("first",))
    sequence.add(first, _result(first, boundary=True))
    with pytest.raises(ScheduledProviderError) as raised:
        current = _stream(
            sequence,
            tools=("first",) if duplicate == "tool" else (),
            request_id=sequence.known_invocations[0].request_id if duplicate == "request" else None,
        )
        sequence.add(current, _result(current))
    assert raised.value.usage_uncertain
    assert len(sequence.known_invocations) == 1


def test_fifth_tool_is_rejected_during_stream_with_prior_ledger_preserved():
    sequence = NativeSequence(session_id=SID)
    first = _stream(sequence, boundary=True, tools=("one", "two", "three"))
    sequence.add(first, _result(first, boundary=True))
    current = NativeStream(session_id=SID, qualification=False)
    sequence.prepare(current)
    for event in _tool("four"):
        sequence.accept(current, event)
    with pytest.raises(ScheduledProviderError) as raised:
        sequence.accept(current, _tool("five")[0])
    assert raised.value.code == "native_tool_limit" and raised.value.usage_uncertain
    assert sequence.observed_tool_calls == 5
    assert len(sequence.known_invocations) == 1


@pytest.mark.parametrize(
    "field,value", [("request_bytes", 65537), ("response_bytes", 1048577), ("elapsed_ms", 120001)]
)
def test_cumulative_attempt_limits_preserve_exact_ledger(field, value):
    sequence = NativeSequence(session_id=SID)
    stream = _stream(sequence)
    sequence.add(stream, _result(stream))
    metrics = {"request_bytes": 100, "response_bytes": 200, "elapsed_ms": 300, field: value}
    with pytest.raises(ScheduledProviderError) as raised:
        sequence.result(**metrics)
    assert raised.value.code == "native_attempt_limit_exceeded"
    assert not raised.value.usage_uncertain and raised.value.exact_usage.total_tokens == 23


def test_boundaries_without_final_response_are_exact_failure():
    sequence = NativeSequence(session_id=SID)
    for ordinal in range(3):
        stream = _stream(sequence, boundary=True, tools=(f"search-{ordinal}",))
        sequence.add(stream, _result(stream, boundary=True))
    with pytest.raises(ScheduledProviderError) as raised:
        sequence.result(request_bytes=300, response_bytes=600, elapsed_ms=900)
    assert raised.value.code == "native_response_incomplete"
    assert raised.value.exact_usage.total_tokens == 69
    assert len(raised.value.exact_usage.native_invocations) == 3


def test_pending_segment_has_observations_but_only_prior_known_subtotal():
    sequence = NativeSequence(session_id=SID)
    first = _stream(sequence, boundary=True, tools=("first",))
    sequence.add(first, _result(first, boundary=True))
    current = NativeStream(session_id=SID, qualification=False)
    sequence.prepare(current)
    sequence.accept(current, {"type": "thought", "data": "discard immediately"})
    snapshot = sequence.snapshot(request_bytes=200, response_bytes=350, elapsed_ms=1000)
    assert snapshot.total_tokens == 23 and len(snapshot.native_invocations) == 1
    assert sequence.observed_stream_events == first.observed_events + 1
    assert sequence.observed_model_turns == 1
    assert current.text == [] and current.completed_text == ""


def test_sequence_rejects_forged_usage_without_losing_prior_ledger():
    sequence = NativeSequence(session_id=SID)
    first = _stream(sequence, boundary=True, tools=("first",))
    sequence.add(first, _result(first, boundary=True))
    current = _stream(sequence)
    with pytest.raises(ScheduledProviderError) as raised:
        sequence.add(current, replace(_result(current), output_tokens=999))
    assert raised.value.usage_uncertain and len(sequence.known_invocations) == 1
