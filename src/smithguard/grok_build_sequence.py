"""Reconcile bounded native invocations without resetting the attempt envelope."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import UUID

from smithguard.grok_build_stream import NATIVE_ROUTE, NativeStream, uncertain
from smithguard.native_usage import NativeInvocationUsage, native_sequence_identity
from smithguard.scheduled_discovery import (
    ProviderResult,
    ProviderUsageSnapshot,
    ScheduledProviderError,
)
from smithguard.spend import NATIVE_SUBSCRIPTION_CONTRACT as NATIVE_LIMITS
from smithguard.xai_settings import (
    XAI_MAX_INPUT_TOKENS,
    XAI_MAX_OUTPUT_TOKENS,
    XAI_MAX_TOTAL_TOKENS,
)


class NativeSequence:
    """One RAM session; complete ledgers survive later uncertain invocations."""

    def __init__(self, *, session_id: str) -> None:
        self.session_id = str(UUID(session_id))
        self._streams: list[NativeStream] = []
        self._known: tuple[NativeInvocationUsage, ...] = ()
        self._tool_ids: set[str] = set()
        self._citations: set[str] = set()
        self._allowed: frozenset[str] | None = None
        self._last_result: ProviderResult | None = None
        self._failed = False

    @property
    def known_invocations(self) -> tuple[NativeInvocationUsage, ...]:
        return self._known

    @property
    def observed_stream_events(self) -> int:
        return sum(stream.observed_events for stream in self._streams)

    @property
    def observed_model_turns(self) -> int:
        return sum(stream.observed_model_turns for stream in self._streams)

    @property
    def observed_tool_calls(self) -> int:
        return sum(stream.observed_tool_calls for stream in self._streams)

    def prepare(self, stream: NativeStream) -> None:
        if (
            self._failed
            or stream.qualification
            or stream.session_id != self.session_id
            or stream in self._streams
            or len(self._streams) != len(self._known)
            or len(self._streams) >= NATIVE_LIMITS["maximum_model_turns"]
            or (self._last_result is not None and not self._known[-1].bounded_turn_limit)
        ):
            raise uncertain("native_sequence_invalid")
        allowed = frozenset(stream.allowed)
        if self._allowed is not None and allowed != self._allowed:
            raise uncertain("native_tools_changed")
        self._allowed = allowed
        stream.maximum_turns = 1
        stream.maximum_tools = NATIVE_LIMITS["maximum_observed_tool_calls"] - len(self._tool_ids)
        self._streams.append(stream)

    def accept(self, stream: NativeStream, event: Mapping[str, Any]) -> None:
        if (
            not self._streams
            or stream is not self._streams[-1]
            or len(self._streams) != len(self._known) + 1
            or frozenset(stream.allowed) != self._allowed
        ):
            raise uncertain("native_sequence_invalid")
        stream.accept(event)
        if event.get("type") == "tool_call" and event.get("toolCallId") in self._tool_ids:
            raise uncertain("native_tool_identity_invalid")

    def _append(self, stream: NativeStream, value: ProviderResult | ProviderUsageSnapshot) -> None:
        if (
            self._failed
            or not self._streams
            or stream is not self._streams[-1]
            or len(self._streams) != len(self._known) + 1
            or len(value.native_invocations) != 1
        ):
            raise uncertain("native_sequence_invalid")
        invocation = value.native_invocations[0]
        if (
            type(invocation) is not NativeInvocationUsage
            or invocation.session_id != self.session_id
            or any(item.request_id == invocation.request_id for item in self._known)
            or set(stream.tools) & self._tool_ids
            or value.response_id != native_sequence_identity((invocation,))
            or value.credential_route != NATIVE_ROUTE
            or invocation.tool_calls != len(stream.tools)
            or any(not tool["complete"] for tool in stream.tools.values())
            or any(
                getattr(value, name) != getattr(invocation, name)
                for name in (
                    "input_tokens",
                    "cached_input_tokens",
                    "output_tokens",
                    "reasoning_tokens",
                    "total_tokens",
                )
            )
            or value.server_side_tool_calls != invocation.tool_calls
        ):
            raise uncertain("native_sequence_invalid")
        self._known += (invocation,)
        self._tool_ids.update(stream.tools)

    def add(self, stream: NativeStream, result: ProviderResult) -> None:
        self._append(stream, result)
        self._last_result = result
        invocation = self._known[-1]
        if (
            invocation.model_turns != 1
            or stream.observed_model_turns != 1
            or invocation.input_tokens > 500_000
            or sum(item.input_tokens for item in self._known) > 1_500_000
            or len(self._tool_ids) > NATIVE_LIMITS["maximum_observed_tool_calls"]
            or invocation.bounded_turn_limit != stream.bounded_continuation
            or (not stream.bounded_continuation and invocation.stop_reason != "end_turn")
        ):
            self._failed = True
            self._raise_failure("provider_token_usage_exceeded", result)
        self._citations.update(result.citation_urls)

    def add_failure(
        self, stream: NativeStream, snapshot: ProviderUsageSnapshot
    ) -> ProviderUsageSnapshot | None:
        """Close a known failed segment; never make it eligible for continuation."""
        self._append(stream, snapshot)
        self._failed = True
        return self._snapshot(
            request_bytes=snapshot.request_bytes,
            response_bytes=snapshot.response_bytes,
            elapsed_ms=snapshot.elapsed_milliseconds,
        )

    def _snapshot(
        self, *, request_bytes: int, response_bytes: int, elapsed_ms: int
    ) -> ProviderUsageSnapshot | None:
        if not self._known:
            raise uncertain("native_usage_invalid")
        counts = {
            name: sum(getattr(item, name) for item in self._known)
            for name in (
                "input_tokens",
                "cached_input_tokens",
                "output_tokens",
                "reasoning_tokens",
                "total_tokens",
            )
        }
        if (
            counts["input_tokens"] > XAI_MAX_INPUT_TOKENS
            or counts["output_tokens"] > XAI_MAX_OUTPUT_TOKENS
            or counts["total_tokens"] > XAI_MAX_TOTAL_TOKENS
        ):
            return None
        if any(
            type(value) is not int or value < 0
            for value in (request_bytes, response_bytes, elapsed_ms)
        ):
            raise uncertain("native_usage_invalid")
        return ProviderUsageSnapshot(
            response_id=native_sequence_identity(self._known),
            server_side_tool_calls=sum(item.tool_calls for item in self._known),
            request_bytes=request_bytes,
            response_bytes=response_bytes,
            elapsed_milliseconds=elapsed_ms,
            credential_route=NATIVE_ROUTE,
            native_invocations=self._known,
            **counts,
        )

    def snapshot(
        self, *, request_bytes: int, response_bytes: int, elapsed_ms: int
    ) -> ProviderUsageSnapshot:
        snapshot = self._snapshot(
            request_bytes=request_bytes, response_bytes=response_bytes, elapsed_ms=elapsed_ms
        )
        if snapshot is None:
            raise uncertain("native_usage_invalid")
        return snapshot

    def _raise_failure(self, code: str, latest: ProviderResult | ProviderUsageSnapshot) -> None:
        snapshot = self._snapshot(
            request_bytes=latest.request_bytes,
            response_bytes=latest.response_bytes,
            elapsed_ms=latest.elapsed_milliseconds,
        )
        raise ScheduledProviderError(
            code, retryable=False, usage_uncertain=snapshot is None, exact_usage=snapshot
        )

    def result(self, *, request_bytes: int, response_bytes: int, elapsed_ms: int) -> ProviderResult:
        snapshot = self.snapshot(
            request_bytes=request_bytes, response_bytes=response_bytes, elapsed_ms=elapsed_ms
        )
        if (
            self._failed
            or self._last_result is None
            or len(self._streams) != len(self._known)
            or self._known[-1].bounded_turn_limit
            or self._known[-1].stop_reason != "end_turn"
        ):
            self._raise_failure("native_response_incomplete", snapshot)
        if (
            request_bytes > 65_536
            or response_bytes > 1_048_576
            or elapsed_ms > NATIVE_LIMITS["maximum_elapsed_seconds"] * 1000
        ):
            self._raise_failure("native_attempt_limit_exceeded", snapshot)
        return ProviderResult(
            output_text=self._last_result.output_text,
            citation_urls=tuple(sorted(self._citations)),
            **{name: getattr(snapshot, name) for name in snapshot.__dataclass_fields__},
        )
