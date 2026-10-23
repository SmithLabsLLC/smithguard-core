"""Content-free accounting for bounded invocations of one native RAM session."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from smithguard.identifiers import sha256_id
from smithguard.xai_settings import (
    XAI_MAX_INPUT_TOKENS,
    XAI_MAX_OUTPUT_TOKENS,
    XAI_MAX_TOTAL_TOKENS,
)


@dataclass(frozen=True, slots=True)
class NativeInvocationUsage:
    """One complete terminal ledger, including rejected over-limit usage.

    These are storage limits, not permission to consume them. The native sequence
    separately enforces input, model-turn, tool, byte and elapsed-time bounds.
    Output tokens have no operational budget; their integer representation and
    exact ledger relationships must still be valid.
    """

    session_id: str
    request_id: str
    input_tokens: int
    cached_input_tokens: int
    output_tokens: int
    reasoning_tokens: int
    total_tokens: int
    model_turns: int
    tool_calls: int
    stop_reason: str
    bounded_turn_limit: bool = False

    def __post_init__(self) -> None:
        for value in (self.session_id, self.request_id):
            if not isinstance(value, str) or str(UUID(value)) != value:
                raise ValueError("native invocation identity invalid")
        for value, maximum in (
            (self.input_tokens, XAI_MAX_INPUT_TOKENS),
            (self.cached_input_tokens, XAI_MAX_INPUT_TOKENS),
            (self.output_tokens, XAI_MAX_OUTPUT_TOKENS),
            (self.reasoning_tokens, XAI_MAX_OUTPUT_TOKENS),
            (self.total_tokens, XAI_MAX_TOTAL_TOKENS),
            (self.model_turns, 10),
            (self.tool_calls, 4),
        ):
            if type(value) is not int or not 0 <= value <= maximum:
                raise ValueError("native invocation count invalid")
        if (
            self.model_turns < 1
            or self.total_tokens != self.input_tokens + self.output_tokens
            or self.cached_input_tokens > self.input_tokens
            or self.reasoning_tokens > self.output_tokens
            or self.stop_reason
            not in {"end_turn", "max_tokens", "max_turn_requests", "refusal", "cancelled"}
            or type(self.bounded_turn_limit) is not bool
            or (
                self.bounded_turn_limit
                and (self.stop_reason != "cancelled" or self.model_turns != 1)
            )
        ):
            raise ValueError("native invocation ledger inconsistent")

    def metadata(self) -> dict[str, str | int | bool]:
        return {
            "session_id_sha256": sha256_id(self.session_id.encode("ascii")),
            "request_id_sha256": sha256_id(self.request_id.encode("ascii")),
            "input_tokens": self.input_tokens,
            "cached_input_tokens": self.cached_input_tokens,
            "output_tokens": self.output_tokens,
            "reasoning_tokens": self.reasoning_tokens,
            "total_tokens": self.total_tokens,
            "model_turns": self.model_turns,
            "tool_calls": self.tool_calls,
            "stop_reason": self.stop_reason,
            "bounded_turn_limit": self.bounded_turn_limit,
        }


def validate_native_invocations(value: tuple[NativeInvocationUsage, ...]) -> None:
    if (
        type(value) is not tuple
        or len(value) > 3
        or any(type(item) is not NativeInvocationUsage for item in value)
        or len({item.session_id for item in value}) > 1
        or len({item.request_id for item in value}) != len(value)
    ):
        raise ValueError("native invocation sequence invalid")


def native_sequence_identity(value: tuple[NativeInvocationUsage, ...]) -> str:
    validate_native_invocations(value)
    if not value:
        raise ValueError("native invocation sequence empty")
    return f"grok-build:{value[0].session_id}:" + ",".join(item.request_id for item in value)
