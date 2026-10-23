"""Immutable warning-lane receipts.

Receipts record dispatch, usage, rejection and failure per provider attempt. The
``provider_cost_observed`` receipt type keeps its historical name; since September
18, 2026 it carries token and tool usage only, never a price or cost.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from smithguard.db.jobs import enqueue
from smithguard.db.models import JobRecord
from smithguard.identifiers import (
    REASON_CODE_SHORT,
    canonical_json_bytes,
    require_aware_utc,
    sha256_id,
    timestamp,
)
from smithguard.native_usage import (
    NativeInvocationUsage,
    native_sequence_identity,
    validate_native_invocations,
)
from smithguard.spend import NATIVE_SUBSCRIPTION_CONTRACT
from smithguard.xai_settings import (
    XAI_MAX_INPUT_TOKENS,
    XAI_MAX_OUTPUT_TOKENS,
    XAI_MAX_RECEIPT_REQUEST_BYTES,
    XAI_MAX_RESPONSE_BYTES,
    XAI_MAX_TOTAL_TOKENS,
)

RECEIPT_QUEUE = "ai-warning-receipts"
RECEIPT_JOB_TYPE = "immutable_warning_lane_receipt"
REASON_PATTERN = REASON_CODE_SHORT
MAX_RECEIPT_BYTES = 32 * 1024


class WarningLaneReceiptError(ValueError):
    """A receipt or provider-cost reconciliation is malformed."""


@dataclass(frozen=True, slots=True)
class ProviderUsage:
    """Trusted provider usage for one request: tokens, tools, bytes and time, no cost."""

    stage: str
    model: str
    response_id: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    cached_input_tokens: int
    reasoning_tokens: int
    server_side_tool_calls: int
    configured_maximum_turns: int
    request_bytes: int
    elapsed_milliseconds: int
    response_bytes: int = 0
    credential_route: str | None = None
    native_invocations: tuple[NativeInvocationUsage, ...] = ()


def _aware(value: datetime) -> datetime:
    try:
        return require_aware_utc(value)
    except ValueError as error:
        raise WarningLaneReceiptError("receipt time must be timezone-aware") from error


def content_hash(value: Mapping[str, Any]) -> str:
    """The one content hash of a canonical JSON document (receipt cores, request bodies)."""
    return sha256_id(canonical_json_bytes(value))


def _provider_document(value: ProviderUsage) -> dict[str, Any]:
    if value.credential_route not in {None, "api_key", "grok_build_subscription"}:
        raise WarningLaneReceiptError("provider credential route is invalid")
    text_fields = {
        "stage": (value.stage, 40),
        "model": (value.model, 80),
        "response_id": (value.response_id, 512),
    }
    for field, (item, maximum) in text_fields.items():
        if not isinstance(item, str) or not item.isascii() or not 1 <= len(item) <= maximum:
            raise WarningLaneReceiptError(f"provider {field} is invalid")
    counts = {
        "input_tokens": (value.input_tokens, XAI_MAX_INPUT_TOKENS),
        "output_tokens": (value.output_tokens, XAI_MAX_OUTPUT_TOKENS),
        "total_tokens": (value.total_tokens, XAI_MAX_TOTAL_TOKENS),
        "cached_input_tokens": (value.cached_input_tokens, XAI_MAX_INPUT_TOKENS),
        "reasoning_tokens": (value.reasoning_tokens, XAI_MAX_OUTPUT_TOKENS),
        "server_side_tool_calls": (value.server_side_tool_calls, 100),
        "configured_maximum_turns": (value.configured_maximum_turns, 10),
        "request_bytes": (value.request_bytes, XAI_MAX_RECEIPT_REQUEST_BYTES),
        "elapsed_milliseconds": (value.elapsed_milliseconds, 600_000),
        "response_bytes": (value.response_bytes, XAI_MAX_RESPONSE_BYTES),
    }
    for field, (item, maximum) in counts.items():
        if isinstance(item, bool) or not isinstance(item, int) or not 0 <= item <= maximum:
            raise WarningLaneReceiptError(f"provider {field} is invalid")
    if value.total_tokens != value.input_tokens + value.output_tokens:
        raise WarningLaneReceiptError("provider token totals are inconsistent")
    if value.cached_input_tokens > value.input_tokens:
        raise WarningLaneReceiptError("cached input exceeds total input")
    native = value.credential_route == "grok_build_subscription"
    try:
        validate_native_invocations(value.native_invocations)
    except ValueError as error:
        raise WarningLaneReceiptError("native invocation ledger invalid") from error
    if value.native_invocations:
        if not native or native_sequence_identity(value.native_invocations) != value.response_id:
            raise WarningLaneReceiptError("native invocation identities inconsistent")
        for field in (
            "input_tokens",
            "output_tokens",
            "total_tokens",
            "cached_input_tokens",
            "reasoning_tokens",
        ):
            if sum(getattr(item, field) for item in value.native_invocations) != getattr(
                value, field
            ):
                raise WarningLaneReceiptError("native invocation totals inconsistent")
        if (
            sum(item.tool_calls for item in value.native_invocations)
            != value.server_side_tool_calls
        ):
            raise WarningLaneReceiptError("native invocation tool totals inconsistent")
    return {
        **(
            {
                "identity_scope": (
                    "native_harness_session_and_ordered_requests"
                    if value.native_invocations
                    else "native_harness_session_and_request"
                ),
                "model_scope": "requested_model",
                "actual_model": NATIVE_SUBSCRIPTION_CONTRACT["actual_model"],
                "request_bytes_scope": "input_prompts"
                if value.native_invocations
                else "input_prompt",
                "response_bytes_scope": "stdout_and_stderr_stream",
                "tool_calls_scope": "native_backend_search_and_local_web_fetch",
            }
            if native
            else {}
        ),
        **(
            {"native_invocations": [item.metadata() for item in value.native_invocations]}
            if value.native_invocations
            else {}
        ),
        **(
            {"credential_route": value.credential_route}
            if value.credential_route is not None
            else {}
        ),
        "stage": value.stage,
        "model": value.model,
        "response_id_sha256": sha256_id(value.response_id.encode("utf-8")),
        "input_tokens": value.input_tokens,
        "output_tokens": value.output_tokens,
        "total_tokens": value.total_tokens,
        "cached_input_tokens": value.cached_input_tokens,
        "reasoning_tokens": value.reasoning_tokens,
        ("tool_calls" if native else "server_side_tool_calls"): value.server_side_tool_calls,
        "configured_maximum_turns": value.configured_maximum_turns,
        "request_bytes": value.request_bytes,
        "elapsed_milliseconds": value.elapsed_milliseconds,
        "response_bytes": value.response_bytes,
    }


def append_warning_lane_receipt(
    session: Session,
    *,
    receipt_type: str,
    reason_code: str,
    run_id: str,
    job_id: str | None = None,
    occurred_at: datetime,
    public_metadata: Mapping[str, Any],
    provider_usage: ProviderUsage | None = None,
) -> JobRecord:
    """Append one immutable, immediately completed receipt to the recovered jobs table."""
    now = _aware(occurred_at)
    if not REASON_PATTERN.fullmatch(receipt_type) or not REASON_PATTERN.fullmatch(reason_code):
        raise WarningLaneReceiptError("receipt code is invalid")
    if not isinstance(run_id, str) or not 1 <= len(run_id) <= 512:
        raise WarningLaneReceiptError("receipt run ID is invalid")
    receipt_job_id = run_id if job_id is None else job_id
    if not isinstance(receipt_job_id, str) or not 1 <= len(receipt_job_id) <= 512:
        raise WarningLaneReceiptError("receipt job ID is invalid")
    if not isinstance(public_metadata, Mapping):
        raise WarningLaneReceiptError("receipt metadata is invalid")
    if receipt_type == "provider_failure" and (
        not isinstance(public_metadata.get("error_class"), str)
        or re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,79}", public_metadata["error_class"]) is None
    ):
        raise WarningLaneReceiptError("provider failure error class is invalid")
    core: dict[str, Any] = {
        "schema_version": "3.1.0"
        if provider_usage is not None and provider_usage.native_invocations
        else "3.0.0"
        if provider_usage is not None
        and provider_usage.credential_route == "grok_build_subscription"
        else "2.1.0",
        "receipt_type": receipt_type,
        "reason_code": reason_code,
        "run_id": run_id,
        "job_id_sha256": sha256_id(receipt_job_id.encode("utf-8")),
        "occurred_at": timestamp(now),
        "public_metadata": dict(public_metadata),
        "provider": _provider_document(provider_usage) if provider_usage is not None else None,
    }
    payload = {**core, "receipt_sha256": content_hash(core)}
    if len(canonical_json_bytes(payload)) > MAX_RECEIPT_BYTES:
        raise WarningLaneReceiptError("receipt payload is too large")
    record, created = enqueue(
        session,
        queue=RECEIPT_QUEUE,
        job_type=RECEIPT_JOB_TYPE,
        idempotency_key=f"receipt:{payload['receipt_sha256']}",
        payload=payload,
        payload_classification="internal_control",
        max_attempts=1,
        available_at=now,
        now=now,
    )
    if created:
        record.state = "succeeded"
        record.completed_at = now
        record.updated_at = now
        session.flush()
    elif record.state != "succeeded" or record.payload != payload:
        raise WarningLaneReceiptError("receipt state conflicts with immutable history")
    return record
