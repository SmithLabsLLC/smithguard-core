"""Bounded, data-only inspection of hostile evidence bytes."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from typing import Any
from urllib.parse import urlsplit

from smithguard.contracts.runtime import parse_contract

# Only JSON is acquired: archive inspection was removed with its last transport.
JSON_MEDIA_TYPES = {
    "application/json",
    "application/vnd.smithguard.records+json",
}
SUPPORTED_MEDIA_TYPES = set(JSON_MEDIA_TYPES)
SHA256_PREFIX = "sha256:"
WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")


class AcquisitionRejected(ValueError):
    """A hostile or unsupported acquisition failed closed."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class AcquisitionLimits:
    """Hard limits applied before normalization."""

    max_input_bytes: int = 8 * 1024 * 1024
    max_elapsed_seconds: float = 10.0
    max_redirects: int = 2
    max_expanded_bytes: int = 32 * 1024 * 1024
    max_json_depth: int = 32
    max_json_nodes: int = 100_000
    max_records: int = 5_000

    def __post_init__(self) -> None:
        numeric = (
            self.max_input_bytes,
            self.max_expanded_bytes,
            self.max_json_depth,
            self.max_json_nodes,
            self.max_records,
        )
        if any(value < 1 for value in numeric):
            raise ValueError("acquisition limits must be positive")
        if self.max_input_bytes > 52_428_800:
            raise ValueError("input limit exceeds the frozen RawEvidence contract")
        if self.max_elapsed_seconds <= 0:
            raise ValueError("elapsed-time limit must be positive")
        if self.max_redirects < 0:
            raise ValueError("redirect limit cannot be negative")
        if self.max_expanded_bytes < self.max_input_bytes:
            raise ValueError("expanded-byte limit cannot be smaller than input limit")


@dataclass(frozen=True, slots=True)
class AcquisitionRequest:
    """Transport metadata supplied by a later fixed-host connector or replay."""

    source_record_id: str
    canonical_url: str
    retrieved_at: datetime
    source_published_at: datetime | None
    media_type: str
    source_modified_at: datetime | None = None
    declared_content_length: int | None = None
    redirect_count: int = 0
    transport_elapsed_seconds: float = 0.0


@dataclass(frozen=True, slots=True)
class InspectedEvidence:
    """Validated data ready for source-specific normalization."""

    digest: str
    byte_count: int
    media_type: str
    records: tuple[Mapping[str, Any], ...]
    member_names: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OperationDeadline:
    """One monotonic deadline shared across a complete acquisition operation."""

    deadline: float
    clock: Callable[[], float]

    @classmethod
    def start(
        cls,
        max_elapsed_seconds: float,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> OperationDeadline:
        if max_elapsed_seconds <= 0:
            raise ValueError("operation deadline must be positive")
        return cls(deadline=clock() + max_elapsed_seconds, clock=clock)

    def check(self, code: str = "operation_time_limit") -> None:
        if self.clock() >= self.deadline:
            raise AcquisitionRejected(code)

    def remaining_seconds(self) -> float:
        now = self.clock()
        if now >= self.deadline:
            raise AcquisitionRejected("operation_time_limit")
        return max(0.000001, self.deadline - now)


@dataclass(slots=True)
class _Budget:
    limits: AcquisitionLimits
    deadline: OperationDeadline
    expanded_bytes: int = 0

    def check_time(self) -> None:
        self.deadline.check("inspection_time_limit")

    def add_expanded(self, count: int) -> None:
        self.expanded_bytes += count
        if self.expanded_bytes > self.limits.max_expanded_bytes:
            raise AcquisitionRejected("expanded_byte_limit")
        self.check_time()


def _media_type(value: str) -> str:
    parts = [part.strip().lower() for part in value.split(";")]
    media_type = parts[0]
    if media_type not in SUPPORTED_MEDIA_TYPES:
        raise AcquisitionRejected("unexpected_content_type")
    for parameter in parts[1:]:
        if parameter not in {"charset=utf-8", 'charset="utf-8"'}:
            raise AcquisitionRejected("unexpected_content_type_parameter")
    return media_type


def _allowed_https_url(value: str, allowed_hosts: set[str]) -> None:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise AcquisitionRejected("invalid_source_url") from error
    host = (parsed.hostname or "").lower().rstrip(".")
    if (
        parsed.scheme.lower() != "https"
        or not host
        or host not in allowed_hosts
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.fragment
    ):
        raise AcquisitionRejected("source_url_not_allowed")


def _duplicate_key(
    _pairs: list[tuple[str, Any]],
    *,
    budget: _Budget,
) -> Any:
    budget.check_time()
    result: dict[str, Any] = {}
    for key, value in _pairs:
        if key in result:
            raise AcquisitionRejected("duplicate_json_key")
        result[key] = value
    budget.check_time()
    return result


def _json_nodes(value: Any, *, limits: AcquisitionLimits, budget: _Budget) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > limits.max_json_nodes:
            raise AcquisitionRejected("json_node_limit")
        if depth > limits.max_json_depth:
            raise AcquisitionRejected("json_depth_limit")
        if nodes % 256 == 0:
            budget.check_time()
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
    budget.check_time()


def _parse_json(
    data: bytes,
    limits: AcquisitionLimits,
    *,
    budget: _Budget,
    allow_extra_envelope_fields: bool = False,
) -> tuple[Mapping[str, Any], ...]:
    budget.check_time()
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise AcquisitionRejected("malformed_utf8") from error
    if text.startswith("\ufeff") or "\x00" in text:
        raise AcquisitionRejected("malformed_utf8")
    try:
        document = json.loads(
            text,
            object_pairs_hook=lambda pairs: _duplicate_key(pairs, budget=budget),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                AcquisitionRejected("non_finite_json_number")
            ),
        )
    except AcquisitionRejected:
        raise
    except (RecursionError, json.JSONDecodeError) as error:
        raise AcquisitionRejected("malformed_json") from error
    _json_nodes(document, limits=limits, budget=budget)
    if isinstance(document, list):
        records = document
    elif isinstance(document, dict) and "records" in document:
        if not allow_extra_envelope_fields and set(document) - {"schema_version", "records"}:
            raise AcquisitionRejected("unexpected_json_envelope_field")
        records = document["records"]
    elif isinstance(document, dict):
        records = [document]
    else:
        raise AcquisitionRejected("json_record_shape")
    if not isinstance(records, list) or len(records) > limits.max_records:
        raise AcquisitionRejected("record_limit")
    if not records:
        raise AcquisitionRejected("empty_record_set")
    if not all(isinstance(record, dict) for record in records):
        raise AcquisitionRejected("json_record_shape")
    budget.check_time()
    return tuple(records)


def inspect_evidence(
    *,
    source: Mapping[str, Any],
    request: AcquisitionRequest,
    body: bytes,
    limits: AcquisitionLimits | None = None,
    clock: Callable[[], float] = time.monotonic,
    deadline: OperationDeadline | None = None,
    allow_extra_json_envelope_fields: bool = False,
) -> InspectedEvidence:
    """Inspect one complete response without fetching, extracting, or executing it."""
    limits = limits or AcquisitionLimits()
    operation_deadline = deadline or OperationDeadline.start(
        limits.max_elapsed_seconds,
        clock=clock,
    )
    operation_deadline.check()
    source_document = parse_contract("Source", source).model_dump(mode="json", exclude_none=False)
    allowed_hosts = {host.lower().rstrip(".") for host in source_document["allowed_hosts"]}
    _allowed_https_url(request.canonical_url, allowed_hosts)
    if not request.source_record_id or len(request.source_record_id) > 512:
        raise AcquisitionRejected("source_record_id_limit")
    if request.redirect_count < 0 or request.redirect_count > limits.max_redirects:
        raise AcquisitionRejected("redirect_limit")
    if (
        request.transport_elapsed_seconds < 0
        or request.transport_elapsed_seconds > limits.max_elapsed_seconds
    ):
        raise AcquisitionRejected("transport_time_limit")
    if request.declared_content_length is not None:
        if request.declared_content_length < 0:
            raise AcquisitionRejected("invalid_content_length")
        if request.declared_content_length > limits.max_input_bytes:
            raise AcquisitionRejected("input_byte_limit")
        if request.declared_content_length != len(body):
            raise AcquisitionRejected("content_length_mismatch")
    if len(body) > limits.max_input_bytes:
        raise AcquisitionRejected("input_byte_limit")
    if not body:
        raise AcquisitionRejected("empty_input")

    rights = source_document["rights"]
    if rights["retrieval"] != "allowed":
        raise AcquisitionRejected("retrieval_rights_not_approved")
    if rights["decision"] not in {"approved_public", "approved_internal", "approved_link_only"}:
        raise AcquisitionRejected("source_rights_not_approved")
    review_due = datetime.fromisoformat(rights["review_due_on"]).date()
    if request.retrieved_at.date() > review_due:
        raise AcquisitionRejected("source_rights_review_expired")

    media_type = _media_type(request.media_type)
    budget = _Budget(limits=limits, deadline=operation_deadline)
    budget.add_expanded(len(body))
    records = _parse_json(
        body,
        limits,
        budget=budget,
        allow_extra_envelope_fields=allow_extra_json_envelope_fields,
    )
    member_names: tuple[str, ...] = ()
    budget.check_time()
    if not records:
        raise AcquisitionRejected("empty_record_set")
    digest = SHA256_PREFIX + sha256(body).hexdigest()
    return InspectedEvidence(
        digest=digest,
        byte_count=len(body),
        media_type=media_type,
        records=tuple(records),
        member_names=member_names,
    )
