"""One home for the small shared routines: deterministic identifiers and the canonical
JSON encoders, the strict bounded JSON loader and its reason taxonomy, timestamp
parsing and its reason taxonomy, the JSON shape bounds (provider, ingest, register) and
the shared identifier grammars.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator, Mapping, Sequence
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any


def canonical_json_bytes(value: Any) -> bytes:
    """Return the one canonical JSON representation used for local hashes."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def sha256_id(data: bytes) -> str:
    return "sha256:" + sha256(data).hexdigest()


def stable_id(namespace: str, *parts: str | Mapping[str, Any] | Sequence[Any]) -> str:
    """Build a non-reversible stable ID from bounded canonical inputs."""
    encoded: list[bytes] = []
    for part in parts:
        if isinstance(part, str):
            encoded.append(part.encode("utf-8"))
        else:
            encoded.append(canonical_json_bytes(part))
    digest = sha256(b"\x1f".join(encoded)).hexdigest()
    return f"gbsec:{namespace}:{digest[:40]}"


def timestamp(value: datetime) -> str:
    """Render a timezone-aware value in the frozen contract's UTC form."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def canonical_json_line(value: Any) -> bytes:
    """The canonical representation plus one newline, for line-oriented journals."""
    return canonical_json_bytes(value) + b"\n"


def pretty_json_bytes(value: Any) -> bytes:
    """The indented ASCII representation with a trailing newline, for human files."""
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"
    ).encode("ascii")


class TimestampError(ValueError):
    """A timestamp value was rejected; ``reason`` is bounded, format or naive."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def require_aware_utc(value: datetime) -> datetime:
    """Return ``value`` converted to UTC; reject naive or offset-less datetimes."""
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise TimestampError("naive", "timestamp must be timezone-aware")
    return value.astimezone(UTC)


def parse_timestamp(value: object, *, maximum: int = 64) -> datetime:
    """Parse the frozen contract's UTC form (or any ISO offset form) into an aware UTC value.

    Callers keep their own length bound and wrap the TimestampError in their domain error,
    branching on ``reason`` rather than on the message.
    """
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise TimestampError("bounded", "timestamp must be a bounded string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise TimestampError("format", "timestamp is not ISO 8601") from error
    return require_aware_utc(parsed)


class StrictJsonError(ValueError):
    """A document failed strict JSON loading.

    ``reason`` names the failure class for callers: invalid, duplicate_key,
    non_finite, too_many_nodes, too_deep. The message never embeds document content.
    """

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


class DuplicateJsonKeyError(StrictJsonError):
    """A JSON object repeated a key."""

    def __init__(self) -> None:
        super().__init__("duplicate_key", "JSON object repeats a key")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise StrictJsonError("non_finite", "JSON number is not finite")


# Bounds for the committed registers and journals loaded at process start. They are
# small today; the bound is stated here so the ceiling is visible where it applies.
REGISTER_JSON_MAX_NODES = 200_000
REGISTER_JSON_MAX_DEPTH = 32
# Provider output (one model response) and ingest documents (a full advisory page, a
# retained evidence body, a reviewed OpenSSF blob, site metadata) keep distinct headroom.
PROVIDER_JSON_MAX_NODES = 20_000
PROVIDER_JSON_MAX_DEPTH = 32
# Ingest bodies are capped at 8 MiB and a JSON node costs at least two bytes, so the
# node bound below cannot be reached under those caps; the depth bound is the one that
# can, and every ingest site names it.
INGEST_JSON_MAX_NODES = 4_194_304
INGEST_JSON_MAX_DEPTH = 64


def strict_json_loads(
    body: bytes | str,
    *,
    max_nodes: int = PROVIDER_JSON_MAX_NODES,
    max_depth: int = PROVIDER_JSON_MAX_DEPTH,
    on_node: Callable[[], None] | None = None,
    node_stride: int = 128,
) -> Any:
    """Parse JSON strictly: no duplicate keys, no bare NaN/Infinity tokens, bounded shape.

    Out-of-range float literals such as ``1e400`` still parse as ``json.loads`` parses
    them (``parse_float`` is untouched, matching every replaced loader). Bytes are passed
    to ``json.loads`` unchanged, so encoding detection and the BOM rule are exactly its
    own, and a ``UnicodeDecodeError`` or ``RecursionError`` propagates as it did before so
    every adopter keeps its former classification of both.

    Raises StrictJsonError with a ``reason`` (DuplicateJsonKeyError for repeated keys).
    ``on_node`` runs once per ``node_stride`` nodes visited, so callers can enforce a
    deadline without paying for a call per node.
    """
    try:
        document = json.loads(
            body, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant
        )
    except json.JSONDecodeError as error:
        raise StrictJsonError("invalid", "invalid JSON") from error
    # The walk keeps one iterator per open container, so its working set is bounded
    # by the document's depth rather than by its width: a wide array never expands
    # into a stack of its own size before the bound can fire.
    nodes = 0
    stack: list[tuple[Iterator[Any], int]] = [(iter((document,)), 1)]
    while stack:
        iterator, depth = stack[-1]
        try:
            value = next(iterator)
        except StopIteration:
            stack.pop()
            continue
        nodes += 1
        if nodes > max_nodes:
            raise StrictJsonError("too_many_nodes", "JSON document has too many nodes")
        if depth > max_depth:
            raise StrictJsonError("too_deep", "JSON document is nested too deeply")
        if on_node is not None and nodes % node_stride == 0:
            on_node()
        if isinstance(value, dict):
            stack.append((iter(value.values()), depth + 1))
        elif isinstance(value, list):
            stack.append((iter(value), depth + 1))
    return document


# Identifier grammars shared across modules. These strings are frozen: the same text is
# embedded in the generated contract schemas and in PostgreSQL CHECK constraints.
STABLE_ID = re.compile(r"^gbsec:[a-z0-9][a-z0-9:._/-]+$")
SHA256 = re.compile(r"^sha256:[a-f0-9]{64}$")
SHA256_HEX = re.compile(r"^[a-f0-9]{64}$")
SHA1_HEX = re.compile(r"^[a-f0-9]{40}$")
SHARD = re.compile(r"^[a-f0-9]{2}$")
CWE_ID = re.compile(r"^CWE-[1-9][0-9]{0,5}$")
ACTOR_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._/-]{2,159}$")
# Two reason-code grammars are deliberately kept: long (authority, inventory, jobs) and
# short (warning lane receipts and discovery). Unifying them changes which documents exist.
REASON_CODE_LONG = re.compile(r"^[a-z0-9][a-z0-9_]{1,119}$")
REASON_CODE_SHORT = re.compile(r"^[a-z0-9][a-z0-9_]{1,79}$")
