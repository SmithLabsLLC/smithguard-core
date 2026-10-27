"""Verify original assessment JSON; trust and freshness remain separate facts."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

MAX_RESPONSE_BYTES = 1_048_576
CANONICALIZATION = "smithguard-canonical-json-v1"
SCHEMAS = frozenset({"2.1.0", "2.2.0", "2.3.0", "2.4.0"})


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def strict_json(raw: bytes, *, limit: int = MAX_RESPONSE_BYTES) -> dict[str, Any]:
    if not isinstance(raw, bytes) or len(raw) > limit:
        raise ValueError("document byte limit exceeded")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def constant(_value):
        raise ValueError("nonfinite JSON number")

    value = json.loads(
        raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs, parse_constant=constant
    )
    if not isinstance(value, dict):
        raise ValueError("document must be an object")
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 64:
            raise ValueError("JSON nesting limit exceeded")
        if isinstance(item, str):
            item.encode("utf-8", errors="strict")
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError("nonfinite JSON number")
        elif isinstance(item, dict):
            pending.extend((k, depth + 1) for k in item)
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
    return value


@dataclass(frozen=True)
class Verification:
    status: str
    reason: str
    signature_valid: bool
    key_status: str
    key_status_current: bool
    response_fresh: bool
    original: bytes

    @property
    def document(self) -> dict[str, Any]:
        """Return a new parsed view; callers cannot mutate verified stored bytes."""
        return strict_json(self.original)

    @property
    def original_sha256(self) -> str:
        return hashlib.sha256(self.original).hexdigest()

    @property
    def current_decision_eligible(self) -> bool:
        return (
            self.status == "verified"
            and self.key_status == "active"
            and self.key_status_current
            and self.response_fresh
        )


def verify_assessment(
    raw: bytes,
    *,
    expected_artifact: dict[str, Any],
    key_raw: bytes | None,
    key_fetched_at: datetime | None = None,
    now: datetime | None = None,
    historical: bool = False,
    max_age_seconds: int = 300,
) -> Verification:
    """A live HTTPS key read establishes current key status, not source truth.

    Offline keys may prove the signature mathematically, but cannot establish
    current revocation status. No key cache or assessment response is persisted.
    """
    now = now or datetime.now(UTC)
    if now.utcoffset() is None or not 1 <= max_age_seconds <= 3600:
        raise ValueError("aware time and a 1..3600 second age limit required")
    key_status = "unknown"
    key_current = False
    fresh = False

    def result(status, reason, valid=False):
        # An invalid/unchecked document stays available for explicitly labeled
        # display, but downstream decisions must check current_decision_eligible.
        return Verification(status, reason, valid, key_status, key_current, fresh, raw)

    try:
        body = strict_json(raw)
        if body.get("schema_version") not in SCHEMAS:
            return result("unchecked", "unsupported_schema")
        signature = body.get("signature")
        if not isinstance(signature, dict):
            return result("unchecked", "missing_signature")
        if (
            signature.get("algorithm") != "Ed25519"
            or signature.get("canonicalization") != CANONICALIZATION
        ):
            return result("unchecked", "unsupported_signature_format")
        schema = json.loads(
            files("smithguard_client.schemas").joinpath("assessment.json").read_text()
        )
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(body)
        if body["artifact"] != expected_artifact:
            return result("invalid", "coordinate_mismatch")
        if key_raw is None:
            return result("unchecked", "key_unavailable")
        key = strict_json(key_raw, limit=16384)
        if key.get("algorithm") != "Ed25519" or key.get("canonicalization") != CANONICALIZATION:
            return result("unchecked", "unsupported_key_format")
        key_status = key.get("status", "unknown")
        if key_status == "revoked":
            return result("invalid", "key_revoked")
        if key_status not in {"active", "verification_only"}:
            return result("unchecked", "key_status_unknown")
        if key_status == "verification_only" and not historical:
            return result("invalid", "retired_key_for_current_answer")
        key_bytes = base64.b64decode(key["public_key_base64"], validate=True)
        key_hash = "sha256:" + hashlib.sha256(key_bytes).hexdigest()
        key_id = (
            "gbsec:snapshot-public-key:" + hashlib.sha256(key_hash.encode("ascii")).hexdigest()[:40]
        )
        if key["public_key_id"] != key_id or signature["public_key_id"] != key_id:
            return result("invalid", "key_identity_mismatch")
        Ed25519PublicKey.from_public_bytes(key_bytes).verify(
            base64.b64decode(signature["value"], validate=True),
            canonical({k: v for k, v in body.items() if k != "signature"}),
        )
        if key_fetched_at is not None:
            if key_fetched_at.utcoffset() is None:
                return result("unchecked", "key_time_unknown", True)
            key_current = 0 <= (now - key_fetched_at).total_seconds() <= 300
        stamp = datetime.fromisoformat(body["updated_at"].replace("Z", "+00:00"))
        fresh = (
            stamp.utcoffset() is not None
            and -30 <= (now - stamp).total_seconds() <= max_age_seconds
        )
        if not key_current:
            return result("unchecked", "key_status_not_current", True)
        return result(
            "verified", "historical_signature" if historical else "signature_verified", True
        )
    except InvalidSignature:
        return result("invalid", "signature_mismatch")
    except ValueError, TypeError, KeyError, UnicodeError, RecursionError, binascii.Error:
        return result("invalid", "malformed_document_or_key")
    except ValidationError:
        return result("invalid", "schema_validation_failed")
