"""Portable committed vectors; signing keys are never retained in these fixtures."""

import hashlib
import json
from datetime import datetime
from pathlib import Path

import pytest

from smithguard_client.verification import canonical, strict_json, verify_assessment

VECTORS = Path(__file__).with_name("conformance")
CANONICAL = json.loads((VECTORS / "canonical-v1.json").read_text())
SIGNED = json.loads((VECTORS / "assessment-v1.json").read_text())
CASES = json.loads((VECTORS / "verification-cases-v1.json").read_text())["cases"]


@pytest.mark.parametrize("row", CANONICAL["positive"], ids=lambda row: row["id"])
def test_canonical_bytes(row):
    actual = canonical(strict_json(row["input_utf8"].encode()))
    assert actual == row["canonical_ascii"].encode("ascii")
    assert actual.hex() == row["canonical_hex"]
    assert hashlib.sha256(actual).hexdigest() == row["sha256"]


@pytest.mark.parametrize("row", CANONICAL["reject"], ids=lambda row: row["id"])
def test_reject_ambiguous_input(row):
    with pytest.raises((ValueError, UnicodeError, RecursionError)):
        raw = bytes.fromhex(row["input_hex"]) if "input_hex" in row else row["input_utf8"].encode()
        strict_json(raw)


@pytest.mark.parametrize("row", CASES, ids=lambda row: row["id"])
def test_verification_outcomes(row):
    result = verify_assessment(
        row["assessment_utf8"].encode(),
        expected_artifact=row["expected_artifact"],
        key_raw=row["key_utf8"].encode() if row["key_utf8"] is not None else None,
        now=datetime.fromisoformat(row["now"]),
        key_fetched_at=(
            datetime.fromisoformat(row["key_fetched_at"]) if row["key_fetched_at"] else None
        ),
        historical=row["historical"],
    )
    assert {key: getattr(result, key) for key in row["expected"]} == row["expected"]


def test_signed_canonical_bytes():
    body = strict_json(SIGNED["assessment_utf8"].encode())
    body.pop("signature")
    actual = canonical(body)
    assert actual.hex() == SIGNED["signed_canonical_hex"]
    assert hashlib.sha256(actual).hexdigest() == SIGNED["signed_sha256"]
