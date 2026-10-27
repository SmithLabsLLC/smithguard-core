import base64
import copy
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from smithguard_client.verification import strict_json, verify_assessment

NOW = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)


def oracle_encode(value):
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


@pytest.fixture
def signed():
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    kid = (
        "gbsec:snapshot-public-key:"
        + hashlib.sha256(("sha256:" + hashlib.sha256(pub).hexdigest()).encode()).hexdigest()[:40]
    )
    public = {
        "algorithm": "Ed25519",
        "canonicalization": "smithguard-canonical-json-v1",
        "public_key_id": kid,
        "public_key_base64": base64.b64encode(pub).decode(),
        "status": "active",
    }
    body = json.loads(Path(__file__).with_name("assessment-example.json").read_text())
    body["updated_at"] = NOW.isoformat().replace("+00:00", "Z")
    body.update(
        reason_codes=["identity_unverified"],
        identity_assurance="caller_asserted",
        local_applicability="not_evaluated",
        registry_project_context=None,
    )
    for incident in body["incidents"]:
        incident.update(
            source_fixed_versions=[],
            fix_evidence_incomplete=False,
            local_applicability="not_evaluated",
        )
        for report in incident["source_reports"]:
            report.update(
                source_fixed_versions=[],
                fix_evidence_incomplete=False,
                local_applicability="not_evaluated",
                fix_evidence=[],
                range_bound_evidence=[],
                historical_metadata_incomplete=False,
                source_context=None,
                source_context_state="unavailable",
            )

    def sign(value):
        value = copy.deepcopy(value)
        value.pop("signature", None)
        value["signature"] = {
            "algorithm": "Ed25519",
            "canonicalization": "smithguard-canonical-json-v1",
            "public_key_id": kid,
            "value": base64.b64encode(key.sign(oracle_encode(value))).decode(),
        }
        return oracle_encode(value)

    return body, public, sign


def check(signed, raw=None, **kwargs):
    body, key, sign = signed
    args = {
        "expected_artifact": body["artifact"],
        "key_raw": oracle_encode(key),
        "key_fetched_at": NOW,
        "now": NOW,
    }
    args.update(kwargs)
    return verify_assessment(sign(body) if raw is None else raw, **args)


@pytest.mark.parametrize("schema", ["2.1.0", "2.2.0", "2.3.0", "2.4.0"])
def test_original_signed_document_and_old_schema(signed, schema):
    signed[0]["schema_version"] = schema
    v = check(signed)
    assert v.status == "verified" and v.current_decision_eligible
    changed = v.document
    changed["artifact"]["name"] = "changed"
    assert v.document["artifact"]["name"] != "changed"


@pytest.mark.parametrize(
    "field,value", [("result", "unknown"), ("unknowns", ["changed"]), ("feed_revision", "changed")]
)
def test_signed_field_tampering(signed, field, value):
    body = json.loads(signed[2](signed[0]))
    body[field] = value
    assert check(signed, oracle_encode(body)).status == "invalid"


@pytest.mark.parametrize(
    "raw",
    [
        b'{"x":1,"x":2}',
        b'{"x":NaN}',
        b'{"x":1e999}',
        b'{"x":"\\ud800"}',
        b"\xff",
        b"[]",
        b"{" * 1000,
    ],
)
def test_ambiguous_invalid_json(raw):
    with pytest.raises((ValueError, UnicodeError, RecursionError)):
        strict_json(raw)


def test_limits():
    with pytest.raises(ValueError):
        strict_json(b" " * 1_048_577)
    with pytest.raises(ValueError):
        strict_json(b'{"x":' + b"[" * 66 + b"0" + b"]" * 66 + b"}")


@pytest.mark.parametrize(
    "state,expected",
    [("revoked", "invalid"), ("verification_only", "invalid"), ("mystery", "unchecked")],
)
def test_key_states(signed, state, expected):
    signed[1]["status"] = state
    assert check(signed).status == expected


def test_historical_retired_key_not_current_eligible(signed):
    signed[1]["status"] = "verification_only"
    v = check(signed, historical=True)
    assert v.status == "verified" and not v.current_decision_eligible


def test_offline_key_has_math_proof_without_current_trust(signed):
    v = check(signed, key_fetched_at=None)
    assert v.status == "unchecked" and v.signature_valid and not v.current_decision_eligible


def test_key_age_and_response_age_are_separate(signed):
    assert check(signed, key_fetched_at=NOW - timedelta(hours=1)).status == "unchecked"
    signed[0]["updated_at"] = (NOW - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    v = check(signed)
    assert v.status == "verified" and not v.response_fresh and not v.current_decision_eligible


def test_unknown_formats_and_missing_key(signed):
    assert check(signed, key_raw=None).status == "unchecked"
    signed[0]["schema_version"] = "999.0.0"
    assert check(signed).reason == "unsupported_schema"


def test_coordinate_and_key_identity(signed):
    artifact = {**signed[0]["artifact"], "name": "other"}
    assert check(signed, expected_artifact=artifact).reason == "coordinate_mismatch"
    signed[1]["public_key_id"] += "a"
    assert check(signed).reason == "key_identity_mismatch"


@pytest.mark.parametrize("field", ["reason_codes", "identity_assurance", "local_applicability"])
def test_signed_new_schema_missing_required_field_rejected(signed, field):
    signed[0]["schema_version"] = "2.4.0"
    del signed[0][field]
    assert check(signed).reason == "schema_validation_failed"


@pytest.mark.parametrize(
    "field",
    [
        "fix_evidence",
        "source_context_state",
        "source_fixed_versions",
        "historical_metadata_incomplete",
    ],
)
def test_signed_new_schema_incomplete_source_report_rejected(signed, field):
    signed[0]["schema_version"] = "2.4.0"
    del signed[0]["incidents"][0]["source_reports"][0][field]
    assert check(signed).reason == "schema_validation_failed"


@pytest.mark.parametrize("seconds,eligible", [(30, True), (31, False), (-300, True), (-301, False)])
def test_response_clock_skew_is_bounded(signed, seconds, eligible):
    signed[0]["updated_at"] = (NOW + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
    value = check(signed)
    assert value.status == "verified"
    assert value.response_fresh is eligible
    assert value.current_decision_eligible is eligible
