"""Independent signature checks for contributor verification tools."""

import base64
import hashlib
import json
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CANON = "smithguard-canonical-json-v1"


def canonical(value):
    # Deliberately independent of the service's signer/encoder.
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def exclusive_json(path, value):
    with path.open("x") as f:
        json.dump(value, f, indent=2, allow_nan=False)
        f.write("\n")


def timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.utcoffset() is None:
        raise ValueError("timestamp has no timezone")
    return parsed


def verify_signature(body, key):
    sig = body["signature"]
    if key.get("status") != "active":
        raise ValueError("current answer must use an active key")
    for field, expected in (("algorithm", "Ed25519"), ("canonicalization", CANON)):
        if sig[field] != expected or key[field] != expected:
            raise ValueError("signature metadata mismatch")
    if sig["public_key_id"] != key["public_key_id"]:
        raise ValueError("signing key identity mismatch")
    raw_key = base64.b64decode(key["public_key_base64"], validate=True)
    key_hash = "sha256:" + hashlib.sha256(raw_key).hexdigest()
    derived_id = (
        "gbsec:snapshot-public-key:" + hashlib.sha256(key_hash.encode("ascii")).hexdigest()[:40]
    )
    if key["public_key_id"] != derived_id:
        raise ValueError("key ID does not bind the public key bytes")
    public = Ed25519PublicKey.from_public_bytes(raw_key)
    public.verify(
        base64.b64decode(sig["value"], validate=True),
        canonical({k: v for k, v in body.items() if k != "signature"}),
    )
