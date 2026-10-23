"""Regression checks for the October 2026 eMudhra trust-store incident.

Public certificate-only fixtures pass through the running Python TLS verifier in
memory. There are no sockets, private keys, fabricated certificates or completed
TLS sessions. Positive controls distinguish trust rejection from invalid inputs.
"""

from __future__ import annotations

import hashlib
import json
import re
import ssl
from datetime import UTC, datetime
from pathlib import Path

import certifi
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

FIXTURES = Path(__file__).parent / "fixtures" / "emudhra_20261020" / "public_chains.json"
PUBLIC = json.loads(FIXTURES.read_text())


def _handshake_message(kind: int, body: bytes) -> bytes:
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def _certificate_stage(context: ssl.SSLContext, chain: str, hostname: str) -> None:
    """Accept the certificate stage or raise the engine's exact verify error."""
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers("ECDHE-ECDSA-AES128-GCM-SHA256")
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = context.wrap_bio(incoming, outgoing, server_side=False, server_hostname=hostname)
    with pytest.raises(ssl.SSLWantReadError):
        client.do_handshake()
    assert outgoing.read()[0] == 22
    # Renegotiation info and extended master secret, matching the client offer.
    extensions = b"\xff\x01\x00\x01\x00\x00\x17\x00\x00"
    server_hello = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00\xc0\x2b\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    certificates = [
        c.public_bytes(serialization.Encoding.DER)
        for c in x509.load_pem_x509_certificates(chain.encode())
    ]
    certificate_list = b"".join(len(c).to_bytes(3, "big") + c for c in certificates)
    handshake = _handshake_message(2, server_hello) + _handshake_message(
        11, len(certificate_list).to_bytes(3, "big") + certificate_list
    )
    incoming.write(b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake)
    # A valid certificate advances to waiting for the remaining server handshake.
    with pytest.raises(ssl.SSLWantReadError):
        client.do_handshake()


def test_fixed_bundle_excludes_every_published_incident_anchor() -> None:
    # Hash DER identities without parsing unrelated legacy certificate fields.
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        Path(certifi.where()).read_text(),
        flags=re.DOTALL,
    )
    assert blocks
    installed = {hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest() for pem in blocks}
    for root in PUBLIC["roots"]:
        certificate = x509.load_pem_x509_certificate(root["pem"].encode())
        assert certificate.fingerprint(hashes.SHA256()).hex() == root["sha256"]
        assert root["sha256"] not in installed


@pytest.mark.parametrize("chain", PUBLIC["chains"], ids=lambda c: c["hostname"])
def test_published_chain_is_valid_but_rejected_by_fixed_bundle(chain: dict[str, str]) -> None:
    assert hashlib.sha256(chain["pem"].encode()).hexdigest() == chain["sha256"]
    leaf = x509.load_pem_x509_certificates(chain["pem"].encode())[0]
    checked_at = datetime.now(UTC)
    assert leaf.not_valid_before_utc <= checked_at <= leaf.not_valid_after_utc, (
        f"Refresh the public incident fixtures: leaf validity ends "
        f"{leaf.not_valid_after_utc.isoformat()}; verification clock "
        f"{checked_at.isoformat()}. Do not skip the positive control or accept "
        "an expiry error as proof of a valid TLS path."
    )
    # Trust only the final anchor for this path, so trusted-first cannot bypass
    # the compromised cross-sign link by selecting another self-signed root.
    anchor = (
        "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4"
        if "-aaa-" in chain["hostname"]
        else "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b"
    )
    control = ssl.create_default_context(
        cadata=next(root["pem"] for root in PUBLIC["roots"] if root["sha256"] == anchor)
    )
    _certificate_stage(control, chain["pem"], chain["hostname"])

    candidate = ssl.create_default_context(cafile=certifi.where())
    with pytest.raises(ssl.SSLCertVerificationError) as rejected:
        _certificate_stage(candidate, chain["pem"], chain["hostname"])
    # Missing issuer, not expired fixtures, purpose mismatch or malformed input.
    assert rejected.value.verify_code in (20, 21)
