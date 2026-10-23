"""Ed25519 signing for assessment answers and the public key document.

Every public assessment response is signed (``signature_for``); the snapshot producer
and verifier were removed with the retired public feed, and retained snapshot
envelopes keep their shape.
"""

from __future__ import annotations

import base64
import os
import stat
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from smithguard.identifiers import canonical_json_bytes, sha256_id, stable_id

MAX_SNAPSHOT_BYTES = 16_777_216
SNAPSHOT_CANONICALIZATION = "smithguard-canonical-json-v1"


class SnapshotSigner:
    """An injected Ed25519 signer; private key material is never persisted here."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        public_bytes = private_key.public_key().public_bytes(
            Encoding.Raw,
            PublicFormat.Raw,
        )
        self.public_key_bytes = public_bytes
        self.public_key_id = stable_id("snapshot-public-key", sha256_id(public_bytes))

    @classmethod
    def ephemeral(cls) -> SnapshotSigner:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_private_key_file(cls, path: Path) -> SnapshotSigner:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("snapshot private key path must be a regular file")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise ValueError("snapshot private key path must be a regular file")
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise ValueError("snapshot private key path changed while opening")
            mode = stat.S_IMODE(opened.st_mode)
            if mode & 0o077:
                raise PermissionError(
                    "snapshot private key file must not be group or world accessible"
                )
            body = os.read(descriptor, 33)
        finally:
            os.close(descriptor)
        return cls.from_private_key_bytes(body)

    @classmethod
    def from_private_key_bytes(cls, body: bytes) -> SnapshotSigner:
        """Load exactly one raw Ed25519 key supplied by a trusted secret reader."""
        if len(body) != 32:
            raise ValueError("snapshot private key must contain 32 raw bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(body))

    @classmethod
    def generate_private_key_bytes(cls) -> bytes:
        return Ed25519PrivateKey.generate().private_bytes(
            Encoding.Raw,
            PrivateFormat.Raw,
            NoEncryption(),
        )

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data)

    def signature_for(self, document: dict[str, Any]) -> dict[str, str]:
        """Sign the canonical JSON of a response document (without its signature)."""
        return {
            "algorithm": "Ed25519",
            "public_key_id": self.public_key_id,
            "canonicalization": SNAPSHOT_CANONICALIZATION,
            "value": base64.b64encode(self.sign(canonical_json_bytes(document))).decode("ascii"),
        }

    def public_key_document(self) -> dict[str, str]:
        return {
            "algorithm": "Ed25519",
            "public_key_id": self.public_key_id,
            "public_key_base64": base64.b64encode(self.public_key_bytes).decode("ascii"),
            "status": "active",
            "canonicalization": SNAPSHOT_CANONICALIZATION,
        }
