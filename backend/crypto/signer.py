from __future__ import annotations

import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_PRIVATE_KEY: Ed25519PrivateKey | None = None


def _get_private_key() -> Ed25519PrivateKey:
    global _PRIVATE_KEY
    if _PRIVATE_KEY is None:
        configured_key = os.environ.get("EVIDENCE_SIGNING_PRIVATE_KEY")
        if configured_key:
            _PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(configured_key))
        else:
            _PRIVATE_KEY = Ed25519PrivateKey.generate()
    return _PRIVATE_KEY


def sign_event_data(event_data: str) -> str:
    return _get_private_key().sign(event_data.encode("utf-8")).hex()


def get_signing_public_key() -> str:
    public_key = _get_private_key().public_key()
    raw_key = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw_key.hex()


def get_signing_key_mode() -> str:
    return "configured" if os.environ.get("EVIDENCE_SIGNING_PRIVATE_KEY") else "ephemeral_demo"
