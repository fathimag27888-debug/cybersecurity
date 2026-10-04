from __future__ import annotations

import json
from hashlib import sha256
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

_PRIVATE_KEY = None


def _get_private_key() -> Ed25519PrivateKey:
    global _PRIVATE_KEY
    if _PRIVATE_KEY is None:
        _PRIVATE_KEY = Ed25519PrivateKey.generate()
    return _PRIVATE_KEY


def _canonicalize(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def create_evidence_record(payload: dict[str, Any]) -> dict[str, Any]:
    canonical = _canonicalize(payload)
    digest = sha256(canonical.encode("utf-8")).hexdigest()
    signature = _get_private_key().sign(canonical.encode("utf-8"))
    public_key = _get_private_key().public_key().public_bytes_raw()
    return {
        "payload": payload,
        "hash": digest,
        "signature": signature.hex(),
        "public_key": public_key.hex(),
        "signature_status": "VALID",
    }


def verify_evidence_record(payload: dict[str, Any], signature_hex: str, public_key_hex: str) -> bool:
    try:
        canonical = _canonicalize(payload)
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        public_key.verify(bytes.fromhex(signature_hex), canonical.encode("utf-8"))
        return True
    except Exception:
        return False
