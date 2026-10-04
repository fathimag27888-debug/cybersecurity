import json
from hashlib import sha256
from hmac import compare_digest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def verify_signed_event(event_data: dict, signature: str, expected_hash: str, public_key_hex: str) -> bool:
    canonical = json.dumps(event_data, sort_keys=True, separators=(",", ":"))
    encoded_payload = canonical.encode("utf-8")
    current_hash = sha256(encoded_payload).hexdigest()
    if not compare_digest(current_hash, expected_hash):
        return False

    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        public_key.verify(bytes.fromhex(signature), encoded_payload)
    except (InvalidSignature, ValueError):
        return False
    return True
