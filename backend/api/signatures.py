from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.crypto.signer import get_signing_key_mode, get_signing_public_key, sign_event_data
from backend.crypto.verifier import verify_signed_event
from backend.database.database import STATE, add_audit_entry
from backend.database.evidence_store import get_evidence_record, save_evidence_record

router = APIRouter()


class SignatureRequest(BaseModel):
    event_id: str
    event_data: dict[str, Any]


@router.post("/sign")
def sign_event(payload: SignatureRequest):
    canonical = json.dumps(payload.event_data, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    signature = sign_event_data(canonical)

    record = {
        "event_id": payload.event_id,
        "payload": json.loads(canonical),
        "hash": digest,
        "signature": signature,
        "status": "VALID",
        "public_key": get_signing_public_key(),
        "key_mode": get_signing_key_mode(),
        "signed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    try:
        save_evidence_record(record)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    add_audit_entry("Security event signed", "Digital Signature", payload.event_id, signature_status="VALID")
    return record


@router.post("/verify")
def verify_event(payload: SignatureRequest):
    record = get_evidence_record(payload.event_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Event not found for verification")

    valid = payload.event_data == record["payload"] and verify_signed_event(
        payload.event_data, record["signature"], record["hash"], record["public_key"]
    )
    if not valid:
        STATE["integrity_failures"] += 1
    add_audit_entry("Signature verified", "Digital Signature", payload.event_id, signature_status="VALID" if valid else "INVALID")
    return {
        "verified": valid,
        "status": "VALID" if valid else "INVALID",
        "hash": record["hash"],
        "signature": record["signature"],
        "message": "Signature valid" if valid else "Signature invalid. Possible tampering detected.",
    }


@router.post("/tamper")
def tamper_event(payload: SignatureRequest):
    record = get_evidence_record(payload.event_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Event not found for tamper simulation")

    tampered_event = dict(payload.event_data)
    tampered_event["risk_score"] = 15 if tampered_event.get("risk_score") != 15 else 16
    tampered_hash = hashlib.sha256(json.dumps(tampered_event, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    valid = verify_signed_event(
        tampered_event, record["signature"], record["hash"], record["public_key"]
    )
    if not valid:
        STATE["integrity_failures"] += 1
    add_audit_entry("Tamper simulation executed", "Digital Signature", payload.event_id, signature_status="INVALID")
    return {
        "verified": valid,
        "message": "SIGNATURE INVALID\nEVENT INTEGRITY COMPROMISED",
        "tampered_hash": tampered_hash,
        "tampered_event": tampered_event,
        "status": "INVALID",
    }
