from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from backend.api.auth import require_admin
from backend.database.database import STATE, add_audit_entry

router = APIRouter()


class IncidentCreateRequest(BaseModel):
    threat_id: str
    threat_type: str
    severity: str
    source: str
    risk_score: int
    confidence: float
    status: str = "OPEN"
    assigned_analyst: str = "Security Analyst"


@router.get("")
def list_incidents():
    return {"items": STATE["incidents"]}


@router.post("")
def create_incident(payload: IncidentCreateRequest):
    incident = {
        "id": f"INC-{len(STATE['incidents']) + 3001}",
        "threat_id": payload.threat_id,
        "threat_type": payload.threat_type,
        "severity": payload.severity,
        "source": payload.source,
        "detected_at": "2026-09-25T12:00:00Z",
        "risk_score": payload.risk_score,
        "confidence": payload.confidence,
        "status": payload.status,
        "assigned_analyst": payload.assigned_analyst,
    }
    STATE["incidents"].append(incident)
    add_audit_entry("Incident created", "Incidents", incident["id"])
    return incident


@router.patch("/{incident_id}")
def update_incident(incident_id: str, payload: dict, admin_role: str = Depends(require_admin)):
    for incident in STATE["incidents"]:
        if incident["id"] == incident_id:
            incident.update(payload)
            add_audit_entry("Incident status changed", "Incidents", incident_id, signature_status="VALID")
            return incident
    raise HTTPException(status_code=404, detail="Incident not found")
