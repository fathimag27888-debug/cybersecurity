from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.database.database import STATE, add_audit_entry, record_analytics_event, set_live_monitoring
from backend.llama_service import enrich_threat
from backend.ml.model import analyze_event, get_demo_threats

router = APIRouter()


class ThreatRequest(BaseModel):
    source_ip: str
    destination_ip: str
    source_platform: Literal["windows", "linux", "network", "cloud", "web", "iot"] = "network"
    protocol: str = Field(min_length=1, max_length=32)
    source_port: int = Field(ge=0, le=65535)
    destination_port: int = Field(ge=0, le=65535)
    packet_count: int = Field(ge=0)
    bytes_sent: int = Field(ge=0)
    bytes_received: int = Field(ge=0)
    connection_duration: int = Field(ge=0)
    failed_login_attempts: int = Field(default=0, ge=0)
    request_frequency: int = Field(default=0, ge=0)


class MonitoringRequest(BaseModel):
    enabled: bool = False


@router.get("")
def list_threats():
    return {"data_mode": "simulated", "items": get_demo_threats()}


@router.get("/live")
def live_threats():
    return {
        "data_mode": "simulated",
        "monitoring": STATE["live_monitoring"],
        "simulation_threat_count": sum(1 for item in STATE["live_feed"] if item.get("simulation")),
        "threats": STATE["live_feed"],
    }


@router.post("/monitoring")
def update_monitoring(payload: MonitoringRequest):
    result = set_live_monitoring(payload.enabled)
    add_audit_entry(
        "Live monitoring toggled",
        "Threat Detection",
        "LIVE-SYSTEM",
        signature_status="VALID" if result["monitoring"] else "N/A",
    )
    return result


@router.get("/{threat_id}")
def get_threat(threat_id: str):
    for threat in get_demo_threats():
        if threat["id"] == threat_id:
            return threat
    raise HTTPException(status_code=404, detail="Threat not found")


@router.post("/analyze")
def analyze_threat(payload: ThreatRequest):
    event = payload.model_dump()
    result = analyze_event(event)
    if not result:
        raise HTTPException(status_code=400, detail="Unable to analyze event. Please check the supplied data.")
    result = enrich_threat(result, event)

    record_analytics_event(result)
    add_audit_entry("Threat analyzed", "Threat Detection", result["id"], signature_status=result["signature_status"])
    return result
