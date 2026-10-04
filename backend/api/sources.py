from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field, HttpUrl

from backend.database.database import STATE, add_audit_entry, record_analytics_event
from backend.database.source_store import (
    add_website_event,
    authenticate_source,
    list_website_events,
    list_website_sources,
    register_website_source,
)
from backend.detection.engine import detect_security_event

router = APIRouter()


class SecuritySourceRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    type: Literal["windows", "linux", "network", "cloud", "web", "iot"]


class WebsiteSourceRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    url: HttpUrl


class WebsiteEventRequest(BaseModel):
    event: dict[str, Any]


def _require_source_token(source_id: str, token: str | None) -> None:
    if not token or not authenticate_source(source_id, token):
        raise HTTPException(status_code=401, detail="Invalid website ingestion token")


@router.get("")
def list_sources():
    return {"data_mode": "simulated", "items": STATE["security_sources"]}


@router.post("")
def add_source(payload: SecuritySourceRequest):
    source = {
        "name": payload.name,
        "type": payload.type,
        "status": "Configured",
        "connection_status": "not_connected",
        "last_event": None,
        "events_received": 0,
        "threats_detected": 0,
    }
    STATE["security_sources"].append(source)
    return source


@router.get("/websites")
def list_websites():
    return {"items": list_website_sources()}


@router.post("/websites")
def add_website(payload: WebsiteSourceRequest):
    try:
        source = register_website_source(payload.name, str(payload.url))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    add_audit_entry("Website source configured", "Security Sources", source["id"])
    return source


@router.post("/websites/{source_id}/events")
def ingest_website_event(
    source_id: str,
    payload: WebsiteEventRequest,
    x_source_token: str | None = Header(default=None, alias="X-Source-Token"),
):
    _require_source_token(source_id, x_source_token)
    raw_event = {**payload.event, "source_platform": "web"}
    detection = detect_security_event(raw_event)
    try:
        add_website_event(source_id, detection)
    except Exception as exc:
        raise HTTPException(status_code=409, detail="Event could not be recorded") from exc
    record_analytics_event(detection)
    add_audit_entry("Website event received", "Security Sources", detection["event_id"], signature_status="N/A")
    return detection


@router.get("/websites/{source_id}/events")
def get_website_events(
    source_id: str,
    x_source_token: str | None = Header(default=None, alias="X-Source-Token"),
    limit: int = 50,
):
    _require_source_token(source_id, x_source_token)
    return {"items": list_website_events(source_id, max(1, min(limit, 100)))}
