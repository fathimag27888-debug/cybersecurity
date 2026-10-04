from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any


def normalize_security_event(raw_event: dict[str, Any]) -> dict[str, Any]:
    platform = str(raw_event.get("source_platform") or raw_event.get("platform") or "unknown").lower()
    source = raw_event.get("source") or raw_event.get("source_ip") or "unknown"
    destination = raw_event.get("destination") or raw_event.get("destination_ip") or "unknown"
    event_type = raw_event.get("event_type") or raw_event.get("classification") or "security"
    protocol = str(raw_event.get("protocol") or "UNKNOWN").upper()
    source_port = int(raw_event.get("source_port") or 0)
    destination_port = int(raw_event.get("destination_port") or 0)
    failed_attempts = int(raw_event.get("failed_attempts", raw_event.get("failed_login_attempts", 0) or 0))
    byte_count = int(raw_event.get("bytes", raw_event.get("bytes_sent", 0) or 0))
    user = raw_event.get("user") or raw_event.get("username") or "unknown"
    event_id = raw_event.get("event_id") or f"EVT-{uuid.uuid4().hex[:8].upper()}"

    return {
        "event_id": event_id,
        "timestamp": raw_event.get("timestamp") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_platform": platform,
        "source": source,
        "destination": destination,
        "event_type": event_type,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "failed_attempts": failed_attempts,
        "bytes": byte_count,
        "user": user,
        "raw_event": raw_event.get("raw_event") or raw_event,
        "features": {},
        "risk_score": 0,
        "threat_type": "unknown",
        "confidence": 0.0,
        "severity": "LOW",
    }
