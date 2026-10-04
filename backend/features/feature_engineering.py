from __future__ import annotations

from typing import Any


def extract_features(event: dict[str, Any]) -> dict[str, Any]:
    failed_attempts = int(event.get("failed_attempts", event.get("failed_login_attempts", 0) or 0))
    bytes_total = int(event.get("bytes", event.get("bytes_sent", 0) or 0))
    protocol = str(event.get("protocol") or "").upper()
    destination_port = int(event.get("destination_port") or 0)
    event_type = str(event.get("event_type") or "").lower()
    request_frequency = int(event.get("request_frequency") or 0)
    raw_event = event.get("raw_event") if isinstance(event.get("raw_event"), dict) else {}
    unique_destination_ports = int(raw_event.get("unique_destination_ports") or event.get("unique_destination_ports") or 0)

    if bytes_total < 5000:
        traffic_volume_bucket = "low"
    elif bytes_total < 200000:
        traffic_volume_bucket = "medium"
    else:
        traffic_volume_bucket = "high"

    return {
        "failed_attempts": failed_attempts,
        "bytes_total": bytes_total,
        "traffic_volume_bucket": traffic_volume_bucket,
        "protocol": protocol,
        "source_port": int(event.get("source_port") or 0),
        "destination_port": destination_port,
        "request_frequency": request_frequency,
        "unique_destination_ports": unique_destination_ports,
        "is_ssh_access": destination_port == 22 or "SSH" in protocol,
        "is_high_frequency": failed_attempts >= 10 or bytes_total >= 200000 or request_frequency >= 50,
        "is_port_scan": unique_destination_ports >= 10 or "port_scan" in event_type,
        "is_auth_event": (event.get("event_type") or "").lower() in {"authentication", "login", "auth"},
    }
