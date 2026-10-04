from __future__ import annotations

from typing import Any

from backend.detection.engine import detect_security_event
from backend.risk.risk_engine import calculate_security_risk


def analyze_event(event: dict[str, Any]) -> dict[str, Any] | None:
    required_keys = {
        "source_ip",
        "destination_ip",
        "protocol",
        "source_port",
        "destination_port",
        "packet_count",
        "bytes_sent",
        "bytes_received",
        "connection_duration",
        "failed_login_attempts",
        "request_frequency",
    }
    if not required_keys.issubset(event.keys()):
        return None

    normalized = detect_security_event({
        "source_platform": event.get("source_platform", "network"),
        "source": event.get("source_ip"),
        "destination": event.get("destination_ip"),
        "event_type": event.get("event_type", "security"),
        "protocol": event.get("protocol"),
        "source_port": event.get("source_port"),
        "destination_port": event.get("destination_port"),
        "failed_attempts": event.get("failed_login_attempts", 0),
        "bytes": event.get("bytes_sent", 0),
        "raw_event": event,
    })
    risk_result = calculate_security_risk(normalized["risk_score"], normalized["confidence"])

    return {
        "id": normalized.get("event_id", "THR-1042"),
        "classification": normalized["threat_type"],
        "risk_score": int(risk_result["risk_score"]),
        "confidence": float(normalized["confidence"]),
        "severity": risk_result["level"],
        "signature_status": "UNSIGNED",
        "detection_method": normalized["detection_method"],
        "selected_features": [],
        "optimization_status": "not_run_during_live_inference",
        "confidence_type": normalized["confidence_type"],
        "source_ip": event["source_ip"],
        "destination_ip": event["destination_ip"],
        "protocol": event["protocol"],
        "event_data": {**event, "features": normalized["features"], "risk_score": int(risk_result["risk_score"])},
        "explanations": normalized.get("explanations", []),
        "reason": normalized.get("reason", "No suspicious activity detected."),
        "recommended_action": normalized.get("recommended_action", "Continue routine monitoring."),
        "remediation_steps": normalized.get("remediation_steps", []),
    }


def get_demo_threats() -> list[dict[str, Any]]:
    return [
        {
            "id": "THR-1042",
            "source": "192.168.10.12",
            "classification": "Brute Force",
            "risk_score": 91,
            "confidence": 96.2,
            "severity": "CRITICAL",
            "status": "OPEN",
            "signature_status": "VALID",
            "reason": "Repeated failed authentication attempts indicate a brute-force attack against the identity layer.",
            "recommended_action": "Block the source IP, reset impacted credentials, and enforce MFA across the target accounts.",
            "remediation_steps": [
                "Block the offending source in the firewall and WAF.",
                "Force password resets and require MFA for affected identities.",
                "Review logs and isolate any compromised sessions.",
            ],
        },
        {
            "id": "THR-1043",
            "source": "203.0.113.27",
            "classification": "Port Scan",
            "risk_score": 74,
            "confidence": 88.1,
            "severity": "HIGH",
            "status": "INVESTIGATING",
            "signature_status": "VALID",
            "reason": "The host is probing a broad range of ports, which is typical of reconnaissance before exploitation.",
            "recommended_action": "Restrict unnecessary ports, block the scanner, and harden exposed services.",
            "remediation_steps": [
                "Apply network ACL rules to restrict exposure.",
                "Harden service banners and close unused ports.",
                "Inspect the source and correlate it with previous campaigns.",
            ],
        },
        {
            "id": "THR-1044",
            "source": "198.51.100.44",
            "classification": "DoS/DDoS",
            "risk_score": 88,
            "confidence": 93.7,
            "severity": "CRITICAL",
            "status": "CONTAINED",
            "signature_status": "VALID",
            "reason": "Traffic volume is elevated beyond baseline and consistent with a denial-of-service attack aimed at service saturation.",
            "recommended_action": "Activate rate limits, involve the CDN/WAF, and scale the critical service behind the attack.",
            "remediation_steps": [
                "Enable DDoS filtering and rate limiting.",
                "Scale the service behind the load balancer.",
                "Block malicious traffic and inspect the upstream path for botnet activity.",
            ],
        },
    ]
