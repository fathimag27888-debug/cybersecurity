from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone

from backend.database.analytics_store import save_analytics_event
from backend.database.auth_store import authenticate_user, register_user, seed_auth_users
from backend.database.evidence_store import count_evidence_records

STATE = {
    "demo_loaded": False,
    "events": [],
    "analytics_events": [],
    "simulation_runs": {},
    "custom_simulation_scenarios": {},
    "threats": [],
    "incidents": [],
    "audit_logs": [],
    "security_events": [],
    "evidence_records": [],
    "security_sources": [],
    "model_metrics": [],
    "integrity_failures": 0,
    "live_monitoring": False,
    "live_feed": [
        {
            "id": "THR-LIVE-01",
            "classification": "Credential Stuffing",
            "risk_score": 84,
            "confidence": 91.3,
            "severity": "HIGH",
            "source": "198.51.100.18",
            "destination_ip": "10.0.0.9",
            "status": "active",
            "protocol": "HTTPS",
        },
        {
            "id": "THR-LIVE-02",
            "classification": "Suspicious Beaconing",
            "risk_score": 76,
            "confidence": 87.8,
            "severity": "MEDIUM",
            "source": "203.0.113.44",
            "destination_ip": "10.0.0.7",
            "status": "monitoring",
            "protocol": "TCP",
        },
    ],
}


def _time_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def seed_database() -> None:
    seed_auth_users()
    if STATE["demo_loaded"]:
        return

    demo_events = [
        {
            "id": "EVT-1001",
            "source_ip": "192.168.10.12",
            "destination_ip": "10.0.0.8",
            "protocol": "SSH",
            "source_port": 48211,
            "destination_port": 22,
            "packet_count": 540,
            "bytes_sent": 124000,
            "bytes_received": 9000,
            "connection_duration": 180,
            "failed_login_attempts": 37,
            "request_frequency": 9,
            "classification": "Brute Force",
            "risk_score": 91,
            "confidence": 96.2,
            "severity": "CRITICAL",
            "signature_status": "VALID",
            "status": "open",
            "created_at": _time_stamp(),
        },
        {
            "id": "EVT-1002",
            "source_ip": "203.0.113.27",
            "destination_ip": "10.0.0.5",
            "protocol": "TCP",
            "source_port": 52144,
            "destination_port": 80,
            "packet_count": 2400,
            "bytes_sent": 160000,
            "bytes_received": 50000,
            "connection_duration": 120,
            "failed_login_attempts": 2,
            "request_frequency": 75,
            "classification": "Port Scan",
            "risk_score": 74,
            "confidence": 88.1,
            "severity": "HIGH",
            "signature_status": "VALID",
            "status": "investigating",
            "created_at": _time_stamp(),
        },
        {
            "id": "EVT-1003",
            "source_ip": "198.51.100.44",
            "destination_ip": "10.0.0.11",
            "protocol": "UDP",
            "source_port": 53,
            "destination_port": 8080,
            "packet_count": 8600,
            "bytes_sent": 630000,
            "bytes_received": 180000,
            "connection_duration": 82,
            "failed_login_attempts": 0,
            "request_frequency": 62,
            "classification": "DoS/DDoS",
            "risk_score": 88,
            "confidence": 93.7,
            "severity": "CRITICAL",
            "signature_status": "VALID",
            "status": "contained",
            "created_at": _time_stamp(),
        },
        {
            "id": "EVT-1004",
            "source_ip": "10.0.0.2",
            "destination_ip": "172.16.0.10",
            "protocol": "HTTP",
            "source_port": 51230,
            "destination_port": 443,
            "packet_count": 730,
            "bytes_sent": 22000,
            "bytes_received": 89000,
            "connection_duration": 54,
            "failed_login_attempts": 0,
            "request_frequency": 30,
            "classification": "Normal Traffic",
            "risk_score": 18,
            "confidence": 97.1,
            "severity": "LOW",
            "signature_status": "VALID",
            "status": "resolved",
            "created_at": _time_stamp(),
        },
    ]

    demo_threats = [
        {
            "id": "THR-1042",
            "event_id": "EVT-1001",
            "source": "192.168.10.12",
            "classification": "Brute Force",
            "risk_score": 91,
            "confidence": 96.2,
            "severity": "CRITICAL",
            "status": "open",
            "signature_status": "VALID",
            "detected_at": _time_stamp(),
            "protocol": "SSH",
            "destination_ip": "10.0.0.8",
            "failed_login_attempts": 37,
        },
        {
            "id": "THR-1043",
            "event_id": "EVT-1002",
            "source": "203.0.113.27",
            "classification": "Port Scan",
            "risk_score": 74,
            "confidence": 88.1,
            "severity": "HIGH",
            "status": "investigating",
            "signature_status": "VALID",
            "detected_at": _time_stamp(),
            "protocol": "TCP",
            "destination_ip": "10.0.0.5",
            "failed_login_attempts": 2,
        },
    ]

    demo_incidents = [
        {
            "id": "INC-3001",
            "threat_id": "THR-1042",
            "threat_type": "Brute Force",
            "severity": "CRITICAL",
            "source": "192.168.10.12",
            "detected_at": "2026-09-25T10:15:00Z",
            "risk_score": 91,
            "confidence": 96.2,
            "status": "OPEN",
            "assigned_analyst": "Security Analyst",
            "event": demo_events[0],
        }
    ]

    demo_audit_logs = [
        {
            "timestamp": "2026-09-25T10:12:00Z",
            "user": "Security Analyst",
            "action": "Analyst logged in",
            "resource": "Login",
            "event_id": "SYS-LOGIN",
            "signature_status": "VALID",
        },
        {
            "timestamp": "2026-09-25T10:13:40Z",
            "user": "Security Analyst",
            "action": "Threat analyzed",
            "resource": "Threat Detection",
            "event_id": "THR-1042",
            "signature_status": "VALID",
        },
        {
            "timestamp": "2026-09-25T10:14:02Z",
            "user": "Security Analyst",
            "action": "Incident created",
            "resource": "Incidents",
            "event_id": "INC-3001",
            "signature_status": "VALID",
        },
    ]

    STATE["events"] = demo_events
    STATE["threats"] = demo_threats
    STATE["incidents"] = demo_incidents
    STATE["audit_logs"] = demo_audit_logs
    STATE["security_events"] = []
    STATE["analytics_events"] = []
    STATE["simulation_runs"] = {}
    STATE["custom_simulation_scenarios"] = {}
    STATE["security_sources"] = [
        {"name": "Windows Endpoints", "type": "windows", "status": "Connected", "last_event": _time_stamp(), "events_received": 4218, "threats_detected": 32, "connection_status": "active"},
        {"name": "Linux Servers", "type": "linux", "status": "Active", "last_event": _time_stamp(), "events_received": 2684, "threats_detected": 18, "connection_status": "active"},
        {"name": "Network Sensors", "type": "network", "status": "Warning", "last_event": _time_stamp(), "events_received": 1772, "threats_detected": 11, "connection_status": "warning"},
        {"name": "Cloud Audit", "type": "cloud", "status": "Connected", "last_event": _time_stamp(), "events_received": 963, "threats_detected": 7, "connection_status": "active"},
        {"name": "Web Applications", "type": "web", "status": "Active", "last_event": _time_stamp(), "events_received": 2456, "threats_detected": 13, "connection_status": "active"},
        {"name": "IoT Fleet", "type": "iot", "status": "Offline", "last_event": _time_stamp(), "events_received": 538, "threats_detected": 4, "connection_status": "offline"},
    ]
    STATE["model_metrics"] = []
    STATE["demo_loaded"] = True


def get_state() -> dict:
    return STATE


def add_audit_entry(action: str, resource: str, event_id: str, user: str = "Security Analyst", signature_status: str = "N/A") -> None:
    STATE["audit_logs"].append(
        {
            "timestamp": _time_stamp(),
            "user": user,
            "action": action,
            "resource": resource,
            "event_id": event_id,
            "signature_status": signature_status,
        }
    )


def record_analytics_event(event: dict) -> dict:
    record = {
        "event_id": event.get("id") or event.get("event_id") or "unknown",
        "timestamp": _time_stamp(),
        "classification": event.get("classification") or event.get("threat_type") or "Unclassified",
        "severity": str(event.get("severity") or "UNKNOWN").upper(),
        "risk_score": int(event.get("risk_score") or event.get("risk") or 0),
        "source_platform": event.get("source_platform") or "unknown",
        "ai_enhanced": bool(event.get("ai_enhanced", False)),
        "simulation": bool(event.get("simulation", False)),
    }
    save_analytics_event(record)
    STATE["analytics_events"].append(record)
    del STATE["analytics_events"][:-5000]
    return record


def set_live_monitoring(enabled: bool) -> dict:
    STATE["live_monitoring"] = enabled
    return {
        "status": "active" if enabled else "paused",
        "monitoring": enabled,
        "threats": STATE["live_feed"],
    }


def get_dashboard_summary() -> dict:
    return {
        "total_events": len(STATE["events"]),
        "threats_detected": len(STATE["threats"]),
        "critical_threats": sum(1 for threat in STATE["threats"] if str(threat.get("severity", "")).upper() in {"CRITICAL", "HIGH"}),
        "active_incidents": len(STATE["incidents"]),
        "resolved_incidents": sum(1 for item in STATE["incidents"] if str(item.get("status", "")).upper() == "RESOLVED"),
        "verified_evidence": count_evidence_records(),
        "integrity_failures": STATE["integrity_failures"],
        "model_metrics": STATE["model_metrics"],
        "security_sources": STATE["security_sources"],
    }
