from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from backend.database.database import STATE, add_audit_entry, record_analytics_event
from backend.detection.engine import detect_security_event
from backend.llama_service import answer_security_question, get_llama_status

SCENARIO_GROUPS = {
    "NETWORK": [
        ("port-scan", "Port Scanning Simulation", "port_scan"),
        ("brute-force", "Brute Force Simulation", "brute_force"),
        ("ddos-pattern", "DDoS Pattern Simulation", "ddos"),
        ("dns-anomaly", "DNS Anomaly Simulation", "dns_anomaly"),
        ("arp-spoofing", "ARP Spoofing Pattern", "arp_spoofing"),
        ("suspicious-network", "Suspicious Network Traffic", "network_anomaly"),
        ("lateral-movement", "Lateral Movement Pattern", "lateral_movement"),
    ],
    "WEB / APPLICATION": [
        ("sql-injection", "SQL Injection Pattern", "sql_injection"),
        ("xss", "XSS Pattern", "xss"),
        ("ssrf", "SSRF Pattern", "ssrf"),
        ("path-traversal", "Path Traversal Pattern", "path_traversal"),
        ("auth-bypass", "Authentication Bypass Pattern", "auth_bypass"),
        ("api-abuse", "API Abuse Pattern", "api_abuse"),
        ("file-upload", "Suspicious File Upload", "file_upload"),
        ("session-hijacking", "Session Hijacking Pattern", "session_hijacking"),
    ],
    "IDENTITY": [
        ("password-spraying", "Password Spraying", "password_spraying"),
        ("credential-stuffing", "Credential Stuffing", "credential_stuffing"),
        ("impossible-travel", "Impossible Travel", "impossible_travel"),
        ("mfa-abuse", "MFA Abuse Pattern", "mfa_abuse"),
        ("privilege-escalation", "Privilege Escalation Pattern", "privilege_escalation"),
        ("suspicious-login", "Suspicious Login", "suspicious_login"),
    ],
    "ENDPOINT": [
        ("suspicious-process", "Suspicious Process Execution", "suspicious_process"),
        ("persistence", "Persistence Pattern", "persistence"),
        ("endpoint-privilege", "Privilege Escalation", "privilege_escalation"),
        ("file-modification", "Unauthorized File Modification", "file_modification"),
        ("process-injection", "Process Injection Pattern", "process_injection"),
        ("command-control", "Command-and-Control Pattern", "command_control"),
    ],
    "CLOUD": [
        ("iam-activity", "Suspicious IAM Activity", "iam_anomaly"),
        ("cloud-credentials", "Cloud Credential Abuse", "credential_stuffing"),
        ("cloud-api", "Unusual API Activity", "api_abuse"),
        ("storage-access", "Storage Access Anomaly", "data_access"),
        ("cloud-privilege", "Privilege Escalation", "privilege_escalation"),
        ("cloud-resource-abuse", "Cloud Resource Abuse", "resource_abuse"),
    ],
    "DATA": [
        ("unusual-data-access", "Unusual Data Access", "data_access"),
        ("large-transfer", "Large Data Transfer", "data_exfiltration"),
        ("database-anomaly", "Database Access Anomaly", "data_access"),
        ("data-exfiltration", "Data Exfiltration Pattern", "data_exfiltration"),
        ("sensitive-file", "Sensitive File Access", "data_access"),
    ],
    "AI SECURITY": [
        ("prompt-injection", "Prompt Injection Simulation", "prompt_injection"),
        ("data-poisoning", "Data Poisoning Pattern", "data_poisoning"),
        ("model-abuse", "Model Abuse Pattern", "model_abuse"),
        ("ai-api-usage", "Suspicious AI API Usage", "api_abuse"),
    ],
    "CRYPTOGRAPHIC / QUANTUM": [
        ("weak-crypto", "Weak Cryptography Detection", "weak_crypto"),
        ("deprecated-algorithm", "Deprecated Algorithm Usage", "weak_crypto"),
        ("quantum-vulnerable", "Quantum-Vulnerable Cryptography", "quantum_crypto_risk"),
        ("harvest-decrypt-later", "Harvest-Now-Decrypt-Later Risk Simulation", "quantum_crypto_risk"),
        ("post-quantum-migration", "Post-Quantum Migration Risk", "quantum_crypto_risk"),
    ],
    "UNIVERSAL": [
        ("universal-cross-platform", "UNIVERSAL CROSS-PLATFORM ATTACK", "cross_platform"),
    ],
}

SCENARIOS = {
    scenario_id: {"id": scenario_id, "name": name, "category": category, "pattern": pattern}
    for category, scenarios in SCENARIO_GROUPS.items()
    for scenario_id, name, pattern in scenarios
}

PLATFORMS = ["web", "api", "cloud", "linux", "database", "identity", "network", "endpoint"]
SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
DIFFICULTIES = ["EASY", "MEDIUM", "HARD", "ADVERSARIAL", "UNKNOWN"]

CREDENTIAL_SEQUENCE = [
    ("Reconnaissance", "port_scan", "network", 0, 40_000, 24, 443),
    ("Initial Access", "authentication_failure", "identity", 15, 3_000, 16, 443),
    ("Credential Abuse", "credential_stuffing", "identity", 18, 5_000, 22, 443),
    ("Privilege Escalation", "privilege_escalation", "linux", 0, 8_000, 4, 22),
    ("Lateral Movement", "lateral_movement", "linux", 0, 30_000, 18, 445),
    ("Data Access", "database_access_anomaly", "database", 0, 45_000, 8, 5432),
    ("Exfiltration Pattern", "data_exfiltration", "database", 0, 280_000, 6, 443),
]

UNIVERSAL_SEQUENCE = [
    ("Reconnaissance", "port_scan", "web", 0, 12_000, 21, 443),
    ("Initial Access", "sql_injection_attempt", "web", 0, 8_000, 42, 443),
    ("API Abuse", "api_abuse", "api", 0, 18_000, 55, 443),
    ("Credential Abuse", "credential_stuffing", "identity", 16, 5_000, 21, 443),
    ("Privilege Escalation", "privilege_escalation", "cloud", 0, 12_000, 7, 443),
    ("Lateral Movement", "lateral_movement", "linux", 0, 36_000, 18, 22),
    ("Data Access", "database_access_anomaly", "database", 0, 260_000, 8, 5432),
]


def list_scenarios() -> list[dict[str, str]]:
    return [
        {"id": item["id"], "name": item["name"], "category": item["category"]}
        for item in SCENARIOS.values()
    ]


def _stage_sequence(scenario: dict[str, Any], target_platform: str) -> list[tuple[str, str, str, int, int, int, int]]:
    if scenario["pattern"] == "cross_platform":
        return UNIVERSAL_SEQUENCE
    if scenario["pattern"] in {"brute_force", "password_spraying", "credential_stuffing", "suspicious_login", "impossible_travel", "mfa_abuse"}:
        return CREDENTIAL_SEQUENCE[1:4] + CREDENTIAL_SEQUENCE[5:]
    if scenario["pattern"] == "ddos":
        return [("Traffic Surge", "ddos_traffic_surge", "network", 0, 320_000, 90, 443)]
    if scenario["pattern"] == "port_scan":
        return [("Reconnaissance", "port_scan", "network", 0, 40_000, 35, 443)]
    if scenario["pattern"] in {"data_exfiltration", "data_access"}:
        return CREDENTIAL_SEQUENCE[5:]
    if scenario["pattern"] == "lateral_movement":
        return CREDENTIAL_SEQUENCE[3:6]
    return [(scenario["name"], scenario["pattern"], target_platform, 0, 12_000, 38, 443)]


def _synthetic_event(
    run_id: str,
    index: int,
    config: dict[str, Any],
    stage: tuple[str, str, str, int, int, int, int],
    expected_threat: bool,
    timestamp: datetime,
) -> dict[str, Any]:
    stage_name, event_type, platform, failed_attempts, bytes_sent, frequency, destination_port = stage
    severity_multiplier = {"LOW": 0.6, "MEDIUM": 0.9, "HIGH": 1.2, "CRITICAL": 1.5}[config["severity"]]
    user = config.get("target_identity") or "demo_user_01"
    return {
        "simulation": True,
        "simulation_id": run_id,
        "event_id": f"{run_id}-EVT-{index + 1:04d}",
        "timestamp": timestamp.isoformat(),
        "source_platform": platform,
        "source_ip": ["198.51.100.42", "203.0.113.29", "192.0.2.18"][index % 3],
        "destination_ip": f"demo-{platform}-service-01",
        "destination": f"demo-{platform}-service-01.test",
        "protocol": config.get("protocol", "TCP"),
        "source_port": 52000 + index % 1000,
        "destination_port": destination_port,
        "packet_count": max(1, frequency * 3),
        "bytes_sent": int(bytes_sent * severity_multiplier),
        "bytes_received": 1200,
        "connection_duration": 3 + index % 45,
        "failed_login_attempts": failed_attempts,
        "request_frequency": frequency,
        "event_type": event_type,
        "simulation_stage": stage_name,
        "simulation_pattern": config["scenario_pattern"],
        "expected_threat": expected_threat,
        "username": user,
        "attacker_identity": config.get("attacker_identity") or "demo_attacker_01",
        "target_identity": user,
        "synthetic_domain": "demo-lab.test",
        "raw_event": {
            "simulation": True,
            "marker": "SIMULATION",
            "simulation_stage": stage_name,
            "expected_threat": expected_threat,
            "source_platform": platform,
        },
    }


def _event_templates(config: dict[str, Any]) -> list[tuple[str, str, str, int, int, int, int]]:
    scenario = SCENARIOS.get(config["scenario_id"], {
        "name": config.get("scenario_name", "Custom Synthetic Scenario"),
        "pattern": config.get("pattern", "network_anomaly"),
    })
    if config.get("custom_sequence"):
        return [
            (stage.replace("_", " ").title(), stage.lower(), config["target_platform"], 0, 12_000, 40, 443)
            for stage in config["custom_sequence"]
        ]
    return _stage_sequence(scenario, config["target_platform"])


def _generate_batch(run: dict[str, Any]) -> None:
    config = run["config"]
    templates = _event_templates(config)
    volume = config["event_volume"]
    noise_rate = max(
        {"EASY": 0, "MEDIUM": 0.05, "HARD": 0.15, "ADVERSARIAL": 0.25, "UNKNOWN": 0.35}[config["difficulty"]],
        {"LOW": 0, "MEDIUM": 0.1, "HIGH": 0.25}.get(config.get("noise_level"), 0),
    )
    start = datetime.now(timezone.utc) - timedelta(seconds=config["duration_seconds"])
    duration = config["duration_seconds"]
    detection_times = []
    expected_positive = 0
    true_positive = 0
    true_negative = 0
    false_positive = 0
    missed = 0
    stage_findings: dict[str, dict[str, Any]] = {}

    for index in range(volume):
        is_noise = noise_rate > 0 and (index + 1) % max(2, int(1 / noise_rate)) == 0
        template = ("Benign Background Activity", "routine_activity", config["target_platform"], 0, 700, 2, 443) if is_noise else templates[index % len(templates)]
        ratio = index / max(1, volume - 1)
        pattern = config.get("timestamp_pattern", "SEQUENTIAL")
        if pattern == "BURST":
            ratio = min(1, ratio * 0.3)
        elif pattern == "IRREGULAR":
            ratio = min(1, ((index * 37) % max(1, volume)) / max(1, volume - 1))
        timestamp = start + timedelta(seconds=duration * ratio)
        raw_event = _synthetic_event(run["id"], index, config, template, not is_noise, timestamp)
        started = time.perf_counter()
        detection = detect_security_event(raw_event)
        detection_times.append((time.perf_counter() - started) * 1000)
        detected = detection["risk_score"] > 0
        if not is_noise:
            expected_positive += 1
            if detected:
                true_positive += 1
            else:
                missed += 1
        elif detected:
            false_positive += 1
        else:
            true_negative += 1

        event = {
            **detection,
            "id": raw_event["event_id"],
            "simulation": True,
            "simulation_marker": "SIMULATION",
            "simulation_stage": template[0],
            "expected_threat": not is_noise,
            "source_ip": raw_event["source_ip"],
            "destination": raw_event["destination"],
            "source_platform": raw_event["source_platform"],
            "username": raw_event["username"],
            "timestamp": raw_event["timestamp"],
            "risk_score": detection["risk_score"],
            "confidence": detection["confidence"],
        }
        run["events"].append(event)
        record_analytics_event({**event, "ai_enhanced": False})
        run["events_generated"] += 1
        if detected:
            run["threats_detected"] += 1
            stage_findings[template[0]] = event
            STATE["live_feed"].insert(0, {
                "id": event["id"],
                "classification": event["threat_type"],
                "risk_score": event["risk_score"],
                "confidence": event["confidence"],
                "severity": event["severity"],
                "source": event["source_ip"],
                "destination_ip": event["destination"],
                "status": "SIMULATION",
                "protocol": event["protocol"],
                "timestamp": event["timestamp"],
                "simulation": True,
                "simulation_marker": "SIMULATION",
                "simulation_run_id": run["id"],
                "simulation_stage": template[0],
            })
            del STATE["live_feed"][100:]
        run["event_stream"].append({
            "timestamp": raw_event["timestamp"],
            "event_type": raw_event["event_type"].upper(),
            "source_platform": raw_event["source_platform"],
            "stage": template[0],
            "result": "THREAT_DETECTED" if detected else "BENIGN_ACTIVITY",
            "simulation": True,
        })
        if len(run["event_stream"]) > 250:
            del run["event_stream"][:-250]
        time.sleep(0.04)

    elapsed_ms = sum(detection_times)
    detection_rate = true_positive / expected_positive * 100 if expected_positive else 0
    total = len(run["events"])
    run["metrics"] = {
        "detection_rate": round(detection_rate, 1),
        "false_positive_rate": round(false_positive / max(1, false_positive + true_negative) * 100, 1),
        "detection_latency_ms": round(elapsed_ms, 2),
        "average_detection_time_ms": round(elapsed_ms / max(1, run["threats_detected"]), 2),
        "events_processed": total,
        "threats_detected": run["threats_detected"],
        "incidents_created": 0,
        "correct_classifications": true_positive + true_negative,
        "missed_threats": missed,
        "false_positives": false_positive,
        "correlation_accuracy": round(len(stage_findings) / max(1, len(templates)) * 100, 1),
        "ai_confidence": round(sum(item["confidence"] for item in run["events"]) / max(1, total), 1),
        "quantum_inspired_score": round(min(99.0, 55 + len(stage_findings) * 6.5), 1),
    }
    correlated = len(stage_findings) >= min(3, len(templates)) and run["threats_detected"] >= 3
    run["attack_graph"] = [
        {
            "id": event["id"],
            "event": event.get("classification") or event.get("threat_type", "Detected anomaly"),
            "stage": stage_name,
            "timestamp": event["timestamp"],
            "risk": event["risk_score"],
            "confidence": event["confidence"],
            "platform": event["source_platform"],
            "simulation": True,
        }
        for stage_name, event in stage_findings.items()
    ]
    run["correlation"] = {
        "triggered": correlated,
        "title": "Possible Account Compromise & Data Access" if correlated else None,
        "reason": f"{len(stage_findings)} distinct attack stages produced detections within one isolated simulation run." if correlated else "Insufficient correlated detections to create an incident.",
        "related_stages": list(stage_findings),
        "quantum_inspired_label": "Quantum-Inspired Simulation",
        "feature_importance": ["Authentication", "Privilege", "Data Access"] if correlated else [item["stage"] for item in run["attack_graph"]],
    }

    if correlated:
        mitre_by_stage = {
            "Reconnaissance": {"id": "T1046", "name": "Network Service Discovery"},
            "Initial Access": {"id": "T1190", "name": "Exploit Public-Facing Application"},
            "API Abuse": {"id": "T1190", "name": "Exploit Public-Facing Application"},
            "Credential Abuse": {"id": "T1110", "name": "Brute Force"},
            "Privilege Escalation": {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
            "Lateral Movement": {"id": "T1021", "name": "Remote Services"},
            "Data Access": {"id": "T1213", "name": "Data from Information Repositories"},
            "Exfiltration Pattern": {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
        }
        mitre_mapping = []
        for stage in stage_findings:
            technique = mitre_by_stage.get(stage)
            if technique and technique not in mitre_mapping:
                mitre_mapping.append(technique)
        if config.get("expected_mitre_mapping"):
            mitre_mapping.append({"id": "CUSTOM", "name": config["expected_mitre_mapping"]})
        incident_id = f"SIM-{datetime.now(timezone.utc):%Y%m%d}-{len(STATE['simulation_runs']) :03d}"
        incident = {
            "id": incident_id,
            "threat_id": run["id"],
            "threat_type": run["correlation"]["title"],
            "severity": config["severity"],
            "source": "198.51.100.42 (SIMULATION)",
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "risk_score": max((event["risk_score"] for event in run["events"]), default=0),
            "confidence": max((event["confidence"] for event in run["events"]), default=0),
            "status": "ACTIVE — SIMULATION",
            "assigned_analyst": "Simulation Lab",
            "simulation": True,
            "simulation_run_id": run["id"],
            "evidence_count": len(run["attack_graph"]),
            "mitre_mapping": mitre_mapping,
        }
        STATE["incidents"].append(incident)
        run["incident"] = incident
        run["metrics"]["incidents_created"] = 1
        add_audit_entry("Simulation incident created", "Threat Simulation Lab", incident_id, signature_status="SIMULATION")
        run["event_stream"].append({
            "timestamp": incident["detected_at"],
            "event_type": "INCIDENT_CREATED",
            "stage": "Correlation",
            "result": "SIMULATION",
            "simulation": True,
        })

    if config.get("use_ai_analysis") and get_llama_status()["configured"]:
        analysis = answer_security_question(
            "Summarize this synthetic security simulation. Identify the stages detected, evidence, gaps, and safe next steps. Explicitly state this was a simulation; do not claim any external response was performed.",
            "Threat Simulation Lab",
            {
                "simulation": True,
                "scenario": config["scenario_name"],
                "events_generated": total,
                "threats_detected": run["threats_detected"],
                "metrics": run["metrics"],
                "correlation": run["correlation"],
            },
        )
        run["ai_analysis"] = analysis

    run["status"] = "completed"
    run["completed_at"] = datetime.now(timezone.utc).isoformat()
    add_audit_entry("Synthetic simulation completed", "Threat Simulation Lab", run["id"], signature_status="SIMULATION")


def start_simulation(config: dict[str, Any]) -> dict[str, Any]:
    run_id = f"SIMRUN-{uuid4().hex[:10].upper()}"
    run = {
        "id": run_id,
        "status": "running",
        "simulation": True,
        "simulation_marker": "SIMULATION",
        "environment": "DEMO / ISOLATED",
        "config": config,
        "events_generated": 0,
        "threats_detected": 0,
        "incidents_created": 0,
        "events": [],
        "event_stream": [],
        "attack_graph": [],
        "correlation": {"triggered": False, "reason": "Simulation is running."},
        "metrics": {},
        "started_at": datetime.now(timezone.utc).isoformat(),
        "responses": [],
    }
    STATE["simulation_runs"][run_id] = run
    if len(STATE["simulation_runs"]) > 20:
        oldest = next(iter(STATE["simulation_runs"]))
        if oldest != run_id:
            STATE["simulation_runs"].pop(oldest, None)
    return run


def execute_simulation(run_id: str) -> None:
    run = STATE["simulation_runs"].get(run_id)
    if run and run["status"] == "running":
        try:
            _generate_batch(run)
        except Exception as exc:
            run["status"] = "failed"
            run["error"] = f"Simulation pipeline failed: {type(exc).__name__}"


def simulation_public_view(run: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in run.items() if key not in {"config"}} | {
        "config": {key: value for key, value in run["config"].items() if key not in {"custom_sequence"}},
    }
