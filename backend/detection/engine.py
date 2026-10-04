from __future__ import annotations

from typing import Any

from backend.features.feature_engineering import extract_features
from backend.normalization.normalize import normalize_security_event
from backend.risk.risk_engine import calculate_security_risk


def detect_security_event(event: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_security_event(event)
    normalized["features"] = extract_features(normalized)

    failed_attempts = int(normalized["features"].get("failed_attempts", 0))
    bytes_total = int(normalized["features"].get("bytes_total", 0))
    event_kind = str(normalized.get("event_type") or "").lower()

    explanations: list[str] = []
    remediation_steps: list[str] = []
    reason = "No suspicious activity detected."
    recommended_action = "Continue routine monitoring."
    threat_type = "Normal Activity"
    confidence = 0.0
    risk_score = 0
    detection_method = "Rule Detection"

    if failed_attempts >= 10:
        threat_type = "Brute Force"
        confidence = min(99.0, 60.0 + failed_attempts * 1.5)
        risk_score = min(100, 50 + failed_attempts * 3)
        reason = (
            "The login system is receiving repeated failed authentication attempts, which is a strong indicator "
            "of credential stuffing, password guessing, or targeted brute-force activity."
        )
        recommended_action = "Block the offending source, enforce account lockout policies, and require MFA for the impacted identities."
        explanations = [
            f"Observed {failed_attempts} failed authentication attempts within a short window.",
            "Configured brute-force threshold of 10 attempts was exceeded.",
            "The destination service is under active credential attack pressure.",
        ]
        remediation_steps = [
            "Block the source IP at the firewall, WAF, or edge gateway for 30 minutes to stop the attack window.",
            "Force a password reset and enforce multi-factor authentication for affected accounts.",
            "Reduce login retry tolerance and enable temporary account lockouts after repeated failures.",
            "Review authentication logs for suspicious credential reuse and revoke any compromised sessions.",
        ]
    elif any(term in event_kind for term in ("ddos", "traffic_surge", "denial_of_service")):
        threat_type = "DDoS Traffic Pattern"
        confidence = 94.0
        risk_score = 88
        reason = "Request frequency and traffic-volume indicators match a simulated denial-of-service traffic surge pattern."
        recommended_action = "Apply edge rate limits and inspect capacity indicators in the isolated lab scenario."
        explanations = [f"Observed request frequency of {normalized['features'].get('request_frequency', 0)} per event window.", "Traffic surge signature matched the DDoS pattern rule."]
        remediation_steps = ["Review rate-limit thresholds.", "Validate service capacity telemetry.", "Keep response actions in simulation mode."]
    elif normalized["features"].get("is_port_scan"):
        threat_type = "Port Scan"
        confidence = 88.0
        risk_score = 74
        reason = "Connection-probing behavior indicates reconnaissance across multiple destination ports."
        recommended_action = "Review exposed services and apply restrictive network policy in the isolated environment."
        explanations = [f"Observed {normalized['features'].get('unique_destination_ports', 0)} unique destination ports or a port-scan event signature.", "Reconnaissance pattern matched the network detection rule."]
        remediation_steps = ["Review exposed service inventory.", "Restrict unnecessary destination ports.", "Correlate reconnaissance with subsequent authentication activity."]
    elif any(term in event_kind for term in ("sql_injection", "xss", "ssrf", "path_traversal", "auth_bypass", "api_abuse", "file_upload", "session_hijacking", "prompt_injection", "data_poisoning", "model_abuse")):
        threat_type = "Application or AI Abuse Pattern"
        confidence = 91.0
        risk_score = 84
        reason = f"The normalized event type '{normalized['event_type']}' matched a suspicious application or AI usage signature."
        recommended_action = "Inspect the synthetic request evidence and validate application-layer controls."
        explanations = [f"Event type matched application/AI signature: {normalized['event_type']}.", "No request was sent to a real service; this signal is contained in the simulation event." ]
        remediation_steps = ["Review input validation and request policy.", "Check relevant application audit events.", "Keep all response actions in simulation mode."]
    elif any(term in event_kind for term in ("privilege_escalation", "iam_anomaly", "resource_abuse", "persistence", "suspicious_process", "process_injection", "command_control", "file_modification", "arp_spoofing", "dns_anomaly", "network_anomaly", "quantum_crypto", "weak_crypto", "impossible_travel", "mfa_abuse", "lateral_movement", "database_access", "data_access", "data_exfiltration", "credential_stuffing", "password_spraying", "suspicious_login")):
        threat_type = "Behavioral Security Anomaly"
        confidence = 89.0
        risk_score = 82
        reason = f"The normalized event type '{normalized['event_type']}' matched a monitored identity, endpoint, cloud, data, or cryptographic anomaly pattern."
        recommended_action = "Correlate this signal with adjacent identity, network, and resource-access events."
        explanations = [f"Behavioral event signature matched: {normalized['event_type']}.", "Cross-event context is evaluated by the simulation correlation stage." ]
        remediation_steps = ["Validate the affected identity or resource.", "Review adjacent events for an attack sequence.", "Do not apply controls outside the isolated simulation."]
    elif bytes_total >= 200000 or normalized["features"].get("request_frequency", 0) >= 50:
        threat_type = "High-Volume Traffic"
        confidence = min(95.0, 50.0 + bytes_total / 10_000)
        risk_score = min(90, 40 + bytes_total // 10_000)
        reason = (
            "The system is handling an abnormal volume of traffic that exceeds the normal throughput baseline, which "
            "can indicate a volumetric attack or service saturation event."
        )
        recommended_action = "Rate-limit the affected path, scale capacity, and inspect upstream network controls for traffic spikes."
        explanations = [
            f"Observed {bytes_total} bytes and request frequency {normalized['features'].get('request_frequency', 0)}, exceeding a configured traffic threshold.",
            "Configured high-volume threshold of 200000 bytes was reached.",
            "The application or edge network is experiencing abnormal load conditions.",
        ]
        remediation_steps = [
            "Enable rate limiting and bot protection at the CDN or load balancer layer.",
            "Increase upstream capacity or add auto-scaling rules to absorb the surge safely.",
            "Inspect the source network for malicious traffic and isolate any compromised hosts.",
            "Review application logs to determine whether the surge is malicious or due to a configuration issue.",
        ]

    risk_result = calculate_security_risk(risk_score, confidence)
    normalized["risk_score"] = risk_result["risk_score"]
    normalized["confidence"] = confidence
    normalized["threat_type"] = threat_type
    normalized["severity"] = risk_result["level"]
    normalized["detection_method"] = detection_method
    normalized["explanations"] = explanations
    normalized["reason"] = reason
    normalized["recommended_action"] = recommended_action
    normalized["remediation_steps"] = remediation_steps
    normalized["confidence_type"] = "rule_indicator_strength"

    return normalized
