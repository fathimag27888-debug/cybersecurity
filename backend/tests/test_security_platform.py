import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend.api.auth import LoginRequest, OTPVerificationRequest, RegisterRequest, _issue_session, login, register, require_admin, verify_login_otp
from backend.api.ai import CopilotRequest, ai_status, ask_copilot
from backend.api.analytics import analytics
from backend.api.simulations import SimulatedResponseRequest, simulate_response
from backend.api.incidents import update_incident
from backend.api.signatures import SignatureRequest, sign_event, tamper_event, verify_event
from backend.api.sources import WebsiteEventRequest, WebsiteSourceRequest, add_website, ingest_website_event, list_websites
from backend.database.auth_store import authenticate_user, register_user, seed_auth_users
from backend.database.database import STATE
from backend.database.evidence_store import get_evidence_record
from backend.detection.engine import detect_security_event
from backend.evidence.records import create_evidence_record, verify_evidence_record
from backend.llama_service import LlamaProviderError, answer_security_question, enrich_threat, get_llama_status
from backend.features.feature_engineering import extract_features
from backend.ml.model import analyze_event
from backend.normalization.normalize import normalize_security_event
from backend.risk.risk_engine import calculate_security_risk
from backend.simulation_lab import SCENARIOS, execute_simulation, start_simulation


@pytest.fixture(autouse=True)
def isolate_database_for_test(monkeypatch, tmp_path):
    monkeypatch.setenv("SECURITY_DATABASE_PATH", str(tmp_path / "security-platform.sqlite3"))
    from backend import llama_service

    monkeypatch.setattr(llama_service, "_installed_models", lambda: [])


def test_analytics_aggregates_recent_real_detection_events(monkeypatch):
    now = datetime.now(timezone.utc)
    monkeypatch.setitem(STATE, "analytics_events", [
        {
            "event_id": "EVT-CRITICAL",
            "timestamp": now.isoformat(),
            "classification": "Brute Force",
            "severity": "CRITICAL",
            "risk_score": 91,
            "ai_enhanced": True,
        },
        {
            "event_id": "EVT-HIGH",
            "timestamp": (now - timedelta(hours=2)).isoformat(),
            "classification": "Port Scan",
            "severity": "HIGH",
            "risk_score": 78,
            "ai_enhanced": False,
        },
        {
            "event_id": "EVT-OLD",
            "timestamp": (now - timedelta(hours=13)).isoformat(),
            "classification": "Old event",
            "severity": "CRITICAL",
            "risk_score": 100,
            "ai_enhanced": True,
        },
        {
            "event_id": "EVT-EXPIRED",
            "timestamp": (now - timedelta(days=6)).isoformat(),
            "classification": "Expired event",
            "severity": "LOW",
            "risk_score": 20,
            "ai_enhanced": False,
        },
    ])
    monkeypatch.setattr(
        "backend.api.analytics.get_analytics_events",
        lambda since: STATE["analytics_events"],
    )

    result = analytics()

    assert result["data_mode"] == "live"
    assert result["window_days"] == 5
    assert result["event_count"] == 3
    assert result["average_risk"] == 90
    assert result["critical_count"] == 2
    assert result["ai_enriched_count"] == 2
    assert result["severity_distribution"]["CRITICAL"] == 2
    assert result["severity_distribution"]["HIGH"] == 1
    assert result["classification_distribution"] == {
        "Brute Force": 1,
        "Port Scan": 1,
        "Old event": 1,
    }
    assert len(result["threats_over_time"]) == 5
    assert sum(bucket["total"] for bucket in result["threats_over_time"]) == 3


def test_analytics_reports_empty_state_without_invented_chart_data(monkeypatch):
    monkeypatch.setitem(STATE, "analytics_events", [])
    monkeypatch.setattr("backend.api.analytics.get_analytics_events", lambda since: [])

    result = analytics()

    assert result["data_mode"] == "awaiting_events"
    assert result["event_count"] == 0
    assert result["average_risk"] == 0
    assert len(result["threats_over_time"]) == 5
    assert all(bucket["total"] == 0 for bucket in result["threats_over_time"])
    assert sum(result["severity_distribution"].values()) == 0


def test_analytics_history_persists_and_expires_after_five_days(monkeypatch, tmp_path):
    from backend.database.analytics_store import get_analytics_events, save_analytics_event
    from backend.database.database import record_analytics_event

    monkeypatch.setenv("SECURITY_DATABASE_PATH", str(tmp_path / "analytics-history.sqlite3"))
    now = datetime.now(timezone.utc)
    save_analytics_event({
        "event_id": "EVT-RECENT-HISTORY",
        "timestamp": (now - timedelta(days=4)).isoformat(),
        "classification": "Credential Stuffing",
        "severity": "HIGH",
        "risk_score": 82,
    })
    save_analytics_event({
        "event_id": "EVT-EXPIRED-HISTORY",
        "timestamp": (now - timedelta(days=6)).isoformat(),
        "classification": "Expired Event",
        "severity": "LOW",
        "risk_score": 10,
    })
    recorded_event = record_analytics_event({
        "id": "EVT-PERSISTED-THROUGH-INGESTION",
        "classification": "Brute Force",
        "severity": "CRITICAL",
        "risk_score": 94,
    })

    saved_events = get_analytics_events(since=now - timedelta(days=5))

    assert [event["event_id"] for event in saved_events] == [
        "EVT-RECENT-HISTORY",
        "EVT-PERSISTED-THROUGH-INGESTION",
    ]
    assert saved_events[1] == recorded_event

    result = analytics()

    assert result["event_count"] == 2
    assert result["live_event_count"] == 2
    assert result["critical_count"] == 1
    assert sum(bucket["total"] for bucket in result["threats_over_time"]) == 2


def test_universal_simulation_flows_through_detector_and_correlates(monkeypatch):
    monkeypatch.setitem(STATE, "simulation_runs", {})
    monkeypatch.setitem(STATE, "analytics_events", [])
    monkeypatch.setitem(STATE, "incidents", [])
    monkeypatch.setitem(STATE, "live_feed", [])
    run = start_simulation({
        "scenario_id": "universal-cross-platform",
        "scenario_name": "UNIVERSAL CROSS-PLATFORM ATTACK",
        "scenario_pattern": "cross_platform",
        "target_platform": "linux",
        "severity": "HIGH",
        "event_volume": 47,
        "duration_seconds": 20,
        "difficulty": "MEDIUM",
        "use_ai_analysis": False,
    })

    execute_simulation(run["id"])

    completed = STATE["simulation_runs"][run["id"]]
    platforms = {event["source_platform"] for event in completed["events"]}
    assert completed["status"] == "completed"
    assert completed["events_generated"] == 47
    assert all(event["simulation_marker"] == "SIMULATION" for event in completed["events"])
    assert {event["source_ip"] for event in completed["events"]}.issubset({"198.51.100.42", "203.0.113.29", "192.0.2.18"})
    assert all(event["destination"].endswith(".test") for event in completed["events"])
    assert {"web", "api", "cloud", "linux", "database", "identity"}.issubset(platforms)
    assert completed["correlation"]["triggered"] is True
    assert completed["incident"]["simulation"] is True
    assert completed["metrics"]["incidents_created"] == 1
    assert completed["metrics"]["missed_threats"] == 0
    assert len(STATE["analytics_events"]) == 47
    assert len(STATE["live_feed"]) == completed["threats_detected"]
    assert all(item["simulation_marker"] == "SIMULATION" for item in STATE["live_feed"])


def test_simulated_response_only_records_lab_action(monkeypatch):
    monkeypatch.setitem(STATE, "simulation_runs", {})
    run = start_simulation({
        "scenario_id": "brute-force",
        "scenario_name": "Brute Force Simulation",
        "scenario_pattern": "brute_force",
        "target_platform": "linux",
        "severity": "HIGH",
        "event_volume": 1,
        "duration_seconds": 5,
        "difficulty": "EASY",
        "use_ai_analysis": False,
    })
    token = _issue_session({"role": "admin"})

    response = simulate_response(run["id"], SimulatedResponseRequest(action="SIMULATE_ENDPOINT_ISOLATION"), f"Bearer {token}")

    assert response["result"] == "SUCCESS — SIMULATION ONLY"
    assert response["simulation"] is True
    assert run["events"] == []


def test_every_catalog_scenario_emits_a_detectable_synthetic_signal(monkeypatch):
    monkeypatch.setitem(STATE, "simulation_runs", {})
    monkeypatch.setitem(STATE, "analytics_events", [])
    monkeypatch.setitem(STATE, "incidents", [])

    for scenario in SCENARIOS.values():
        run = start_simulation({
            "scenario_id": scenario["id"],
            "scenario_name": scenario["name"],
            "scenario_pattern": scenario["pattern"],
            "target_platform": "linux",
            "severity": "HIGH",
            "event_volume": 1,
            "duration_seconds": 5,
            "difficulty": "EASY",
            "use_ai_analysis": False,
        })
        execute_simulation(run["id"])
        completed = STATE["simulation_runs"][run["id"]]

        assert completed["status"] == "completed", scenario["id"]
        assert completed["threats_detected"] == 1, scenario["id"]


def test_simulation_run_api_requires_admin_and_returns_pipeline_result(monkeypatch):
    monkeypatch.setitem(STATE, "simulation_runs", {})
    monkeypatch.setitem(STATE, "analytics_events", [])
    monkeypatch.setitem(STATE, "incidents", [])
    admin_token = _issue_session({"role": "admin"})
    customer_token = _issue_session({"role": "customer"})
    client = TestClient(__import__("backend.main", fromlist=["app"]).app)
    payload = {
        "scenario_id": "port-scan",
        "target_platform": "network",
        "severity": "HIGH",
        "event_volume": 3,
        "duration_seconds": 5,
        "difficulty": "EASY",
        "use_ai_analysis": False,
    }

    assert client.get("/api/simulations/scenarios").status_code == 401
    assert client.post("/api/simulations/run", json=payload, headers={"Authorization": f"Bearer {customer_token}"}).status_code == 403
    response = client.post("/api/simulations/run", json=payload, headers={"Authorization": f"Bearer {admin_token}"})

    assert response.status_code == 200
    run_id = response.json()["id"]
    run = client.get(f"/api/simulations/runs/{run_id}", headers={"Authorization": f"Bearer {admin_token}"}).json()
    assert run["status"] == "completed"
    assert run["events_generated"] == 3
    assert all(event["simulation"] is True for event in run["events"])


def test_normalize_event_creates_common_security_event():
    raw_event = {
        "source_platform": "windows",
        "source": "192.168.10.4",
        "destination": "secure-auth",
        "event_type": "authentication",
        "protocol": "TCP",
        "source_port": 52032,
        "destination_port": 443,
        "failed_attempts": 18,
        "bytes": 4200,
        "user": "alice",
        "raw_event": {"log_name": "Security"},
    }

    event = normalize_security_event(raw_event)

    assert event["source_platform"] == "windows"
    assert event["event_type"] == "authentication"
    assert event["failed_attempts"] == 18
    assert event["risk_score"] == 0
    assert "event_id" in event


def test_feature_engineering_sets_expected_features():
    event = {
        "source_platform": "linux",
        "failed_attempts": 15,
        "bytes": 20000,
        "source_port": 50112,
        "destination_port": 22,
        "protocol": "TCP",
    }

    features = extract_features(event)

    assert features["failed_attempts"] == 15
    assert features["is_ssh_access"] is True
    assert features["traffic_volume_bucket"] in {"low", "medium", "high"}


def test_detect_threat_returns_severity_and_explanations():
    event = {
        "source_platform": "windows",
        "source": "192.168.30.8",
        "destination": "auth-gateway",
        "event_type": "authentication",
        "protocol": "TCP",
        "source_port": 52031,
        "destination_port": 443,
        "failed_attempts": 18,
        "bytes": 4300,
        "user": "admin",
        "raw_event": {},
        "features": {"failed_attempts": 18, "is_ssh_access": False, "traffic_volume_bucket": "medium"},
    }

    detection = detect_security_event(event)

    assert detection["threat_type"] == "Brute Force"
    assert detection["severity"] in {"HIGH", "CRITICAL"}
    assert detection["explanations"]
    assert detection["confidence_type"] == "rule_indicator_strength"
    assert detection["reason"]
    assert detection["remediation_steps"]
    assert all("baseline" not in explanation.lower() for explanation in detection["explanations"])


def test_live_analysis_does_not_claim_optimization_or_signature():
    event = {
        "source_platform": "linux",
        "source_ip": "192.0.2.10",
        "destination_ip": "192.0.2.20",
        "protocol": "TCP",
        "source_port": 52000,
        "destination_port": 22,
        "packet_count": 12,
        "bytes_sent": 800,
        "bytes_received": 600,
        "connection_duration": 30,
        "failed_login_attempts": 0,
        "request_frequency": 1,
    }

    result = analyze_event(event)

    assert result["event_data"]["source_platform"] == "linux"
    assert result["optimization_status"] == "not_run_during_live_inference"
    assert result["signature_status"] == "UNSIGNED"


def test_llama_status_reports_local_model_without_api_key(monkeypatch):
    from backend import llama_service

    monkeypatch.setattr(llama_service, "_installed_models", lambda: ["llama3.2:3B"])

    status = get_llama_status()

    assert status["configured"] is True
    assert status["provider"] == "Ollama"
    assert status["model"] == "llama3.2:3B"


def test_threat_enrichment_keeps_rule_based_risk_authoritative(monkeypatch):
    from backend import llama_service

    monkeypatch.setattr(llama_service, "_installed_models", lambda: ["llama3.2:3B"])
    monkeypatch.setattr(llama_service, "_generate_json", lambda prompt: {
        "reason": "Repeated failed authentication attempts target the service.",
        "recommended_action": "Rate-limit the source and review impacted identities.",
        "remediation_steps": ["Block the source", "Reset affected credentials"],
        "risk_score": 1,
        "severity": "LOW",
    })
    original = {"risk_score": 91, "severity": "CRITICAL", "confidence": 96.2, "reason": "Rule reason"}

    result = enrich_threat(original, {"failed_login_attempts": 18})

    assert result["risk_score"] == 91
    assert result["severity"] == "CRITICAL"
    assert result["reason"] == "Repeated failed authentication attempts target the service."
    assert result["ai_enhanced"] is True


def test_threat_enrichment_falls_back_without_ollama_model():

    result = enrich_threat({"risk_score": 42, "reason": "Local reason"}, {})

    assert result["risk_score"] == 42
    assert result["reason"] == "Local reason"
    assert result["ai_enhanced"] is False
    assert result["analysis_provider"] == "Rule-based Detection"


def test_copilot_falls_back_when_ollama_is_unavailable(monkeypatch):
    from backend import llama_service

    monkeypatch.setattr(llama_service, "_installed_models", lambda: ["llama3.2:3B"])
    monkeypatch.setattr(llama_service, "_generate", lambda *args, **kwargs: (_ for _ in ()).throw(LlamaProviderError("provider_unavailable")))

    result = answer_security_question("Summarize risk", "Dashboard", {})

    assert result["status"] == "provider_unavailable"
    assert "Ollama is temporarily unavailable" in result["answer"]
    assert "retry in a moment" not in result["answer"]


def test_llama_endpoints_require_session_and_report_safe_fallback(monkeypatch):
    from fastapi import HTTPException
    from backend import llama_service

    monkeypatch.setattr(llama_service, "_installed_models", lambda: None)
    try:
        ai_status(None)
        raise AssertionError("AI status endpoint accepted an unauthenticated request")
    except HTTPException as exc:
        assert exc.status_code == 401

    token = _issue_session({"role": "customer"})
    authorization = f"Bearer {token}"
    status = ai_status(authorization)
    answer = ask_copilot(CopilotRequest(
        question="Summarize current risk",
        current_page="Dashboard",
        context={"metrics": {"average_risk": 32}},
    ), authorization)

    assert status["configured"] is False
    assert status["provider"] == "Ollama"
    assert "Ollama is not running" in answer["answer"]
    assert answer["status"] == "offline"


def test_risk_engine_sets_severity():
    severity = calculate_security_risk(96, 97.5)

    assert severity["level"] == "CRITICAL"
    assert severity["risk_score"] == 96


def test_risk_severity_does_not_increase_from_confidence_alone():
    severity = calculate_security_risk(18, 99.0)

    assert severity["level"] == "LOW"
    assert severity["risk_score"] == 18


def test_evidence_signing_verifies_and_detects_tamper():
    record = create_evidence_record({"incident_id": "INC-1001", "threat_type": "Brute Force"})

    assert record["signature_status"] == "VALID"
    assert verify_evidence_record(record["payload"], record["signature"], record["public_key"])

    tampered = dict(record["payload"])
    tampered["threat_type"] = "Port Scan"
    assert not verify_evidence_record(tampered, record["signature"], record["public_key"])


def test_sql_authenticates_seeded_roles_and_rejects_role_mismatch(monkeypatch, tmp_path):
    monkeypatch.setenv("SECURITY_DATABASE_PATH", str(tmp_path / "auth.sqlite3"))
    seed_auth_users()

    admin = authenticate_user("ADMIN@quantumcyberdefense.demo", "admin123", "admin")
    customer = authenticate_user("customer@quantumcyberdefense.demo", "customer123", "customer")

    assert admin and admin["role"] == "admin"
    assert customer and customer["role"] == "customer"
    assert authenticate_user("admin@quantumcyberdefense.demo", "admin123", "customer") is None
    assert authenticate_user("admin@quantumcyberdefense.demo", "incorrect", "admin") is None


def test_sql_registration_persists_only_password_hash(monkeypatch, tmp_path):
    database_path = tmp_path / "auth.sqlite3"
    monkeypatch.setenv("SECURITY_DATABASE_PATH", str(database_path))

    user = register_user("analyst@example.com", "strong-password", "Analyst")
    authenticated = authenticate_user(user["email"], "strong-password", "customer")

    assert authenticated == user
    with sqlite3.connect(database_path) as connection:
        stored_hash = connection.execute(
            "SELECT password_hash FROM users WHERE email = ?", (user["email"],)
        ).fetchone()[0]
    assert stored_hash.startswith("pbkdf2_sha256$")
    assert "strong-password" not in stored_hash


def test_registered_customer_can_log_in_with_saved_email_and_password(monkeypatch, tmp_path):
    from backend.api import auth

    monkeypatch.setenv("SECURITY_DATABASE_PATH", str(tmp_path / "registered-customer.sqlite3"))
    monkeypatch.setattr(auth, "_send_otp_email", lambda recipient_email, otp_code: False)
    registered = register(RegisterRequest(
        name="New Customer",
        email="customer@company.example.com",
        password="customer-password",
    ))

    login_response = login(LoginRequest(
        email="customer@company.example.com",
        password="customer-password",
        role="customer",
    ))
    verified = verify_login_otp(OTPVerificationRequest(
        email="customer@company.example.com",
        password="customer-password",
        role="customer",
        otp=login_response["otp_code"],
    ))

    assert "token" not in registered
    assert login_response["requires_otp"] is True
    assert verified["user"]["id"] == registered["user"]["id"]
    assert verified["user"]["email"] == registered["user"]["email"]


def test_auth_api_uses_sql_and_self_registration_cannot_create_admin(monkeypatch, tmp_path):
    monkeypatch.setenv("SECURITY_DATABASE_PATH", str(tmp_path / "auth.sqlite3"))
    seed_auth_users()

    admin_response = login(LoginRequest(
        email="admin@quantumcyberdefense.demo",
        password="admin123",
        role="admin",
    ))
    registration_response = register(RegisterRequest(
        name="New User",
        email="new.user@example.com",
        password="strong-password",
        role="admin",
    ))

    assert admin_response["user"]["role"] == "admin"
    assert registration_response["user"]["role"] == "customer"
    assert authenticate_user("new.user@example.com", "strong-password", "admin") is None


def test_auth_api_requires_otp_for_valid_credentials(monkeypatch, tmp_path):
    monkeypatch.setenv("SECURITY_DATABASE_PATH", str(tmp_path / "auth.sqlite3"))
    seed_auth_users()

    login_response = login(LoginRequest(
        email="customer@quantumcyberdefense.demo",
        password="customer123",
        role="customer",
    ))

    assert login_response["requires_otp"] is True
    assert login_response["otp_code"]

    verified = verify_login_otp(OTPVerificationRequest(
        email="customer@quantumcyberdefense.demo",
        password="customer123",
        role="customer",
        otp=login_response["otp_code"],
    ))

    assert verified["user"]["role"] == "customer"
    assert verified["token"]


def test_incident_response_actions_require_admin_session(monkeypatch):
    from fastapi import HTTPException

    monkeypatch.setitem(STATE, "incidents", [{"id": "INC-AUTHZ-1", "status": "OPEN"}])
    monkeypatch.setitem(STATE, "audit_logs", [])
    customer_token = _issue_session({"role": "customer"})
    admin_token = _issue_session({"role": "admin"})

    try:
        customer_role = require_admin(f"Bearer {customer_token}")
        update_incident("INC-AUTHZ-1", {"status": "RESOLVED"}, customer_role)
        raise AssertionError("Customer session was allowed to update an incident")
    except HTTPException as exc:
        assert exc.status_code == 403

    admin_role = require_admin(f"Bearer {admin_token}")
    updated = update_incident("INC-AUTHZ-1", {"status": "CONTAINED"}, admin_role)

    assert updated["status"] == "CONTAINED"


def test_signature_api_verifies_ed25519_and_detects_controlled_tamper(monkeypatch, tmp_path):
    monkeypatch.setenv("SECURITY_DATABASE_PATH", str(tmp_path / "evidence.sqlite3"))
    monkeypatch.setitem(STATE, "integrity_failures", 0)
    monkeypatch.setitem(STATE, "audit_logs", [])
    request = SignatureRequest(event_id="EVT-SIGNED-1", event_data={"risk_score": 91})

    record = sign_event(request)
    valid_result = verify_event(request)
    tamper_result = tamper_event(request)
    modified_request = SignatureRequest(event_id=request.event_id, event_data=tamper_result["tampered_event"])

    assert len(record["signature"]) == 128
    assert valid_result["verified"] is True
    assert get_evidence_record(request.event_id)["payload"] == request.event_data
    assert tamper_result["status"] == "INVALID"
    assert verify_event(modified_request)["verified"] is False
    assert STATE["integrity_failures"] == 2


def test_website_portal_registers_site_and_ingests_authenticated_threat_events(monkeypatch, tmp_path):
    monkeypatch.setenv("SECURITY_DATABASE_PATH", str(tmp_path / "website-sources.sqlite3"))
    source = add_website(WebsiteSourceRequest(name="Production site", url="https://example.com/"))
    event = WebsiteEventRequest(event={
        "event_id": "WEB-EVT-1",
        "source": "198.51.100.25",
        "destination": "login",
        "event_type": "authentication",
        "failed_attempts": 12,
    })

    from fastapi import HTTPException
    try:
        ingest_website_event(source["id"], event, "incorrect-token")
        raise AssertionError("An invalid source token was accepted")
    except HTTPException as exc:
        assert exc.status_code == 401

    result = ingest_website_event(source["id"], event, source["ingestion_token"])
    listed_source = list_websites()["items"][0]

    assert source["url"] == "https://example.com"
    assert result["source_platform"] == "web"
    assert result["threat_type"] == "Brute Force"
    assert listed_source["status"] == "receiving_events"
    assert listed_source["event_count"] == 1
    assert listed_source["threat_count"] == 1
