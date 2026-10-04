from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Header, HTTPException
from pydantic import BaseModel, Field

from backend.api.auth import require_admin
from backend.database.database import STATE, add_audit_entry
from backend.simulation_lab import DIFFICULTIES, PLATFORMS, SCENARIOS, SEVERITIES, execute_simulation, list_scenarios, simulation_public_view, start_simulation

router = APIRouter()

SimulationStage = Literal[
    "port_scan", "authentication_failure", "credential_stuffing", "privilege_escalation",
    "lateral_movement", "database_access_anomaly", "data_exfiltration", "routine_activity",
    "sql_injection_attempt", "api_abuse", "dns_anomaly", "suspicious_process", "iam_anomaly",
]


class SimulationRequest(BaseModel):
    scenario_id: str = Field(min_length=2, max_length=80)
    target_platform: Literal["web", "api", "cloud", "linux", "database", "identity", "network", "endpoint"] = "linux"
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "HIGH"
    protocol: Literal["TCP", "UDP", "HTTPS", "DNS"] = "TCP"
    timestamp_pattern: Literal["SEQUENTIAL", "BURST", "SLOW_DRIP", "IRREGULAR"] = "SEQUENTIAL"
    event_volume: int = Field(default=25, ge=1, le=250)
    duration_seconds: int = Field(default=30, ge=5, le=120)
    difficulty: Literal["EASY", "MEDIUM", "HARD", "ADVERSARIAL", "UNKNOWN"] = "MEDIUM"
    attacker_identity: str = Field(default="demo_attacker_01", pattern=r"^demo_[a-z0-9_]{1,32}$")
    target_identity: str = Field(default="demo_user_01", pattern=r"^demo_[a-z0-9_]{1,32}$")
    use_ai_analysis: bool = True


class CustomScenarioRequest(BaseModel):
    name: str = Field(min_length=3, max_length=80)
    category: Literal["NETWORK", "WEB / APPLICATION", "IDENTITY", "ENDPOINT", "CLOUD", "DATA", "AI SECURITY", "CRYPTOGRAPHIC / QUANTUM"]
    target_platform: Literal["web", "api", "cloud", "linux", "database", "identity", "network", "endpoint"]
    event_sequence: list[SimulationStage] = Field(min_length=1, max_length=8)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "HIGH"
    event_volume: int = Field(default=15, ge=1, le=250)
    difficulty: Literal["EASY", "MEDIUM", "HARD", "ADVERSARIAL", "UNKNOWN"] = "MEDIUM"
    noise_level: Literal["LOW", "MEDIUM", "HIGH"] = "MEDIUM"
    expected_detection: str = Field(default="Anomaly detected by the shared rule pipeline", max_length=240)
    expected_mitre_mapping: str = Field(default="T1110 - Brute Force", max_length=120)
    expected_response: str = Field(default="Review evidence and apply a simulated response", max_length=240)


class SimulatedResponseRequest(BaseModel):
    action: Literal[
        "SIMULATE_ACCOUNT_LOCK", "SIMULATE_ENDPOINT_ISOLATION", "SIMULATE_IP_BLOCK",
        "SIMULATE_SESSION_REVOCATION", "SIMULATE_CREDENTIAL_ROTATION", "SIMULATE_INCIDENT_ESCALATION",
    ]


def _authorize(authorization: str | None) -> None:
    require_admin(authorization)


@router.get("/scenarios")
def scenarios(authorization: str | None = Header(default=None)):
    _authorize(authorization)
    return {"environment": "DEMO / ISOLATED", "simulation_only": True, "items": list_scenarios() + [
        {"id": scenario_id, "name": item["name"], "category": item["category"], "custom": True}
        for scenario_id, item in STATE["custom_simulation_scenarios"].items()
    ]}


@router.post("/custom-scenarios")
def create_custom_scenario(payload: CustomScenarioRequest, authorization: str | None = Header(default=None)):
    _authorize(authorization)
    slug = re.sub(r"[^a-z0-9]+", "-", payload.name.lower()).strip("-")[:40]
    scenario_id = f"custom-{slug}"
    if scenario_id in SCENARIOS or scenario_id in STATE["custom_simulation_scenarios"]:
        raise HTTPException(status_code=409, detail="A scenario with that name already exists")
    STATE["custom_simulation_scenarios"][scenario_id] = {
        "name": payload.name,
        "category": payload.category,
        "target_platform": payload.target_platform,
        "custom_sequence": payload.event_sequence,
        "severity": payload.severity,
        "event_volume": payload.event_volume,
        "difficulty": payload.difficulty,
        "noise_level": payload.noise_level,
        "expected_detection": payload.expected_detection,
        "expected_mitre_mapping": payload.expected_mitre_mapping,
        "expected_response": payload.expected_response,
    }
    add_audit_entry("Custom simulation scenario created", "Threat Simulation Lab", scenario_id, signature_status="SIMULATION")
    return {"id": scenario_id, "name": payload.name, "category": payload.category, "simulation_only": True}


@router.post("/run")
def run_simulation(
    payload: SimulationRequest,
    background_tasks: BackgroundTasks,
    authorization: str | None = Header(default=None),
):
    _authorize(authorization)
    scenario = SCENARIOS.get(payload.scenario_id)
    custom = STATE["custom_simulation_scenarios"].get(payload.scenario_id)
    if not scenario and not custom:
        raise HTTPException(status_code=404, detail="Simulation scenario not found")

    if custom:
        config = {
            **payload.model_dump(),
            "scenario_name": custom["name"],
            "scenario_pattern": "custom",
            "custom_sequence": custom["custom_sequence"],
            "target_platform": custom["target_platform"],
            "noise_level": custom["noise_level"],
            "expected_detection": custom["expected_detection"],
            "expected_mitre_mapping": custom["expected_mitre_mapping"],
            "expected_response": custom["expected_response"],
        }
    else:
        config = {
            **payload.model_dump(),
            "scenario_name": scenario["name"],
            "scenario_pattern": scenario["pattern"],
        }
    run = start_simulation(config)
    background_tasks.add_task(execute_simulation, run["id"])
    return simulation_public_view(run)


@router.get("/runs")
def list_runs(authorization: str | None = Header(default=None)):
    _authorize(authorization)
    return {"items": [simulation_public_view(run) for run in reversed(list(STATE["simulation_runs"].values()))]}


@router.get("/runs/{run_id}")
def get_run(run_id: str, authorization: str | None = Header(default=None)):
    _authorize(authorization)
    run = STATE["simulation_runs"].get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Simulation run not found")
    return simulation_public_view(run)


@router.get("/metrics")
def simulation_metrics(authorization: str | None = Header(default=None)):
    _authorize(authorization)
    runs = [run for run in STATE["simulation_runs"].values() if run["status"] == "completed"]
    metrics = [run["metrics"] for run in runs]
    processed = sum(item.get("events_processed", 0) for item in metrics)
    return {
        "environment": "DEMO / ISOLATED",
        "simulation_only": True,
        "runs_completed": len(runs),
        "events_processed": processed,
        "threats_detected": sum(item.get("threats_detected", 0) for item in metrics),
        "incidents_created": sum(item.get("incidents_created", 0) for item in metrics),
        "detection_rate": round(sum(item.get("detection_rate", 0) for item in metrics) / max(1, len(metrics)), 1),
        "false_positive_rate": round(sum(item.get("false_positive_rate", 0) for item in metrics) / max(1, len(metrics)), 1),
        "average_detection_time_ms": round(sum(item.get("average_detection_time_ms", 0) for item in metrics) / max(1, len(metrics)), 2),
        "missed_threats": sum(item.get("missed_threats", 0) for item in metrics),
        "latest_run_id": runs[-1]["id"] if runs else None,
    }


@router.post("/runs/{run_id}/responses")
def simulate_response(
    run_id: str,
    payload: SimulatedResponseRequest,
    authorization: str | None = Header(default=None),
):
    _authorize(authorization)
    run = STATE["simulation_runs"].get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Simulation run not found")
    response = {
        "action": payload.action,
        "target": run["config"].get("target_identity", "demo-endpoint-01"),
        "result": "SUCCESS — SIMULATION ONLY",
        "simulation": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    run["responses"].append(response)
    run["event_stream"].append({
        "timestamp": response["timestamp"],
        "event_type": payload.action,
        "stage": "Simulated Response",
        "result": "SUCCESS — SIMULATION ONLY",
        "simulation": True,
    })
    add_audit_entry("Simulated response executed", "Threat Simulation Lab", run_id, signature_status="SIMULATION")
    return response
