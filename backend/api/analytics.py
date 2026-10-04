from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter

from backend.database.analytics_store import get_analytics_events
from backend.database.database import get_dashboard_summary

router = APIRouter()


@router.get("")
def analytics():
    summary = get_dashboard_summary()
    now = datetime.now(timezone.utc)
    first_bucket = now - timedelta(days=5)
    buckets = [
        {
            "time": (first_bucket + timedelta(days=index)).strftime("%b %d"),
            "total": 0,
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0,
        }
        for index in range(5)
    ]
    recent_events = []
    for event in get_analytics_events(since=first_bucket):
        try:
            timestamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        except (KeyError, TypeError, ValueError):
            continue
        age = now - timestamp
        if age < timedelta(0) or age >= timedelta(days=5):
            continue
        bucket_index = int((timestamp - first_bucket).total_seconds() // timedelta(days=1).total_seconds())
        if not 0 <= bucket_index < len(buckets):
            continue
        severity = str(event.get("severity") or "UNKNOWN").upper()
        bucket = buckets[bucket_index]
        bucket["total"] += 1
        bucket[severity if severity in bucket else "UNKNOWN"] += 1
        recent_events.append(event)

    severity_distribution = {severity: 0 for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")}
    classification_distribution: dict[str, int] = {}
    for event in recent_events:
        severity = str(event.get("severity") or "UNKNOWN").upper()
        severity_distribution[severity if severity in severity_distribution else "UNKNOWN"] += 1
        classification = str(event.get("classification") or "Unclassified")
        classification_distribution[classification] = classification_distribution.get(classification, 0) + 1

    risk_scores = [int(event.get("risk_score") or 0) for event in recent_events]
    latest_event = max(recent_events, key=lambda event: event["timestamp"], default=None)
    simulated_event_count = sum(1 for event in recent_events if event.get("simulation"))
    return {
        "data_mode": "simulation" if simulated_event_count else "live" if recent_events else "awaiting_events",
        "window_days": 5,
        "threats_over_time": buckets,
        "severity_distribution": severity_distribution,
        "classification_distribution": classification_distribution,
        "event_count": len(recent_events),
        "simulated_event_count": simulated_event_count,
        "live_event_count": len(recent_events) - simulated_event_count,
        "ai_enriched_count": sum(1 for event in recent_events if event.get("ai_enhanced")),
        "average_risk": round(sum(risk_scores) / len(risk_scores)) if risk_scores else 0,
        "high_risk_count": sum(1 for score in risk_scores if score >= 75),
        "critical_count": severity_distribution["CRITICAL"],
        "latest_event_at": latest_event["timestamp"] if latest_event else None,
        "updated_at": now.isoformat(),
        "signature_results": {"VALID": 0, "INVALID": 0},
        "model_performance": None,
        "model_performance_status": "not_measured",
    }


@router.get("/overview")
def overview():
    return get_dashboard_summary()
