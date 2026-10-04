from __future__ import annotations


def calculate_security_risk(risk_score: int | float, confidence: float) -> dict[str, float | str | int]:
    score = max(0, min(int(risk_score), 100))
    if score >= 80:
        level = "CRITICAL"
        rationale = "The operational risk score is at least 80."
    elif score >= 60:
        level = "HIGH"
        rationale = "The operational risk score is at least 60."
    elif score >= 35:
        level = "MEDIUM"
        rationale = "The operational risk score is at least 35."
    else:
        level = "LOW"
        rationale = "The operational risk score is below 35."

    return {
        "level": level,
        "risk_score": score,
        "confidence": float(confidence),
        "rationale": rationale,
    }
