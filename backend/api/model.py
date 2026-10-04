from __future__ import annotations

from fastapi import APIRouter

from backend.database.database import STATE

router = APIRouter()


@router.get("/performance")
def model_performance():
    return {"status": "not_measured", "items": STATE["model_metrics"]}


@router.get("/comparison")
def model_comparison():
    metrics = STATE["model_metrics"]
    if len(metrics) < 2:
        return {
            "status": "not_measured",
            "classical": None,
            "quantum_inspired": None,
            "comparison": None,
        }

    baseline, optimized = metrics[:2]
    return {
        "status": "measured",
        "classical": baseline,
        "quantum_inspired": optimized,
        "comparison": {
            "precision_gain": optimized["precision"] - baseline["precision"],
            "recall_gain": optimized["recall"] - baseline["recall"],
            "f1_gain": optimized["f1_score"] - baseline["f1_score"],
            "false_positive_reduction": baseline["false_positive_rate"] - optimized["false_positive_rate"],
        },
    }
