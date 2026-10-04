from __future__ import annotations

from datetime import datetime, timezone


def create_audit_record(actor: str, action: str, resource: str, result: str = "SUCCESS", metadata: dict | None = None) -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "actor": actor,
        "action": action,
        "resource": resource,
        "result": result,
        "metadata": metadata or {},
    }
