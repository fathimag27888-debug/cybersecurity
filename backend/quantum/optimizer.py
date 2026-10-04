from __future__ import annotations

from typing import Any


def run_quantum_inspired_optimization(event: dict[str, Any]) -> list[str]:
    features = [
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
    ]

    # Lightweight quantum-inspired prototype optimization: score feature importance using probability-like weights.
    candidate_states = []
    for idx, feature in enumerate(features):
        weight = 0.7 + ((idx % 4) * 0.15)
        if event.get("failed_login_attempts", 0) > 10 and feature in {"failed_login_attempts", "request_frequency", "destination_port", "protocol"}:
            weight += 0.55
        if event.get("packet_count", 0) > 1000 and feature in {"packet_count", "bytes_sent", "bytes_received", "connection_duration"}:
            weight += 0.45
        candidate_states.append((feature, weight))

    ranked = sorted(candidate_states, key=lambda item: item[1], reverse=True)
    selected = [name for name, _ in ranked[:7]]
    return selected
