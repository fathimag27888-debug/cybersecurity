from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

from backend.database.auth_store import get_database_path


ANALYTICS_RETENTION_DAYS = 5


@contextmanager
def _connection() -> Iterator[sqlite3.Connection]:
    path = get_database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS analytics_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            payload_json TEXT NOT NULL
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_analytics_events_timestamp ON analytics_events(timestamp)"
    )
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _normalize_timestamp(value: str) -> str:
    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def save_analytics_event(event: dict[str, Any]) -> None:
    record = {**event, "timestamp": _normalize_timestamp(str(event["timestamp"]))}
    cutoff = (datetime.now(timezone.utc) - timedelta(days=ANALYTICS_RETENTION_DAYS)).isoformat().replace("+00:00", "Z")
    with _connection() as connection:
        connection.execute("DELETE FROM analytics_events WHERE timestamp < ?", (cutoff,))
        if record["timestamp"] >= cutoff:
            connection.execute(
                "INSERT INTO analytics_events (timestamp, payload_json) VALUES (?, ?)",
                (record["timestamp"], json.dumps(record, separators=(",", ":"))),
            )


def get_analytics_events(since: datetime | None = None) -> list[dict[str, Any]]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=ANALYTICS_RETENTION_DAYS)
    if since is not None:
        requested_start = since if since.tzinfo else since.replace(tzinfo=timezone.utc)
        cutoff = max(cutoff, requested_start.astimezone(timezone.utc))
    cutoff_text = cutoff.isoformat().replace("+00:00", "Z")

    with _connection() as connection:
        connection.execute("DELETE FROM analytics_events WHERE timestamp < ?", (cutoff_text,))
        rows = connection.execute(
            "SELECT payload_json FROM analytics_events WHERE timestamp >= ? ORDER BY timestamp, id",
            (cutoff_text,),
        ).fetchall()
    return [json.loads(row["payload_json"]) for row in rows]