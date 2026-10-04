from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from typing import Any, Iterator

from backend.database.auth_store import get_database_path


@contextmanager
def _connection() -> Iterator[sqlite3.Connection]:
    path = get_database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS evidence_records (
            event_id TEXT PRIMARY KEY,
            payload_json TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            signature TEXT NOT NULL,
            public_key TEXT NOT NULL,
            key_mode TEXT NOT NULL,
            signed_at TEXT NOT NULL
        )
        """
    )
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def save_evidence_record(record: dict[str, Any]) -> None:
    try:
        with _connection() as connection:
            connection.execute(
                """
                INSERT INTO evidence_records
                    (event_id, payload_json, content_hash, signature, public_key, key_mode, signed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["event_id"],
                    json.dumps(record["payload"], sort_keys=True, separators=(",", ":")),
                    record["hash"],
                    record["signature"],
                    record["public_key"],
                    record["key_mode"],
                    record["signed_at"],
                ),
            )
    except sqlite3.IntegrityError as exc:
        raise ValueError("Evidence has already been signed for this event") from exc


def get_evidence_record(event_id: str) -> dict[str, Any] | None:
    with _connection() as connection:
        row = connection.execute(
            """
            SELECT event_id, payload_json, content_hash, signature, public_key, key_mode, signed_at
            FROM evidence_records WHERE event_id = ?
            """,
            (event_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        "event_id": row["event_id"],
        "payload": json.loads(row["payload_json"]),
        "hash": row["content_hash"],
        "signature": row["signature"],
        "public_key": row["public_key"],
        "key_mode": row["key_mode"],
        "signed_at": row["signed_at"],
        "status": "VALID",
    }


def count_evidence_records() -> int:
    with _connection() as connection:
        row = connection.execute("SELECT COUNT(*) AS count FROM evidence_records").fetchone()
    return int(row["count"])
