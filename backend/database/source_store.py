from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator
from urllib.parse import urlsplit, urlunsplit

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
        CREATE TABLE IF NOT EXISTS website_sources (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            url TEXT NOT NULL COLLATE NOCASE UNIQUE,
            token_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_event_at TEXT
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS website_events (
            event_id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL REFERENCES website_sources(id),
            event_json TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            received_at TEXT NOT NULL
        )
        """
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_website_events_source_received ON website_events(source_id, received_at)")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _normalize_url(url: str) -> str:
    parsed = urlsplit(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a complete HTTP or HTTPS website URL")
    if parsed.username or parsed.password:
        raise ValueError("Website URLs must not contain credentials")
    netloc = parsed.hostname.lower()
    if parsed.port and not (parsed.scheme == "http" and parsed.port == 80) and not (parsed.scheme == "https" and parsed.port == 443):
        netloc = f"{netloc}:{parsed.port}"
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))


def register_website_source(name: str, url: str) -> dict[str, Any]:
    normalized_name = name.strip()
    if not normalized_name:
        raise ValueError("Website name is required")
    normalized_url = _normalize_url(url)
    source_id = f"web-{uuid.uuid4().hex[:12]}"
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        with _connection() as connection:
            connection.execute(
                "INSERT INTO website_sources (id, name, url, token_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                (source_id, normalized_name, normalized_url, token_hash, created_at),
            )
    except sqlite3.IntegrityError as exc:
        raise ValueError("This website URL is already registered") from exc
    return {
        "id": source_id,
        "name": normalized_name,
        "url": normalized_url,
        "status": "awaiting_events",
        "created_at": created_at,
        "event_count": 0,
        "threat_count": 0,
        "ingestion_token": token,
    }


def list_website_sources() -> list[dict[str, Any]]:
    with _connection() as connection:
        rows = connection.execute(
            """
            SELECT s.id, s.name, s.url, s.created_at, s.last_event_at,
                   COUNT(e.event_id) AS event_count,
                   COALESCE(SUM(CASE WHEN e.risk_score >= 35 THEN 1 ELSE 0 END), 0) AS threat_count
            FROM website_sources AS s
            LEFT JOIN website_events AS e ON e.source_id = s.id
            GROUP BY s.id
            ORDER BY s.created_at DESC
            """
        ).fetchall()
    return [
        {
            "id": row["id"],
            "name": row["name"],
            "url": row["url"],
            "status": "receiving_events" if row["last_event_at"] else "awaiting_events",
            "created_at": row["created_at"],
            "last_event_at": row["last_event_at"],
            "event_count": row["event_count"],
            "threat_count": row["threat_count"],
        }
        for row in rows
    ]


def authenticate_source(source_id: str, token: str) -> bool:
    with _connection() as connection:
        row = connection.execute("SELECT token_hash FROM website_sources WHERE id = ?", (source_id,)).fetchone()
    if row is None:
        return False
    candidate = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return secrets.compare_digest(candidate, row["token_hash"])


def add_website_event(source_id: str, detection: dict[str, Any]) -> None:
    received_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with _connection() as connection:
        connection.execute(
            """
            INSERT INTO website_events
                (event_id, source_id, event_json, threat_type, risk_score, severity, confidence, received_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                detection["event_id"],
                source_id,
                json.dumps(detection, sort_keys=True, separators=(",", ":")),
                detection["threat_type"],
                detection["risk_score"],
                detection["severity"],
                detection["confidence"],
                received_at,
            ),
        )
        connection.execute("UPDATE website_sources SET last_event_at = ? WHERE id = ?", (received_at, source_id))


def list_website_events(source_id: str, limit: int = 50) -> list[dict[str, Any]]:
    with _connection() as connection:
        rows = connection.execute(
            "SELECT event_json FROM website_events WHERE source_id = ? ORDER BY received_at DESC LIMIT ?",
            (source_id, limit),
        ).fetchall()
    return [json.loads(row["event_json"]) for row in rows]
