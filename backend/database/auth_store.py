from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


DEFAULT_USERS = (
    ("admin-demo", "System Admin", "admin", "admin@quantumcyberdefense.demo", "admin123"),
    ("customer-demo", "Customer Portal", "customer", "customer@quantumcyberdefense.demo", "customer123"),
)
PASSWORD_ITERATIONS = 310_000


def get_database_path() -> Path:
    configured_path = os.environ.get("SECURITY_DATABASE_PATH")
    return Path(configured_path) if configured_path else Path(__file__).with_name("security_platform.sqlite3")


def _connect() -> sqlite3.Connection:
    path = get_database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin', 'customer')),
            email TEXT NOT NULL COLLATE NOCASE UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_users_email_role ON users(email, role)")
    return connection


@contextmanager
def _connection() -> Iterator[sqlite3.Connection]:
    connection = _connect()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt.hex()}${digest.hex()}"


def _password_matches(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations, salt, expected_digest = stored_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iterations)
        ).hex()
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest, expected_digest)


def seed_auth_users() -> None:
    with _connection() as connection:
        for user_id, name, role, email, password in DEFAULT_USERS:
            if connection.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone():
                continue
            connection.execute(
                "INSERT OR IGNORE INTO users (id, name, role, email, password_hash) VALUES (?, ?, ?, ?, ?)",
                (user_id, name, role, email, _hash_password(password)),
            )


def register_user(email: str, password: str, name: str = "Customer Portal") -> dict:
    normalized_email = email.strip().lower()
    normalized_name = name.strip() or "Customer Portal"
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")

    try:
        with _connection() as connection:
            cursor = connection.execute(
                "INSERT INTO users (id, name, role, email, password_hash) VALUES (?, ?, 'customer', ?, ?)",
                (f"user-{secrets.token_hex(12)}", normalized_name, normalized_email, _hash_password(password)),
            )
            row = connection.execute(
                "SELECT id, name, role, email FROM users WHERE rowid = ?", (cursor.lastrowid,)
            ).fetchone()
    except sqlite3.IntegrityError as exc:
        raise ValueError("User already exists") from exc

    return dict(row)


def authenticate_user(email: str, password: str, role: str | None = None) -> dict | None:
    normalized_email = email.strip().lower()
    requested_role = (role or "").strip().lower()
    if requested_role and requested_role not in {"admin", "customer"}:
        return None

    with _connection() as connection:
        if requested_role:
            row = connection.execute(
                "SELECT id, name, role, email, password_hash FROM users WHERE email = ? AND role = ?",
                (normalized_email, requested_role),
            ).fetchone()
        else:
            row = connection.execute(
                "SELECT id, name, role, email, password_hash FROM users WHERE email = ?",
                (normalized_email,),
            ).fetchone()

    if row is None or not _password_matches(password, row["password_hash"]):
        return None
    return {key: row[key] for key in ("id", "name", "role", "email")}