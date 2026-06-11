"""SQLite connection helper and forward-only migrations."""
from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_V1 = [
    """
    CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS probe_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        probe TEXT NOT NULL,
        run_at TEXT NOT NULL,
        metrics_json TEXT NOT NULL,
        artifacts_json TEXT NOT NULL,
        errors_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hash TEXT UNIQUE NOT NULL,
        domain TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        body_md TEXT NOT NULL,
        evidence_json TEXT NOT NULL,
        suggested_action TEXT NOT NULL,
        proposed_artifact TEXT,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        status TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id INTEGER NOT NULL,
        channel TEXT NOT NULL,
        sent_at TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        FOREIGN KEY(finding_id) REFERENCES findings(id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS agent_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent TEXT NOT NULL,
        started_at TEXT NOT NULL,
        ended_at TEXT,
        status TEXT NOT NULL,
        input_tokens INTEGER DEFAULT 0,
        output_tokens INTEGER DEFAULT 0,
        tool_calls_json TEXT NOT NULL,
        output_hash TEXT,
        finding_ids_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS cooldowns (
        probe TEXT NOT NULL,
        metric TEXT NOT NULL,
        last_woken_at TEXT NOT NULL,
        PRIMARY KEY (probe, metric)
    )
    """,
]


def connect(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def migrate(conn: sqlite3.Connection) -> None:
    from datetime import datetime, timezone
    for stmt in SCHEMA_V1:
        conn.execute(stmt)
    cur = conn.execute("SELECT COALESCE(MAX(version), 0) FROM schema_version")
    current = cur.fetchone()[0]
    if current < 1:
        conn.execute(
            "INSERT INTO schema_version(version, applied_at) VALUES (?, ?)",
            (1, datetime.now(tz=timezone.utc).isoformat()),
        )
    conn.commit()
