"""Persistencia de pending approvals en SQLite.

Almacena el plan del Narrator + status + audit trail. Single-source-of-truth
para el endpoint /approve/{token}.

Tabla: pending_approvals
  - token TEXT PRIMARY KEY     (secrets.token_urlsafe(32), ~256 bits entropy)
  - alert_id TEXT NOT NULL
  - plan_json TEXT NOT NULL    (NarratorPlan.model_dump_json())
  - alert_json TEXT NOT NULL   (NormalizedAlert.model_dump_json() para reproducibilidad)
  - status TEXT                ('pending', 'approved', 'rejected', 'expired', 'executed')
  - created_at TEXT NOT NULL   (ISO8601)
  - decided_at TEXT
  - decided_by_ip TEXT
  - decided_by_ua TEXT
  - executed_at TEXT
  - execution_result TEXT      (JSON, list[ExecutionResult])

Usamos sqlite3 stdlib + asyncio.to_thread para no agregar deps. La DB es
single-writer (FastAPI single-process), no necesitamos un pool.
"""
from __future__ import annotations

import asyncio
import json
import logging
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

logger = logging.getLogger("soc-l1")

SCHEMA = """
CREATE TABLE IF NOT EXISTS pending_approvals (
    token TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL,
    plan_json TEXT NOT NULL,
    alert_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    decided_at TEXT,
    decided_by_ip TEXT,
    decided_by_ua TEXT,
    selected_actions TEXT,
    executed_at TEXT,
    execution_result TEXT,
    invgate_request_id INTEGER
);

CREATE INDEX IF NOT EXISTS idx_pending_approvals_alert_id ON pending_approvals(alert_id);
CREATE INDEX IF NOT EXISTS idx_pending_approvals_status ON pending_approvals(status);
"""

# Migrations idempotentes para DBs existentes (ALTER TABLE silencia el error
# si ya existe la columna vía try/except en _init_db_sync).
_MIGRATIONS = [
    "ALTER TABLE pending_approvals ADD COLUMN selected_actions TEXT",
    "ALTER TABLE pending_approvals ADD COLUMN invgate_request_id INTEGER",
]

ApprovalStatus = str  # 'pending' | 'approved' | 'rejected' | 'expired' | 'executed'


@contextmanager
def _connect(db_path: str) -> Iterator[sqlite3.Connection]:
    """Context manager: abre conexión, configura WAL + row_factory, commit/cierra."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        yield conn
    finally:
        conn.close()


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


# ===== Sync helpers (corren bajo asyncio.to_thread) =====


def _init_db_sync(db_path: str) -> None:
    with _connect(db_path) as conn:
        conn.executescript(SCHEMA)
        # Migraciones idempotentes: ignorar si la columna ya existe
        for stmt in _MIGRATIONS:
            try:
                conn.execute(stmt)
            except sqlite3.OperationalError:
                pass  # columna ya existe


def _create_pending_sync(
    db_path: str,
    alert_id: str,
    plan_json: str,
    alert_json: str,
    invgate_request_id: int | None = None,
) -> str:
    token = secrets.token_urlsafe(32)
    with _connect(db_path) as conn:
        conn.execute(
            "INSERT INTO pending_approvals "
            "(token, alert_id, plan_json, alert_json, status, created_at, invgate_request_id) "
            "VALUES (?, ?, ?, ?, 'pending', ?, ?)",
            (token, alert_id, plan_json, alert_json, _now(), invgate_request_id),
        )
    return token


def _get_pending_sync(db_path: str, token: str) -> dict[str, Any] | None:
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM pending_approvals WHERE token = ?", (token,)
        ).fetchone()
        return dict(row) if row else None


def _decide_sync(
    db_path: str,
    token: str,
    decision: str,
    ip: str | None,
    user_agent: str | None,
    ttl_hours: int,
    selected_action_indices: list[int] | None = None,
) -> tuple[str, dict[str, Any] | None]:
    """Aplica decisión si el token está pending y no expiró.

    selected_action_indices: lista de índices (0-based) de plan.actions que el humano
    aprobó individualmente. Si None y decision='approved', se interpreta como "approve all".

    Retorna (result_status, row):
      - 'ok'              → row con la fila actualizada (post-update)
      - 'not_found'       → token no existe
      - 'already_decided' → status != pending
      - 'expired'         → TTL vencido (la marca como 'expired' en DB)
    """
    assert decision in ("approved", "rejected"), f"decision inválida: {decision}"
    cutoff = (datetime.now(tz=timezone.utc) - timedelta(hours=ttl_hours)).isoformat()

    selected_json: str | None = None
    if selected_action_indices is not None:
        selected_json = json.dumps(sorted(set(selected_action_indices)))

    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM pending_approvals WHERE token = ?", (token,)
        ).fetchone()
        if row is None:
            return ("not_found", None)
        if row["status"] != "pending":
            return ("already_decided", dict(row))
        if row["created_at"] < cutoff:
            conn.execute(
                "UPDATE pending_approvals SET status='expired' WHERE token=? AND status='pending'",
                (token,),
            )
            updated = conn.execute(
                "SELECT * FROM pending_approvals WHERE token = ?", (token,)
            ).fetchone()
            return ("expired", dict(updated) if updated else None)

        # CAS-style: solo update si sigue pending (race-safe)
        cur = conn.execute(
            "UPDATE pending_approvals "
            "SET status=?, decided_at=?, decided_by_ip=?, decided_by_ua=?, "
            "    selected_actions=? "
            "WHERE token=? AND status='pending'",
            (decision, _now(), ip, user_agent, selected_json, token),
        )
        if cur.rowcount == 0:
            # Race: alguien decidió en el mientras tanto
            fresh = conn.execute(
                "SELECT * FROM pending_approvals WHERE token = ?", (token,)
            ).fetchone()
            return ("already_decided", dict(fresh) if fresh else None)

        updated = conn.execute(
            "SELECT * FROM pending_approvals WHERE token = ?", (token,)
        ).fetchone()
        return ("ok", dict(updated) if updated else None)


def _mark_executed_sync(db_path: str, token: str, execution_result_json: str) -> None:
    with _connect(db_path) as conn:
        conn.execute(
            "UPDATE pending_approvals "
            "SET status='executed', executed_at=?, execution_result=? "
            "WHERE token=?",
            (_now(), execution_result_json, token),
        )


# ===== Async wrappers públicas =====


async def init_db(db_path: str) -> None:
    """Crea tablas si no existen. Llamar una vez al startup."""
    await asyncio.to_thread(_init_db_sync, db_path)
    logger.info("state: SQLite inicializada en %s", db_path)


async def create_pending_approval(
    db_path: str,
    alert_id: str,
    plan_json: str,
    alert_json: str,
    invgate_request_id: int | None = None,
) -> str:
    """Crea un pending approval y devuelve el token único.

    invgate_request_id: id del ticket InvGate ya creado (si lo está). Se persiste
    para que /approve, /reject y el executor puedan agregar comentarios al mismo ticket.
    """
    return await asyncio.to_thread(
        _create_pending_sync, db_path, alert_id, plan_json, alert_json,
        invgate_request_id,
    )


async def get_pending_approval(db_path: str, token: str) -> dict[str, Any] | None:
    """Trae la fila por token. None si no existe."""
    return await asyncio.to_thread(_get_pending_sync, db_path, token)


async def decide_approval(
    db_path: str,
    token: str,
    decision: str,
    ip: str | None = None,
    user_agent: str | None = None,
    ttl_hours: int = 24,
    selected_action_indices: list[int] | None = None,
) -> tuple[str, dict[str, Any] | None]:
    """Aplica una decisión. Idempotente: segunda llamada retorna 'already_decided'.

    selected_action_indices: si viene, guarda qué índices de plan.actions se aprobaron.
    Si es None y decision='approved', se interpreta como "approved all" (backwards compat).
    """
    return await asyncio.to_thread(
        _decide_sync, db_path, token, decision, ip, user_agent, ttl_hours,
        selected_action_indices,
    )


async def mark_executed(db_path: str, token: str, execution_result: list[dict]) -> None:
    """Marca el approval como ejecutado y guarda el resultado de las acciones."""
    await asyncio.to_thread(
        _mark_executed_sync,
        db_path,
        token,
        json.dumps(execution_result, default=str),
    )


# ===== List / query for dashboard =====


def _list_approvals_sync(
    db_path: str,
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """Lista approvals con filtro opcional por status. Retorna (rows, total_count)."""
    # Sanity en limit/offset (defensa contra DoS por queries enormes)
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))

    with _connect(db_path) as conn:
        if status:
            count_row = conn.execute(
                "SELECT COUNT(*) FROM pending_approvals WHERE status = ?", (status,)
            ).fetchone()
            rows = conn.execute(
                "SELECT token, alert_id, status, created_at, decided_at, "
                "       decided_by_ip, decided_by_ua, selected_actions, "
                "       executed_at, plan_json, invgate_request_id "
                "FROM pending_approvals WHERE status = ? "
                "ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (status, limit, offset),
            ).fetchall()
        else:
            count_row = conn.execute("SELECT COUNT(*) FROM pending_approvals").fetchone()
            rows = conn.execute(
                "SELECT token, alert_id, status, created_at, decided_at, "
                "       decided_by_ip, decided_by_ua, selected_actions, "
                "       executed_at, plan_json, invgate_request_id "
                "FROM pending_approvals "
                "ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()

    total = int(count_row[0] if count_row else 0)
    return ([dict(r) for r in rows], total)


async def list_approvals(
    db_path: str,
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """Lista approvals (más nuevos primero). status opcional filtra por estado.

    Retorna (rows, total_count). El total cuenta TODOS los matches (no solo la página).
    Cada row tiene los campos básicos + plan_json (no parseado, lo parsea el caller si necesita).
    """
    return await asyncio.to_thread(
        _list_approvals_sync, db_path, status, limit, offset
    )
