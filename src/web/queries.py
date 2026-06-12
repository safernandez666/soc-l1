"""Consultas read-only sobre state.db para el panel /ui.

Todo se calcula desde la tabla pending_approvals (single source of truth). No
escribe nada. Las funciones públicas son async y corren bajo asyncio.to_thread,
igual que src/state.py, para no bloquear el event loop.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

# Orden canónico de estados para tablas/gráficos
STATUS_ORDER = ["pending", "approved", "executed", "rejected", "expired"]


def _connect_ro(db_path: str) -> sqlite3.Connection:
    """Conexión read-only (mode=ro). Si el archivo no existe, sqlite lo reporta."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except (TypeError, ValueError):
        return None


def _loads(s: str | None) -> Any:
    if not s:
        return None
    try:
        return json.loads(s)
    except (TypeError, ValueError):
        return None


def _human_duration(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h {(seconds % 3600) // 60}m"
    return f"{seconds // 86400}d {(seconds % 86400) // 3600}h"


def humanize_age(created_at: str | None, *, now: datetime | None = None) -> str:
    dt = _parse_dt(created_at)
    if dt is None:
        return "—"
    now = now or datetime.now(tz=timezone.utc)
    return _human_duration((now - dt).total_seconds())


# ===== Métricas del panel =====


def _metrics_sync(db_path: str) -> dict[str, Any]:
    now = datetime.now(tz=timezone.utc)
    try:
        conn = _connect_ro(db_path)
    except sqlite3.OperationalError:
        # DB todavía no existe (Narrator nunca corrió). Panel vacío, no error.
        return _empty_metrics()

    with conn:
        rows = conn.execute(
            "SELECT rowid, status, created_at, decided_at, executed_at, plan_json, "
            "       execution_result, alert_json "
            "FROM pending_approvals"
        ).fetchall()

    status_counts: Counter[str] = Counter()
    risk_counts: Counter[str] = Counter()
    actions_exec: Counter[str] = Counter()
    actions_ok: Counter[str] = Counter()
    host_counts: Counter[str] = Counter()
    user_counts: Counter[str] = Counter()
    mtta_samples: list[float] = []
    mttr_samples: list[float] = []
    per_day: Counter[str] = Counter()
    oldest_pending: datetime | None = None
    n_decided = n_approvedish = 0
    # Volumen reciente
    t24, t7, t30, t14 = (now - timedelta(hours=24), now - timedelta(days=7),
                         now - timedelta(days=30), now - timedelta(days=14))
    vol_24 = vol_7 = vol_30 = vol_prev7 = 0
    # Acciones: total/ok + últimas fallidas
    act_total = act_ok = 0
    failed_actions: list[dict[str, Any]] = []

    for r in rows:
        st = r["status"] or "pending"
        status_counts[st] += 1

        created = _parse_dt(r["created_at"])
        if created:
            per_day[created.date().isoformat()] += 1
            if created >= t24:
                vol_24 += 1
            if created >= t7:
                vol_7 += 1
            if created >= t30:
                vol_30 += 1
            if t14 <= created < t7:
                vol_prev7 += 1

        plan = _loads(r["plan_json"]) or {}
        risk_counts[(plan.get("risk_level") or "unknown")] += 1

        alert = _loads(r["alert_json"]) or {}
        device = alert.get("device") or {}
        host = device.get("hostname") or device.get("fqdn")
        if host:
            host_counts[host] += 1
        for u in (alert.get("users_involved") or []):
            sam = (u or {}).get("sam")
            if sam:
                user_counts[sam] += 1

        if st == "pending" and created:
            if oldest_pending is None or created < oldest_pending:
                oldest_pending = created

        decided = _parse_dt(r["decided_at"])
        if decided and created:
            mtta_samples.append((decided - created).total_seconds())

        executed = _parse_dt(r["executed_at"])
        if executed and created:
            mttr_samples.append((executed - created).total_seconds())

        if st in ("approved", "executed", "rejected"):
            n_decided += 1
        if st in ("approved", "executed"):
            n_approvedish += 1

        for er in (_loads(r["execution_result"]) or []):
            if isinstance(er, dict):
                at = er.get("action_type") or "unknown"
                actions_exec[at] += 1
                act_total += 1
                if er.get("ok"):
                    actions_ok[at] += 1
                    act_ok += 1
                else:
                    failed_actions.append({
                        "rowid": r["rowid"],
                        "action_type": at,
                        "target": er.get("target"),
                        "message": er.get("message"),
                        "ts": r["executed_at"],
                    })

    # Serie de los últimos 14 días (rellena días sin datos con 0)
    days: list[tuple[str, int]] = []
    for i in range(13, -1, -1):
        d = (now.date().fromordinal(now.date().toordinal() - i)).isoformat()
        days.append((d, per_day.get(d, 0)))

    def _avg(xs: list[float]) -> float | None:
        return sum(xs) / len(xs) if xs else None

    # Tendencia 7d vs 7d previos
    trend_7d: int | None = None
    if vol_prev7 > 0:
        trend_7d = round(100 * (vol_7 - vol_prev7) / vol_prev7)

    # SLA: expirados sobre el universo de casos que ya no están pendientes
    expired = status_counts.get("expired", 0)
    closed = n_decided + expired
    expiry_rate = round(100 * expired / closed) if closed else None

    # Últimas 6 acciones fallidas (más recientes primero)
    failed_actions.sort(key=lambda f: f.get("ts") or "", reverse=True)

    return {
        "total": sum(status_counts.values()),
        "status_counts": {s: status_counts.get(s, 0) for s in STATUS_ORDER},
        "risk_counts": dict(risk_counts),
        "actions_exec": dict(actions_exec),
        "actions_ok": dict(actions_ok),
        "mtta_human": _human_duration(_avg(mtta_samples)),
        "mttr_human": _human_duration(_avg(mttr_samples)),
        "approval_rate": round(100 * n_approvedish / n_decided) if n_decided else None,
        "pending": status_counts.get("pending", 0),
        "oldest_pending_human": _human_duration(
            (now - oldest_pending).total_seconds() if oldest_pending else None
        ),
        "per_day": days,
        # Volumen reciente
        "vol_24": vol_24, "vol_7": vol_7, "vol_30": vol_30, "trend_7d": trend_7d,
        # Tasa de éxito de acciones
        "act_total": act_total, "act_ok": act_ok,
        "act_success_rate": round(100 * act_ok / act_total) if act_total else None,
        "failed_actions": failed_actions[:6],
        # SLA / vencimientos
        "expired": expired, "expiry_rate": expiry_rate,
        # Top hosts / usuarios
        "top_hosts": host_counts.most_common(6),
        "top_users": user_counts.most_common(6),
    }


def _empty_metrics() -> dict[str, Any]:
    return {
        "total": 0,
        "status_counts": {s: 0 for s in STATUS_ORDER},
        "risk_counts": {},
        "actions_exec": {},
        "actions_ok": {},
        "mtta_human": "—",
        "mttr_human": "—",
        "approval_rate": None,
        "pending": 0,
        "oldest_pending_human": "—",
        "per_day": [],
        "vol_24": 0, "vol_7": 0, "vol_30": 0, "trend_7d": None,
        "act_total": 0, "act_ok": 0, "act_success_rate": None, "failed_actions": [],
        "expired": 0, "expiry_rate": None,
        "top_hosts": [], "top_users": [],
    }


# ===== Lista de casos (cola) =====


def _list_cases_sync(
    db_path: str, status: str | None, limit: int, offset: int
) -> tuple[list[dict[str, Any]], int]:
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))
    try:
        conn = _connect_ro(db_path)
    except sqlite3.OperationalError:
        return ([], 0)

    with conn:
        if status:
            total = conn.execute(
                "SELECT COUNT(*) FROM pending_approvals WHERE status=?", (status,)
            ).fetchone()[0]
            rows = conn.execute(
                "SELECT rowid, alert_id, status, created_at, decided_at, decided_by_ip, "
                "       executed_at, plan_json, alert_json, invgate_request_id "
                "FROM pending_approvals WHERE status=? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (status, limit, offset),
            ).fetchall()
        else:
            total = conn.execute("SELECT COUNT(*) FROM pending_approvals").fetchone()[0]
            rows = conn.execute(
                "SELECT rowid, alert_id, status, created_at, decided_at, decided_by_ip, "
                "       executed_at, plan_json, alert_json, invgate_request_id "
                "FROM pending_approvals ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()

    cases = [_summarize_row(dict(r)) for r in rows]
    return (cases, int(total))


def _summarize_row(r: dict[str, Any]) -> dict[str, Any]:
    """Aplana una fila para la tabla de cola. NUNCA incluye el token."""
    plan = _loads(r.get("plan_json")) or {}
    alert = _loads(r.get("alert_json")) or {}
    device = alert.get("device") or {}
    return {
        "rowid": r.get("rowid"),
        "alert_id": r.get("alert_id"),
        "status": r.get("status"),
        "created_at": r.get("created_at"),
        "decided_at": r.get("decided_at"),
        "decided_by_ip": r.get("decided_by_ip"),
        "executed_at": r.get("executed_at"),
        "invgate_request_id": r.get("invgate_request_id"),
        "risk_level": plan.get("risk_level") or "unknown",
        "title": alert.get("title") or "(no title)",
        "host": device.get("hostname") or device.get("fqdn") or "—",
        "n_actions": len(plan.get("actions") or []),
    }


# ===== Detalle de un caso =====


def _get_case_sync(db_path: str, rowid: int) -> dict[str, Any] | None:
    try:
        conn = _connect_ro(db_path)
    except sqlite3.OperationalError:
        return None
    with conn:
        row = conn.execute(
            "SELECT rowid, alert_id, status, created_at, decided_at, decided_by_ip, "
            "       decided_by_ua, selected_actions, executed_at, execution_result, "
            "       plan_json, alert_json, timeline_json, invgate_request_id "
            "FROM pending_approvals WHERE rowid=?",
            (rowid,),
        ).fetchone()
    if row is None:
        return None
    r = dict(row)
    return {
        "rowid": r["rowid"],
        "alert_id": r["alert_id"],
        "status": r["status"],
        "created_at": r["created_at"],
        "decided_at": r["decided_at"],
        "decided_by_ip": r["decided_by_ip"],
        "decided_by_ua": r["decided_by_ua"],
        "executed_at": r["executed_at"],
        "invgate_request_id": r["invgate_request_id"],
        "selected_actions": _loads(r["selected_actions"]),
        "plan": _loads(r["plan_json"]) or {},
        "alert": _loads(r["alert_json"]) or {},
        "timeline": _loads(r["timeline_json"]) or [],
        "execution_result": _loads(r["execution_result"]) or [],
    }


# ===== Wrappers async =====


async def dashboard_metrics(db_path: str) -> dict[str, Any]:
    return await asyncio.to_thread(_metrics_sync, db_path)


async def list_cases(
    db_path: str, status: str | None = None, limit: int = 50, offset: int = 0
) -> tuple[list[dict[str, Any]], int]:
    return await asyncio.to_thread(_list_cases_sync, db_path, status, limit, offset)


async def get_case(db_path: str, rowid: int) -> dict[str, Any] | None:
    return await asyncio.to_thread(_get_case_sync, db_path, rowid)
