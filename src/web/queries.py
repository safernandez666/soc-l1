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

from src.config import Settings

# Orden canónico de estados para tablas/gráficos
STATUS_ORDER = ["pending", "approved", "executed", "rejected", "expired"]

# Acciones que cuentan como "contención / bloqueo" para los KPIs (aislar host,
# deshabilitar cuenta, forzar reset de password, bloquear IP). scan_host /
# escalate_l2 / notify_only NO son contención.
CONTAINMENT_ACTIONS = ("isolate_host", "disable_user", "force_password_change", "block_ip")


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


def _human_bytes(n: float | None) -> str:
    if n is None:
        return "—"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def _period(first: datetime | None, last: datetime | None) -> dict[str, Any]:
    """Rango de fechas legible para 'desde que arrancamos con Wazuh'."""
    if first is None:
        return {"first": None, "last": None, "days": 0, "label": "—"}
    last = last or first
    days = max(1, (last.date() - first.date()).days + 1)
    label = f"{first.date().isoformat()} → {last.date().isoformat()} ({days}d)"
    return {"first": first.date().isoformat(), "last": last.date().isoformat(),
            "days": days, "label": label}


# ===== Métricas del panel =====


def _metrics_sync(db_path: str, baseline_iso: str = "") -> dict[str, Any]:
    now = datetime.now(tz=timezone.utc)
    baseline = _parse_dt(baseline_iso)
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
    per_day_closed: Counter[str] = Counter()
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
        created = _parse_dt(r["created_at"])
        # Línea base de medición: ignorar lo anterior al corte (no se borra, no se cuenta).
        if baseline and (created is None or created < baseline):
            continue

        st = r["status"] or "pending"
        status_counts[st] += 1

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

        # Día de "cierre" para la serie abierto/cerrado: decisión o, si no, ejecución.
        closed_dt = decided or executed
        if closed_dt:
            per_day_closed[closed_dt.date().isoformat()] += 1

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

    # Series de los últimos 14 días (rellena días sin datos con 0)
    days: list[tuple[str, int]] = []
    days_closed: list[tuple[str, int]] = []
    for i in range(13, -1, -1):
        d = (now.date().fromordinal(now.date().toordinal() - i)).isoformat()
        days.append((d, per_day.get(d, 0)))
        days_closed.append((d, per_day_closed.get(d, 0)))

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
        "per_day_closed": days_closed,
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
        "per_day_closed": [],
        "vol_24": 0, "vol_7": 0, "vol_30": 0, "trend_7d": None,
        "act_total": 0, "act_ok": 0, "act_success_rate": None, "failed_actions": [],
        "expired": 0, "expiry_rate": None,
        "top_hosts": [], "top_users": [],
    }


# ===== KPIs (presentación): contención + salud de Wazuh =====


def _containment_sync(db_path: str, baseline_iso: str = "") -> dict[str, Any]:
    """KPIs de contención/bloqueos acumulados desde state.db (desde el baseline)."""
    baseline = _parse_dt(baseline_iso)
    try:
        conn = _connect_ro(db_path)
    except sqlite3.OperationalError:
        return {"available": False}

    with conn:
        rows = conn.execute(
            "SELECT created_at, plan_json, execution_result, alert_json "
            "FROM pending_approvals"
        ).fetchall()
    if baseline:
        rows = [r for r in rows if (_parse_dt(r["created_at"]) or datetime.min.replace(tzinfo=timezone.utc)) >= baseline]

    proposed: Counter[str] = Counter()      # contención propuesta por los agentes
    executed: Counter[str] = Counter()      # ejecutada (simulada bajo dry-run)
    cases_with_containment = 0
    hosts_contained: set[str] = set()
    first_dt: datetime | None = None
    last_dt: datetime | None = None

    for r in rows:
        created = _parse_dt(r["created_at"])
        if created:
            first_dt = created if first_dt is None else min(first_dt, created)
            last_dt = created if last_dt is None else max(last_dt, created)

        plan = _loads(r["plan_json"]) or {}
        actions = plan.get("actions") or []
        case_has = False
        for a in actions:
            t = (a or {}).get("type")
            if t in CONTAINMENT_ACTIONS:
                proposed[t] += 1
                case_has = True
        if case_has:
            cases_with_containment += 1
            alert = _loads(r["alert_json"]) or {}
            device = alert.get("device") or {}
            host = device.get("hostname") or device.get("fqdn")
            if host:
                hosts_contained.add(host)

        for er in (_loads(r["execution_result"]) or []):
            if isinstance(er, dict):
                t = er.get("action_type")
                if t in CONTAINMENT_ACTIONS:
                    executed[t] += 1

    total_cases = len(rows)
    return {
        "available": True,
        "period": _period(first_dt, last_dt),
        "total_cases": total_cases,
        "cases_with_containment": cases_with_containment,
        "containment_rate": (
            round(100 * cases_with_containment / total_cases) if total_cases else None
        ),
        "proposed_total": sum(proposed.values()),
        "executed_total": sum(executed.values()),
        "hosts_contained": len(hosts_contained),
        "by_type": [
            (t, proposed.get(t, 0), executed.get(t, 0))
            for t in CONTAINMENT_ACTIONS
            if proposed.get(t, 0) or executed.get(t, 0)
        ],
    }


def _latest_metrics(conn: sqlite3.Connection, probe: str) -> dict[str, Any]:
    row = conn.execute(
        "SELECT metrics_json, run_at FROM probe_runs WHERE probe=? "
        "ORDER BY run_at DESC LIMIT 1",
        (probe,),
    ).fetchone()
    if row is None:
        return {}
    m = _loads(row["metrics_json"]) or {}
    m["_run_at"] = row["run_at"]
    return m


def _health_sync(db_path: str) -> dict[str, Any]:
    """KPIs de salud de Wazuh desde wazuh-health.db (último valor de cada probe)."""
    try:
        conn = _connect_ro(db_path)
    except sqlite3.OperationalError:
        return {"available": False}

    with conn:
        try:
            coverage = _latest_metrics(conn, "coverage")
            capacity = _latest_metrics(conn, "capacity")
            hygiene = _latest_metrics(conn, "hygiene")
            span = conn.execute(
                "SELECT MIN(run_at), MAX(run_at), COUNT(*) FROM probe_runs"
            ).fetchone()
        except sqlite3.OperationalError:
            return {"available": False}

    if not (coverage or capacity or hygiene):
        return {"available": False}

    first = _parse_dt(span[0]) if span else None
    last = _parse_dt(span[1]) if span else None
    return {
        "available": True,
        "period": _period(first, last),
        "runs": int(span[2]) if span else 0,
        "coverage": coverage,
        "capacity": capacity,
        "hygiene": hygiene,
    }


def _alert_volume_sync(cache_path: str) -> dict[str, Any]:
    """Lee el JSON precalculado por scripts/aggregate_alert_volume.py (solo-lectura)."""
    try:
        with open(cache_path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {"available": False}
    months = data.get("months") or []
    if not months:
        return {"available": False}
    return {"available": True, **data}


def _kpis_sync(
    state_db_path: str, health_db_path: str, alert_cache_path: str, baseline_iso: str = ""
) -> dict[str, Any]:
    # health_db_path queda en la firma por compatibilidad; la sección "Salud de Wazuh"
    # se quitó del panel (la corrida de prueba contradecía la posture en vivo).
    return {
        "containment": _containment_sync(state_db_path, baseline_iso),
        "alert_volume": _alert_volume_sync(alert_cache_path),
    }


async def _wazuh_posture(settings: Settings) -> dict[str, Any]:
    """Snapshot del Wazuh manager API (best-effort). Nunca tira la página."""
    try:
        from src.tools.wazuh_api import WazuhApiClient
        async with WazuhApiClient(settings) as c:
            snap = await c.posture_snapshot()
        snap["available"] = bool(snap.get("agents"))
        return snap
    except Exception as e:
        return {"available": False, "error": str(e)[:200]}


async def _fortigate_blocks(settings: Settings) -> dict[str, Any]:
    """Lista de IPs en quarantine de FortiGate (best-effort)."""
    if not (settings.fortigate_host and settings.fortigate_token):
        return {"available": False, "error": "FortiGate no configurado"}
    try:
        from src.tools.fortigate import FortigateClient
        async with FortigateClient(settings) as fg:
            banned = await fg.list_banned()
        return {"available": True, "count": len(banned), "banned": banned[:20]}
    except Exception as e:
        return {"available": False, "error": str(e)[:200]}


# ===== Lista de casos (cola) =====


def _list_cases_sync(
    db_path: str, status: str | None, limit: int, offset: int, baseline_iso: str = ""
) -> tuple[list[dict[str, Any]], int]:
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))
    try:
        conn = _connect_ro(db_path)
    except sqlite3.OperationalError:
        return ([], 0)

    # WHERE dinámico: status (opcional) + baseline de medición (opcional).
    # created_at se guarda en ISO8601 con offset uniforme, así que el >= textual
    # equivale al cronológico; las filas con created_at NULL quedan excluidas bajo baseline.
    conds: list[str] = []
    params: list[Any] = []
    if status:
        conds.append("status=?")
        params.append(status)
    if baseline_iso:
        conds.append("created_at >= ?")
        params.append(baseline_iso)
    where = (" WHERE " + " AND ".join(conds)) if conds else ""

    with conn:
        total = conn.execute(
            f"SELECT COUNT(*) FROM pending_approvals{where}", params
        ).fetchone()[0]
        rows = conn.execute(
            "SELECT rowid, alert_id, status, created_at, decided_at, decided_by_ip, "
            "       executed_at, plan_json, alert_json, invgate_request_id "
            f"FROM pending_approvals{where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()

    cases = [_summarize_row(dict(r)) for r in rows]
    return (cases, int(total))


def _cases_in_range_sync(
    db_path: str,
    date_from: str | None,
    date_to: str | None,
    status: str | None,
    risk: str | None,
    cap: int = 2000,
) -> list[dict[str, Any]]:
    """Casos en un rango de fechas (para reportería). Lista completa (hasta `cap`).

    Filtra fecha/estado en SQL; el riesgo (vive en plan_json) se post-filtra en Python.
    No aplica baseline: el rango de fechas es el filtro explícito del reporte.
    """
    try:
        conn = _connect_ro(db_path)
    except sqlite3.OperationalError:
        return []
    conds: list[str] = []
    params: list[Any] = []
    if status:
        conds.append("status=?")
        params.append(status)
    if date_from:
        conds.append("created_at >= ?")
        params.append(date_from)
    if date_to:
        # si llega solo fecha (sin hora), cubrir hasta el fin del día
        params.append(date_to if "T" in date_to else f"{date_to}T23:59:59")
        conds.append("created_at <= ?")
    where = (" WHERE " + " AND ".join(conds)) if conds else ""
    with conn:
        rows = conn.execute(
            "SELECT rowid, alert_id, status, created_at, decided_at, decided_by_ip, "
            "       executed_at, plan_json, alert_json, invgate_request_id "
            f"FROM pending_approvals{where} ORDER BY created_at DESC LIMIT ?",
            [*params, max(1, min(int(cap), 5000))],
        ).fetchall()
    cases = [_summarize_row(dict(r)) for r in rows]
    if risk:
        cases = [c for c in cases if c["risk_level"] == risk]
    return cases


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


async def dashboard_metrics(db_path: str, baseline_iso: str = "") -> dict[str, Any]:
    return await asyncio.to_thread(_metrics_sync, db_path, baseline_iso)


async def kpis_metrics(settings: Settings) -> dict[str, Any]:
    """KPIs de presentación: DBs locales (en thread) + fuentes vivas (Wazuh API,
    FortiGate) en paralelo. Cada fuente viva es best-effort y no tira la página."""
    base = await asyncio.to_thread(
        _kpis_sync,
        settings.state_db_path,
        settings.wazuh_health_db_path,
        settings.alert_volume_cache_path,
        settings.metrics_baseline_at,
    )
    posture, fortigate = await asyncio.gather(
        _wazuh_posture(settings), _fortigate_blocks(settings)
    )
    base["posture"] = posture
    base["fortigate"] = fortigate
    return base


async def cases_in_range(
    db_path: str,
    date_from: str | None = None,
    date_to: str | None = None,
    status: str | None = None,
    risk: str | None = None,
) -> list[dict[str, Any]]:
    return await asyncio.to_thread(
        _cases_in_range_sync, db_path, date_from, date_to, status, risk
    )


async def list_cases(
    db_path: str,
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
    baseline_iso: str = "",
) -> tuple[list[dict[str, Any]], int]:
    return await asyncio.to_thread(
        _list_cases_sync, db_path, status, limit, offset, baseline_iso
    )


async def get_case(db_path: str, rowid: int) -> dict[str, Any] | None:
    return await asyncio.to_thread(_get_case_sync, db_path, rowid)
