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
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from src.config import Settings
from src.vuln.scoring import EPSS_HIGH_THRESHOLD, PRIORITY_THRESHOLD

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
    db_path: str,
    status: str | None,
    limit: int,
    offset: int,
    baseline_iso: str = "",
    since_iso: str = "",
) -> tuple[list[dict[str, Any]], int]:
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))
    try:
        conn = _connect_ro(db_path)
    except sqlite3.OperationalError:
        return ([], 0)

    # WHERE dinámico: status (opcional) + baseline de medición (opcional) +
    # ventana de tiempo elegida en la cola (opcional).
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
    if since_iso:
        conds.append("created_at >= ?")
        params.append(since_iso)
    where = (" WHERE " + " AND ".join(conds)) if conds else ""

    with conn:
        total = conn.execute(
            f"SELECT COUNT(*) FROM pending_approvals{where}", params
        ).fetchone()[0]
        rows = conn.execute(
            "SELECT rowid, alert_id, status, created_at, decided_at, decided_by_ip, "
            "       executed_at, plan_json, alert_json, invgate_request_id, "
            "       invgate_status_id, invgate_resolved, invgate_checked_at "
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
            "       executed_at, plan_json, alert_json, invgate_request_id, "
            "       invgate_status_id, invgate_resolved, invgate_checked_at "
            f"FROM pending_approvals{where} ORDER BY created_at DESC LIMIT ?",
            [*params, max(1, min(int(cap), 5000))],
        ).fetchall()
    cases = [_summarize_row(dict(r)) for r in rows]
    if risk:
        cases = [c for c in cases if c["risk_level"] == risk]
    return cases


def _invgate_state(r: dict[str, Any]) -> dict[str, Any]:
    """Estado del ticket InvGate según el snapshot de reconciliación (fuente de
    verdad). ``state``: sin_ticket | sin_verificar | resuelto | abierto."""
    rid = r.get("invgate_request_id")
    if rid is None:
        state = "sin_ticket"
    elif r.get("invgate_checked_at") is None:
        state = "sin_verificar"
    elif r.get("invgate_resolved"):
        state = "resuelto"
    else:
        state = "abierto"
    return {
        "invgate_request_id": rid,
        "invgate_status_id": r.get("invgate_status_id"),
        "invgate_resolved": (
            None if r.get("invgate_resolved") is None else bool(r.get("invgate_resolved"))
        ),
        "invgate_checked_at": r.get("invgate_checked_at"),
        "invgate_state": state,
    }


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
        "risk_level": plan.get("risk_level") or "unknown",
        "title": alert.get("title") or "(no title)",
        "host": device.get("hostname") or device.get("fqdn") or "—",
        "n_actions": len(plan.get("actions") or []),
        **_invgate_state(r),
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
            "       plan_json, alert_json, timeline_json, invgate_request_id, "
            "       invgate_status_id, invgate_resolved, invgate_checked_at "
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
        "selected_actions": _loads(r["selected_actions"]),
        "plan": _loads(r["plan_json"]) or {},
        "alert": _loads(r["alert_json"]) or {},
        "timeline": _loads(r["timeline_json"]) or [],
        "execution_result": _mark_simulated(_loads(r["execution_result"]) or []),
        **_invgate_state(r),
    }


# El executor marca cada acción simulada con el prefijo "DRY_RUN: " en el message
# (ver executor.execute_action). Lo derivamos por fila y no del dry_run de HOY,
# para que un caso viejo siga contando la verdad aunque el modo haya cambiado.
_DRY_RUN_PREFIX = "DRY_RUN:"


def _mark_simulated(results: Any) -> list[dict[str, Any]]:
    if not isinstance(results, list):
        return []
    out: list[dict[str, Any]] = []
    for er in results:
        if not isinstance(er, dict):
            continue
        message = er.get("message") or ""
        out.append({**er, "simulated": str(message).startswith(_DRY_RUN_PREFIX)})
    return out


def _get_case_token_sync(db_path: str, rowid: int) -> dict[str, Any] | None:
    """Token + estado de un caso. SOLO para uso server-side (decidir desde /ui).

    El token nunca sale en las respuestas JSON del dashboard: es la capability que
    viaja en el link del correo. Acá se resuelve adentro del proceso para poder
    reusar la misma ruta de decisión sin exponerlo al browser.
    """
    try:
        conn = _connect_ro(db_path)
    except sqlite3.OperationalError:
        return None
    with conn:
        row = conn.execute(
            "SELECT token, status, alert_id FROM pending_approvals WHERE rowid=?",
            (rowid,),
        ).fetchone()
    return dict(row) if row is not None else None


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
    since_iso: str = "",
) -> tuple[list[dict[str, Any]], int]:
    return await asyncio.to_thread(
        _list_cases_sync, db_path, status, limit, offset, baseline_iso, since_iso
    )


async def get_case(db_path: str, rowid: int) -> dict[str, Any] | None:
    return await asyncio.to_thread(_get_case_sync, db_path, rowid)


async def get_case_token(db_path: str, rowid: int) -> dict[str, Any] | None:
    """Token + estado de un caso, para decidir desde /ui. No exponer al browser."""
    return await asyncio.to_thread(_get_case_token_sync, db_path, rowid)


# ===== Reconciliación InvGate (vista "tickets abiertos") =====


def _invgate_reconcile_sync(db_path: str) -> dict[str, Any]:
    """Resumen de reconciliación InvGate + lista de casos con ticket ABIERTO.

    InvGate es la fuente de verdad: el snapshot lo escribe el sweeper. La lista
    prioriza la discrepancia que importa — casos cuyo lado nuestro ya terminó
    (executed/rejected/expired) pero cuyo ticket sigue abierto en InvGate."""
    try:
        conn = _connect_ro(db_path)
    except sqlite3.OperationalError:
        return {"counts": {}, "open_cases": [], "last_checked": None}
    with conn:
        rows = conn.execute(
            "SELECT rowid, alert_id, status, created_at, decided_at, decided_by_ip, "
            "       executed_at, plan_json, alert_json, invgate_request_id, "
            "       invgate_status_id, invgate_resolved, invgate_checked_at "
            "FROM pending_approvals WHERE invgate_request_id IS NOT NULL"
        ).fetchall()

    counts = {"resuelto": 0, "abierto": 0, "sin_verificar": 0}
    open_cases: list[dict[str, Any]] = []
    last_checked: str | None = None
    for row in rows:
        c = _summarize_row(dict(row))
        st = c["invgate_state"]
        counts[st] = counts.get(st, 0) + 1
        if c["invgate_checked_at"] and (not last_checked or c["invgate_checked_at"] > last_checked):
            last_checked = c["invgate_checked_at"]
        if st in ("abierto", "sin_verificar"):
            open_cases.append(c)
    # Los ya-terminales de nuestro lado primero (la discrepancia real), luego por fecha.
    _terminal = {"executed", "rejected", "expired"}
    open_cases.sort(
        key=lambda c: (c["status"] not in _terminal, c["created_at"] or ""),
    )
    return {
        "counts": counts,
        "total_with_ticket": len(rows),
        "open_cases": open_cases,
        "last_checked": last_checked,
    }


async def invgate_reconcile_view(db_path: str) -> dict[str, Any]:
    """Datos para la vista de reconciliación InvGate del dashboard."""
    return await asyncio.to_thread(_invgate_reconcile_sync, db_path)


# ===== Vulnerabilidades (vuln_lifecycle.db) =====
#
# Base aparte de state.db: la escribe el pipeline de vuln (indexer → store) y acá
# se lee SOLO en modo lectura, igual que el resto del panel.

# Buckets de severidad. Wazuh reporta severity '-' (con cvss_score -1) para los CVE
# que todavía no puntuó: no es riesgo cero, es riesgo DESCONOCIDO, así que va a su
# propio bucket en vez de mezclarse con Low o desaparecer del total.
VULN_UNTRIAGED = "Untriaged"
VULN_SEVERITIES = ("Critical", "High", "Medium", "Low", VULN_UNTRIAGED)

# El corte que importa para remediar: un hallazgo de OS se cierra con un
# acumulativo/KB, uno de Packages actualizando la aplicación.
VULN_CATEGORIES = ("OS", "Packages")

VULN_PER_PAGE = 50
_VULN_MAX_HOSTS = 5  # nombres de agente que se muestran por CVE

# Un hallazgo cuenta como activo mientras el ciclo de vida no lo dé por resuelto.
_VULN_ACTIVE = "lifecycle_status != 'resolved'"

# Normalización de severidad a los 5 buckets, del lado SQL para no traer 16k filas.
_SEV_BUCKET = (
    "CASE WHEN severity IN ('Critical','High','Medium','Low') "
    f"THEN severity ELSE '{VULN_UNTRIAGED}' END"
)

# Ranking de severidad (1 = peor). Un CVE puede aparecer con distinta severidad en
# distintos hosts: el grupo se muestra con la PEOR, que es la que manda para priorizar.
_SEV_RANK_SQL = (
    "CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 "
    "WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END"
)
_SEV_BY_RANK = {1: "Critical", 2: "High", 3: "Medium", 4: "Low", 5: VULN_UNTRIAGED}

# Estado del grupo: si algo apareció nuevo o reapareció, eso es lo que hay que ver;
# "ongoing" es el caso aburrido y por eso queda último.
_LIFECYCLE_PRIORITY = ("new", "reopened", "ongoing")


def _vuln_columns(conn: sqlite3.Connection) -> set[str]:
    return {r[1] for r in conn.execute("PRAGMA table_info(vuln_lifecycle)")}


def _categoria_expr(cols: set[str]) -> str:
    """Expresión SQL para `categoria`, que puede no existir todavía.

    La base se abre read-only: si el pipeline aún no corrió con el esquema nuevo,
    no podemos migrarla desde el panel y la columna se lee como ''.
    """
    return "categoria" if "categoria" in cols else "''"


def _like_term(q: str) -> str:
    """Término para LIKE ... ESCAPE '\\', con los comodines del usuario neutralizados."""
    escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _vuln_filters(
    cols: set[str],
    severidad: str | None,
    categoria: str | None,
    agente: str | None,
    kev: bool,
    q: str | None,
) -> tuple[str, list[Any]]:
    """WHERE (siempre sobre hallazgos activos) + params, compartido por las dos consultas."""
    where = [_VULN_ACTIVE]
    params: list[Any] = []
    if severidad in VULN_SEVERITIES:
        where.append(f"{_SEV_BUCKET} = ?")
        params.append(severidad)
    if categoria in VULN_CATEGORIES:
        where.append(f"{_categoria_expr(cols)} = ?")
        params.append(categoria)
    if agente:
        where.append("agent_name = ?")
        params.append(agente)
    if kev:
        where.append("cisa_kev = 1")
    if q:
        where.append("(cve LIKE ? ESCAPE '\\' OR package_name LIKE ? ESCAPE '\\')")
        term = _like_term(q)
        params += [term, term]
    return " AND ".join(where), params


def _vuln_cobertura(conn: sqlite3.Connection) -> dict[str, Any]:
    """Snapshot de cobertura que dejó la última ingesta.

    Los agentes SIN ningún hallazgo no dejan rastro en vuln_lifecycle, así que la
    pantalla no puede deducirlos de la base: si no los mostramos, un servidor que
    el detector nunca evaluó se ve igual que uno limpio. El snapshot lo escribe
    persist_coverage() en cada ingesta, con la lista de la API del manager.
    """
    try:
        row = conn.execute(
            "SELECT updated_at, state FROM vuln_state_cache WHERE id = 1"
        ).fetchone()
    except sqlite3.OperationalError:
        return {"disponible": False}
    if not row:
        return {"disponible": False}
    try:
        data = json.loads(row["state"])
    except (TypeError, ValueError):
        return {"disponible": False}
    sin_datos = data.get("sin_datos") or []
    return {
        "disponible": True,
        "actualizado": row["updated_at"],
        "agentes_total": data.get("agentes_total", 0),
        "agentes_con_datos": data.get("agentes_con_datos", 0),
        "sin_datos": sin_datos,
        "desfasados": data.get("desfasados") or [],
        "hallazgos_dudosos": data.get("hallazgos_dudosos", 0),
    }


def _vulns_summary_sync(db_path: str) -> dict[str, Any]:
    """Resumen del inventario activo + serie histórica de corridas."""
    try:
        conn = _connect_ro(db_path)
    except sqlite3.OperationalError:
        # La base todavía no existe (el pipeline de vuln nunca corrió acá).
        return {"available": False}

    with conn:
        cols = _vuln_columns(conn)
        if not cols:
            return {"available": False}
        cat = _categoria_expr(cols)

        totals = conn.execute(
            f"SELECT count(*) AS activos, count(DISTINCT cve) AS cves_unicos, "
            f"       count(DISTINCT agent_name) AS agentes "
            f"FROM vuln_lifecycle WHERE {_VULN_ACTIVE}"
        ).fetchone()
        resueltas = conn.execute(
            "SELECT count(*) FROM vuln_lifecycle WHERE lifecycle_status = 'resolved'"
        ).fetchone()[0]

        por_severidad = dict.fromkeys(VULN_SEVERITIES, 0)
        for r in conn.execute(
            f"SELECT {_SEV_BUCKET} AS bucket, count(*) AS n "
            f"FROM vuln_lifecycle WHERE {_VULN_ACTIVE} GROUP BY bucket"
        ):
            por_severidad[r["bucket"]] = r["n"]

        # Solo OS/Packages: las filas sin categoría (esquema viejo, hallazgo sin el
        # campo) no se inventan como una ni como otra, quedan fuera del corte.
        por_categoria = dict.fromkeys(VULN_CATEGORIES, 0)
        for r in conn.execute(
            f"SELECT {cat} AS categoria, count(*) AS n "
            f"FROM vuln_lifecycle WHERE {_VULN_ACTIVE} GROUP BY 1"
        ):
            if r["categoria"] in por_categoria:
                por_categoria[r["categoria"]] = r["n"]

        kev = conn.execute(
            f"SELECT count(*) AS hallazgos, count(DISTINCT cve) AS cves "
            f"FROM vuln_lifecycle WHERE {_VULN_ACTIVE} AND cisa_kev = 1"
        ).fetchone()
        umbrales = conn.execute(
            f"SELECT sum(epss_score >= ?) AS epss_alto, sum(priority_score >= ?) AS prio_alta "
            f"FROM vuln_lifecycle WHERE {_VULN_ACTIVE}",
            (EPSS_HIGH_THRESHOLD, PRIORITY_THRESHOLD),
        ).fetchone()

        top_hosts = [
            {
                "agent_name": r["agent_name"],
                "total": r["total"],
                "criticas": r["criticas"],
                "kev": r["kev"],
            }
            for r in conn.execute(
                f"SELECT agent_name, count(*) AS total, "
                f"       sum(severity = 'Critical') AS criticas, "
                f"       sum(cisa_kev = 1) AS kev "
                f"FROM vuln_lifecycle "
                f"WHERE {_VULN_ACTIVE} AND agent_name IS NOT NULL AND agent_name != '' "
                f"GROUP BY agent_name ORDER BY total DESC, agent_name LIMIT 10"
            )
        ]

        last_run = conn.execute(
            "SELECT started_at, total_active, new_count, resolved_count "
            "FROM vuln_runs ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        tendencia = _vuln_tendencia(conn)

        cobertura = _vuln_cobertura(conn)

    return {
        "available": True,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        # None si nunca corrió el pipeline: es la única forma honesta de decir
        # "no hay corridas" sin fabricar una de ceros al lado de N activos.
        "last_run": dict(last_run) if last_run is not None else None,
        "totals": {
            "activos": totals["activos"],
            "cves_unicos": totals["cves_unicos"],
            "agentes": totals["agentes"],
            "resueltas_total": resueltas,
        },
        "por_severidad": por_severidad,
        "por_categoria": por_categoria,
        "kev": {"hallazgos": kev["hallazgos"], "cves": kev["cves"]},
        "epss_alto": int(umbrales["epss_alto"] or 0),
        "prioridad_alta": int(umbrales["prio_alta"] or 0),
        "top_hosts": top_hosts,
        "tendencia": tendencia,
        "cobertura": cobertura,
    }


def _vuln_tendencia(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Serie diaria desde vuln_runs. Con menos de 2 corridas devuelve lo que haya."""
    por_dia: dict[str, dict[str, int]] = {}
    for r in conn.execute(
        "SELECT started_at, total_active, new_count, resolved_count "
        "FROM vuln_runs WHERE started_at IS NOT NULL ORDER BY started_at"
    ):
        # Varias corridas el mismo día: los activos son un NIVEL (vale el de la
        # última corrida), nuevas/resueltas son FLUJO (se acumulan en el día).
        dia = por_dia.setdefault(
            str(r["started_at"])[:10], {"activos": 0, "nuevas": 0, "resueltas": 0}
        )
        dia["activos"] = int(r["total_active"] or 0)
        dia["nuevas"] += int(r["new_count"] or 0)
        dia["resueltas"] += int(r["resolved_count"] or 0)
    return [
        {
            "fecha": fecha,
            "activos": d["activos"],
            "nuevas": d["nuevas"],
            "resueltas": d["resueltas"],
        }
        for fecha, d in sorted(por_dia.items())
    ]


def _vulns_cves_sync(
    db_path: str,
    severidad: str | None = None,
    categoria: str | None = None,
    agente: str | None = None,
    kev: bool = False,
    q: str | None = None,
    page: int = 1,
) -> dict[str, Any]:
    """Hallazgos activos agrupados por CVE, filtrados y paginados (50 por página).

    Son ~16k hallazgos y ~4.3k CVEs únicos: sin paginar la pantalla es inusable.
    """
    page = max(1, int(page))
    filtros = {
        "severidad": severidad if severidad in VULN_SEVERITIES else None,
        "categoria": categoria if categoria in VULN_CATEGORIES else None,
        "agente": agente or None,
        "kev": bool(kev),
        "q": q or None,
    }
    vacio = {"cves": [], "total": 0, "page": page, "per_page": VULN_PER_PAGE, "filtros": filtros}

    try:
        conn = _connect_ro(db_path)
    except sqlite3.OperationalError:
        return vacio

    with conn:
        cols = _vuln_columns(conn)
        if not cols:
            return vacio
        cat = _categoria_expr(cols)
        where, params = _vuln_filters(
            cols, filtros["severidad"], filtros["categoria"],
            filtros["agente"], filtros["kev"], filtros["q"],
        )

        total = conn.execute(
            f"SELECT count(DISTINCT cve) FROM vuln_lifecycle WHERE {where}", params
        ).fetchone()[0]

        # 1) La página de CVEs con los agregados numéricos.
        grupos = conn.execute(
            f"SELECT cve, "
            f"       max(priority_score) AS priority_score, "
            f"       max(cvss_score) AS cvss_score, "
            f"       max(epss_score) AS epss_score, "
            f"       max(cisa_kev) AS cisa_kev, "
            f"       min({_SEV_RANK_SQL}) AS sev_rank, "
            f"       count(DISTINCT agent_name) AS hosts_count, "
            f"       min(first_seen_at) AS first_seen_at "
            f"FROM vuln_lifecycle WHERE {where} "
            f"GROUP BY cve ORDER BY priority_score DESC, cve "
            f"LIMIT ? OFFSET ?",
            [*params, VULN_PER_PAGE, (page - 1) * VULN_PER_PAGE],
        ).fetchall()
        if not grupos:
            return {**vacio, "total": total}

        # 2) El detalle textual de esos CVEs (hosts, paquete, categoría, estado).
        #    Segunda pasada acotada a la página: como mucho unos cientos de filas.
        cves = [g["cve"] for g in grupos]
        marcas = ",".join("?" * len(cves))
        detalle: dict[str, dict[str, Any]] = {
            c: {"hosts": set(), "paquetes": Counter(), "categorias": Counter(), "estados": set()}
            for c in cves
        }
        for r in conn.execute(
            f"SELECT cve, agent_name, package_name, {cat} AS categoria, lifecycle_status "
            f"FROM vuln_lifecycle WHERE {where} AND cve IN ({marcas})",
            [*params, *cves],
        ):
            d = detalle[r["cve"]]
            if r["agent_name"]:
                d["hosts"].add(r["agent_name"])
            if r["package_name"]:
                d["paquetes"][r["package_name"]] += 1
            if r["categoria"]:
                d["categorias"][r["categoria"]] += 1
            d["estados"].add(r["lifecycle_status"])

    return {
        "cves": [_vuln_cve_row(g, detalle[g["cve"]]) for g in grupos],
        "total": total,
        "page": page,
        "per_page": VULN_PER_PAGE,
        "filtros": filtros,
    }


def _vuln_cve_row(grupo: sqlite3.Row, detalle: dict[str, Any]) -> dict[str, Any]:
    estados = detalle["estados"]
    return {
        "cve": grupo["cve"],
        "priority_score": float(grupo["priority_score"] or 0),
        "cvss_score": float(grupo["cvss_score"] or 0),
        "epss_score": float(grupo["epss_score"] or 0),
        "cisa_kev": bool(grupo["cisa_kev"]),
        "severity": _SEV_BY_RANK.get(grupo["sev_rank"], VULN_UNTRIAGED),
        "categoria": _mas_frecuente(detalle["categorias"]),
        "hosts_count": grupo["hosts_count"],
        "hosts": sorted(detalle["hosts"])[:_VULN_MAX_HOSTS],
        "package_name": _mas_frecuente(detalle["paquetes"]),
        "first_seen_at": grupo["first_seen_at"],
        "lifecycle_status": next(
            (st for st in _LIFECYCLE_PRIORITY if st in estados),
            next(iter(estados), ""),
        ),
    }


def _mas_frecuente(contador: Counter) -> str:
    return contador.most_common(1)[0][0] if contador else ""


# ===== Wrappers async (vulns) =====


async def vulns_summary(db_path: str) -> dict[str, Any]:
    return await asyncio.to_thread(_vulns_summary_sync, db_path)


async def vulns_cves(
    db_path: str,
    severidad: str | None = None,
    categoria: str | None = None,
    agente: str | None = None,
    kev: bool = False,
    q: str | None = None,
    page: int = 1,
) -> dict[str, Any]:
    return await asyncio.to_thread(
        _vulns_cves_sync, db_path, severidad, categoria, agente, kev, q, page
    )
