"""Rescan forzado de los agentes que el detector de vulnerabilidades no re-evalúa.

El problema (ver `assess_coverage` en `store.py`): hay hosts que reportan
inventario a syscollector pero cuyo módulo de vulnerabilidades del manager quedó
con una foto vieja. Se manifiesta de dos formas, las dos mentirosas:

  - DESFASADO: el índice tiene un build de SO viejo, así que hallazgos ya
    parcheados siguen contando (SRVDC2 y SRVDCFICO1: 1.770 hallazgos, 11% del
    total, al 2026-08-29).
  - SIN DATOS: el agente está activo pero no generó un solo hallazgo, así que el
    host no aparece en el reporte y se lee igual que uno sano (SRVWSUS, el que
    distribuye los parches, es uno de esos).

El destrabe conocido es reiniciar el agente: al arrancar, syscollector corre el
scan completo (`scan_on_start`) y el manager vuelve a evaluar el inventario. No
requiere root ni tocar el manager, sólo el permiso `agent:restart` de la API.

Este módulo NO decide solo: es deliberadamente conservador porque reinicia
agentes de servidores productivos.

  * Sólo toca hosts que el último snapshot de cobertura marcó como problema.
  * Sólo agentes en estado `active` (reiniciar uno desconectado no hace nada).
  * Nunca el agente 000 (es el propio manager).
  * Cooldown por host: no se reintenta antes de `COOLDOWN_DAYS`.
  * Tope de agentes por corrida, para no reiniciar el parque entero por un
    snapshot de cobertura malo.

Cada pedido queda en `vuln_rescans` con el estado del host en ese momento, y la
pasada de verificación compara contra la cobertura posterior. Eso responde la
pregunta que importa: **el reinicio destraba de verdad al detector, o hay que
escalar a un fix en el manager**. Sin la bitácora, un host que converge no se
distingue de uno que alguien parcheó a mano.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import requests

from src.vuln.store import _now_iso

logger = logging.getLogger("vuln_priority")

# Días mínimos entre dos rescans del mismo host. Un agente que no converge no se
# arregla reiniciándolo todos los días; sí genera ruido y un reinicio diario de
# un servidor productivo.
COOLDOWN_DAYS = 7

# Tope de agentes por corrida.
MAX_AGENTS = 5

# Cuánto se espera antes de juzgar un rescan. El agente reinicia en segundos,
# pero el manager re-evalúa el inventario y el índice tarda en reflejarlo; la
# ingesta diaria corre 06:15, así que 24h garantiza al menos una pasada nueva.
GRACE_HOURS = 24

MOTIVO_SIN_DATOS = "sin_datos"
MOTIVO_DESFASADO = "desfasado"


@dataclass
class RescanTarget:
    """Un host elegible para rescan, con el estado que motivó el pedido."""

    host: str
    agent_id: str
    motivo: str
    build_indexado: str = ""
    build_real: str = ""
    hallazgos: int = 0

    def descripcion(self) -> str:
        if self.motivo == MOTIVO_DESFASADO:
            return (
                f"indexado {self.build_indexado} vs real {self.build_real} "
                f"({self.hallazgos} hallazgos dudosos)"
            )
        return "activo pero sin ningún hallazgo en el índice"


@dataclass
class Seleccion:
    """Resultado de `select_targets`: qué se va a reiniciar y qué se descartó."""

    elegibles: list[RescanTarget] = field(default_factory=list)
    descartados: list[tuple[str, str]] = field(default_factory=list)  # (host, por qué)


def _parse_iso(value: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def select_targets(
    cov: dict,
    agentes: dict[str, dict],
    ultimos: dict[str, str],
    *,
    cooldown_days: int = COOLDOWN_DAYS,
    max_agents: int = MAX_AGENTS,
    solo_hosts: list[str] | None = None,
    ahora: datetime | None = None,
) -> Seleccion:
    """Decide qué agentes reiniciar. Función pura: no toca red ni base.

    `cov`      snapshot de `assess_coverage` / `load_coverage`.
    `agentes`  índice por nombre de host: {"id": "002", "status": "active"}.
    `ultimos`  último `solicitado_at` por host, para el cooldown.
    """
    ahora = ahora or datetime.now(UTC)
    sel = Seleccion()

    if not cov.get("disponible", True) or (not cov.get("sin_datos") and not cov.get("desfasados")):
        return sel

    # Desfasados primero y por volumen: son los que más ensucian el total del
    # reporte. Los sin datos van después, alfabéticos, porque no hay señal para
    # ordenarlos entre sí.
    candidatos: list[RescanTarget] = [
        RescanTarget(
            host=d.get("host", ""),
            agent_id="",
            motivo=MOTIVO_DESFASADO,
            build_indexado=d.get("indexado", ""),
            build_real=d.get("actual", ""),
            hallazgos=int(d.get("hallazgos") or 0),
        )
        for d in sorted(cov.get("desfasados", []), key=lambda d: -int(d.get("hallazgos") or 0))
    ]
    candidatos += [
        RescanTarget(host=h, agent_id="", motivo=MOTIVO_SIN_DATOS)
        for h in sorted(cov.get("sin_datos", []))
    ]

    filtro = {h.upper() for h in (solo_hosts or [])}
    limite = ahora - timedelta(days=cooldown_days)

    for t in candidatos:
        if not t.host:
            continue
        if filtro and t.host.upper() not in filtro:
            sel.descartados.append((t.host, "no está en --host"))
            continue

        agente = agentes.get(t.host)
        if agente is None:
            sel.descartados.append((t.host, "no figura en la API del manager"))
            continue
        if str(agente.get("id")) == "000":
            sel.descartados.append((t.host, "es el manager (agente 000)"))
            continue
        if (agente.get("status") or "").lower() != "active":
            estado = agente.get("status") or "sin estado"
            sel.descartados.append((t.host, f"agente {estado}, reiniciarlo no haría nada"))
            continue

        previo = _parse_iso(ultimos.get(t.host, ""))
        if previo and previo > limite:
            dias = (ahora - previo).days
            sel.descartados.append((t.host, f"rescan hace {dias}d, cooldown de {cooldown_days}d"))
            continue

        if len(sel.elegibles) >= max_agents:
            sel.descartados.append((t.host, f"tope de {max_agents} agentes por corrida"))
            continue

        t.agent_id = str(agente.get("id") or "")
        sel.elegibles.append(t)

    return sel


# --------------------------------------------------------------------------
# API del manager (sync, igual que el resto del pipeline de vulnerabilidades).
# El cliente async de src/tools/wazuh_api.py es del Enricher; unificar los tres
# clientes que conviven en el repo es un pendiente aparte.
# --------------------------------------------------------------------------
def _manager() -> tuple[str, str]:
    """Devuelve (base_url, token) contra la API del manager."""
    from src.config import Settings

    s = Settings()
    pw = s.wazuh_api_password
    pw = pw.get_secret_value() if hasattr(pw, "get_secret_value") else pw
    base = f"https://{s.wazuh_api_host}:{s.wazuh_api_port}"
    resp = requests.post(
        f"{base}/security/user/authenticate",
        auth=(s.wazuh_api_user, pw), verify=False, timeout=25,
    )
    resp.raise_for_status()
    return base, resp.json()["data"]["token"]


def fetch_agents() -> dict[str, dict]:
    """Parque de agentes indexado por nombre: {"SRVDC2": {"id", "status", "os"}}.

    Falla fuerte a propósito: sin este dato no se puede decidir a quién reiniciar,
    y equivocarse acá significa reiniciar el agente equivocado.
    """
    base, tok = _manager()
    r = requests.get(
        f"{base}/agents?limit=1000&select=id,name,status,os.version",
        headers={"Authorization": f"Bearer {tok}"}, verify=False, timeout=25,
    )
    r.raise_for_status()
    return {
        a["name"]: {
            "id": str(a.get("id") or ""),
            "status": a.get("status") or "",
            "os": (a.get("os") or {}).get("version", ""),
        }
        for a in r.json()["data"]["affected_items"]
        if a.get("name")
    }


def restart_agents(agent_ids: list[str]) -> dict[str, str]:
    """Reinicia los agentes pedidos. Devuelve {agent_id: 'ok' | 'error: ...'}."""
    if not agent_ids:
        return {}
    base, tok = _manager()
    r = requests.put(
        f"{base}/agents/restart",
        params={"agents_list": ",".join(agent_ids)},
        headers={"Authorization": f"Bearer {tok}"}, verify=False, timeout=60,
    )
    try:
        payload = r.json()
    except ValueError:
        r.raise_for_status()
        return {aid: f"error: respuesta no-JSON ({r.status_code})" for aid in agent_ids}

    data = payload.get("data", {}) or {}
    out = {str(a): "ok" for a in data.get("affected_items", [])}
    for fallo in data.get("failed_items", []) or []:
        motivo = (fallo.get("error", {}) or {}).get("message", "sin detalle")
        for aid in fallo.get("id", []) or []:
            out[str(aid)] = f"error: {motivo}"
    # Lo que el manager no mencionó tampoco se puede dar por hecho.
    for aid in agent_ids:
        out.setdefault(aid, f"error: el manager no lo reportó (HTTP {r.status_code})")
    return out


# --------------------------------------------------------------------------
# Bitácora
# --------------------------------------------------------------------------
def load_last_rescans(conn) -> dict[str, str]:
    """Último `solicitado_at` por host, para aplicar el cooldown.

    Sólo cuentan los pedidos que realmente salieron: un dry-run ('simulado') no
    tiene por qué frenar el rescan real de mañana.
    """
    rows = conn.execute(
        "SELECT host, MAX(solicitado_at) FROM vuln_rescans "
        "WHERE resultado = 'ok' GROUP BY host"
    ).fetchall()
    return {r[0]: r[1] for r in rows}


def record_rescan(conn, target: RescanTarget, resultado: str, detalle: str = "") -> None:
    conn.execute(
        "INSERT INTO vuln_rescans (host, agent_id, motivo, solicitado_at, resultado, "
        "detalle, build_indexado, build_real, hallazgos) VALUES (?,?,?,?,?,?,?,?,?)",
        (
            target.host, target.agent_id, target.motivo, _now_iso(), resultado,
            detalle, target.build_indexado, target.build_real, target.hallazgos,
        ),
    )
    conn.commit()


def verify_pending(
    conn, cov: dict, *, grace_hours: int = GRACE_HOURS, ahora: datetime | None = None,
) -> list[dict]:
    """Juzga los rescans que ya cumplieron la ventana de gracia.

    Compara contra el snapshot de cobertura actual: si el host salió del problema
    que motivó el pedido, el reinicio sirvió. Es la única forma de saber si la
    Fase 3 arregla algo o hay que escalar el detector.
    """
    if not cov.get("disponible"):
        return []

    ahora = ahora or datetime.now(UTC)
    corte = ahora - timedelta(hours=grace_hours)
    sin_datos = set(cov.get("sin_datos", []))
    desfasados = {d.get("host"): d.get("indexado", "") for d in cov.get("desfasados", [])}

    fallos: list[dict] = []
    rows = conn.execute(
        "SELECT id, host, motivo, solicitado_at, build_indexado FROM vuln_rescans "
        "WHERE verificado IS NULL AND resultado = 'ok' ORDER BY solicitado_at"
    ).fetchall()

    for row in rows:
        pedido = _parse_iso(row[3])
        if pedido is None or pedido > corte:
            continue  # todavía dentro de la ventana de gracia

        host, motivo, build_previo = row[1], row[2], row[4]
        if motivo == MOTIVO_SIN_DATOS:
            convergio = host not in sin_datos
        else:
            # Convergió si dejó de estar desfasado, o si al menos el build
            # indexado se movió (el detector volvió a evaluar).
            actual = desfasados.get(host)
            convergio = actual is None or (build_previo and actual != build_previo)

        veredicto = "convergio" if convergio else "sin_cambio"
        conn.execute(
            "UPDATE vuln_rescans SET verificado = ?, verificado_at = ? WHERE id = ?",
            (veredicto, _now_iso(), row[0]),
        )
        registro = {
            "host": host, "motivo": motivo,
            "veredicto": veredicto, "solicitado_at": row[3],
        }
        if not convergio:
            fallos.append(registro)
        logger.info("Rescan %-14s %-10s pedido %s → %s", host, motivo, row[3], veredicto)

    conn.commit()
    return fallos
