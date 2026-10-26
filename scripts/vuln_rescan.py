#!/usr/bin/env python3
"""
Rescan forzado de los agentes que el detector de vulnerabilidades dejó desfasados.

Reinicia por la API del manager los agentes que el último snapshot de cobertura
marcó como problema, para que syscollector re-inventaríe y el manager vuelva a
evaluar. Es el fix de fondo del detector stale: no necesita root, sólo el
permiso `agent:restart` de la API.

Es conservador a propósito (reinicia agentes de servidores productivos): sólo
hosts marcados por la cobertura, sólo agentes `active`, cooldown por host y tope
por corrida. Sin `--apply` no reinicia nada.

Uso:
  python3 scripts/vuln_rescan.py                      # dry-run: dice a quién reiniciaría
  python3 scripts/vuln_rescan.py --apply              # reinicia de verdad
  python3 scripts/vuln_rescan.py --apply --host SRVWSUS
  python3 scripts/vuln_rescan.py --verify-only        # sólo juzga los rescans previos

La cobertura la refresca la ingesta diaria (`run_report.sh vuln-ingest`, 06:15).
Si está vieja, este script avisa y no hace nada.

Exit codes: 0 OK, 1 error.
"""
from __future__ import annotations

import argparse
import logging
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import urllib3

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.vuln.rescan import (
    COOLDOWN_DAYS,
    GRACE_HOURS,
    MAX_AGENTS,
    fetch_agents,
    load_last_rescans,
    record_rescan,
    restart_agents,
    select_targets,
    verify_pending,
)
from src.vuln.store import STATE_DB, load_coverage, open_state

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("vuln_priority")

# Más allá de esto la cobertura no describe el parque de hoy y reiniciar a ciegas
# no se justifica.
MAX_COBERTURA_HORAS = 48


def main() -> int:
    ap = argparse.ArgumentParser(description="Rescan forzado de agentes con inventario de vulnerabilidades desfasado")
    ap.add_argument("--apply", action="store_true", help="Reiniciar de verdad (sin esto es dry-run)")
    ap.add_argument("--host", action="append", default=[], help="Limitar a este host (repetible)")
    ap.add_argument("--max", type=int, default=MAX_AGENTS, dest="max_agents", help=f"Tope de agentes por corrida (default {MAX_AGENTS})")
    ap.add_argument("--cooldown-days", type=int, default=COOLDOWN_DAYS, help=f"Días entre rescans del mismo host (default {COOLDOWN_DAYS})")
    ap.add_argument("--grace-hours", type=int, default=GRACE_HOURS, help=f"Horas antes de juzgar un rescan (default {GRACE_HOURS})")
    ap.add_argument("--verify-only", action="store_true", help="Sólo verificar rescans previos, no reiniciar nada")
    ap.add_argument("--db", default=STATE_DB, help=f"Base de estado (default {STATE_DB})")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    conn = open_state(args.db)
    cov = load_coverage(conn)
    if not cov:
        logger.error("No hay snapshot de cobertura en %s: corré primero la ingesta diaria", args.db)
        return 1

    # La cobertura la escribe la ingesta; si quedó vieja, el parque pudo cambiar.
    edad_horas = None
    try:
        actualizado = datetime.fromisoformat(cov.get("updated_at", ""))
        if actualizado.tzinfo is None:
            actualizado = actualizado.replace(tzinfo=UTC)
        edad_horas = (datetime.now(UTC) - actualizado).total_seconds() / 3600
    except (TypeError, ValueError):
        pass

    if edad_horas is None:
        logger.warning("La cobertura no tiene fecha legible; sigo igual")
    else:
        logger.info("Cobertura del %s (%.1f h)", cov.get("updated_at"), edad_horas)
        if edad_horas > MAX_COBERTURA_HORAS and args.apply:
            logger.error(
                "Cobertura de hace %.0f h (máximo %s): corré la ingesta antes de reiniciar nada",
                edad_horas, MAX_COBERTURA_HORAS,
            )
            return 1

    # 1. Juzgar los rescans previos que ya cumplieron la ventana de gracia.
    fallos = verify_pending(conn, cov, grace_hours=args.grace_hours)
    for f in fallos:
        logger.warning("%s sigue %s después del rescan del %s: el reinicio no lo destrabó",
                       f["host"], f["motivo"], f["solicitado_at"])
    if args.verify_only:
        return 0

    sin_datos = cov.get("sin_datos", [])
    desfasados = cov.get("desfasados", [])
    logger.info("Cobertura: %s desfasado(s) (%s hallazgos dudosos) | %s sin datos",
                len(desfasados), cov.get("hallazgos_dudosos", 0), len(sin_datos))

    if not sin_datos and not desfasados:
        logger.info("Nada que reiniciar: la cobertura no reporta problemas")
        return 0

    # 2. Elegir a quién reiniciar.
    try:
        agentes = fetch_agents()
    except Exception as exc:
        logger.error("No se pudo consultar el parque de agentes: %s", exc)
        return 1

    sel = select_targets(
        cov, agentes, load_last_rescans(conn),
        cooldown_days=args.cooldown_days,
        max_agents=args.max_agents,
        solo_hosts=args.host or None,
    )

    for host, motivo in sel.descartados:
        logger.info("  omitido  %-14s %s", host, motivo)

    if not sel.elegibles:
        logger.info("Ningún agente elegible en esta corrida")
        return 0

    for t in sel.elegibles:
        logger.info("  rescan   %-14s agente %-4s %-10s %s",
                    t.host, t.agent_id, t.motivo, t.descripcion())

    # 3. Reiniciar (o simular).
    if not args.apply:
        for t in sel.elegibles:
            record_rescan(conn, t, "simulado", "dry-run")
        logger.info("DRY-RUN: %s agente(s) se reiniciarían. Volvé a correr con --apply.",
                    len(sel.elegibles))
        return 0

    try:
        resultados = restart_agents([t.agent_id for t in sel.elegibles])
    except Exception as exc:
        logger.error("Falló el pedido de reinicio: %s", exc)
        for t in sel.elegibles:
            record_rescan(conn, t, "error", str(exc)[:200])
        return 1

    ok = 0
    for t in sel.elegibles:
        res = resultados.get(t.agent_id, "error: sin respuesta")
        if res == "ok":
            ok += 1
            record_rescan(conn, t, "ok")
            logger.info("Reiniciado %-14s (agente %s)", t.host, t.agent_id)
        else:
            record_rescan(conn, t, "error", res[:200])
            logger.error("No se pudo reiniciar %-14s (agente %s): %s", t.host, t.agent_id, res)

    proxima = (datetime.now(UTC) + timedelta(hours=args.grace_hours)).strftime("%Y-%m-%d %H:%M UTC")
    logger.info("Rescan pedido para %s/%s agente(s). Se verifica a partir del %s.",
                ok, len(sel.elegibles), proxima)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
