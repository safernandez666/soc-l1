#!/usr/bin/env python3
"""
Priorización de vulnerabilidades Wazuh con EPSS (FIRST) + CISA KEV.

Equivalente programático del workflow n8n "Track and prioritize Wazuh
vulnerabilities with EPSS and CISA KEV", pensado para engancharse al
"Reporte Semanal de Cumplimiento de Parches" de Grupo Alemana
(/opt/wazuh-scripts/weekly_comparison.py).

Qué hace:
  1. Lee el inventario completo de vulnerabilidades del indexer (scroll API).
  2. Enriquece cada CVE con EPSS (probabilidad de explotación a 30 días) y
     con el catálogo CISA KEV (explotación confirmada in-the-wild).
  3. Calcula un score de prioridad explicable 0-100:
        prioridad = CVSS x 5  +  EPSS x 30  +  KEV x 20   (tope 100)
  4. Trackea el ciclo de vida de cada hallazgo en SQLite (nueva / persistente /
     resuelta / reabierta), reemplazando el Data Table de n8n.
  5. Genera la sección HTML del reporte y, opcionalmente, la manda por mail.

Uso:
  python3 vuln_priority.py --dry-run                      # no manda mail ni escribe estado
  python3 vuln_priority.py --html-out /tmp/prio.html      # guarda el HTML
  python3 vuln_priority.py --email --to alguien@dom.com   # manda mail
  python3 vuln_priority.py --fragment-out /tmp/frag.html  # solo la sección, para embeber

Exit codes: 0 OK, 1 error.
"""
from __future__ import annotations

import argparse
import logging
import smtplib
import sys
from datetime import datetime
from pathlib import Path

import requests
import urllib3

# Permitir importar src/ desde scripts/: este archivo se ejecuta por ruta
# absoluta desde cron (scripts/cron/run_report.sh), no como módulo.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import report_theme as _theme
from src.vuln.feeds import fetch_epss, fetch_kev
from src.vuln.indexer import (
    INDEXER_PASS,
    INDEXER_USER,
    fetch_agent_os_versions,
    fetch_inventory,
)
from src.vuln.report import (
    CSS,
    EMAIL_CONFIG_FILE,
    TOP_LIMIT,
    load_email_config,
    render_compliance_fragment,
    render_coverage_notice,
    render_email,
    render_fragment,
    render_plain,
    send_email,
)
from src.vuln.scoring import (
    EPSS_HIGH_THRESHOLD,
    PRIORITY_THRESHOLD,
    apply_threat_intel,
)
from src.vuln.store import (
    HISTORICAL_DIR,
    STATE_DB,
    assess_coverage,
    build_summary,
    compare_hosts,
    compute_host_counts,
    compute_lifecycle,
    group_by_cve,
    load_previous_snapshot,
    open_state,
    persist_coverage,
    persist_lifecycle,
    persist_run,
    save_snapshot,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("vuln_priority")

# Superficie pública del script. La lógica vive en src/vuln/*, pero estos
# nombres se siguen importando desde acá (tests de regresión del reporte),
# así que el re-export es explícito y parte del contrato.
__all__ = [
    "apply_threat_intel",
    "assess_coverage",
    "build_summary",
    "compare_hosts",
    "compute_host_counts",
    "group_by_cve",
    "main",
    "render_compliance_fragment",
    "render_coverage_notice",
    "render_email",
    "render_fragment",
    "render_plain",
]


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Priorización de vulnerabilidades Wazuh con EPSS + CISA KEV")
    ap.add_argument("--email", action="store_true", help="Enviar el reporte por mail")
    ap.add_argument("--to", action="append", default=[], help="Destinatario (repetible). Default: el de email-config.json")
    ap.add_argument("--subject", default=None, help="Asunto del mail")
    ap.add_argument("--top", type=int, default=TOP_LIMIT, help=f"Cantidad de CVEs en el top (default {TOP_LIMIT})")
    ap.add_argument("--html-out", default=None, help="Guardar el HTML completo en un archivo")
    ap.add_argument("--fragment-out", default=None, help="Guardar solo la sección embebible")
    ap.add_argument("--dry-run", action="store_true", help="No manda mail ni persiste el estado de ciclo de vida")
    ap.add_argument("--smtp-debug", action="store_true", help="Mostrar la conversación SMTP completa")
    ap.add_argument("--historical-dir", default=HISTORICAL_DIR,
                    help=f"Directorio de snapshots semanales, solo lectura (default {HISTORICAL_DIR})")
    ap.add_argument("--no-snapshot", action="store_true",
                    help="No escribir el snapshot semanal (por defecto sí se escribe)")
    ap.add_argument("--no-compliance", action="store_true",
                    help="Omitir la sección de cumplimiento de parches por host")
    ap.add_argument("--db", default=STATE_DB, help=f"Ruta de la base de ciclo de vida (default {STATE_DB})")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    if not INDEXER_PASS:
        logger.error("Falta VULN_INDEXER_PASS en el entorno")
        return 1

    session = requests.Session()
    session.auth = (INDEXER_USER, INDEXER_PASS)
    session.verify = False
    session.headers["Content-Type"] = "application/json"

    try:
        findings = fetch_inventory(session)
    except requests.RequestException as exc:
        logger.error("No se pudo leer el inventario del indexer: %s", exc)
        return 1

    if not findings:
        logger.error("El inventario vino vacío")
        return 1

    epss = fetch_epss([f["cve"] for f in findings])
    kev = fetch_kev()
    findings = apply_threat_intel(findings, epss, kev)

    conn = open_state(args.db)
    rows, baseline = compute_lifecycle(conn, findings)
    summary = build_summary(rows, baseline)

    if args.dry_run:
        logger.info("dry-run: no se persiste el ciclo de vida")
    else:
        persist_lifecycle(conn, rows)
        persist_run(conn, summary)

    active = [r for r in rows if r["lifecycle_status"] != "resolved"]
    groups = group_by_cve(active)

    # Cumplimiento de parches: conteos por host del inventario actual, comparados
    # contra el snapshot semanal anterior (lectura únicamente).
    agent_os = fetch_agent_os_versions()
    cov = assess_coverage(active, agent_os)
    # El snapshot de cobertura lo consume /ui: sin esto la pantalla no puede saber
    # que hay agentes sin ningún hallazgo, porque no dejan rastro en la base.
    if not args.dry_run:
        persist_coverage(conn, cov, len(agent_os))
    conn.close()
    if cov.get("disponible"):
        logger.info(
            "Calidad del dato: %s host(s) desfasados (%s hallazgos dudosos) | %s sin datos",
            len(cov["desfasados"]), cov["hallazgos_dudosos"], len(cov["sin_datos"]),
        )
        for d in cov["desfasados"]:
            logger.info("  desfasado %-18s indexado %-22s real %-22s (%s hallazgos)",
                        d["host"], d["indexado"], d["actual"], d["hallazgos"])

    host_counts = compute_host_counts(active)
    previous_hosts, prev_file = load_previous_snapshot(args.historical_dir)
    comp = compare_hosts(host_counts, previous_hosts)
    # El snapshot se escribe DESPUÉS de comparar: load_previous_snapshot() excluye
    # los del día, pero escribir antes dejaría la comparativa a merced de ese orden.
    if not args.dry_run and not args.no_snapshot:
        save_snapshot(host_counts, args.historical_dir)
    logger.info(
        "Cumplimiento: %s hosts | criticas %s (%+d) | altas %s (%+d) | SLA %.0f%%",
        comp["total_hosts"], comp["critical_now"], comp["critical_delta"],
        comp["high_now"], comp["high_delta"], comp["sla"],
    )

    logger.info(
        "Resumen: %s activos | KEV %s (ransomware %s) | EPSS>=%.0f%% %s | prioridad>=%.0f %s",
        summary["total_active"], summary["kev_count"], summary["kev_ransomware_count"],
        EPSS_HIGH_THRESHOLD * 100, summary["epss_high_count"],
        PRIORITY_THRESHOLD, summary["priority_high_count"],
    )
    for g in groups[:5]:
        logger.info(
            "  %-18s prio %5.1f  CVSS %4.1f  EPSS %6.2f%%  KEV %-3s  hosts %s",
            g["cve"], g["priority_score"], g["cvss_score"], g["epss_score"] * 100,
            "sí" if g["cisa_kev"] else "no", g["hosts_count"],
        )

    comp_arg = None if args.no_compliance else comp
    html = render_email(summary, groups, args.top, comp=comp_arg, prev_file=prev_file, cov=cov)

    if args.html_out:
        with open(args.html_out, "w", encoding="utf-8") as fh:
            fh.write(html)
        logger.info("HTML guardado en %s", args.html_out)

    if args.fragment_out:
        with open(args.fragment_out, "w", encoding="utf-8") as fh:
            frag = render_coverage_notice(cov) + (render_compliance_fragment(comp, prev_file) if comp_arg else "")
            fh.write(CSS + frag + render_fragment(summary, groups, args.top))
        logger.info("Fragmento guardado en %s", args.fragment_out)

    if args.email and not args.dry_run:
        cfg = load_email_config(EMAIL_CONFIG_FILE)
        recipients = args.to or cfg.get("to", [])
        if not recipients:
            logger.error("No hay destinatarios")
            return 1
        subject = args.subject or _theme.subject(
            "VULNS", "PRIORIDAD",
            f"{summary['priority_high_count']} explotables de {summary['total_active']}",
            datetime.now().strftime("%d/%m"),
        )
        try:
            plain = render_plain(summary, groups, args.top, comp=comp_arg, cov=cov)
            if not send_email(cfg, html, subject, recipients, plain=plain, debug=args.smtp_debug):
                return 1
        except (smtplib.SMTPException, OSError) as exc:
            logger.error("Error enviando el mail: %s", exc)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
