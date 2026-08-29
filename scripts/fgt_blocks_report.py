#!/usr/bin/env python3
"""
Reporte Semanal de Bloqueos Automáticos - FortiGate / SOC-L1.

Port de /var/ossec/bin/weekly-blocks-report.sh (bash + python embebido) al
sistema de diseño compartido `src/report_theme.py`, para que quede en la misma
familia visual que el reporte de vulnerabilidades.

Fuentes de datos (las mismas que el script original):
  - Ataques IPS: alertas con rule.id que empieza en "1962", del alerts.json en
    vivo más los archivados .json.gz de los 7 días de la semana.
  - Bloqueos: el ledger de SOC-L1 (`fgt_observations.jsonl`), contando IPs
    DISTINTAS con executed=true y block_ok=true. Ojo: NO usar el grep viejo de
    "IP ... BLOQUEADA" sobre integrations.log, que quedó clavado en 0 tras el
    cutover del 2026-06-23.

Ventana: lunes 00:00 -> lunes siguiente 00:00, hora local ART (-03).

Uso:
  python3 fgt_blocks_report.py --dry-run --html-out /tmp/blocks.html
  python3 fgt_blocks_report.py --email --to alguien@dom.com
"""
from __future__ import annotations

import argparse
import glob
import gzip
import json
import logging
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import report_theme as t  # noqa: E402

ALERTS_LIVE = os.getenv("FGT_ALERTS_LIVE", "/var/ossec/logs/alerts/alerts.json")
ALERTS_DIR = os.getenv("FGT_ALERTS_DIR", "/var/ossec/logs/alerts")
OBSERVATIONS = os.getenv("FGT_OBSERVATIONS", "/opt/soc-l1/fgt_observations.jsonl")
EMAIL_CONFIG_FILE = os.getenv("FGT_EMAIL_CONFIG", "/var/ossec/etc/email-config.json")
ORG_NAME = os.getenv("VULN_ORG_NAME", "Grupo Alemana")

IPS_RULE_PREFIX = "1962"
LIVE_TAIL_LINES = 100_000
ART = timezone(timedelta(hours=-3))

logger = logging.getLogger("fgt_blocks_report")


# --------------------------------------------------------------------------
# Ventana semanal
# --------------------------------------------------------------------------
def week_window(ref: datetime | None = None) -> tuple[datetime, datetime]:
    """Lunes 00:00 de la semana cerrada más reciente, y el lunes siguiente."""
    now = ref or datetime.now(ART)
    # Si hoy es lunes, la semana cerrada arrancó hace 7 días.
    days_since_monday = now.weekday()
    last_monday = now - timedelta(days=7 if days_since_monday == 0 else days_since_monday)
    start = last_monday.replace(hour=0, minute=0, second=0, microsecond=0)
    return start, start + timedelta(days=7)


# --------------------------------------------------------------------------
# Ataques IPS
# --------------------------------------------------------------------------
def _iter_alert_lines(start: datetime, end: datetime):
    """Alertas del alerts.json en vivo (cola) más los archivados de la semana."""
    try:
        with open(ALERTS_LIVE, encoding="utf-8", errors="replace") as fh:
            tail = fh.readlines()[-LIVE_TAIL_LINES:]
        yield from tail
    except OSError as exc:
        logger.warning("No se pudo leer %s: %s", ALERTS_LIVE, exc)

    # Wazuh rota un .json.gz por día bajo AAAA/Mmm/. El nombre del mes es en
    # inglés capitalizado, así que se arma con una tabla fija y no con %b, que
    # depende del locale (ese bug hacía que nunca se leyeran los archivados).
    meses = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
             "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    for d in range(7):
        day = start + timedelta(days=d)
        path = os.path.join(
            ALERTS_DIR, f"{day.year}", meses[day.month - 1],
            f"ossec-alerts-{day.day:02d}.json.gz",
        )
        if not os.path.exists(path):
            continue
        try:
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
                yield from fh
        except OSError as exc:
            logger.warning("No se pudo leer %s: %s", path, exc)


def collect_ips_alerts(start: datetime, end: datetime) -> list[dict]:
    """Alertas IPS (regla 1962*) de la ventana, deduplicadas por id."""
    start_s, end_s = start.strftime("%Y-%m-%d"), end.strftime("%Y-%m-%d")
    seen: set[str] = set()
    out: list[dict] = []
    for line in _iter_alert_lines(start, end):
        line = line.strip()
        if not line or IPS_RULE_PREFIX not in line:
            continue
        try:
            a = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        rid = str(a.get("rule", {}).get("id", ""))
        if not rid.startswith(IPS_RULE_PREFIX):
            continue
        ts = a.get("timestamp", "")
        if not (start_s <= ts[:10] < end_s):
            continue
        aid = a.get("id") or f"{ts}|{rid}|{a.get('data',{}).get('srcip','')}"
        if aid in seen:
            continue
        seen.add(aid)
        out.append(a)
    logger.info("Ataques IPS en la ventana: %s", len(out))
    return out


# --------------------------------------------------------------------------
# Bloqueos ejecutados (ledger de SOC-L1)
# --------------------------------------------------------------------------
def collect_blocks(start: datetime, end: datetime) -> tuple[set[str], set[str]]:
    """IPs distintas bloqueadas en la semana y en la anterior."""
    prev_start = start - timedelta(days=7)
    cur: set[str] = set()
    prev: set[str] = set()
    try:
        with open(OBSERVATIONS, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                # Bloqueo real = se ejecutó el quarantine y FortiGate lo aceptó.
                if not (r.get("executed") and r.get("block_ok")):
                    continue
                ip, ts = r.get("ip"), r.get("ts")
                if not ip or not ts:
                    continue
                try:
                    dt = datetime.fromisoformat(ts)
                except ValueError:
                    continue
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if start <= dt < end:
                    cur.add(ip)
                elif prev_start <= dt < start:
                    prev.add(ip)
    except FileNotFoundError:
        logger.warning("No existe el ledger %s", OBSERVATIONS)
    logger.info("IPs bloqueadas: %s (semana previa: %s)", len(cur), len(prev))
    return cur, prev


# --------------------------------------------------------------------------
# Estadísticas
# --------------------------------------------------------------------------
def build_stats(alerts: list[dict], blocked: set[str], prev_blocked: set[str]) -> dict:
    level = lambda a: int(a.get("rule", {}).get("level", 0) or 0)  # noqa: E731
    critical = sum(1 for a in alerts if level(a) >= 12)
    high = sum(1 for a in alerts if 10 <= level(a) < 12)
    med_low = sum(1 for a in alerts if level(a) < 10)
    high_sev = critical + high

    src = [a.get("data", {}).get("srcip") for a in alerts]
    src = [ip for ip in src if ip]
    dst = [a.get("data", {}).get("dstip") for a in alerts]
    dst = [ip for ip in dst if ip]
    rules = [
        (str(a.get("rule", {}).get("id", "")), a.get("rule", {}).get("description", ""))
        for a in alerts
    ]

    # SLA: cobertura de bloqueo sobre los ataques graves. Sin ataques graves no
    # hay nada que bloquear, así que el 100% es correcto (no es un default).
    if high_sev > 0:
        sla = min(round(len(blocked) / high_sev * 100), 100)
    else:
        sla = 100

    return {
        "total_attacks": len(alerts),
        "critical": critical,
        "high": high,
        "med_low": med_low,
        "high_severity": high_sev,
        "unique_ips": len(set(src)),
        "blocked": len(blocked),
        "prev_blocked": len(prev_blocked),
        "delta_blocked": len(blocked) - len(prev_blocked),
        "sla": sla,
        "top_ips": Counter(src).most_common(10),
        "top_targets": Counter(dst).most_common(10),
        "top_rules": Counter(rules).most_common(10),
        "blocked_set": blocked,
    }


# --------------------------------------------------------------------------
# Render
# --------------------------------------------------------------------------
def render_body(st: dict, start: datetime, end: datetime) -> str:
    sla = st["sla"]
    sla_color = t.C_OK if sla >= 80 else t.C_HIGH if sla >= 50 else t.C_CRIT
    sla_text = (
        "Cobertura correcta" if sla >= 80
        else "Requiere atenci&oacute;n" if sla >= 50
        else "Acci&oacute;n requerida"
    )

    cards = [
        t.metric_card("IPS BLOQUEADAS", t.num(st["blocked"]), t.C_GREEN,
                      f"{t.delta_badge(st['delta_blocked'], lower_is_better=False)} vs. semana anterior"),
        t.metric_card("ATAQUES DETECTADOS", t.num(st["total_attacks"]), t.C_TEXT,
                      f"desde {t.num(st['unique_ips'])} IPs distintas"),
        t.metric_card("ALTA SEVERIDAD", t.num(st["high_severity"]), t.C_CRIT,
                      f"cr&iacute;ticas {t.num(st['critical'])} &middot; altas {t.num(st['high'])}"),
        t.metric_card("MEDIAS / BAJAS", t.num(st["med_low"]), t.C_MUTED, "nivel &lt; 10"),
        t.metric_card("COBERTURA DE BLOQUEO", f"{sla}%", sla_color, sla_text),
    ]

    aviso = ""
    if st["high_severity"] == 0 and st["blocked"] > 0:
        aviso = t.notice(
            "No hubo ataques de alta severidad esta semana. Los bloqueos "
            "registrados fueron preventivos, sobre actividad de menor nivel.",
            accent=t.C_GREEN, bg="#f0f7ec",
        )
    elif st["total_attacks"] == 0:
        aviso = t.notice(
            "No se registraron intentos de intrusi&oacute;n en el per&iacute;odo.",
            accent=t.C_GREEN, bg="#f0f7ec",
        )

    body = t.section(
        "Resumen de la semana",
        f"{start.strftime('%d/%m/%Y')} al {(end - timedelta(days=1)).strftime('%d/%m/%Y')}",
        aviso + t.metric_row(cards),
    )

    # --- Top IPs atacantes ---------------------------------------------------
    if st["top_ips"]:
        rows = []
        for i, (ip, count) in enumerate(st["top_ips"], 1):
            # El reporte viejo etiquetaba TODAS las IPs del top como BLOQUEADA,
            # incluso las que nunca se bloquearon. Acá se verifica contra el ledger.
            estado = (
                t.badge_ok("BLOQUEADA") if ip in st["blocked_set"]
                else t.badge_warn("NO BLOQUEADA")
            )
            rows.append(
                t.table_row(
                    [
                        (str(i), "left", ""),
                        (f'<code style="font-size:12px;">{escape(ip)}</code>', "left", "font-weight:bold;"),
                        (t.num(count), "right", ""),
                        (estado, "center", ""),
                    ],
                    i,
                )
            )
        body += t.section(
            "Top IPs atacantes",
            "Ordenadas por cantidad de intentos detectados",
            t.table_open([
                ("#", "24", "left"), ("Direcci&oacute;n IP", None, "left"),
                ("Intentos", "70", "right"), ("Estado", "110", "center"),
            ]) + "".join(rows) + t.TABLE_CLOSE,
        )

    # --- Top ataques ---------------------------------------------------------
    if st["top_rules"]:
        rows = []
        for i, ((rid, desc), count) in enumerate(st["top_rules"], 1):
            rows.append(
                t.table_row(
                    [
                        (str(i), "left", ""),
                        (escape(desc or "&mdash;"), "left", ""),
                        (f'<code style="font-size:11px;color:{t.C_MUTED};">{escape(rid)}</code>', "left", ""),
                        (t.num(count), "right", "font-weight:bold;"),
                    ],
                    i,
                )
            )
        body += t.section(
            "Tipos de ataque m&aacute;s frecuentes",
            "Firmas IPS de FortiGate con más disparos",
            t.table_open([
                ("#", "24", "left"), ("Descripci&oacute;n", None, "left"),
                ("Regla", "70", "left"), ("Eventos", "62", "right"),
            ]) + "".join(rows) + t.TABLE_CLOSE,
        )

    # --- Top destinos --------------------------------------------------------
    if st["top_targets"]:
        rows = []
        for i, (ip, count) in enumerate(st["top_targets"], 1):
            rows.append(
                t.table_row(
                    [
                        (str(i), "left", ""),
                        (f'<code style="font-size:12px;">{escape(ip)}</code>', "left", "font-weight:bold;"),
                        (t.num(count), "right", ""),
                    ],
                    i,
                )
            )
        body += t.section(
            "Destinos m&aacute;s apuntados",
            "Activos que recibieron más intentos",
            t.table_open([
                ("#", "24", "left"), ("Destino", None, "left"), ("Intentos", "70", "right"),
            ]) + "".join(rows) + t.TABLE_CLOSE,
        )

    body += t.section(
        "C&oacute;mo leer este reporte",
        "",
        f"""<p style="font-family:{t.FONT};font-size:12px;line-height:18px;color:{t.C_MUTED};margin:0 0 8px 0;">
        <strong style="color:{t.C_TEXT};">IPs bloqueadas</strong> son direcciones distintas que SOC-L1 puso en
        cuarentena en el FortiGate y el equipo confirm&oacute; (ledger de bloqueos, no el log de integraciones).
        </p>
        <p style="font-family:{t.FONT};font-size:12px;line-height:18px;color:{t.C_MUTED};margin:0 0 8px 0;">
        <strong style="color:{t.C_TEXT};">Cobertura de bloqueo</strong> es la proporci&oacute;n de ataques de alta
        severidad (nivel &ge; 10) frente a la cantidad de IPs efectivamente bloqueadas. Es una medida de alcance
        de la respuesta autom&aacute;tica, no de efectividad del perimetro.
        </p>
        <p style="font-family:{t.FONT};font-size:12px;line-height:18px;color:{t.C_MUTED};margin:0;">
        <strong style="color:{t.C_TEXT};">Estado</strong> en el top de IPs se verifica contra el ledger: una IP
        aparece como bloqueada solo si efectivamente se ejecut&oacute; el bloqueo.
        </p>""",
    )
    return body


def render_plain(st: dict, start: datetime, end: datetime) -> str:
    out = [
        f"{ORG_NAME} - Gerencia Tecnologia",
        f"Reporte Semanal de Bloqueos Automaticos - FortiGate",
        f"Periodo: {start.strftime('%d/%m/%Y')} al {(end - timedelta(days=1)).strftime('%d/%m/%Y')}",
        "",
        f"IPs bloqueadas: {st['blocked']} ({st['delta_blocked']:+d} vs. semana anterior)",
        f"Ataques detectados: {st['total_attacks']} desde {st['unique_ips']} IPs distintas",
        f"Alta severidad: {st['high_severity']} (criticas {st['critical']}, altas {st['high']})",
        f"Medias/bajas: {st['med_low']}",
        f"Cobertura de bloqueo: {st['sla']}%",
        "",
    ]
    if st["top_ips"]:
        out.append("TOP IPS ATACANTES")
        for i, (ip, c) in enumerate(st["top_ips"], 1):
            estado = "bloqueada" if ip in st["blocked_set"] else "NO bloqueada"
            out.append(f"  {i:2d}. {ip:<18} {c:>6} intentos  [{estado}]")
        out.append("")
    if st["top_rules"]:
        out.append("TIPOS DE ATAQUE MAS FRECUENTES")
        for i, ((rid, desc), c) in enumerate(st["top_rules"], 1):
            out.append(f"  {i:2d}. [{rid}] {desc[:60]} - {c} eventos")
        out.append("")
    out.append("Generado por Wazuh SIEM / SOC-L1.")
    return "\n".join(out)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Reporte semanal de bloqueos FortiGate")
    ap.add_argument("--email", action="store_true")
    ap.add_argument("--to", action="append", default=[])
    ap.add_argument("--subject", default=None)
    ap.add_argument("--html-out", default=None)
    ap.add_argument("--dry-run", action="store_true", help="No manda mail")
    ap.add_argument("--smtp-debug", action="store_true")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    start, end = week_window()
    logger.info("Ventana: %s -> %s", start.date(), end.date())

    alerts = collect_ips_alerts(start, end)
    blocked, prev_blocked = collect_blocks(start, end)
    st = build_stats(alerts, blocked, prev_blocked)
    logger.info(
        "Resumen: %s bloqueadas (%+d) | %s ataques | alta sev %s | cobertura %s%%",
        st["blocked"], st["delta_blocked"], st["total_attacks"],
        st["high_severity"], st["sla"],
    )

    html = t.document(
        org=ORG_NAME,
        title="Reporte Semanal de Bloqueos Autom&aacute;ticos",
        subtitle=(
            f"{start.strftime('%d/%m/%Y')} al {(end - timedelta(days=1)).strftime('%d/%m/%Y')}"
            f" &nbsp;&middot;&nbsp; {t.num(st['blocked'])} IPs bloqueadas"
        ),
        body=render_body(st, start, end),
        footer="Generado autom&aacute;ticamente por Wazuh SIEM &middot; Respuesta autom&aacute;tica SOC-L1 sobre FortiGate",
        doc_title=f"Reporte Semanal de Bloqueos - {ORG_NAME}",
    )

    if args.html_out:
        with open(args.html_out, "w", encoding="utf-8") as fh:
            fh.write(html)
        logger.info("HTML guardado en %s", args.html_out)

    if args.email and not args.dry_run:
        with open(EMAIL_CONFIG_FILE, encoding="utf-8") as fh:
            cfg = json.load(fh)
        recipients = args.to or cfg.get("to", [])
        if not recipients:
            logger.error("No hay destinatarios")
            return 1
        subject = args.subject or t.subject(
            "BLOQUEOS", "SEMANAL", f"{st['blocked']} bloqueos",
            f"{start.strftime('%d/%m')}-{end.strftime('%d/%m')}",
        )
        ok, info = t.send_report(
            cfg, html=html, plain=render_plain(st, start, end),
            subject=subject, recipients=recipients, debug=args.smtp_debug,
        )
        if not ok:
            logger.error("Error enviando el mail: %s", info)
            return 1
        logger.info("Mail aceptado para: %s (%s)", ", ".join(recipients), info)

    return 0


if __name__ == "__main__":
    sys.exit(main())
