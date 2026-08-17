#!/usr/bin/env python3
"""
Alarma de cobertura de agentes: equipos que dejaron de reportar.

Cubre dos puntos ciegos que el umbral actual de wazuh-health
(`agents.disconnected >= 3`) no detecta, y que son inversos entre sí:

  A) Agente ACTIVO pero SIN datos de vulnerabilidades.
     Caso real (2026-08-17): SRVWSUS respondía keepalives con normalidad y tenía
     0 documentos en el índice. El host simplemente desapareció del reporte
     semanal, que es la falla más peligrosa porque parece que se resolvió todo.

  B) Agente DESCONECTADO que conserva datos viejos.
     Caso real: TECO-PRD-AD-01, dos días sin conectar, seguía mostrando 392
     vulnerabilidades. En el reporte figura "estable" con información vencida.

Ninguno de los dos dispara con un umbral global de 3 agentes desconectados.

Estado en SQLite para no repetir el aviso en cada corrida: solo notifica cuando
una condición APARECE, y avisa cuando se RESUELVE.

Uso:
  python3 agent_coverage_alert.py --dry-run          # solo muestra
  python3 agent_coverage_alert.py --teams --email    # notifica por ambos
  python3 agent_coverage_alert.py --force            # reenvía aunque ya se avisó
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path

import requests
import urllib3

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import report_theme as t  # noqa: E402

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INDEXER_URL = os.getenv("VULN_INDEXER_URL", "https://localhost:9200")
INDEXER_USER = os.getenv("VULN_INDEXER_USER", "admin")
INDEXER_PASS = os.getenv("VULN_INDEXER_PASS", "")
INDEX_PATTERN = os.getenv("VULN_INDEX_PATTERN", "wazuh-states-vulnerabilities-*")

EMAIL_CONFIG_FILE = os.getenv("VULN_EMAIL_CONFIG", "/var/ossec/etc/email-config.json")
STATE_DB = os.getenv("COVERAGE_STATE_DB", "/opt/soc-l1/agent_coverage.db")
ORG_NAME = os.getenv("VULN_ORG_NAME", "Grupo Alemana")

# Umbrales
DISCONNECTED_HOURS = float(os.getenv("COVERAGE_DISCONNECTED_HOURS", "12"))

logger = logging.getLogger("agent_coverage_alert")

SCHEMA = """
CREATE TABLE IF NOT EXISTS coverage_state (
    agent_name  TEXT NOT NULL,
    issue       TEXT NOT NULL,
    first_seen  TEXT,
    last_seen   TEXT,
    notified_at TEXT,
    detail      TEXT,
    PRIMARY KEY (agent_name, issue)
);
"""

ISSUE_NO_DATA = "sin_datos_vulnerabilidades"
ISSUE_DISCONNECTED = "agente_desconectado"

ISSUE_LABEL = {
    ISSUE_NO_DATA: "Activo pero sin datos de vulnerabilidades",
    ISSUE_DISCONNECTED: "Agente desconectado",
}

# Se descartó un tercer check basado en `vulnerability.detected_at` ("sin hallazgos
# nuevos hace N días"): daba falsos positivos en hosts sanos. SRVDC2 llevaba 110 días
# sin detecciones nuevas simplemente porque su set de paquetes no cambió, mientras
# syscollector escaneaba con normalidad. La señal buena es la de abajo: el agente
# inventaría paquetes pero el detector de vulnerabilidades no produce nada.


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------
# Recolección
# --------------------------------------------------------------------------
def fetch_agents() -> list[dict]:
    """Lista de agentes desde la API de Wazuh."""
    from src.config import Settings

    s = Settings()
    pw = s.wazuh_api_password
    pw = pw.get_secret_value() if hasattr(pw, "get_secret_value") else pw
    base = f"https://{s.wazuh_api_host}:{s.wazuh_api_port}"
    tok = requests.post(
        f"{base}/security/user/authenticate",
        auth=(s.wazuh_api_user, pw), verify=False, timeout=25,
    ).json()["data"]["token"]
    r = requests.get(
        f"{base}/agents?limit=1000&select=id,name,status,lastKeepAlive,version",
        headers={"Authorization": f"Bearer {tok}"}, verify=False, timeout=25,
    )
    r.raise_for_status()
    agents = r.json()["data"]["affected_items"]
    # El agente 000 es el propio manager, no tiene inventario propio que vigilar.
    return [a for a in agents if str(a.get("id")) != "000"]


def fetch_vuln_coverage() -> dict[str, dict]:
    """Por agente: cantidad de documentos y fecha del último hallazgo detectado."""
    body = {
        "size": 0,
        "aggs": {
            "per_agent": {
                "terms": {"field": "agent.name", "size": 1000},
                "aggs": {"ultimo": {"max": {"field": "vulnerability.detected_at"}}},
            }
        },
    }
    r = requests.post(
        f"{INDEXER_URL}/{INDEX_PATTERN}/_search",
        auth=(INDEXER_USER, INDEXER_PASS), json=body, verify=False, timeout=60,
    )
    r.raise_for_status()
    out: dict[str, dict] = {}
    for b in r.json()["aggregations"]["per_agent"]["buckets"]:
        out[b["key"]] = {
            "docs": b["doc_count"],
            "ultimo": b["ultimo"].get("value_as_string"),
        }
    return out


# --------------------------------------------------------------------------
# Detección
# --------------------------------------------------------------------------
def fetch_package_counts(agent_ids: dict[str, str]) -> dict[str, int]:
    """Paquetes inventariados por syscollector, solo para los agentes sospechosos.

    Es la evidencia que separa "el agente no está recolectando" de "el detector de
    vulnerabilidades no produce nada para este host": si syscollector tiene paquetes
    y el índice tiene cero hallazgos, el problema está en el detector.
    """
    from src.config import Settings

    s = Settings()
    pw = s.wazuh_api_password
    pw = pw.get_secret_value() if hasattr(pw, "get_secret_value") else pw
    base = f"https://{s.wazuh_api_host}:{s.wazuh_api_port}"
    try:
        tok = requests.post(
            f"{base}/security/user/authenticate",
            auth=(s.wazuh_api_user, pw), verify=False, timeout=25,
        ).json()["data"]["token"]
    except (requests.RequestException, KeyError, ValueError) as exc:
        logger.warning("No se pudo autenticar contra la API para syscollector: %s", exc)
        return {}

    h = {"Authorization": f"Bearer {tok}"}
    out: dict[str, int] = {}
    for name, aid in agent_ids.items():
        try:
            r = requests.get(
                f"{base}/syscollector/{aid}/packages?limit=1",
                headers=h, verify=False, timeout=25,
            )
            out[name] = r.json().get("data", {}).get("total_affected_items", 0)
        except (requests.RequestException, ValueError):
            out[name] = -1
    return out


def detect_issues(agents: list[dict], coverage: dict[str, dict]) -> list[dict]:
    now = _now()
    issues: list[dict] = []
    sin_datos: dict[str, str] = {}

    for a in agents:
        name = a.get("name") or a.get("id")
        status = a.get("status")
        cov = coverage.get(name, {"docs": 0, "ultimo": None})

        # B) Desconectado hace rato. Conserva su último inventario, así que sigue
        #    figurando en los reportes con datos vencidos y aparenta estar estable.
        if status != "active":
            horas = None
            last = a.get("lastKeepAlive")
            if last:
                try:
                    dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
                    horas = (now - dt).total_seconds() / 3600
                except ValueError:
                    pass
            if horas is None or horas >= DISCONNECTED_HOURS:
                issues.append({
                    "agent": name, "issue": ISSUE_DISCONNECTED,
                    "detail": (
                        f"estado {status}"
                        + (f", sin conectar hace {horas:.0f} h" if horas else "")
                        + (f"; conserva {cov['docs']} vulnerabilidades con datos vencidos"
                           if cov["docs"] else "")
                    ),
                    "docs": cov["docs"], "status": status, "horas": horas,
                })
            continue

        # A) Activo pero sin ningún hallazgo: la falla silenciosa.
        if cov["docs"] == 0:
            sin_datos[name] = str(a.get("id"))

    if sin_datos:
        paquetes = fetch_package_counts(sin_datos)
        for name in sin_datos:
            n = paquetes.get(name, -1)
            if n > 0:
                detalle = (
                    f"syscollector inventaría {n} paquetes pero el detector de "
                    "vulnerabilidades no genera ningún hallazgo: el host desaparece del reporte"
                )
            elif n == 0:
                detalle = (
                    "el agente responde pero no inventaría ningún paquete, "
                    "así que no hay nada sobre lo que evaluar vulnerabilidades"
                )
            else:
                detalle = (
                    "el agente responde pero no tiene hallazgos en el índice "
                    "(no se pudo consultar syscollector)"
                )
            issues.append({
                "agent": name, "issue": ISSUE_NO_DATA, "detail": detalle,
                "docs": 0, "status": "active", "horas": None, "packages": n,
            })

    issues.sort(key=lambda i: (i["issue"], i["agent"]))
    return issues


# --------------------------------------------------------------------------
# Estado (para no repetir el aviso en cada corrida)
# --------------------------------------------------------------------------
def open_state(path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def reconcile(conn: sqlite3.Connection, issues: list[dict], force: bool = False):
    """Devuelve (nuevos, resueltos). Solo los nuevos ameritan notificación."""
    now = _now().isoformat(timespec="seconds")
    previos = {
        (r["agent_name"], r["issue"]): dict(r)
        for r in conn.execute("SELECT * FROM coverage_state")
    }
    actuales = {(i["agent"], i["issue"]): i for i in issues}

    nuevos = []
    for key, i in actuales.items():
        old = previos.get(key)
        if old is None or force:
            nuevos.append(i)
        conn.execute(
            """INSERT INTO coverage_state (agent_name, issue, first_seen, last_seen, notified_at, detail)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT(agent_name, issue) DO UPDATE SET
                 last_seen=excluded.last_seen, detail=excluded.detail""",
            (i["agent"], i["issue"], (old or {}).get("first_seen") or now, now,
             now if (old is None or force) else (old or {}).get("notified_at"),
             i["detail"]),
        )

    resueltos = []
    for key, old in previos.items():
        if key not in actuales:
            resueltos.append({"agent": old["agent_name"], "issue": old["issue"]})
            conn.execute(
                "DELETE FROM coverage_state WHERE agent_name=? AND issue=?", key
            )

    conn.commit()
    return nuevos, resueltos


# --------------------------------------------------------------------------
# Salidas
# --------------------------------------------------------------------------
def render_html(issues: list[dict], resueltos: list[dict], total_agents: int) -> str:
    por_tipo: dict[str, list] = {}
    for i in issues:
        por_tipo.setdefault(i["issue"], []).append(i)

    cards = [
        t.metric_card("AGENTES", t.num(total_agents), t.C_TEXT, "en el parque"),
        t.metric_card("SIN DATOS", t.num(len(por_tipo.get(ISSUE_NO_DATA, []))),
                      t.C_CRIT, "activos pero invisibles"),
        t.metric_card("DESCONECTADOS", t.num(len(por_tipo.get(ISSUE_DISCONNECTED, []))),
                      t.C_HIGH, f"hace más de {DISCONNECTED_HOURS:.0f} h"),
    ]

    body = t.section(
        "Cobertura de agentes",
        "Equipos que dejaron de aportar datos de vulnerabilidades",
        t.metric_row(cards),
    )

    if issues:
        rows = []
        for idx, i in enumerate(issues, 1):
            if i["issue"] == ISSUE_NO_DATA:
                sev = t.badge_bad("SIN DATOS")
            else:
                sev = t.badge_warn("DESCONECTADO")
            rows.append(
                t.table_row(
                    [
                        (str(idx), "left", ""),
                        (escape(i["agent"]), "left", "font-weight:bold;"),
                        (sev, "center", ""),
                        (escape(i["detail"]), "left", f"color:{t.C_MUTED};"),
                    ],
                    idx,
                )
            )
        body += t.section(
            "Detalle",
            "",
            t.table_open([
                ("#", "24", "left"), ("Equipo", "150", "left"),
                ("Estado", "110", "center"), ("Observaci&oacute;n", None, "left"),
            ]) + "".join(rows) + t.TABLE_CLOSE,
        )

    if resueltos:
        lista = ", ".join(escape(r["agent"]) for r in resueltos)
        body += t.section(
            "Resueltos desde la corrida anterior", "",
            t.notice(f"Volvieron a reportar con normalidad: <strong>{lista}</strong>.",
                     accent=t.C_GREEN, bg="#f0f7ec"),
        )

    body += t.section(
        "Por qu&eacute; importa", "",
        f"""<p style="font-family:{t.FONT};font-size:12px;line-height:18px;color:{t.C_MUTED};margin:0 0 8px 0;">
        Un equipo <strong style="color:{t.C_TEXT};">activo pero sin datos</strong> es la falla m&aacute;s
        enga&ntilde;osa: el agente responde, nadie recibe una alerta de desconexi&oacute;n, y el host
        desaparece del reporte de vulnerabilidades como si estuviera limpio.
        </p>
        <p style="font-family:{t.FONT};font-size:12px;line-height:18px;color:{t.C_MUTED};margin:0;">
        Un equipo <strong style="color:{t.C_TEXT};">desconectado</strong> conserva su &uacute;ltimo inventario,
        as&iacute; que sigue figurando en los reportes con datos vencidos y aparenta estar estable.
        </p>""",
    )
    return t.document(
        org=ORG_NAME,
        title="Alerta de Cobertura de Agentes",
        subtitle=f"{len(issues)} equipo(s) con problemas de reporte &nbsp;&middot;&nbsp; {datetime.now().strftime('%d/%m/%Y %H:%M')}",
        body=body,
        footer="Generado autom&aacute;ticamente por SOC-L1 &middot; Cobertura de agentes Wazuh",
        doc_title=f"Cobertura de agentes - {ORG_NAME}",
    )


def render_plain(issues: list[dict], resueltos: list[dict], total_agents: int) -> str:
    out = [
        f"{ORG_NAME} - Alerta de cobertura de agentes",
        f"{datetime.now().strftime('%d/%m/%Y %H:%M')}",
        "",
        f"Agentes en el parque: {total_agents}",
        f"Con problemas de reporte: {len(issues)}",
        "",
    ]
    for i in issues:
        out.append(f"  [{ISSUE_LABEL[i['issue']]}] {i['agent']}")
        out.append(f"      {i['detail']}")
    if resueltos:
        out += ["", "Resueltos: " + ", ".join(r["agent"] for r in resueltos)]
    out += [
        "",
        "Un agente activo sin datos no dispara alerta de desconexion y el host",
        "desaparece del reporte de vulnerabilidades como si estuviera limpio.",
    ]
    return "\n".join(out)


async def notify_teams(issues: list[dict], resueltos: list[dict]) -> bool:
    from src.config import Settings
    from src import teams

    s = Settings()
    if not teams.is_configured(s):
        logger.warning("Teams no está configurado, se omite")
        return False

    lineas = []
    for i in issues:
        lineas.append((i["agent"], f"{ISSUE_LABEL[i['issue']]} — {i['detail']}"))

    color = "attention" if any(i["issue"] == ISSUE_NO_DATA for i in issues) else "warning"
    body = [
        teams._title_block("🛰️ Cobertura de agentes · equipos sin reportar", color),
        teams._text(
            f"{len(issues)} equipo(s) dejaron de aportar datos de vulnerabilidades. "
            "Un agente activo sin datos no dispara alerta de desconexión y su host "
            "desaparece del reporte como si estuviera limpio."
        ),
        teams._facts(lineas),
    ]
    if resueltos:
        body.append(
            teams._text("✅ Volvieron a reportar: " + ", ".join(r["agent"] for r in resueltos))
        )
    # _post_card es fire-and-forget: nunca propaga y devuelve None.
    await teams._post_card(
        s, teams._card(body), kind="agent-coverage",
        alert_id=f"coverage-{datetime.now().strftime('%Y%m%d%H%M')}",
    )
    return True


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Alarma de agentes que dejaron de reportar")
    ap.add_argument("--teams", action="store_true", help="Notificar por Teams")
    ap.add_argument("--email", action="store_true", help="Notificar por mail")
    ap.add_argument("--to", action="append", default=[])
    ap.add_argument("--dry-run", action="store_true", help="No notifica ni persiste estado")
    ap.add_argument("--force", action="store_true", help="Notificar aunque ya se haya avisado")
    ap.add_argument("--html-out", default=None)
    ap.add_argument("--db", default=STATE_DB)
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    if not INDEXER_PASS:
        logger.error("Falta VULN_INDEXER_PASS en el entorno")
        return 1

    agents = fetch_agents()
    coverage = fetch_vuln_coverage()
    issues = detect_issues(agents, coverage)
    logger.info("Agentes: %s | con problemas: %s", len(agents), len(issues))
    for i in issues:
        logger.info("  %-28s %-32s %s", i["agent"], i["issue"], i["detail"])

    if args.dry_run:
        nuevos, resueltos = issues, []
        logger.info("dry-run: no se persiste estado")
    else:
        conn = open_state(args.db)
        nuevos, resueltos = reconcile(conn, issues, force=args.force)
        conn.close()
        logger.info("Nuevos para notificar: %s | resueltos: %s", len(nuevos), len(resueltos))

    html = render_html(issues, resueltos, len(agents))
    if args.html_out:
        with open(args.html_out, "w", encoding="utf-8") as fh:
            fh.write(html)
        logger.info("HTML guardado en %s", args.html_out)

    if not nuevos and not resueltos:
        logger.info("Sin novedades, no se notifica")
        return 0

    if args.teams and not args.dry_run:
        ok = asyncio.run(notify_teams(nuevos or issues, resueltos))
        logger.info("Teams: %s", "enviado" if ok else "falló")

    if args.email and not args.dry_run:
        with open(EMAIL_CONFIG_FILE, encoding="utf-8") as fh:
            cfg = json.load(fh)
        recipients = args.to or cfg.get("to", [])
        n = len(issues)
        subject = f"[Wazuh SIEM] {n} equipo(s) dejaron de reportar vulnerabilidades"
        ok, info = t.send_report(
            cfg, html=html, plain=render_plain(issues, resueltos, len(agents)),
            subject=subject, recipients=recipients,
        )
        logger.info("Mail: %s (%s)", "enviado" if ok else "falló", info)
        if not ok:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
