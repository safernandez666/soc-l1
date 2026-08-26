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
import json
import logging
import os
import smtplib
import sqlite3
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from email.charset import QP, Charset
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid, parseaddr
from html import escape
from pathlib import Path

import requests
import urllib3

# Permitir importar src/ desde scripts/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import report_theme as _theme  # noqa: E402

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --------------------------------------------------------------------------
# Configuración (todo overrideable por variable de entorno)
# --------------------------------------------------------------------------
INDEXER_URL = os.getenv("VULN_INDEXER_URL", "https://localhost:9200")
INDEXER_USER = os.getenv("VULN_INDEXER_USER", "admin")
INDEXER_PASS = os.getenv("VULN_INDEXER_PASS", "")
INDEX_PATTERN = os.getenv("VULN_INDEX_PATTERN", "wazuh-states-vulnerabilities-*")

EMAIL_CONFIG_FILE = os.getenv("VULN_EMAIL_CONFIG", "/var/ossec/etc/email-config.json")
STATE_DB = os.getenv("VULN_STATE_DB", "/opt/soc-l1/vuln_lifecycle.db")
CACHE_DIR = os.getenv("VULN_CACHE_DIR", "/opt/soc-l1/.cache")

# Snapshots semanales del reporte de cumplimiento de parches. Los escribe
# weekly_comparison.py (root); acá se leen SOLO en modo lectura para comparar
# semana contra semana. No escribimos nada en ese directorio para no romperle
# la lógica de baseline al script original.
HISTORICAL_DIR = os.getenv("VULN_HISTORICAL_DIR", "/opt/wazuh-scripts/historical")

EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_TTL_H = 12
EPSS_BATCH = 100          # CVEs por request a FIRST
EPSS_PAUSE_S = 0.25       # cortesía entre batches

# Pesos del score (mismos que el workflow n8n de referencia)
W_CVSS = float(os.getenv("VULN_W_CVSS", "5"))
W_EPSS = float(os.getenv("VULN_W_EPSS", "30"))
W_KEV = float(os.getenv("VULN_W_KEV", "20"))

EPSS_HIGH_THRESHOLD = float(os.getenv("VULN_EPSS_THRESHOLD", "0.5"))
PRIORITY_THRESHOLD = float(os.getenv("VULN_PRIORITY_THRESHOLD", "80"))
TOP_LIMIT = int(os.getenv("VULN_TOP_LIMIT", "15"))

ORG_NAME = os.getenv("VULN_ORG_NAME", "Grupo Alemana")

logger = logging.getLogger("vuln_priority")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------
# 1. Inventario desde el indexer
# --------------------------------------------------------------------------
def fetch_inventory(session: requests.Session) -> list[dict]:
    """Trae el inventario completo vía scroll API y lo normaliza."""
    findings: list[dict] = []
    url = f"{INDEXER_URL}/{INDEX_PATTERN}/_search?scroll=3m"
    body = {"size": 1000, "query": {"match_all": {}}, "track_total_hits": True}

    resp = session.post(url, json=body, timeout=90)
    resp.raise_for_status()
    payload = resp.json()
    total = payload.get("hits", {}).get("total", {}).get("value", 0)
    scroll_id = payload.get("_scroll_id")
    logger.info("Inventario: %s hallazgos reportados por el indexer", total)

    while True:
        hits = payload.get("hits", {}).get("hits", [])
        if not hits:
            break
        findings.extend(_normalize(h) for h in hits)
        resp = session.post(
            f"{INDEXER_URL}/_search/scroll",
            json={"scroll": "3m", "scroll_id": scroll_id},
            timeout=90,
        )
        resp.raise_for_status()
        payload = resp.json()
        scroll_id = payload.get("_scroll_id", scroll_id)

    if scroll_id:
        try:
            session.delete(
                f"{INDEXER_URL}/_search/scroll",
                json={"scroll_id": [scroll_id]},
                timeout=30,
            )
        except requests.RequestException:
            pass

    logger.info("Inventario: %s hallazgos normalizados", len(findings))
    return findings


def _normalize(hit: dict) -> dict:
    src = hit.get("_source", {}) or {}
    vuln = src.get("vulnerability", {}) or {}
    pkg = src.get("package", {}) or {}
    agent = src.get("agent", {}) or {}
    score = vuln.get("score", {}) or {}
    return {
        "finding_key": hit.get("_id")
        or "|".join([agent.get("id", ""), vuln.get("id", ""), pkg.get("name", ""), pkg.get("version", "")]),
        "cve": (vuln.get("id") or "").strip().upper(),
        "agent_id": agent.get("id", ""),
        "agent_name": agent.get("name", ""),
        "package_name": pkg.get("name", ""),
        "package_version": pkg.get("version", ""),
        "severity": vuln.get("severity") or "Unknown",
        "cvss_score": float(score.get("base") or 0),
        "detected_at": vuln.get("detected_at") or src.get("@timestamp") or _now_iso(),
        "published_at": vuln.get("published_at") or "",
        "description": vuln.get("description") or "",
        "reference": vuln.get("reference") or "",
    }


# --------------------------------------------------------------------------
# 2. Enriquecimiento: EPSS + CISA KEV
# --------------------------------------------------------------------------
def fetch_epss(cves: list[str]) -> dict[str, dict]:
    """Consulta EPSS en lotes. Solo viajan identificadores CVE, ningún dato del parque."""
    out: dict[str, dict] = {}
    valid = sorted({c for c in cves if c.startswith("CVE-")})
    batches = [valid[i : i + EPSS_BATCH] for i in range(0, len(valid), EPSS_BATCH)]
    logger.info("EPSS: %s CVEs únicos en %s lotes", len(valid), len(batches))

    for i, batch in enumerate(batches, 1):
        for attempt in range(3):
            try:
                r = requests.get(
                    EPSS_API, params={"cve": ",".join(batch)}, timeout=30
                )
                r.raise_for_status()
                for entry in r.json().get("data", []):
                    cve = (entry.get("cve") or "").upper()
                    if cve:
                        out[cve] = {
                            "epss": float(entry.get("epss") or 0),
                            "percentile": float(entry.get("percentile") or 0),
                            "date": entry.get("date"),
                        }
                break
            except (requests.RequestException, ValueError) as exc:
                if attempt == 2:
                    logger.warning("EPSS lote %s falló tras 3 intentos: %s", i, exc)
                else:
                    time.sleep(2 * (attempt + 1))
        time.sleep(EPSS_PAUSE_S)

    logger.info("EPSS: %s CVEs con score", len(out))
    return out


def fetch_kev() -> dict[str, dict]:
    """Descarga el catálogo CISA KEV (cacheado en disco por KEV_CACHE_TTL_H horas)."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache = os.path.join(CACHE_DIR, "cisa_kev.json")

    if os.path.exists(cache):
        age_h = (time.time() - os.path.getmtime(cache)) / 3600
        if age_h < KEV_CACHE_TTL_H:
            try:
                with open(cache, encoding="utf-8") as fh:
                    data = json.load(fh)
                logger.info("KEV: usando caché (%.1f h)", age_h)
                return _index_kev(data)
            except (OSError, ValueError):
                pass

    try:
        r = requests.get(KEV_URL, timeout=60)
        r.raise_for_status()
        data = r.json()
        with open(cache, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
    except (requests.RequestException, ValueError, OSError) as exc:
        logger.warning("KEV: no se pudo descargar (%s), intento caché vieja", exc)
        if os.path.exists(cache):
            with open(cache, encoding="utf-8") as fh:
                data = json.load(fh)
        else:
            return {}

    return _index_kev(data)


def _index_kev(data: dict) -> dict[str, dict]:
    out = {}
    for entry in data.get("vulnerabilities", []):
        cve = (entry.get("cveID") or "").upper()
        if cve:
            out[cve] = {
                "vendor": entry.get("vendorProject"),
                "product": entry.get("product"),
                "name": entry.get("vulnerabilityName"),
                "date_added": entry.get("dateAdded"),
                "due_date": entry.get("dueDate"),
                "ransomware": entry.get("knownRansomwareCampaignUse"),
                "required_action": entry.get("requiredAction"),
            }
    logger.info("KEV: %s CVEs en el catálogo", len(out))
    return out


# --------------------------------------------------------------------------
# 3. Scoring
# --------------------------------------------------------------------------
def apply_threat_intel(
    findings: list[dict], epss: dict[str, dict], kev: dict[str, dict]
) -> list[dict]:
    for f in findings:
        e = epss.get(f["cve"], {})
        k = kev.get(f["cve"])
        epss_score = float(e.get("epss", 0))
        f["epss_score"] = epss_score
        f["epss_percentile"] = float(e.get("percentile", 0))
        f["cisa_kev"] = bool(k)
        f["kev"] = k
        f["kev_ransomware"] = bool(k and str(k.get("ransomware", "")).lower() == "known")
        f["priority_score"] = min(
            100.0,
            round(f["cvss_score"] * W_CVSS + epss_score * W_EPSS + (W_KEV if k else 0), 1),
        )
    return findings


# --------------------------------------------------------------------------
# 4. Ciclo de vida en SQLite
# --------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS vuln_lifecycle (
    finding_key      TEXT PRIMARY KEY,
    cve              TEXT,
    agent_id         TEXT,
    agent_name       TEXT,
    package_name     TEXT,
    package_version  TEXT,
    severity         TEXT,
    cvss_score       REAL,
    epss_score       REAL,
    cisa_kev         INTEGER,
    priority_score   REAL,
    lifecycle_status TEXT,
    first_seen_at    TEXT,
    last_seen_at     TEXT,
    resolved_at      TEXT,
    detection_count  INTEGER,
    context_object   TEXT
);
CREATE INDEX IF NOT EXISTS idx_lifecycle_cve ON vuln_lifecycle(cve);
CREATE INDEX IF NOT EXISTS idx_lifecycle_status ON vuln_lifecycle(lifecycle_status);

CREATE TABLE IF NOT EXISTS vuln_runs (
    run_id          TEXT PRIMARY KEY,
    started_at      TEXT,
    completed_at    TEXT,
    run_status      TEXT,
    total_active    INTEGER,
    new_count       INTEGER,
    ongoing_count   INTEGER,
    resolved_count  INTEGER,
    critical_count  INTEGER,
    high_count      INTEGER,
    summary_object  TEXT
);
"""


def open_state(path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def compute_lifecycle(conn: sqlite3.Connection, current: list[dict]) -> tuple[list[dict], bool]:
    """Clasifica cada hallazgo en new / ongoing / reopened, y marca resueltos.

    Devuelve (filas, es_baseline).
    """
    previous = {
        row["finding_key"]: dict(row)
        for row in conn.execute("SELECT * FROM vuln_lifecycle")
    }
    baseline = not previous
    now = _now_iso()
    rows: list[dict] = []
    seen: set[str] = set()

    for f in current:
        old = previous.get(f["finding_key"])
        seen.add(f["finding_key"])
        if not old:
            status = "new"
        elif old["lifecycle_status"] == "resolved":
            status = "reopened"
        else:
            status = "ongoing"
        rows.append(
            {
                **f,
                "lifecycle_status": status,
                "first_seen_at": (old or {}).get("first_seen_at") or f.get("detected_at") or now,
                "last_seen_at": now,
                "resolved_at": None,
                "detection_count": int((old or {}).get("detection_count") or 0) + 1,
            }
        )

    for key, old in previous.items():
        if key not in seen and old["lifecycle_status"] != "resolved":
            rows.append(
                {
                    **old,
                    "cisa_kev": bool(old["cisa_kev"]),
                    "kev": None,
                    "kev_ransomware": False,
                    "lifecycle_status": "resolved",
                    "last_seen_at": old["last_seen_at"] or now,
                    "resolved_at": now,
                }
            )

    return rows, baseline


def persist_lifecycle(conn: sqlite3.Connection, rows: list[dict]) -> None:
    conn.executemany(
        """
        INSERT INTO vuln_lifecycle (
            finding_key, cve, agent_id, agent_name, package_name, package_version,
            severity, cvss_score, epss_score, cisa_kev, priority_score,
            lifecycle_status, first_seen_at, last_seen_at, resolved_at,
            detection_count, context_object
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(finding_key) DO UPDATE SET
            severity=excluded.severity,
            cvss_score=excluded.cvss_score,
            epss_score=excluded.epss_score,
            cisa_kev=excluded.cisa_kev,
            priority_score=excluded.priority_score,
            lifecycle_status=excluded.lifecycle_status,
            last_seen_at=excluded.last_seen_at,
            resolved_at=excluded.resolved_at,
            detection_count=excluded.detection_count,
            context_object=excluded.context_object
        """,
        [
            (
                r["finding_key"], r.get("cve"), r.get("agent_id"), r.get("agent_name"),
                r.get("package_name"), r.get("package_version"), r.get("severity"),
                float(r.get("cvss_score") or 0), float(r.get("epss_score") or 0),
                1 if r.get("cisa_kev") else 0, float(r.get("priority_score") or 0),
                r["lifecycle_status"], r.get("first_seen_at"), r.get("last_seen_at"),
                r.get("resolved_at"), int(r.get("detection_count") or 1),
                json.dumps(
                    {
                        "epss_percentile": r.get("epss_percentile"),
                        "kev": r.get("kev"),
                        "formula": f"CVSSx{W_CVSS:g} + EPSSx{W_EPSS:g} + KEVx{W_KEV:g}",
                    },
                    ensure_ascii=False,
                ),
            )
            for r in rows
        ],
    )
    conn.commit()


def build_summary(rows: list[dict], baseline: bool) -> dict:
    active = [r for r in rows if r["lifecycle_status"] != "resolved"]
    count = lambda st: sum(1 for r in rows if r["lifecycle_status"] == st)  # noqa: E731
    sev = lambda lv: sum(1 for r in active if str(r.get("severity", "")).lower() == lv)  # noqa: E731
    now = _now_iso()
    return {
        "run_id": f"wazuh-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "started_at": now,
        "completed_at": now,
        "run_status": "baseline" if baseline else "completed",
        "baseline": baseline,
        "total_active": len(active),
        "new_count": count("new"),
        "ongoing_count": count("ongoing"),
        "reopened_count": count("reopened"),
        "resolved_count": count("resolved"),
        "critical_count": sev("critical"),
        "high_count": sev("high"),
        "kev_count": sum(1 for r in active if r.get("cisa_kev")),
        "kev_ransomware_count": sum(1 for r in active if r.get("kev_ransomware")),
        "epss_high_count": sum(1 for r in active if float(r.get("epss_score") or 0) >= EPSS_HIGH_THRESHOLD),
        "priority_high_count": sum(1 for r in active if float(r.get("priority_score") or 0) >= PRIORITY_THRESHOLD),
        "hosts_affected": len({r.get("agent_name") for r in active if r.get("agent_name")}),
    }


def persist_run(conn: sqlite3.Connection, summary: dict) -> None:
    conn.execute(
        """INSERT OR REPLACE INTO vuln_runs (run_id, started_at, completed_at, run_status,
           total_active, new_count, ongoing_count, resolved_count, critical_count,
           high_count, summary_object) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (
            summary["run_id"], summary["started_at"], summary["completed_at"],
            summary["run_status"], summary["total_active"], summary["new_count"],
            summary["ongoing_count"] + summary["reopened_count"], summary["resolved_count"],
            summary["critical_count"], summary["high_count"],
            json.dumps(summary, ensure_ascii=False),
        ),
    )
    conn.commit()


# --------------------------------------------------------------------------
# 5. Agrupación por CVE (lo que le sirve al cliente para accionar)
# --------------------------------------------------------------------------
def group_by_cve(active: list[dict]) -> list[dict]:
    groups: dict[str, dict] = {}
    hosts: dict[str, set] = defaultdict(set)
    pkgs: dict[str, set] = defaultdict(set)

    for r in active:
        cve = r.get("cve") or "SIN-CVE"
        hosts[cve].add(r.get("agent_name") or r.get("agent_id"))
        if r.get("package_name"):
            pkgs[cve].add(r["package_name"])
        g = groups.get(cve)
        if not g or float(r.get("priority_score") or 0) > float(g.get("priority_score") or 0):
            groups[cve] = dict(r)

    out = []
    for cve, g in groups.items():
        g["hosts_count"] = len(hosts[cve])
        g["hosts_list"] = sorted(h for h in hosts[cve] if h)
        g["packages"] = sorted(pkgs[cve])[:3]
        g["is_new_group"] = g.get("lifecycle_status") in ("new", "reopened")
        out.append(g)

    out.sort(
        key=lambda g: (
            g["priority_score"],
            g["epss_score"],
            g["hosts_count"],
        ),
        reverse=True,
    )
    return out


# --------------------------------------------------------------------------
# 5a. Calidad del dato: ¿el inventario refleja el estado real del parque?
# --------------------------------------------------------------------------
def fetch_agent_os_versions() -> dict[str, str]:
    """Build de SO que reporta hoy cada agente, según la API de Wazuh.

    Falla en silencio (devuelve {}) para no tumbar el reporte si la API no está:
    sin este dato el reporte sale igual, solo que sin el aviso de calidad.
    """
    try:
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
            f"{base}/agents?limit=1000&select=id,name,status,os.version",
            headers={"Authorization": f"Bearer {tok}"}, verify=False, timeout=25,
        )
        r.raise_for_status()
        return {
            a["name"]: (a.get("os") or {}).get("version", "")
            for a in r.json()["data"]["affected_items"]
            if a.get("name") and str(a.get("id")) != "000"
        }
    except Exception as exc:  # noqa: BLE001 - fail-open deliberado
        logger.warning("No se pudo consultar la API de Wazuh para calidad de dato: %s", exc)
        return {}


def assess_coverage(active: list[dict], agent_os: dict[str, str]) -> dict:
    """Compara el build de SO indexado contra el que reporta el agente hoy.

    Dos problemas distintos, ambos hacen que el total del reporte no sea el estado real:

      - DESFASADO: el índice tiene un build viejo y el host ya se parcheó. Sus
        hallazgos siguen contando aunque probablemente ya estén resueltos.
      - SIN DATOS: el agente está activo pero el detector no generó ningún hallazgo,
        así que el host no aparece y parece limpio.

    Detectado el 2026-08-17: 4 hosts desfasados (2.632 hallazgos, 21% del total) y
    8 con cobertura nula o parcial. Los datos de entrada (paquetes, hotfixes, build)
    estaban completos, así que es el detector de Wazuh el que no re-evalúa.
    """
    if not agent_os:
        return {"disponible": False, "desfasados": [], "sin_datos": [], "hallazgos_dudosos": 0}

    # Build de SO que quedó indexado por host, y cuántos hallazgos tiene cada uno.
    os_indexado: dict[str, str] = {}
    por_host: dict[str, int] = defaultdict(int)
    for r in active:
        host = r.get("agent_name")
        if not host:
            continue
        por_host[host] += 1
        # Los hallazgos de SO traen el build en package.version.
        pkg = r.get("package_name") or ""
        if "Windows" in pkg and host not in os_indexado:
            ver = r.get("package_version") or ""
            if ver:
                os_indexado[host] = ver

    desfasados = []
    for host, indexado in os_indexado.items():
        actual = agent_os.get(host)
        if actual and indexado and actual != indexado:
            desfasados.append({
                "host": host, "indexado": indexado, "actual": actual,
                "hallazgos": por_host.get(host, 0),
            })
    desfasados.sort(key=lambda d: -d["hallazgos"])

    sin_datos = sorted(h for h in agent_os if por_host.get(h, 0) == 0)

    return {
        "disponible": True,
        "desfasados": desfasados,
        "sin_datos": sin_datos,
        "hallazgos_dudosos": sum(d["hallazgos"] for d in desfasados),
    }


# --------------------------------------------------------------------------
# 5b. Cumplimiento de parches por host (los datos del reporte semanal original)
# --------------------------------------------------------------------------
SEVERITIES = ("Critical", "High", "Medium", "Low")


_SEV_RANK = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


def compute_host_counts(active: list[dict]) -> dict[str, dict]:
    """Conteo por host y severidad, contando CVEs DISTINTOS por host.

    Esto es deliberado: weekly_comparison.py agrega por `vulnerability.id` y suma
    1 por CVE, así que un mismo CVE que afecta a varios paquetes del host cuenta
    una sola vez. Si acá contáramos hallazgos, los números saldrían inflados y el
    delta contra sus snapshots sería basura (todos los hosts "empeorarían").
    """
    per_host: dict[str, dict[str, str]] = defaultdict(dict)
    for r in active:
        host = r.get("agent_name") or r.get("agent_id") or "desconocido"
        cve = r.get("cve") or ""
        if not cve:
            continue
        sev = str(r.get("severity", "")).capitalize()
        if sev not in _SEV_RANK:
            continue
        prev = per_host[host].get(cve)
        # Ante severidades distintas para el mismo CVE en el host, gana la más alta.
        if prev is None or _SEV_RANK[sev] > _SEV_RANK[prev]:
            per_host[host][cve] = sev

    counts: dict[str, dict] = {}
    for host, cves in per_host.items():
        bucket = dict.fromkeys(SEVERITIES, 0)
        for sev in cves.values():
            bucket[sev] += 1
        counts[host] = bucket
    return counts


def load_previous_snapshot(directory: str = HISTORICAL_DIR) -> tuple[dict, str]:
    """Carga el snapshot más reciente que no sea de hoy. Devuelve ({}, '') si no hay."""
    import glob

    today = datetime.now().strftime("%Y%m%d")
    candidates = [
        f
        for f in glob.glob(os.path.join(directory, "snapshot_*.csv"))
        if not os.path.basename(f).startswith(f"snapshot_{today}")
    ]
    if not candidates:
        logger.info("Cumplimiento: no hay snapshot anterior para comparar")
        return {}, ""

    latest = max(candidates, key=os.path.getmtime)
    data: dict[str, dict] = {}
    try:
        with open(latest, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("Host,"):
                    continue
                parts = line.split(",")
                if len(parts) >= 5:
                    try:
                        data[parts[0]] = {
                            "Critical": int(parts[1]),
                            "High": int(parts[2]),
                            "Medium": int(parts[3]),
                            "Low": int(parts[4]),
                        }
                    except ValueError:
                        continue
    except OSError as exc:
        logger.warning("Cumplimiento: no se pudo leer %s: %s", latest, exc)
        return {}, ""

    logger.info("Cumplimiento: comparando contra %s (%s hosts)", os.path.basename(latest), len(data))
    return data, latest


def save_snapshot(counts: dict[str, dict], directory: str = HISTORICAL_DIR) -> str:
    """Escribe el snapshot semanal, en el mismo formato que weekly_comparison.py.

    Hasta el 2026-08-17 esto lo hacía el script viejo y acá solo se leía. Al
    desactivarlo en el cutover nadie escribía más snapshots, así que la
    comparativa semana contra semana se habría congelado en la última que
    dejó el script viejo. El formato se mantiene idéntico para que ambos
    scripts puedan leer los archivos del otro si hiciera falta revertir.
    """
    if not counts:
        return ""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(directory, f"snapshot_{ts}.csv")
    try:
        os.makedirs(directory, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"# Snapshot generado: {datetime.now().isoformat()}\n")
            fh.write(f"# Total hosts: {len(counts)}\n")
            fh.write("Host,Critical,High,Medium,Low,Total\n")
            for host in sorted(counts):
                v = counts[host]
                total = v["Critical"] + v["High"] + v["Medium"] + v["Low"]
                fh.write(
                    f"{host},{v['Critical']},{v['High']},{v['Medium']},{v['Low']},{total}\n"
                )
    except OSError as exc:
        logger.warning("No se pudo escribir el snapshot en %s: %s", path, exc)
        return ""
    logger.info("Snapshot guardado: %s (%s hosts)", os.path.basename(path), len(counts))
    return path


def compare_hosts(current: dict[str, dict], previous: dict[str, dict]) -> dict:
    """Compara conteos por host. El foco es Critical+High, igual que el reporte original."""
    zero = dict.fromkeys(SEVERITIES, 0)
    rows = []
    for host in sorted(set(current) | set(previous)):
        cur = current.get(host, zero)
        prev = previous.get(host, zero)
        cur_ch = cur["Critical"] + cur["High"]
        prev_ch = prev["Critical"] + prev["High"]
        delta = cur_ch - prev_ch
        rows.append(
            {
                "host": host,
                "critical_now": cur["Critical"], "high_now": cur["High"],
                "medium_now": cur["Medium"], "low_now": cur["Low"],
                "critical_before": prev["Critical"], "high_before": prev["High"],
                "critical_delta": cur["Critical"] - prev["Critical"],
                "high_delta": cur["High"] - prev["High"],
                "total_delta": delta,
                "percent_change": (delta / prev_ch * 100) if prev_ch else 0.0,
                "trend": "improved" if delta < 0 else "worsened" if delta > 0 else "stable",
                "is_new": host not in previous,
                "was_removed": host not in current,
            }
        )

    # Un host que dejó de reportar aparecería como "mejoró a 0", que es falso:
    # el agente se cayó o lo dieron de baja, no lo parchearon. Va aparte y no
    # entra en el SLA. (El script semanal original sí lo cuenta como mejora.)
    removed = [r for r in rows if r["was_removed"]]
    tracked = [r for r in rows if not r["is_new"] and not r["was_removed"]] or rows
    improved = sum(1 for r in tracked if r["trend"] == "improved")
    return {
        "rows": rows,
        "total_hosts": len([r for r in rows if not r["was_removed"]]),
        "improved": improved,
        "worsened": sum(1 for r in tracked if r["trend"] == "worsened"),
        "stable": sum(1 for r in tracked if r["trend"] == "stable"),
        "new_hosts": sum(1 for r in rows if r["is_new"]),
        "removed_hosts": [r["host"] for r in removed],
        "critical_now": sum(r["critical_now"] for r in rows if not r["was_removed"]),
        "high_now": sum(r["high_now"] for r in rows if not r["was_removed"]),
        "medium_now": sum(r["medium_now"] for r in rows if not r["was_removed"]),
        "low_now": sum(r["low_now"] for r in rows if not r["was_removed"]),
        "critical_delta": sum(r["critical_delta"] for r in rows if not r["is_new"] and not r["was_removed"]),
        "high_delta": sum(r["high_delta"] for r in rows if not r["is_new"] and not r["was_removed"]),
        "sla": (improved / len(tracked) * 100) if tracked else 0.0,
        "has_previous": bool(previous),
    }


# --------------------------------------------------------------------------
# 6. Render HTML
# --------------------------------------------------------------------------
# El diseño NO depende de este bloque: todo el layout va en <table> con CSS
# inline (Outlook 2016 / Exchange renderiza con el motor de Word e ignora buena
# parte de un <style>). Esto es solo refuerzo progresivo para los clientes que
# sí lo soportan (webmail, Apple Mail, móviles).
# Sistema de diseño compartido. Ver src/report_theme.py para las restricciones
# de Outlook y las señales antispam que hay que evitar.
CSS = _theme.CSS
FONT = _theme.FONT
C_GREEN, C_GREEN_DK = _theme.C_GREEN, _theme.C_GREEN_DK
C_CRIT, C_HIGH, C_MED = _theme.C_CRIT, _theme.C_HIGH, _theme.C_MED
C_MUTED, C_TEXT, C_BORDER, C_BG = _theme.C_MUTED, _theme.C_TEXT, _theme.C_BORDER, _theme.C_BG

_sev_color = _theme.sev_color
_num = _theme.num
_badge = _theme.badge
_metric_card = _theme.metric_card
_delta_badge = _theme.delta_badge



def render_coverage_notice(cov: dict) -> str:
    """Aviso de calidad del dato, arriba de todo: condiciona la lectura del resto."""
    if not cov.get("disponible"):
        return ""
    desf, sin = cov["desfasados"], cov["sin_datos"]
    if not desf and not sin:
        return ""

    partes = []
    if desf:
        detalle = "; ".join(
            f"{escape(d['host'])} (indexado {escape(d['indexado'])} &rarr; real "
            f"{escape(d['actual'])}, {_num(d['hallazgos'])} hallazgos)"
            for d in desf[:6]
        )
        partes.append(
            f"<strong>{len(desf)} host(s) con inventario desfasado.</strong> El detector de "
            f"vulnerabilidades conserva un build de sistema operativo anterior al que el "
            f"agente reporta hoy, as&iacute; que sus <strong>{_num(cov['hallazgos_dudosos'])} "
            f"hallazgos</strong> pueden estar ya parcheados: {detalle}."
        )
    if sin:
        partes.append(
            f"<strong>{len(sin)} host(s) sin ning&uacute;n hallazgo.</strong> Los agentes est&aacute;n "
            f"activos y reportan paquetes y hotfixes, pero el detector no genera datos para ellos, "
            f"as&iacute; que no aparecen en este reporte: {escape(', '.join(sin[:10]))}."
        )
    partes.append(
        "En ambos casos el problema est&aacute; en el detector de Wazuh, no en los datos que env&iacute;an "
        "los agentes. Los totales de abajo deben leerse con esa salvedad."
    )

    return _theme.section(
        "Aviso sobre la calidad de los datos",
        "Leer antes que los n&uacute;meros",
        _theme.notice(
            "<br><br>".join(partes), accent=_theme.C_HIGH, bg="#fff8e6"
        ),
    )


def render_compliance_fragment(comp: dict, prev_file: str, host_limit: int = 12) -> str:
    """Sección de cumplimiento de parches por host (datos del reporte semanal original)."""
    if not comp["has_previous"]:
        prev_label = "sin semana anterior para comparar"
    else:
        base = os.path.basename(prev_file).replace("snapshot_", "")[:8]
        try:
            prev_label = "vs. " + datetime.strptime(base, "%Y%m%d").strftime("%d/%m/%Y")
        except ValueError:
            prev_label = "vs. semana anterior"

    sla = comp["sla"]
    sla_color = C_GREEN if sla >= 80 else C_HIGH if sla >= 60 else C_CRIT
    sla_text = "Cumpliendo" if sla >= 80 else "Cerca del objetivo" if sla >= 60 else "Acci&oacute;n requerida"

    cards = [
        _metric_card("HOSTS MONITOREADOS", _num(comp["total_hosts"]), C_TEXT,
                     f"+{comp['new_hosts']} nuevos" if comp["new_hosts"] else "sin altas nuevas"),
        _metric_card("CR&Iacute;TICAS", _num(comp["critical_now"]), C_CRIT,
                     f"{_delta_badge(comp['critical_delta'])} vs. anterior"),
        _metric_card("ALTAS", _num(comp["high_now"]), C_HIGH,
                     f"{_delta_badge(comp['high_delta'])} vs. anterior"),
        _metric_card("MEDIAS / BAJAS", _num(comp["medium_now"] + comp["low_now"]), C_MUTED,
                     f"M: {_num(comp['medium_now'])} &middot; B: {_num(comp['low_now'])}"),
        _metric_card("SLA DE PARCHEO", f"{sla:.0f}%", sla_color,
                     f"{sla_text} &middot; {comp['improved']} mejoraron, {comp['worsened']} empeoraron"),
    ]

    gone = comp.get("removed_hosts") or []
    gone_note = ""
    if gone:
        lista = escape(", ".join(gone))
        gone_note = f"""
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#fff8e6" style="background-color:#fff8e6;border-left:4px solid {C_HIGH};border-collapse:separate;border-radius:8px;">
        <tr>
          <td style="padding:10px 12px;font-family:{FONT};font-size:12px;line-height:17px;color:{C_TEXT};">
            <strong>Dej&oacute; de reportar:</strong> {lista}.
            No se cuenta como mejora ni entra en el SLA &mdash; un agente que no reporta no es un host parcheado.
            Conviene verificar el estado del agente Wazuh en ese equipo.
          </td>
        </tr>
      </table>"""

    parts = [f"""
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#ffffff" style="background-color:#ffffff;border:1px solid {C_BORDER};border-collapse:separate;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,0.06);">
  <tr>
    <td style="padding:20px 22px;font-family:{FONT};">
      <div style="font-family:{FONT};font-size:15px;line-height:20px;font-weight:bold;color:{_theme.C_INK};padding-bottom:3px;">Cumplimiento de parches por host</div>
      <div style="font-family:{FONT};font-size:12px;line-height:17px;color:{C_MUTED};padding-bottom:16px;">Evoluci&oacute;n semana contra semana &middot; {prev_label}</div>
{gone_note}
{_theme.metric_row(cards)}
    </td>
  </tr>
</table>
"""]

    # Hosts con mayor movimiento: primero los que empeoraron (accionables), luego los que mejoraron.
    movers = [r for r in comp["rows"] if r["trend"] != "stable" and not r["was_removed"]]
    movers.sort(key=lambda r: (r["trend"] != "worsened", -abs(r["total_delta"])))
    movers = movers[:host_limit]

    if movers:
        th = f"font-family:{FONT};font-size:11px;font-weight:bold;color:#ffffff;padding:10px 9px;letter-spacing:0.3px;text-align:left;"
        td_base = (
            f"font-family:{FONT};font-size:12px;line-height:18px;color:{C_TEXT};"
            f"padding:9px 9px;border-bottom:1px solid {_theme.C_SOFT};vertical-align:top;"
        )
        parts.append(f"""
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#ffffff" style="background-color:#ffffff;border:1px solid {C_BORDER};border-collapse:separate;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,0.06);">
  <tr>
    <td style="padding:20px 22px;font-family:{FONT};">
      <div style="font-family:{FONT};font-size:15px;line-height:20px;font-weight:bold;color:{_theme.C_INK};padding-bottom:3px;">Hosts con mayor movimiento</div>
      <div style="font-family:{FONT};font-size:12px;color:{C_MUTED};padding-bottom:12px;">Cr&iacute;ticas + altas, respecto de la semana anterior</div>
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
        <tr bgcolor="{C_GREEN}" style="background-color:{C_GREEN};">
          <th align="left" style="{th}">Host</th>
          <th width="96" align="center" style="{th}text-align:center;">Cr&iacute;ticas</th>
          <th width="96" align="center" style="{th}text-align:center;">Altas</th>
          <th width="76" align="center" style="{th}text-align:center;">Variaci&oacute;n</th>
          <th width="86" align="center" style="{th}text-align:center;">Estado</th>
        </tr>
""")
        for i, r in enumerate(movers, 1):
            row_bg = "#ffffff" if i % 2 else "#fafbfc"
            if r["trend"] == "improved":
                estado = _badge("MEJOR&Oacute;", "#d4edda", "#155724", "#b7dfc2")
            else:
                estado = _badge("EMPEOR&Oacute;", "#f8d7da", "#721c24", "#f1b7bd")
            nuevo = "<br>" + _badge("NUEVO", "#fff3cd", "#856404", "#ffe6a1") if r["is_new"] else ""
            parts.append(f"""
        <tr bgcolor="{row_bg}" style="background-color:{row_bg};">
          <td style="{td_base}font-weight:bold;">{escape(r['host'])}{nuevo}</td>
          <td align="center" style="{td_base}text-align:center;">{r['critical_before']} &rarr; <strong style="color:{C_CRIT};">{r['critical_now']}</strong></td>
          <td align="center" style="{td_base}text-align:center;">{r['high_before']} &rarr; <strong style="color:{C_HIGH};">{r['high_now']}</strong></td>
          <td align="center" style="{td_base}text-align:center;">{_delta_badge(r['total_delta'])}</td>
          <td align="center" style="{td_base}text-align:center;">{estado}</td>
        </tr>
""")
        parts.append("""
      </table>
    </td>
  </tr>
</table>
""")
    return _theme.spacer(16).join(parts)


def render_fragment(summary: dict, groups: list[dict], top_limit: int = TOP_LIMIT) -> str:
    """Sección HTML de priorización (embebible en el reporte semanal).

    Layout 100% con tablas anidadas y CSS inline: el destinatario lee en
    Outlook 2016 / Exchange (motor de Word), que no soporta grid ni flex e
    ignora buena parte del <style> del head.
    """
    top = groups[:top_limit]
    parts: list[str] = []

    baseline_note = ""
    if summary.get("baseline"):
        baseline_note = f"""
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#f4f6f8" style="background-color:{C_BG};border-left:4px solid {C_MUTED};border-collapse:separate;border-radius:8px;">
        <tr>
          <td style="padding:10px 12px;font-family:{FONT};font-size:12px;line-height:17px;color:{C_MUTED};">
            <strong style="color:{C_TEXT};">Primera corrida:</strong> se estableci&oacute; la l&iacute;nea base.
            El comparativo de ciclo de vida (nuevas / resueltas / reabiertas) arranca la pr&oacute;xima semana.
          </td>
        </tr>
      </table>
"""

    # ---- Sección 1: métricas ejecutivas -----------------------------------
    # 5 métricas sin grid: tabla de 3 columnas, 2 filas; la última tarjeta
    # ocupa 2 columnas (colspan) para no dejar hueco y para que entren los
    # tres números del ciclo de vida en una línea.
    cards = [
        _metric_card(
            "EXPLOTADAS IN-THE-WILD",
            _num(summary["kev_count"]),
            C_CRIT,
            "hallazgos en cat&aacute;logo CISA KEV",
        ),
        _metric_card(
            "USADAS POR RANSOMWARE",
            _num(summary["kev_ransomware_count"]),
            C_CRIT,
            "campa&ntilde;as confirmadas",
        ),
        _metric_card(
            f"EPSS &ge; {EPSS_HIGH_THRESHOLD:.0%}",
            _num(summary["epss_high_count"]),
            C_HIGH,
            "alta prob. de explotaci&oacute;n a 30 d&iacute;as",
        ),
        _metric_card(
            f"PRIORIDAD &ge; {PRIORITY_THRESHOLD:.0f}",
            _num(summary["priority_high_count"]),
            C_HIGH,
            f"de {_num(summary['total_active'])} hallazgos activos",
        ),
        _metric_card(
            "CICLO DE VIDA",
            _num(summary["resolved_count"]),
            C_GREEN,
            f"resueltas &middot; {_num(summary['new_count'])} nuevas "
            f"&middot; {_num(summary['reopened_count'])} reabiertas",
        ),
    ]

    parts.append(f"""
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#ffffff" style="background-color:#ffffff;border:1px solid {C_BORDER};border-collapse:separate;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,0.06);">
  <tr>
    <td style="padding:20px 22px;font-family:{FONT};">
      <div style="font-family:{FONT};font-size:15px;line-height:20px;font-weight:bold;color:{_theme.C_INK};padding-bottom:3px;">Priorizaci&oacute;n por explotabilidad real</div>
      <div style="font-family:{FONT};font-size:12px;line-height:17px;color:{C_MUTED};padding-bottom:16px;">EPSS (FIRST.org) + cat&aacute;logo CISA KEV</div>
{baseline_note}
{_theme.metric_row(cards)}
    </td>
  </tr>
</table>
""")

    # ---- Sección 2: tabla Top N -------------------------------------------
    th = (
        f"font-family:{FONT};font-size:11px;font-weight:bold;color:#ffffff;"
        f"padding:8px 5px;text-align:left;"
    )
    parts.append(f"""
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#ffffff" style="background-color:#ffffff;border:1px solid {C_BORDER};border-collapse:separate;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,0.06);">
  <tr>
    <td style="padding:20px 22px;font-family:{FONT};">
      <div style="font-family:{FONT};font-size:15px;line-height:20px;font-weight:bold;color:{_theme.C_INK};padding-bottom:3px;">Top {len(top)} CVEs a parchear primero</div>
      <div style="font-family:{FONT};font-size:12px;color:{C_MUTED};padding-bottom:12px;">Ordenados por score de prioridad, de mayor a menor</div>
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
        <tr bgcolor="{C_GREEN}" style="background-color:{C_GREEN};">
          <th width="18" align="left" style="{th}">#</th>
          <th width="104" align="left" style="{th}">CVE</th>
          <th width="52" align="left" style="{th}">Sev.</th>
          <th width="34" align="right" style="{th}text-align:right;">CVSS</th>
          <th width="46" align="right" style="{th}text-align:right;">EPSS</th>
          <th width="76" align="center" style="{th}text-align:center;">KEV</th>
          <th width="36" align="right" style="{th}text-align:right;">Hosts</th>
          <th width="52" align="right" style="{th}text-align:right;">Prior.</th>
          <th align="left" style="{th}">Producto afectado</th>
        </tr>
""")

    td_base = (
        f"font-family:{FONT};font-size:12px;line-height:16px;color:{C_TEXT};"
        f"padding:7px 5px;border-bottom:1px solid #eef2f5;vertical-align:top;"
    )

    for i, g in enumerate(top, 1):
        kev_badge = f'<span style="color:{C_MUTED};">&mdash;</span>'
        if g.get("kev_ransomware"):
            kev_badge = _badge("RANSOMWARE", C_CRIT, "#ffffff")
        elif g.get("cisa_kev"):
            kev_badge = _badge("KEV", "#f8d7da", "#721c24", "#f1b7bd")

        new_badge = (
            "<br>" + _badge("NUEVA", "#fff3cd", "#856404", "#ffe6a1")
            if g.get("is_new_group")
            else ""
        )
        pkgs = escape(", ".join(g.get("packages") or [])[:70]) or "&mdash;"
        hosts_tip = escape(", ".join(g.get("hosts_list", [])[:8]))
        ref = g.get("reference") or f"https://nvd.nist.gov/vuln/detail/{g['cve']}"
        prio = float(g["priority_score"])
        prio_color = C_CRIT if prio >= PRIORITY_THRESHOLD else C_TEXT
        row_bg = "#ffffff" if i % 2 else "#fafbfc"

        parts.append(f"""
        <tr bgcolor="{row_bg}" style="background-color:{row_bg};">
          <td align="left" style="{td_base}color:{C_MUTED};">{i}</td>
          <td align="left" style="{td_base}">
            <a href="{escape(ref)}" style="color:{C_GREEN_DK};font-weight:bold;text-decoration:none;">{escape(g['cve'])}</a>{new_badge}
          </td>
          <td align="left" style="{td_base}color:{_sev_color(g.get('severity'))};font-weight:bold;">{escape(str(g.get('severity','')))}</td>
          <td align="right" style="{td_base}text-align:right;">{g['cvss_score']:.1f}</td>
          <td align="right" style="{td_base}text-align:right;">{g['epss_score']*100:.2f}%</td>
          <td align="center" style="{td_base}text-align:center;">{kev_badge}</td>
          <td align="right" title="{hosts_tip}" style="{td_base}text-align:right;">{g['hosts_count']}</td>
          <td align="right" style="{td_base}text-align:right;font-weight:bold;color:{prio_color};">{prio:.1f}</td>
          <td align="left" style="{td_base}color:{C_MUTED};font-size:11px;">{pkgs}</td>
        </tr>
""")

    parts.append("""
      </table>
    </td>
  </tr>
</table>
""")

    # ---- Sección 3: metodología + privacidad -------------------------------
    p = f"font-family:{FONT};font-size:12px;line-height:18px;color:{C_MUTED};margin:0;"
    parts.append(f"""
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#ffffff" style="background-color:#ffffff;border:1px solid {C_BORDER};border-collapse:separate;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,0.06);">
  <tr>
    <td style="padding:20px 22px;font-family:{FONT};">
      <div style="font-family:{FONT};font-size:14px;font-weight:bold;color:{C_TEXT};padding-bottom:10px;">C&oacute;mo leer este reporte</div>
      <p style="{p}padding-bottom:8px;">
        <strong style="color:{C_TEXT};">C&aacute;lculo de la prioridad:</strong>
        CVSS &times; {W_CVSS:g} &nbsp;+&nbsp; EPSS &times; {W_EPSS:g} &nbsp;+&nbsp; CISA&nbsp;KEV &times; {W_KEV:g}, con tope 100.
      </p>
      <p style="{p}padding-bottom:8px;">
        <strong style="color:{C_TEXT};">EPSS</strong> (FIRST.org) estima la probabilidad de que la vulnerabilidad sea
        explotada en los pr&oacute;ximos 30 d&iacute;as. Se considera alta a partir de {EPSS_HIGH_THRESHOLD:.0%}.
      </p>
      <p style="{p}padding-bottom:8px;">
        <strong style="color:{C_TEXT};">CISA KEV</strong> es el cat&aacute;logo oficial de vulnerabilidades con
        explotaci&oacute;n confirmada en ataques reales. Un CVSS 9.8 sin explotaci&oacute;n conocida corre por detr&aacute;s
        de un CVSS 7.5 que ya se est&aacute; explotando activamente.
      </p>
      <p style="{p}">
        <strong style="color:{C_TEXT};">Privacidad:</strong> hacia FIRST y CISA solo viajan identificadores CVE;
        ning&uacute;n dato de activos, paquetes ni credenciales sale del entorno.
      </p>
    </td>
  </tr>
</table>
""")
    return _theme.spacer(16).join(parts)


def render_plain_coverage(cov: dict) -> list[str]:
    """Aviso de calidad del dato para la versión texto plano."""
    if not cov.get("disponible") or (not cov["desfasados"] and not cov["sin_datos"]):
        return []
    out = ["AVISO SOBRE LA CALIDAD DE LOS DATOS", ""]
    if cov["desfasados"]:
        out.append(
            f"{len(cov['desfasados'])} host(s) con inventario desfasado: el detector conserva "
            f"un build de SO anterior al que reporta el agente, asi que sus "
            f"{cov['hallazgos_dudosos']} hallazgos pueden estar ya parcheados."
        )
        for d in cov["desfasados"][:6]:
            out.append(f"  {d['host']:<20} indexado {d['indexado']} -> real {d['actual']} ({d['hallazgos']} hallazgos)")
    if cov["sin_datos"]:
        out.append(
            f"{len(cov['sin_datos'])} host(s) sin ningun hallazgo pese a estar activos: "
            + ", ".join(cov["sin_datos"][:10])
        )
    out += ["", "El problema esta en el detector de Wazuh, no en los datos de los agentes.", ""]
    return out


def render_plain_compliance(comp: dict) -> list[str]:
    """Bloque de cumplimiento para la versión texto plano."""
    if not comp:
        return []
    out = [
        "CUMPLIMIENTO DE PARCHES POR HOST",
        "",
        f"Hosts monitoreados: {comp['total_hosts']} ({comp['new_hosts']} nuevos)",
        f"Criticas: {comp['critical_now']} ({comp['critical_delta']:+d} vs. semana anterior)",
        f"Altas: {comp['high_now']} ({comp['high_delta']:+d} vs. semana anterior)",
        f"Medias/Bajas: {comp['medium_now']} / {comp['low_now']}",
        (f"Dejo de reportar: {', '.join(comp['removed_hosts'])} "
         "(no cuenta como mejora ni entra en el SLA)" if comp.get('removed_hosts') else ""),
        f"SLA de parcheo: {comp['sla']:.0f}% "
        f"({comp['improved']} mejoraron, {comp['worsened']} empeoraron, {comp['stable']} sin cambios)",
        "",
    ]
    movers = [r for r in comp["rows"] if r["trend"] != "stable" and not r["was_removed"]]
    movers.sort(key=lambda r: (r["trend"] != "worsened", -abs(r["total_delta"])))
    if movers:
        out.append("Hosts con mayor movimiento (criticas + altas):")
        for r in movers[:12]:
            marca = "EMPEORO" if r["trend"] == "worsened" else "MEJORO"
            out.append(
                f"  {r['host']:<22} criticas {r['critical_before']}->{r['critical_now']}  "
                f"altas {r['high_before']}->{r['high_now']}  ({r['total_delta']:+d}) {marca}"
            )
        out.append("")
    return out


def render_plain(
    summary: dict,
    groups: list[dict],
    top_limit: int = TOP_LIMIT,
    comp: dict | None = None,
    cov: dict | None = None,
) -> str:
    """Versión texto plano equivalente al HTML.

    No es decorativa: si la parte text/plain no se parece a la HTML, los filtros
    antispam lo penalizan (regla clásica de "multipart alternative diferente").
    """
    fecha = datetime.now().strftime("%d/%m/%Y")
    out = [
        f"{ORG_NAME} - Gerencia Tecnologia",
        f"Reporte de vulnerabilidades y cumplimiento de parches - {fecha}",
        "",
        *render_plain_coverage(cov or {}),
        *render_plain_compliance(comp or {}),
        "PRIORIZACION POR EXPLOTABILIDAD REAL",
        "",
        f"Hallazgos activos: {summary['total_active']} en {summary['hosts_affected']} hosts",
        f"En catalogo CISA KEV: {summary['kev_count']} (ligados a ransomware: {summary['kev_ransomware_count']})",
        f"Con EPSS >= {EPSS_HIGH_THRESHOLD:.0%}: {summary['epss_high_count']}",
        f"Con prioridad >= {PRIORITY_THRESHOLD:.0f}: {summary['priority_high_count']}",
        f"Ciclo de vida: {summary['new_count']} nuevas, {summary['resolved_count']} resueltas, "
        f"{summary['reopened_count']} reabiertas",
        "",
        f"TOP {min(top_limit, len(groups))} A PARCHEAR PRIMERO",
        "",
    ]
    for i, g in enumerate(groups[:top_limit], 1):
        marca = " [KEV]" if g.get("cisa_kev") else ""
        out.append(
            f"{i:2d}. {g['cve']}{marca} | prioridad {g['priority_score']:.1f} | "
            f"CVSS {g['cvss_score']:.1f} | EPSS {g['epss_score']*100:.2f}% | "
            f"{g['hosts_count']} host(s)"
        )
        if g.get("packages"):
            out.append(f"    Producto: {', '.join(g['packages'])[:80]}")
    out += [
        "",
        f"Prioridad = CVSS x {W_CVSS:g} + EPSS x {W_EPSS:g} + CISA KEV x {W_KEV:g}, tope 100.",
        "EPSS (FIRST.org) estima la probabilidad de explotacion en los proximos 30 dias.",
        "CISA KEV es el catalogo oficial de vulnerabilidades con explotacion confirmada.",
        "",
        f"Generado por Wazuh SIEM. Run ID: {summary['run_id']}",
    ]
    return "\n".join(out)


def render_email(
    summary: dict,
    groups: list[dict],
    top_limit: int = TOP_LIMIT,
    comp: dict | None = None,
    prev_file: str = "",
    cov: dict | None = None,
) -> str:
    """Documento HTML completo, ancho fijo 700px centrado con tabla exterior.

    Si viene `comp`, el reporte arranca con el cumplimiento de parches por host
    (los datos del semanal original) y sigue con la priorización.
    """
    fecha = datetime.now().strftime("%d/%m/%Y")
    compliance = render_compliance_fragment(comp, prev_file) if comp else ""
    # El aviso de calidad va primero: condiciona cómo se leen todos los números.
    aviso = render_coverage_notice(cov or {})
    titulo = (
        "Reporte de Vulnerabilidades y Cumplimiento de Parches"
        if comp
        else "Priorizaci&oacute;n de Vulnerabilidades por Explotabilidad Real"
    )
    # Badge del header: lo manda el peor indicador del parque, no el total de
    # hallazgos. Un parque con 3 CVEs en el catálogo KEV es CRITICO aunque el
    # número global haya bajado.
    if not summary.get("total_active"):
        badge_kind = "sin_datos"
    elif summary.get("kev_count"):
        badge_kind = "critico"
    elif summary.get("epss_high_count") or summary.get("priority_high_count"):
        badge_kind = "atencion"
    else:
        badge_kind = "ok"

    return _theme.document(
        org=ORG_NAME,
        title=titulo,
        subtitle=(
            f"{fecha} &nbsp;&middot;&nbsp; {_num(summary['total_active'])} hallazgos "
            f"activos en {_num(summary['hosts_affected'])} hosts"
        ),
        body=f"{aviso}{compliance}{render_fragment(summary, groups, top_limit)}",
        footer=(
            "Generado autom&aacute;ticamente por Wazuh SIEM<br>"
            "Fuentes: Wazuh Vulnerability Detector &middot; FIRST EPSS &middot; CISA KEV<br>"
            f"Run ID: {escape(summary['run_id'])}"
        ),
        doc_title=f"Priorizaci&oacute;n de Vulnerabilidades - {ORG_NAME}",
        badge_kind=badge_kind,
        preheader=(
            f"{_num(summary['total_active'])} hallazgos activos &middot; "
            f"{_num(summary.get('kev_count', 0))} explotadas in-the-wild"
        ),
    )


# --------------------------------------------------------------------------
# 7. Envío
# --------------------------------------------------------------------------
def load_email_config(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def send_email(
    cfg: dict,
    html: str,
    subject: str,
    recipients: list[str],
    plain: str = "",
    debug: bool = False,
) -> bool:
    """Delega en el tema compartido, que centraliza los arreglos antispam."""
    ok, info = _theme.send_report(
        cfg, html=html, plain=plain or "Reporte de vulnerabilidades priorizadas.",
        subject=subject, recipients=recipients, debug=debug,
    )
    if not ok:
        logger.error("Error enviando el mail: %s", info)
        return False
    logger.info("Mail aceptado por el servidor para: %s", ", ".join(recipients))
    logger.info("Message-ID: %s", info)
    return True


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
    conn.close()

    active = [r for r in rows if r["lifecycle_status"] != "resolved"]
    groups = group_by_cve(active)

    # Cumplimiento de parches: conteos por host del inventario actual, comparados
    # contra el snapshot semanal anterior (lectura únicamente).
    agent_os = fetch_agent_os_versions()
    cov = assess_coverage(active, agent_os)
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
