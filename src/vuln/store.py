"""Estado: ciclo de vida en SQLite, agrupación por CVE y snapshots semanales.

Acá vive todo lo que tiene memoria entre corridas: la base de ciclo de vida
(nueva / persistente / resuelta / reabierta), el resumen de la corrida, y los
snapshots de cumplimiento por host que se comparan semana contra semana.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone

from src.vuln.schema import ensure_schema
from src.vuln.scoring import (
    EPSS_HIGH_THRESHOLD,
    PRIORITY_THRESHOLD,
    W_CVSS,
    W_EPSS,
    W_KEV,
)

STATE_DB = os.getenv("VULN_STATE_DB", "/opt/soc-l1/vuln_lifecycle.db")

# Snapshots semanales del reporte de cumplimiento de parches. Los escribe
# weekly_comparison.py (root); acá se leen SOLO en modo lectura para comparar
# semana contra semana. No escribimos nada en ese directorio para no romperle
# la lógica de baseline al script original.
HISTORICAL_DIR = os.getenv("VULN_HISTORICAL_DIR", "/opt/wazuh-scripts/historical")

logger = logging.getLogger("vuln_priority")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# OJO: `src/vuln/schema.py::ensure_schema()` crea estas mismas dos tablas (con
# columnas extra) más las del motor de Patch Genius. Los dos son CREATE TABLE IF
# NOT EXISTS, así que conviven, pero son dos DDL que pueden derivar. Lo natural
# es que `open_state()` termine delegando en `ensure_schema()`; no se hace acá
# porque este refactor no cambia comportamiento.


def open_state(path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    # ensure_schema aplica el DDL y, además, las migraciones idempotentes (columnas
    # y tablas nuevas). Corre en cada apertura: es barato y evita que una base vieja
    # llegue a las consultas nuevas sin las columnas que esperan.
    ensure_schema(conn)
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
# Agrupación por CVE (lo que le sirve al cliente para accionar)
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
# Calidad del dato: ¿el inventario refleja el estado real del parque?
# --------------------------------------------------------------------------
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
# Cumplimiento de parches por host (los datos del reporte semanal original)
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
