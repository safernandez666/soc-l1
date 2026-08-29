"""Lectura del inventario de vulnerabilidades y del parque de agentes.

Dos fuentes distintas del mismo Wazuh: el indexer (hallazgos, vía scroll API) y
la API de management (build de SO que reporta cada agente hoy), que sirve para
detectar inventarios desfasados.
"""
from __future__ import annotations

import logging
import os

import requests

from src.vuln.store import _now_iso

INDEXER_URL = os.getenv("VULN_INDEXER_URL", "https://localhost:9200")
INDEXER_USER = os.getenv("VULN_INDEXER_USER", "admin")
INDEXER_PASS = os.getenv("VULN_INDEXER_PASS", "")
INDEX_PATTERN = os.getenv("VULN_INDEX_PATTERN", "wazuh-states-vulnerabilities-*")

logger = logging.getLogger("vuln_priority")


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
    host_os = (src.get("host", {}) or {}).get("os", {}) or {}
    return {
        "finding_key": hit.get("_id")
        or "|".join([agent.get("id", ""), vuln.get("id", ""), pkg.get("name", ""), pkg.get("version", "")]),
        "cve": (vuln.get("id") or "").strip().upper(),
        "agent_id": agent.get("id", ""),
        "agent_name": agent.get("name", ""),
        "package_name": pkg.get("name", ""),
        "package_version": pkg.get("version", ""),
        "severity": vuln.get("severity") or "Unknown",
        # SO del host ("windows", "linux") y qué se actualiza para cerrar el
        # hallazgo: "OS" se cierra con un acumulativo/KB, "Packages" tocando la app.
        "plataforma": (host_os.get("platform") or "").strip().lower(),
        "categoria": (vuln.get("category") or "").strip(),
        "cvss_score": float(score.get("base") or 0),
        "detected_at": vuln.get("detected_at") or src.get("@timestamp") or _now_iso(),
        "published_at": vuln.get("published_at") or "",
        "description": vuln.get("description") or "",
        "reference": vuln.get("reference") or "",
    }


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
