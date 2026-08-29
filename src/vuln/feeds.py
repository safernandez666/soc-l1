"""Enriquecimiento con fuentes públicas: EPSS (FIRST) y catálogo CISA KEV.

Hacia afuera solo viajan identificadores CVE; ningún dato del parque sale del
entorno.
"""
from __future__ import annotations

import json
import logging
import os
import time

import requests

CACHE_DIR = os.getenv("VULN_CACHE_DIR", "/opt/soc-l1/.cache")

EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_TTL_H = 12
EPSS_BATCH = 100          # CVEs por request a FIRST
EPSS_PAUSE_S = 0.25       # cortesía entre batches

logger = logging.getLogger("vuln_priority")


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
