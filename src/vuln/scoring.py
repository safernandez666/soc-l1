"""Score de prioridad: CVSS + EPSS + CISA KEV.

Los pesos y los umbrales viven acá porque son la definición del score: el resto
de las capas (resumen en `store`, render en `report`) los consume para explicar
de dónde sale cada número.
"""
from __future__ import annotations

import os

# Pesos del score (mismos que el workflow n8n de referencia)
W_CVSS = float(os.getenv("VULN_W_CVSS", "5"))
W_EPSS = float(os.getenv("VULN_W_EPSS", "30"))
W_KEV = float(os.getenv("VULN_W_KEV", "20"))

EPSS_HIGH_THRESHOLD = float(os.getenv("VULN_EPSS_THRESHOLD", "0.5"))
PRIORITY_THRESHOLD = float(os.getenv("VULN_PRIORITY_THRESHOLD", "80"))


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
