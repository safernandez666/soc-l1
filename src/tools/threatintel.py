"""Threat Intel clients: VirusTotal v3 + AbuseIPDB v2.

Async (httpx) + Pydantic response models para validar el contrato.
Sin cache propio: el cache lo maneja el agent context (mismo patrón que Wazuh API).

Auth:
  - VirusTotal: header `x-apikey: <key>`
  - AbuseIPDB:  header `Key: <key>` + `Accept: application/json`

Free tier limits (mayo 2026):
  - VT:        500 lookups/día, 4 req/min
  - AbuseIPDB: 1000 checks/día

Endpoints:
  - VT:        GET https://www.virustotal.com/api/v3/files/{sha256}
  - AbuseIPDB: GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90

Errores comunes:
  - 401: API key inválida
  - 404 (VT): hash no visto antes por VT (no es error real, devolvemos None)
  - 422 (AbuseIPDB): IP inválida
  - 429: rate limit
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from src.config import Settings
from src.models import AbuseipdbReport, VtFileReport

logger = logging.getLogger("soc-l1")


class ThreatIntelError(Exception):
    """Error genérico hablando con VT o AbuseIPDB."""


# ===== Helpers =====


def _ts_to_iso(value: Any) -> str | None:
    """VT y AbuseIPDB usan epoch o ISO. Normalizamos a ISO."""
    if value is None or value == 0 or value == "":
        return None
    if isinstance(value, str):
        return value
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat()
    except (TypeError, ValueError):
        return None


# ===== VirusTotal =====


class VirusTotalClient:
    """Cliente async de VirusTotal API v3.

    Uso:
        async with VirusTotalClient(settings) as vt:
            report = await vt.get_file_report("275a02...")
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, settings: Settings) -> None:
        self._api_key = settings.virustotal_api_key
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "VirusTotalClient":
        if not self._api_key:
            raise ThreatIntelError("VIRUSTOTAL_API_KEY no configurada")
        self._client = httpx.AsyncClient(
            base_url=self.BASE_URL,
            timeout=httpx.Timeout(10.0, connect=5.0),
            headers={"x-apikey": self._api_key, "Accept": "application/json"},
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def get_file_report(self, sha256: str) -> VtFileReport | None:
        """Trae el report de un file por SHA256. None si VT no lo conoce."""
        if self._client is None:
            raise ThreatIntelError("client not initialized - usar async with")

        try:
            resp = await self._client.get(f"/files/{sha256}")
        except httpx.HTTPError as e:
            raise ThreatIntelError(f"VT GET /files failed: {e}") from e

        if resp.status_code == 404:
            return None  # File no visto por VT (esperado para malware nuevo)
        if resp.status_code == 401:
            raise ThreatIntelError("VT auth failed (HTTP 401) - revisar VIRUSTOTAL_API_KEY")
        if resp.status_code == 429:
            raise ThreatIntelError("VT rate limit exceeded (HTTP 429)")
        if resp.status_code != 200:
            raise ThreatIntelError(
                f"VT GET /files/{sha256} → HTTP {resp.status_code} body={resp.text[:200]}"
            )

        return _parse_vt_file(resp.json(), sha256)


def _parse_vt_file(body: dict[str, Any], requested_sha256: str) -> VtFileReport:
    """Mapea response de /files/{sha256} a VtFileReport."""
    attrs = body.get("data", {}).get("attributes", {}) or {}
    stats = attrs.get("last_analysis_stats", {}) or {}
    classification = attrs.get("popular_threat_classification") or {}
    categories_raw = classification.get("popular_threat_category") or []
    categories = [c.get("value") for c in categories_raw if isinstance(c, dict) and c.get("value")]

    total = sum(
        int(stats.get(k, 0) or 0)
        for k in ("harmless", "malicious", "suspicious", "undetected", "timeout")
    )

    return VtFileReport(
        sha256=str(attrs.get("sha256") or requested_sha256),
        malicious_count=int(stats.get("malicious", 0) or 0),
        suspicious_count=int(stats.get("suspicious", 0) or 0),
        undetected_count=int(stats.get("undetected", 0) or 0),
        total_engines=total,
        family=classification.get("suggested_threat_label"),
        categories=categories,
        first_submission=_ts_to_iso(attrs.get("first_submission_date")),
        last_analysis=_ts_to_iso(attrs.get("last_analysis_date")),
        names=list(attrs.get("names") or [])[:10],  # capeamos a 10 para no inflar el prompt
        type_description=attrs.get("type_description"),
        size=int(attrs.get("size")) if attrs.get("size") else None,
    )


# ===== AbuseIPDB =====


class AbuseipdbClient:
    """Cliente async de AbuseIPDB API v2.

    Uso:
        async with AbuseipdbClient(settings) as ab:
            report = await ab.check_ip("8.8.8.8")
    """

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, settings: Settings) -> None:
        self._api_key = settings.abuseipdb_api_key
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "AbuseipdbClient":
        if not self._api_key:
            raise ThreatIntelError("ABUSEIPDB_API_KEY no configurada")
        self._client = httpx.AsyncClient(
            base_url=self.BASE_URL,
            timeout=httpx.Timeout(10.0, connect=5.0),
            headers={"Key": self._api_key, "Accept": "application/json"},
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def check_ip(
        self, ip: str, max_age_days: int = 90, verbose: bool = False
    ) -> AbuseipdbReport | None:
        """Verifica reputation de una IP. None si la API la rechaza (IP inválida).

        max_age_days: ventana hacia atrás para los reports (default 90, max 365).
        verbose: incluye lista de reports recientes (más pesado, no lo usamos por default).
        """
        if self._client is None:
            raise ThreatIntelError("client not initialized - usar async with")

        params: dict[str, Any] = {"ipAddress": ip, "maxAgeInDays": max_age_days}
        if verbose:
            params["verbose"] = ""

        try:
            resp = await self._client.get("/check", params=params)
        except httpx.HTTPError as e:
            raise ThreatIntelError(f"AbuseIPDB GET /check failed: {e}") from e

        if resp.status_code == 422:
            return None  # IP inválida (no es un error real)
        if resp.status_code == 401:
            raise ThreatIntelError(
                "AbuseIPDB auth failed (HTTP 401) - revisar ABUSEIPDB_API_KEY"
            )
        if resp.status_code == 429:
            raise ThreatIntelError("AbuseIPDB rate limit exceeded (HTTP 429)")
        if resp.status_code != 200:
            raise ThreatIntelError(
                f"AbuseIPDB GET /check → HTTP {resp.status_code} body={resp.text[:200]}"
            )

        return _parse_abuseipdb(resp.json(), ip)


def _parse_abuseipdb(body: dict[str, Any], requested_ip: str) -> AbuseipdbReport:
    """Mapea response de /check a AbuseipdbReport."""
    data = body.get("data") or {}
    return AbuseipdbReport(
        ip=str(data.get("ipAddress") or requested_ip),
        abuse_confidence_score=int(data.get("abuseConfidenceScore", 0) or 0),
        country_code=data.get("countryCode"),
        isp=data.get("isp"),
        domain=data.get("domain"),
        total_reports=int(data.get("totalReports", 0) or 0),
        distinct_reporters=int(data.get("numDistinctUsers", 0) or 0),
        last_reported_at=data.get("lastReportedAt"),
        is_whitelisted=bool(data.get("isWhitelisted") or False),
        is_tor=bool(data.get("isTor") or False),
        usage_type=data.get("usageType"),
    )
