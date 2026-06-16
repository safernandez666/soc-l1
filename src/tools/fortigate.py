"""Cliente FortiGate REST API (FortiOS 6.4+).

Soporta dos operaciones:
  - get_ip_context(ip): cuenta sessions activas (como src y dst) + ya quarantined o no
  - quarantine_ip(ip, ttl_seconds): banea la IP a nivel firewall

Auth: header `Authorization: Bearer <FORTIGATE_TOKEN>`.
Default verify_ssl=False (deploys on-prem suelen tener self-signed cert).

Endpoints usados:
  - GET  /api/v2/monitor/firewall/session?srcintf=any&filter=srcip=<ip>
  - GET  /api/v2/monitor/firewall/session?srcintf=any&filter=dstip=<ip>
  - POST /api/v2/monitor/user/banned/add_users  (quarantine)
  - GET  /api/v2/monitor/user/banned/select     (check quarantine status)

Documentación oficial FortiOS REST API:
  https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/...

Free / no rate limit en FortiOS (es la API del propio dispositivo).
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from src.config import Settings
from src.models import FortigateActionResult, FortigateIpContext

logger = logging.getLogger("soc-l1")


class FortigateError(Exception):
    """Error genérico hablando con FortiGate."""


class FortigateClient:
    """Cliente async de FortiGate REST API.

    Uso:
        async with FortigateClient(settings) as fg:
            ctx = await fg.get_ip_context("1.2.3.4")
            result = await fg.quarantine_ip("1.2.3.4", ttl_seconds=3600)
    """

    def __init__(self, settings: Settings) -> None:
        self._host = settings.fortigate_host
        self._token = settings.fortigate_token
        self._verify_ssl = settings.fortigate_verify_ssl
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "FortigateClient":
        if not self._host:
            raise FortigateError("FORTIGATE_HOST no configurado")
        if not self._token:
            raise FortigateError("FORTIGATE_TOKEN no configurado")

        # Si el host no trae scheme, asumimos https (default de FortiGate admin)
        base_url = self._host
        if not base_url.startswith(("http://", "https://")):
            base_url = f"https://{base_url}"

        self._client = httpx.AsyncClient(
            base_url=base_url,
            verify=self._verify_ssl,
            timeout=httpx.Timeout(10.0, connect=5.0),
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/json",
            },
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if self._client is None:
            raise FortigateError("client not initialized - usar async with")
        try:
            resp = await self._client.get(path, params=params)
        except httpx.HTTPError as e:
            raise FortigateError(f"FortiGate GET {path} failed: {e}") from e

        if resp.status_code == 401:
            raise FortigateError("FortiGate auth failed (HTTP 401) - revisar FORTIGATE_TOKEN")
        if resp.status_code == 403:
            raise FortigateError(
                "FortiGate permission denied (HTTP 403) - el token no tiene "
                "scope para este endpoint"
            )
        if resp.status_code != 200:
            raise FortigateError(
                f"FortiGate GET {path} → HTTP {resp.status_code} body={resp.text[:200]}"
            )
        return resp.json()

    async def _post(self, path: str, json: dict[str, Any]) -> dict[str, Any]:
        if self._client is None:
            raise FortigateError("client not initialized - usar async with")
        try:
            resp = await self._client.post(path, json=json)
        except httpx.HTTPError as e:
            raise FortigateError(f"FortiGate POST {path} failed: {e}") from e

        if resp.status_code == 401:
            raise FortigateError("FortiGate auth failed (HTTP 401)")
        if resp.status_code == 403:
            raise FortigateError("FortiGate permission denied (HTTP 403)")
        if resp.status_code not in (200, 201, 204):
            raise FortigateError(
                f"FortiGate POST {path} → HTTP {resp.status_code} body={resp.text[:200]}"
            )
        return resp.json() if resp.text else {}

    # ===== Public API =====

    async def get_ip_context(self, ip: str) -> FortigateIpContext:
        """Trae conteo de sessions + estado de quarantine para una IP."""
        sessions_src = await self._count_sessions(ip, filter_key="srcip")
        sessions_dst = await self._count_sessions(ip, filter_key="dstip")
        quarantined, expires = await self._check_quarantine(ip)
        return FortigateIpContext(
            ip=ip,
            active_sessions=sessions_src + sessions_dst,
            sessions_as_source=sessions_src,
            sessions_as_destination=sessions_dst,
            already_quarantined=quarantined,
            quarantine_expires=expires,
        )

    async def _count_sessions(self, ip: str, filter_key: str) -> int:
        """GET /monitor/firewall/session con filter por src o dst IP."""
        body = await self._get(
            "/api/v2/monitor/firewall/session/select",
            params={"count": "1", "filter": f"{filter_key}={ip}"},
        )
        # FortiOS retorna {"results": [...], "total_lines": N} o {"results": N}
        results = body.get("results")
        if isinstance(results, list):
            return len(results)
        if isinstance(results, int):
            return results
        return int(body.get("total_lines", 0) or 0)

    async def _check_quarantine(self, ip: str) -> tuple[bool, str | None]:
        """Chequea si la IP ya está en la lista de banned users.

        Retorna (is_banned, expires_iso).
        """
        try:
            body = await self._get("/api/v2/monitor/user/banned/select")
        except FortigateError:
            # Algunos modelos no tienen este endpoint; no es bloqueante
            return (False, None)
        for entry in body.get("results", []) or []:
            if str(entry.get("ip_address", "")) == ip:
                expires_secs = entry.get("expires")
                expires_iso: str | None = None
                if expires_secs and expires_secs > 0:
                    expires_iso = datetime.fromtimestamp(
                        int(expires_secs), tz=timezone.utc
                    ).isoformat()
                return (True, expires_iso)
        return (False, None)

    async def list_banned(self) -> list[dict[str, Any]]:
        """Lista todas las IPs en quarantine (banned users) del FortiGate.

        GET /api/v2/monitor/user/banned/select → results: [{ip_address, expires, ...}].
        Read-only; lo usa el panel /ui para el KPI de bloqueos. Devuelve [] si el
        modelo no soporta el endpoint o no hay baneos.
        """
        body = await self._get("/api/v2/monitor/user/banned/select")
        out: list[dict[str, Any]] = []
        for entry in body.get("results", []) or []:
            expires_secs = entry.get("expires")
            expires_iso: str | None = None
            if expires_secs and expires_secs > 0:
                expires_iso = datetime.fromtimestamp(
                    int(expires_secs), tz=timezone.utc
                ).isoformat()
            out.append({
                "ip": str(entry.get("ip_address", "") or ""),
                "expires": expires_iso,
                "source": entry.get("src") or entry.get("source") or None,
            })
        return out

    async def quarantine_ip(
        self, ip: str, ttl_seconds: int = 3600
    ) -> FortigateActionResult:
        """Banea una IP a nivel firewall por `ttl_seconds`.

        FortiOS POST /api/v2/monitor/user/banned/add_users
        Body: {"ip_addresses": ["1.2.3.4"], "expiry": 3600}
        """
        payload = {"ip_addresses": [ip], "expiry": ttl_seconds}
        try:
            body = await self._post("/api/v2/monitor/user/banned/add_users", json=payload)
        except FortigateError as e:
            return FortigateActionResult(
                ok=False, ip=ip, action="quarantine_ip", message=str(e)
            )
        # FortiOS suele responder HTTP 200 con {"status":"error"} ante fallos
        # lógicos: validamos el campo status, no solo el código HTTP. Si el body
        # viene vacío (algunos modelos), el 2xx ya validado en _post alcanza.
        fg_status = str(body.get("status", "")).lower()
        if fg_status and fg_status != "success":
            return FortigateActionResult(
                ok=False, ip=ip, action="quarantine_ip",
                message=f"FortiGate rechazó el ban: status={body.get('status')!r} "
                        f"body={str(body)[:200]}",
            )
        expires_at = (
            datetime.now(tz=timezone.utc) + timedelta(seconds=ttl_seconds)
        ).isoformat()
        return FortigateActionResult(
            ok=True,
            ip=ip,
            action="quarantine_ip",
            expires_at=expires_at,
            message=f"IP {ip} banned for {ttl_seconds}s (until {expires_at})",
        )
