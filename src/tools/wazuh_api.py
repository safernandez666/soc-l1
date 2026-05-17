"""Wazuh manager API client - usado por el Enricher para context.

Endpoints relevantes:
  POST /security/user/authenticate  → JWT (cacheado in-memory por ~14min)
  GET  /rules?rule_ids=N           → detalle de la rule (description, mitre, groups)
  GET  /agents?name=hostname       → agent_id desde hostname (para queries de alertas)

Notas:
  - El JWT del manager expira en 15min. Cacheamos por 14 para tener buffer.
  - En deploys típicos on-prem el cert es self-signed → verify=False.
  - Cliente es async (httpx.AsyncClient) y se usa como context manager.
"""
from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from src.config import Settings
from src.models import WazuhRuleInfo

logger = logging.getLogger("soc-l1")

_JWT_TTL_SECONDS = 14 * 60  # el manager usa 15min, dejamos 1min de margen


class WazuhApiError(Exception):
    """Error genérico hablando con el Wazuh API."""


class WazuhApiClient:
    """Cliente async del Wazuh manager API con auth + cache de JWT.

    Uso:
        async with WazuhApiClient(settings) as client:
            rule = await client.get_rule("60106")
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._base_url = f"https://{settings.wazuh_api_host}:{settings.wazuh_api_port}"
        self._client: httpx.AsyncClient | None = None
        self._jwt: str | None = None
        self._jwt_expires_at: float = 0.0

    async def __aenter__(self) -> "WazuhApiClient":
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            verify=self._settings.wazuh_api_verify_ssl,
            timeout=httpx.Timeout(10.0, connect=5.0),
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _ensure_jwt(self) -> str:
        """Devuelve un JWT válido. Si está cacheado y vigente, no autentica de nuevo."""
        now = time.monotonic()
        if self._jwt and now < self._jwt_expires_at:
            return self._jwt

        if self._client is None:
            raise WazuhApiError("client not initialized - usar async with")

        try:
            resp = await self._client.post(
                "/security/user/authenticate",
                auth=(self._settings.wazuh_api_user, self._settings.wazuh_api_password),
            )
        except httpx.HTTPError as e:
            raise WazuhApiError(f"auth request failed: {e}") from e

        if resp.status_code != 200:
            raise WazuhApiError(
                f"auth failed: HTTP {resp.status_code} body={resp.text[:200]}"
            )

        payload = resp.json()
        token = payload.get("data", {}).get("token")
        if not token:
            raise WazuhApiError(f"auth response sin token: {payload}")

        self._jwt = token
        self._jwt_expires_at = now + _JWT_TTL_SECONDS
        logger.debug("wazuh_api: JWT renovado, válido por %ds", _JWT_TTL_SECONDS)
        return token

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """GET autenticado al manager. Retorna el body JSON parseado."""
        if self._client is None:
            raise WazuhApiError("client not initialized - usar async with")

        jwt = await self._ensure_jwt()
        try:
            resp = await self._client.get(
                path,
                params=params,
                headers={"Authorization": f"Bearer {jwt}"},
            )
        except httpx.HTTPError as e:
            raise WazuhApiError(f"GET {path} failed: {e}") from e

        if resp.status_code == 401:
            # JWT expiró antes del TTL nominal → invalidamos y reintentamos una sola vez
            self._jwt = None
            self._jwt_expires_at = 0.0
            jwt = await self._ensure_jwt()
            resp = await self._client.get(
                path,
                params=params,
                headers={"Authorization": f"Bearer {jwt}"},
            )

        if resp.status_code != 200:
            raise WazuhApiError(
                f"GET {path} → HTTP {resp.status_code} body={resp.text[:200]}"
            )

        return resp.json()

    async def get_rule(self, rule_id: str) -> WazuhRuleInfo | None:
        """Trae el detalle de una rule. Devuelve None si no existe."""
        body = await self._get("/rules", params={"rule_ids": rule_id})
        items = body.get("data", {}).get("affected_items") or []
        if not items:
            return None
        return _parse_rule(items[0])


def _parse_rule(item: dict[str, Any]) -> WazuhRuleInfo:
    """Mapea un item de /rules a WazuhRuleInfo. Tolera estructuras parcialmente vacías."""
    mitre = item.get("mitre") or {}
    return WazuhRuleInfo(
        rule_id=str(item.get("id", "")),
        level=int(item.get("level", 0) or 0),
        description=str(item.get("description", "") or ""),
        groups=list(item.get("groups") or []),
        mitre_ids=list(mitre.get("id") or []),
        mitre_tactics=list(mitre.get("tactic") or []),
        mitre_techniques=list(mitre.get("technique") or []),
        gdpr=list(item.get("gdpr") or []),
        pci_dss=list(item.get("pci_dss") or []),
    )
