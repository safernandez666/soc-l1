"""Cliente Microsoft Defender for Endpoint (MDE) - machine actions.

Cierra el lazo con Defender: hoy solo ingerimos sus alertas vía Wazuh, acá le
devolvemos acciones de respuesta sobre el endpoint (post-aprobación humana):
  - run_av_scan(machine_id):     dispara un antivirus scan (Quick por defecto)
  - isolate_machine(machine_id): aísla la máquina de la red (Full por defecto)
  - unisolate_machine(machine_id): libera el aislamiento (para L2 / cleanup)

Auth: OAuth2 client-credentials contra Entra ID. El App Registration necesita
permisos de aplicación WindowsDefenderATP con admin consent:
  - Machine.Scan       → run_av_scan
  - Machine.Isolate    → isolate / unisolate
  - Machine.Read.All   → resolver hostname → machineId

Identidad de la máquina: las machine actions de MDE requieren el `machineId`
(== mdeDeviceId que ya viene en la alerta de Defender). El executor recibe el
hostname en action.target (legible para el analista y para PROTECTED_HOSTS) y
acá lo resolvemos a machineId vía /api/machines.

Endpoints:
  - token: POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
  - base:  https://api.securitycenter.microsoft.com
    - GET  /api/machines?$filter=...                 (resolver host)
    - POST /api/machines/{id}/runAntiVirusScan
    - POST /api/machines/{id}/isolate
    - POST /api/machines/{id}/unisolate

Docs: https://learn.microsoft.com/en-us/defender-endpoint/api/machine

verify_ssl default True (es un endpoint público de Microsoft con cert válido,
a diferencia de FortiGate/Wazuh on-prem).
"""
from __future__ import annotations

import logging
from typing import Any, Literal

import httpx

from src.config import Settings
from src.models import DefenderActionResult

logger = logging.getLogger("soc-l1")

_LOGIN_BASE = "https://login.microsoftonline.com"
_API_BASE = "https://api.securitycenter.microsoft.com"
_SCOPE = f"{_API_BASE}/.default"


class DefenderError(Exception):
    """Error genérico hablando con la API de MDE."""


class DefenderClient:
    """Cliente async de la API de Microsoft Defender for Endpoint.

    Uso:
        async with DefenderClient(settings) as dc:
            mid = await dc.resolve_machine_id("desktop-5678")
            r = await dc.run_av_scan(mid, comment="SOC-L1 approved")
    """

    def __init__(self, settings: Settings) -> None:
        self._tenant = settings.defender_tenant_id
        self._client_id = settings.defender_client_id
        self._client_secret = settings.defender_client_secret
        self._verify_ssl = settings.defender_verify_ssl
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> DefenderClient:
        if not self._tenant or not self._client_id or not self._client_secret:
            raise DefenderError(
                "Defender no configurado - faltan DEFENDER_TENANT_ID/CLIENT_ID/CLIENT_SECRET"
            )
        token = await self._acquire_token()
        self._client = httpx.AsyncClient(
            base_url=_API_BASE,
            verify=self._verify_ssl,
            timeout=httpx.Timeout(30.0, connect=10.0),
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _acquire_token(self) -> str:
        """OAuth2 client-credentials. Devuelve el access_token (Bearer)."""
        url = f"{_LOGIN_BASE}/{self._tenant}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "scope": _SCOPE,
        }
        try:
            async with httpx.AsyncClient(
                verify=self._verify_ssl, timeout=httpx.Timeout(30.0, connect=10.0)
            ) as auth_client:
                resp = await auth_client.post(url, data=data)
        except httpx.HTTPError as e:
            raise DefenderError(f"token request failed: {e}") from e

        if resp.status_code != 200:
            raise DefenderError(
                f"token endpoint → HTTP {resp.status_code} body={resp.text[:200]}"
            )
        token = resp.json().get("access_token")
        if not token:
            raise DefenderError("token endpoint no devolvió access_token")
        return token

    async def _post(self, path: str, json: dict[str, Any]) -> dict[str, Any]:
        if self._client is None:
            raise DefenderError("client not initialized - usar async with")
        try:
            resp = await self._client.post(path, json=json)
        except httpx.HTTPError as e:
            raise DefenderError(f"MDE POST {path} failed: {e}") from e

        if resp.status_code == 401:
            raise DefenderError("MDE auth failed (HTTP 401) - revisar credenciales/consent")
        if resp.status_code == 403:
            raise DefenderError(
                "MDE permission denied (HTTP 403) - el App Registration no tiene "
                "el permiso requerido (Machine.Scan / Machine.Isolate)"
            )
        if resp.status_code not in (200, 201):
            raise DefenderError(
                f"MDE POST {path} → HTTP {resp.status_code} body={resp.text[:200]}"
            )
        return resp.json() if resp.text else {}

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if self._client is None:
            raise DefenderError("client not initialized - usar async with")
        try:
            resp = await self._client.get(path, params=params)
        except httpx.HTTPError as e:
            raise DefenderError(f"MDE GET {path} failed: {e}") from e
        if resp.status_code == 401:
            raise DefenderError("MDE auth failed (HTTP 401)")
        if resp.status_code == 403:
            raise DefenderError("MDE permission denied (HTTP 403) - falta Machine.Read.All")
        if resp.status_code != 200:
            raise DefenderError(
                f"MDE GET {path} → HTTP {resp.status_code} body={resp.text[:200]}"
            )
        return resp.json()

    # ===== Public API =====

    @staticmethod
    def _machineaction_ok(body: dict[str, Any]) -> tuple[bool, str | None]:
        """Valida la machineAction devuelta por MDE.

        MDE responde 201 con un machineAction cuyo `status` arranca en
        Pending/InProgress (eso es éxito: quedó encolada). Solo Failed/Cancelled
        son fallo real. Sin `id` la respuesta es inesperada → no la damos por ok.
        """
        action_id = body.get("id")
        status = body.get("status")
        if action_id is None:
            return False, "MDE no devolvió id de machineAction (respuesta inesperada)"
        if status in ("Failed", "Cancelled"):
            return False, f"machineAction status={status}"
        return True, None

    async def resolve_machine_id(self, host: str) -> str | None:
        """Resuelve un hostname/FQDN al machineId de MDE.

        Estrategia: match exacto por computerDnsName; si no hay, startswith sobre
        el nombre corto (Defender suele guardar el FQDN). Si hay varias máquinas,
        devuelve la vista más recientemente (lastSeen desc). None si no encuentra.
        """
        host = host.strip()
        if not host:
            return None
        short = host.split(".")[0]

        # 1) match exacto por FQDN/host
        body = await self._get(
            "/api/machines",
            params={"$filter": f"computerDnsName eq '{host}'", "$top": "20"},
        )
        machines = body.get("value") or []

        # 2) fallback: startswith sobre el nombre corto
        if not machines and short:
            body = await self._get(
                "/api/machines",
                params={"$filter": f"startswith(computerDnsName,'{short}')", "$top": "20"},
            )
            machines = body.get("value") or []

        if not machines:
            logger.warning("MDE resolve_machine_id(%r) → 0 máquinas", host)
            return None
        if len(machines) > 1:
            machines.sort(key=lambda m: m.get("lastSeen") or "", reverse=True)
            logger.warning(
                "MDE resolve_machine_id(%r) → %d máquinas, uso la más reciente (id=%s)",
                host, len(machines), machines[0].get("id"),
            )
        return machines[0].get("id")

    async def run_av_scan(
        self,
        machine_id: str,
        comment: str,
        scan_type: Literal["Quick", "Full"] = "Quick",
        host: str | None = None,
    ) -> DefenderActionResult:
        """POST /api/machines/{id}/runAntiVirusScan."""
        try:
            body = await self._post(
                f"/api/machines/{machine_id}/runAntiVirusScan",
                json={"Comment": comment, "ScanType": scan_type},
            )
        except DefenderError as e:
            return DefenderActionResult(
                ok=False, action="run_av_scan", host=host, machine_id=machine_id,
                message=str(e),
            )
        ok, err = self._machineaction_ok(body)
        if not ok:
            return DefenderActionResult(
                ok=False, action="run_av_scan", host=host, machine_id=machine_id,
                message=err,
            )
        return DefenderActionResult(
            ok=True, action="run_av_scan", host=host, machine_id=machine_id,
            action_id=body.get("id"),
            message=f"{scan_type} AV scan lanzado en machineId={machine_id}",
        )

    async def isolate_machine(
        self,
        machine_id: str,
        comment: str,
        isolation_type: Literal["Full", "Selective"] = "Full",
        host: str | None = None,
    ) -> DefenderActionResult:
        """POST /api/machines/{id}/isolate."""
        try:
            body = await self._post(
                f"/api/machines/{machine_id}/isolate",
                json={"Comment": comment, "IsolationType": isolation_type},
            )
        except DefenderError as e:
            return DefenderActionResult(
                ok=False, action="isolate_machine", host=host, machine_id=machine_id,
                message=str(e),
            )
        ok, err = self._machineaction_ok(body)
        if not ok:
            return DefenderActionResult(
                ok=False, action="isolate_machine", host=host, machine_id=machine_id,
                message=err,
            )
        return DefenderActionResult(
            ok=True, action="isolate_machine", host=host, machine_id=machine_id,
            action_id=body.get("id"),
            message=f"aislamiento {isolation_type} solicitado para machineId={machine_id}",
        )

    async def unisolate_machine(
        self, machine_id: str, comment: str, host: str | None = None
    ) -> DefenderActionResult:
        """POST /api/machines/{id}/unisolate. Para cleanup/L2, no se auto-recomienda."""
        try:
            body = await self._post(
                f"/api/machines/{machine_id}/unisolate", json={"Comment": comment}
            )
        except DefenderError as e:
            return DefenderActionResult(
                ok=False, action="unisolate_machine", host=host, machine_id=machine_id,
                message=str(e),
            )
        ok, err = self._machineaction_ok(body)
        if not ok:
            return DefenderActionResult(
                ok=False, action="unisolate_machine", host=host, machine_id=machine_id,
                message=err,
            )
        return DefenderActionResult(
            ok=True, action="unisolate_machine", host=host, machine_id=machine_id,
            action_id=body.get("id"),
            message=f"liberación de aislamiento solicitada para machineId={machine_id}",
        )
