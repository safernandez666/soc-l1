"""InvGate Service Desk REST API client.

El SOC L1 crea un ticket por cada alerta que pasa el Triage (verdict != auto_close)
y lo va actualizando con cada hito del incidente (approve / reject / executed / expired).
El ticket queda como running log para compliance y para que L2 vea el ciclo completo.

Auth: HTTP Basic (USER_INVGATE / PASS_INVGATE). Patrón más común en InvGate; ajustar
si el admin confirma otra cosa (e.g. token API).

Endpoints:
  POST /incident                 → crear ticket (documentado en releases.invgate.com)
  POST /incident/{id}/comment    → agregar nota (asunción - confirmar con admin)
  PUT  /incident/{id}            → cambiar status (asunción - confirmar con admin)

Mapeo priority (NarratorPlan.risk_level → InvGate priority_id):
  low → 1 (Low)
  medium → 2 (Medium)
  high → 3 (High)
  critical → 5 (Critical)
  (Urgent=4 no se mapea desde el Narrator)
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from src.config import Settings
from src.models import InvgateTicketResult

logger = logging.getLogger("soc-l1")


_RISK_TO_PRIORITY: dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 5,
}
_DEFAULT_PRIORITY = 2  # Medium si el risk_level no matchea (no debería pasar con Literal)

# type_id del POST /incident: 1=Incident, 2=Service Request, 3=Question, 4=Problem,
# 5=Change, 6=Major Incident. Para SOC alerts usamos Incident por default.
TYPE_INCIDENT = 1


def priority_id_from_risk(risk_level: str) -> int:
    """Mapea NarratorPlan.risk_level a InvGate priority_id (1..5)."""
    return _RISK_TO_PRIORITY.get((risk_level or "").lower(), _DEFAULT_PRIORITY)


def is_configured(settings: Settings) -> bool:
    """True si todas las vars críticas de InvGate están seteadas.

    creator_id es int con default=0 -> 0 cuenta como "no seteado".
    Si falta cualquiera, el pipeline saltea InvGate sin abortar.
    """
    return bool(
        settings.invgate_host
        and settings.invgate_user
        and settings.invgate_password
        and settings.invgate_creator_id  # int != 0
    )


class InvgateClient:
    """Cliente async para InvGate Service Desk.

    Uso:
        async with InvgateClient(settings) as client:
            result = await client.create_incident(
                title="...",
                description="...",
                priority_id=3,
            )
            if result.ok:
                await client.add_comment(result.request_id, "...")
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._base_url = settings.invgate_host.rstrip("/")
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "InvgateClient":
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            auth=(self._settings.invgate_user, self._settings.invgate_password),
            verify=self._settings.invgate_verify_ssl,
            timeout=httpx.Timeout(15.0, connect=5.0),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ===== Helpers =====

    def _missing_config_result(self) -> InvgateTicketResult:
        return InvgateTicketResult(
            ok=False,
            error="invgate not configured (faltan vars en .env)",
        )

    def _not_initialized_result(self) -> InvgateTicketResult:
        return InvgateTicketResult(
            ok=False,
            error="client not initialized - usar async with InvgateClient(...)",
        )

    def _parse_response(self, resp: httpx.Response) -> InvgateTicketResult:
        """InvGate retorna { status: 'OK'|'ERROR', request_id: N, info: '...' }.
        HTTP >= 400 cuenta como error (sin parsear).
        """
        if resp.status_code >= 400:
            return InvgateTicketResult(
                ok=False,
                error=f"HTTP {resp.status_code}: {resp.text[:200]}",
            )

        try:
            data = resp.json()
        except ValueError:
            return InvgateTicketResult(
                ok=False,
                error=f"invalid JSON response: {resp.text[:200]}",
            )

        status = (data.get("status") or "").upper()
        rid = data.get("request_id")
        info = data.get("info")
        try:
            rid_int = int(rid) if rid is not None else None
        except (TypeError, ValueError):
            rid_int = None

        if status != "OK":
            return InvgateTicketResult(
                ok=False,
                request_id=rid_int,
                info=info,
                error=f"invgate status={status!r}",
            )

        return InvgateTicketResult(ok=True, request_id=rid_int, info=info)

    # ===== API methods =====

    async def create_incident(
        self,
        *,
        title: str,
        description: str,
        priority_id: int,
        type_id: int = TYPE_INCIDENT,
    ) -> InvgateTicketResult:
        """POST /incident. Crea un ticket. Devuelve InvgateTicketResult.

        Errores no propagan: devuelven result.ok=False con detalle en .error.
        Esto es deliberado - el pipeline no debe abortar si InvGate está caído.
        """
        if not is_configured(self._settings):
            return self._missing_config_result()
        if self._client is None:
            return self._not_initialized_result()

        payload: dict[str, Any] = {
            "creator_id": self._settings.invgate_creator_id,
            "customer_id": self._settings.invgate_customer_id,
            "category_id": self._settings.invgate_category_id,
            "priority_id": priority_id,
            "type_id": type_id,
            "title": title[:200],  # cap por las dudas
            "description": description,
        }

        try:
            resp = await self._client.post("/incident", json=payload)
        except httpx.HTTPError as e:
            logger.error("invgate: create_incident HTTP error: %s", e)
            return InvgateTicketResult(ok=False, error=f"http error: {e}")

        result = self._parse_response(resp)
        if result.ok:
            logger.info(
                "🎫 INVGATE create_incident ok | request_id=%s priority=%d",
                result.request_id, priority_id,
            )
        else:
            logger.warning(
                "🎫 INVGATE create_incident FAILED | error=%s", result.error
            )
        return result

    async def add_comment(
        self, request_id: int, body: str, *, internal: bool = False,
        is_solution: bool = False,
    ) -> InvgateTicketResult:
        """POST /incident.comment — agrega un comentario a un ticket existente.

        internal: True → nota interna (customer_visible=0), False → público.
        is_solution: True → marca el comentario como SOLUCIÓN propuesta del incidente
            (paso 1 del cierre; luego close_incident lo acepta). OJO: la solución DEBE
            ser pública — InvGate rechaza marcar un comentario interno como solución
            ("Cannot mark an internal comment as the solution"), así que con is_solution
            forzamos customer_visible=1 aunque venga internal=True.

        Requisito para is_solution: la cuenta de API necesita permiso de "resolver"
        (habilitado 2026-07-23). Sin él responde 409 "not allowed to solve".
        """
        if not is_configured(self._settings):
            return self._missing_config_result()
        if self._client is None:
            return self._not_initialized_result()

        # La solución tiene que ser pública sí o sí (ver docstring).
        customer_visible = 1 if is_solution else (0 if internal else 1)
        payload: dict[str, Any] = {
            "request_id": request_id,
            "author_id": self._settings.invgate_creator_id,
            "comment": body,
            "customer_visible": customer_visible,
        }
        if is_solution:
            payload["is_solution"] = 1

        try:
            resp = await self._client.post(
                "/incident.comment",
                json=payload,
            )
        except httpx.HTTPError as e:
            logger.error("invgate: add_comment HTTP error: %s", e)
            return InvgateTicketResult(ok=False, request_id=request_id, error=f"http error: {e}")

        result = self._parse_response(resp)
        # Mantener request_id en el resultado aunque la API no lo devuelva
        if result.request_id is None:
            result = result.model_copy(update={"request_id": request_id})
        if result.ok:
            logger.info("🎫 INVGATE add_comment ok | request_id=%s", request_id)
        else:
            logger.warning(
                "🎫 INVGATE add_comment FAILED | request_id=%s error=%s",
                request_id, result.error,
            )
        return result

    async def get_incident(self, request_id: int) -> dict[str, Any] | None:
        """Lee un ticket: GET /incident?id=N → dict del ticket, o None si falla.

        Descubierto por probe read-only (2026-07-24): el endpoint devuelve el
        incidente completo, incluyendo status_id / solved_at / closed_at /
        closed_reason. Se usa para verificar que un cierre realmente aterrizó.
        """
        if not is_configured(self._settings) or self._client is None:
            return None
        try:
            resp = await self._client.get("/incident", params={"id": request_id})
        except httpx.HTTPError as e:
            logger.warning("invgate: get_incident HTTP error id=%s: %s", request_id, e)
            return None
        if resp.status_code != 200:
            logger.warning(
                "invgate: get_incident id=%s → HTTP %s", request_id, resp.status_code
            )
            return None
        try:
            data = resp.json()
        except ValueError:
            return None
        return data if isinstance(data, dict) else None

    def _ticket_is_resolved(self, ticket: dict[str, Any]) -> bool:
        """¿El ticket llegó a un estado resuelto/cerrado? Señal primaria:
        solved_at o closed_at presentes (InvGate los setea al resolver). Fallback:
        status_id en INVGATE_CLOSED_STATUS_IDS, por si un workflow no poblara las
        fechas."""
        if ticket.get("solved_at") or ticket.get("closed_at"):
            return True
        sid = ticket.get("status_id")
        try:
            return int(sid) in self._settings.invgate_closed_status_ids_set()
        except (TypeError, ValueError):
            return False

    async def close_incident(
        self, request_id: int, rating: int = 5,
        *, solution_comment: str | None = "Cierre automático SOC-L1: caso contenido, "
        "no requiere acción humana.",
    ) -> InvgateTicketResult:
        """Cierra el ticket: propone una solución y la acepta (workflow InvGate).

        InvGate NO tiene endpoint de cierre directo. La secuencia es:
          1. POST /incident.comment con is_solution=1 (PÚBLICO) → propone la solución.
          2. PUT  /incident.solution.accept (id, rating) → la acepta = cierra.

        Detalles que causaban fallas (todos ya resueltos, validado e2e el 2026-07-23):
          - El accept exige el parámetro `id` (NO `request_id`) en QUERY STRING. Mandarlo
            en el body daba HTTP 428 "El parámetro id es requerido en PUT".
          - La solución debe ser PÚBLICA (add_comment fuerza customer_visible=1 con
            is_solution); si es interna → 409 "Cannot mark an internal comment as solution".
          - Sin solución propuesta, el accept devuelve status=ERROR (no hay qué aceptar).
          - rating<4 requeriría `comment`; usamos rating=5 por default para evitarlo.

        PERMISO: proponer/aceptar solución necesita el permiso de "resolver solicitud" en
        la cuenta de API (habilitado 2026-07-23). Sin él, el paso 1 responde 409 y el
        ticket queda ABIERTO (best-effort). También puede fallar (409/ERROR) si el ticket
        está en un estado que no admite solución (p.ej. ya intervenido por otro agente);
        el llamador trata todo cierre como best-effort y nunca aborta por esto.
        """
        if not is_configured(self._settings):
            return self._missing_config_result()
        if self._client is None:
            return self._not_initialized_result()

        # Paso 1: proponer la solución (pública). Si falla (409 sin permiso o estado no
        # soluble), no tiene sentido intentar el accept: devolvemos el error tal cual.
        if solution_comment:
            sol = await self.add_comment(request_id, solution_comment, is_solution=True)
            if not sol.ok:
                logger.warning(
                    "🎫 INVGATE propose-solution FAILED | request_id=%s error=%s "
                    "(ticket queda abierto)",
                    request_id, sol.error,
                )
                return sol

        # Paso 2: aceptar la solución = cerrar.
        try:
            resp = await self._client.put(
                "/incident.solution.accept",
                params={"id": request_id, "rating": rating},
            )
        except httpx.HTTPError as e:
            logger.error("invgate: close_incident HTTP error: %s", e)
            return InvgateTicketResult(ok=False, request_id=request_id, error=f"http error: {e}")

        result = self._parse_response(resp)
        if result.request_id is None:
            result = result.model_copy(update={"request_id": request_id})

        # Si el accept ya reportó ERROR, ni verificamos: devolvemos el fallo.
        if not result.ok:
            logger.warning(
                "🎫 INVGATE close_incident FAILED (accept) | request_id=%s error=%s",
                request_id, result.error,
            )
            return result

        # VERIFICACIÓN read-back: que el accept devuelva OK NO garantiza que el
        # ticket haya transicionado a resuelto (visto en prod: accept OK y el
        # ticket sigue en status 7). Releemos y confirmamos con solved_at/closed_at.
        ticket = await self.get_incident(request_id)
        if ticket is None:
            # No pudimos verificar. No mentimos: éxito no confirmado.
            logger.warning(
                "🎫 INVGATE close_incident UNVERIFIED | request_id=%s "
                "(accept OK pero no se pudo releer el ticket)",
                request_id,
            )
            return result.model_copy(
                update={
                    "ok": False,
                    "error": "accept OK pero no se pudo verificar el cierre (get_incident falló)",
                }
            )

        sid = ticket.get("status_id")
        try:
            sid_int = int(sid) if sid is not None else None
        except (TypeError, ValueError):
            sid_int = None

        if self._ticket_is_resolved(ticket):
            logger.info(
                "🎫 INVGATE close_incident ok+verificado | request_id=%s status_id=%s",
                request_id, sid_int,
            )
            return result.model_copy(update={"status_id": sid_int})

        logger.warning(
            "🎫 INVGATE close_incident NO-CERRÓ | request_id=%s accept=OK pero "
            "status_id=%s (sin solved_at/closed_at) — ticket sigue ABIERTO",
            request_id, sid_int,
        )
        return result.model_copy(
            update={
                "ok": False,
                "status_id": sid_int,
                "error": (
                    f"accept devolvió OK pero el ticket sigue abierto "
                    f"(status_id={sid_int}, sin solved_at/closed_at)"
                ),
            }
        )
