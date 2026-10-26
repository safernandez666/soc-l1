"""Tests de la verificación read-back de close_incident (feat/invgate-close-verify).

El bug que cubren: el accept de InvGate puede devolver status=OK sin que el
ticket transicione a resuelto (visto en prod: accept OK, ticket sigue en status
7). close_incident ahora relee el ticket (GET /incident?id=N) y solo reporta
ok=True si realmente quedó resuelto (solved_at/closed_at o status_id en el set
de cerrados). Todo mockeado con respx — no toca InvGate real.
"""
from __future__ import annotations

import httpx
import pytest
import respx

from src.config import Settings
from src.tools.invgate import InvgateClient

BASE = "https://invgate.test/api/v1"


@pytest.fixture
def settings() -> Settings:
    return Settings(
        openai_api_key="x",
        HOST_INVGATE=BASE,
        USER_INVGATE="api",
        PASS_INVGATE="secret",
        CREATOR_ID_INVGATE=1,
        INVGATE_VERIFY_SSL=False,
    )


def _ok(**extra):
    return httpx.Response(200, json={"status": "OK", "request_id": 999, **extra})


def _ticket(status_id: int, *, solved: bool = False, closed: bool = False):
    return httpx.Response(
        200,
        json={
            "id": 999,
            "status_id": status_id,
            "solved_at": "2026-07-24T10:00:00Z" if solved else None,
            "closed_at": "2026-07-24T10:00:00Z" if closed else None,
            "closed_reason": None,
        },
    )


@pytest.mark.asyncio
async def test_close_verified_when_ticket_solved(settings: Settings) -> None:
    """accept OK + ticket queda en status 5 (solved) → ok=True, status_id=5."""
    with respx.mock as mock:
        mock.post(f"{BASE}/incident.comment").mock(return_value=_ok())
        mock.put(f"{BASE}/incident.solution.accept").mock(return_value=_ok())
        mock.get(f"{BASE}/incident").mock(return_value=_ticket(5, solved=True))
        async with InvgateClient(settings) as c:
            res = await c.close_incident(999)
    assert res.ok is True
    assert res.status_id == 5


@pytest.mark.asyncio
async def test_close_fails_when_ticket_still_open(settings: Settings) -> None:
    """accept OK pero el ticket sigue en status 7 (abierto) → ok=False, se explica."""
    with respx.mock as mock:
        mock.post(f"{BASE}/incident.comment").mock(return_value=_ok())
        mock.put(f"{BASE}/incident.solution.accept").mock(return_value=_ok())
        mock.get(f"{BASE}/incident").mock(return_value=_ticket(7))
        async with InvgateClient(settings) as c:
            res = await c.close_incident(999)
    assert res.ok is False
    assert res.status_id == 7
    assert "sigue abierto" in (res.error or "")


@pytest.mark.asyncio
async def test_close_unverified_when_readback_fails(settings: Settings) -> None:
    """accept OK pero no se puede releer el ticket → ok=False (no mentimos éxito)."""
    with respx.mock as mock:
        mock.post(f"{BASE}/incident.comment").mock(return_value=_ok())
        mock.put(f"{BASE}/incident.solution.accept").mock(return_value=_ok())
        mock.get(f"{BASE}/incident").mock(return_value=httpx.Response(500))
        async with InvgateClient(settings) as c:
            res = await c.close_incident(999)
    assert res.ok is False
    assert "no se pudo verificar" in (res.error or "")


@pytest.mark.asyncio
async def test_close_short_circuits_when_solution_fails(settings: Settings) -> None:
    """Si proponer la solución falla (sin permiso), no se intenta el accept."""
    accept_route = None
    with respx.mock as mock:
        mock.post(f"{BASE}/incident.comment").mock(
            return_value=httpx.Response(409, text="Cannot mark ...")
        )
        accept_route = mock.put(f"{BASE}/incident.solution.accept").mock(
            return_value=_ok()
        )
        async with InvgateClient(settings) as c:
            res = await c.close_incident(999)
    assert res.ok is False
    assert accept_route.called is False  # nunca llegó al accept


@pytest.mark.asyncio
async def test_close_verified_via_status_id_fallback(settings: Settings) -> None:
    """Si el ticket no trae solved_at/closed_at pero el status_id está en el set
    configurado de cerrados, igual cuenta como resuelto (fallback)."""
    with respx.mock as mock:
        mock.post(f"{BASE}/incident.comment").mock(return_value=_ok())
        mock.put(f"{BASE}/incident.solution.accept").mock(return_value=_ok())
        mock.get(f"{BASE}/incident").mock(return_value=_ticket(5))  # sin fechas
        async with InvgateClient(settings) as c:
            res = await c.close_incident(999)
    assert res.ok is True


@pytest.mark.asyncio
async def test_get_incident_returns_dict(settings: Settings) -> None:
    with respx.mock as mock:
        mock.get(f"{BASE}/incident").mock(return_value=_ticket(7))
        async with InvgateClient(settings) as c:
            t = await c.get_incident(999)
    assert t is not None and t["status_id"] == 7


@pytest.mark.asyncio
async def test_get_incident_none_on_404(settings: Settings) -> None:
    with respx.mock as mock:
        mock.get(f"{BASE}/incident").mock(return_value=httpx.Response(404))
        async with InvgateClient(settings) as c:
            t = await c.get_incident(999)
    assert t is None
