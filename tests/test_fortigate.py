"""Tests de FortiGate client con respx (sin tocar FortiGate real)."""
from __future__ import annotations

import httpx
import pytest
import respx

from src.config import Settings
from src.tools.fortigate import FortigateClient, FortigateError

BASE_URL = "https://fortigate.test:4443"


@pytest.fixture
def settings() -> Settings:
    return Settings(
        openai_api_key="x",
        fortigate_host="fortigate.test:4443",
        fortigate_token="FG-TOKEN-TEST",
        fortigate_verify_ssl=False,
    )


def _sessions_response(count: int) -> httpx.Response:
    """Sim una respuesta de /monitor/firewall/session/select con N resultados."""
    return httpx.Response(
        200,
        json={
            "results": [{"srcip": "1.2.3.4", "dstip": "8.8.8.8"} for _ in range(count)],
            "total_lines": count,
        },
    )


def _banned_response(banned_ips: list[tuple[str, int]]) -> httpx.Response:
    """Sim de /monitor/user/banned/select. banned_ips=[(ip, expires_epoch)]."""
    return httpx.Response(
        200,
        json={
            "results": [
                {"ip_address": ip, "expires": exp} for ip, exp in banned_ips
            ]
        },
    )


# ===== get_ip_context =====


@pytest.mark.asyncio
async def test_get_ip_context_aggregates_sessions(settings) -> None:
    with respx.mock(base_url=BASE_URL) as mock:
        # srcip filter → 3 results
        mock.get(
            "/api/v2/monitor/firewall/session/select",
            params={"count": "1", "filter": "srcip=1.2.3.4"},
        ).mock(return_value=_sessions_response(3))
        # dstip filter → 2 results
        mock.get(
            "/api/v2/monitor/firewall/session/select",
            params={"count": "1", "filter": "dstip=1.2.3.4"},
        ).mock(return_value=_sessions_response(2))
        # banned list: no encuentra
        mock.get("/api/v2/monitor/user/banned/select").mock(
            return_value=_banned_response([])
        )

        async with FortigateClient(settings) as fg:
            ctx = await fg.get_ip_context("1.2.3.4")

    assert ctx.ip == "1.2.3.4"
    assert ctx.sessions_as_source == 3
    assert ctx.sessions_as_destination == 2
    assert ctx.active_sessions == 5
    assert ctx.already_quarantined is False
    assert ctx.quarantine_expires is None


@pytest.mark.asyncio
async def test_get_ip_context_detects_existing_quarantine(settings) -> None:
    with respx.mock(base_url=BASE_URL) as mock:
        mock.get(
            "/api/v2/monitor/firewall/session/select", params__contains={"filter": "srcip=1.2.3.4"}
        ).mock(return_value=_sessions_response(0))
        mock.get(
            "/api/v2/monitor/firewall/session/select", params__contains={"filter": "dstip=1.2.3.4"}
        ).mock(return_value=_sessions_response(0))
        mock.get("/api/v2/monitor/user/banned/select").mock(
            return_value=_banned_response([("1.2.3.4", 1800000000)])
        )

        async with FortigateClient(settings) as fg:
            ctx = await fg.get_ip_context("1.2.3.4")

    assert ctx.already_quarantined is True
    assert ctx.quarantine_expires is not None
    assert ctx.quarantine_expires.startswith("2027-")  # epoch 1800000000 = 2027-01-15


@pytest.mark.asyncio
async def test_get_ip_context_handles_missing_banned_endpoint(settings) -> None:
    """Algunos FortiOS no exponen /banned/select - no debe romper get_ip_context."""
    with respx.mock(base_url=BASE_URL) as mock:
        mock.get(
            "/api/v2/monitor/firewall/session/select"
        ).mock(return_value=_sessions_response(1))
        mock.get("/api/v2/monitor/user/banned/select").mock(
            return_value=httpx.Response(404)
        )

        async with FortigateClient(settings) as fg:
            ctx = await fg.get_ip_context("1.2.3.4")

    assert ctx.already_quarantined is False  # default seguro


# ===== quarantine_ip =====


@pytest.mark.asyncio
async def test_quarantine_ip_happy_path(settings) -> None:
    with respx.mock(base_url=BASE_URL) as mock:
        route = mock.post("/api/v2/monitor/user/banned/add_users").mock(
            return_value=httpx.Response(200, json={"status": "success"})
        )
        async with FortigateClient(settings) as fg:
            result = await fg.quarantine_ip("1.2.3.4", ttl_seconds=3600)

    # Verificar payload enviado
    assert route.called
    body = route.calls.last.request.content
    import json as json_mod
    payload = json_mod.loads(body)
    assert payload == {"ip_addresses": ["1.2.3.4"], "expiry": 3600}

    assert result.ok is True
    assert result.ip == "1.2.3.4"
    assert result.action == "quarantine_ip"
    assert result.expires_at is not None
    assert "1.2.3.4" in result.message
    assert "3600s" in result.message


@pytest.mark.asyncio
async def test_quarantine_ip_handles_auth_error(settings) -> None:
    with respx.mock(base_url=BASE_URL) as mock:
        mock.post("/api/v2/monitor/user/banned/add_users").mock(
            return_value=httpx.Response(401, json={"error": "bad token"})
        )
        async with FortigateClient(settings) as fg:
            result = await fg.quarantine_ip("1.2.3.4")

    assert result.ok is False
    assert "auth failed" in result.message.lower()


# ===== Sanity / init =====


@pytest.mark.asyncio
async def test_client_requires_host() -> None:
    s = Settings(openai_api_key="x", fortigate_host="", fortigate_token="t")
    with pytest.raises(FortigateError, match="FORTIGATE_HOST"):
        async with FortigateClient(s):
            pass


@pytest.mark.asyncio
async def test_client_requires_token() -> None:
    s = Settings(openai_api_key="x", fortigate_host="fg.test", fortigate_token="")
    with pytest.raises(FortigateError, match="FORTIGATE_TOKEN"):
        async with FortigateClient(s):
            pass


@pytest.mark.asyncio
async def test_client_auto_adds_https_scheme(settings) -> None:
    """Si fortigate_host viene sin scheme, asumimos https."""
    # settings.fortigate_host = "fortigate.test:4443" (sin https://)
    # El __aenter__ debe agregar https:// para que httpx funcione
    with respx.mock(base_url="https://fortigate.test:4443") as mock:
        mock.get("/api/v2/monitor/firewall/session/select").mock(
            return_value=_sessions_response(0)
        )
        mock.get("/api/v2/monitor/user/banned/select").mock(
            return_value=_banned_response([])
        )
        async with FortigateClient(settings) as fg:
            ctx = await fg.get_ip_context("1.2.3.4")
    assert ctx.ip == "1.2.3.4"
