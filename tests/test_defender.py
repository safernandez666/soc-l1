"""Tests del cliente Defender/MDE con respx (sin tocar la API real)."""
from __future__ import annotations

import json as json_mod

import httpx
import pytest
import respx

from src.config import Settings
from src.tools.defender import DefenderClient, DefenderError

TOKEN_URL = "https://login.microsoftonline.com/tenant-test/oauth2/v2.0/token"
API = "https://api.securitycenter.microsoft.com"


@pytest.fixture
def settings() -> Settings:
    return Settings(
        openai_api_key="x",
        defender_tenant_id="tenant-test",
        defender_client_id="client-test",
        defender_client_secret="secret-test",
        defender_verify_ssl=True,
    )


def _token_ok() -> httpx.Response:
    return httpx.Response(200, json={"access_token": "fake-jwt", "expires_in": 3600})


def _machines(value: list[dict]) -> httpx.Response:
    return httpx.Response(200, json={"value": value})


# ===== auth =====


@pytest.mark.asyncio
async def test_missing_creds_raises() -> None:
    s = Settings(
        openai_api_key="x",
        defender_tenant_id="", defender_client_id="", defender_client_secret="",
    )
    with pytest.raises(DefenderError, match="no configurado"):
        async with DefenderClient(s):
            pass


@pytest.mark.asyncio
async def test_token_failure_raises(settings) -> None:
    with respx.mock as mock:
        mock.post(TOKEN_URL).mock(return_value=httpx.Response(401, text="bad secret"))
        with pytest.raises(DefenderError, match="token endpoint"):
            async with DefenderClient(settings):
                pass


# ===== resolve_machine_id =====


@pytest.mark.asyncio
async def test_resolve_exact_match(settings) -> None:
    with respx.mock as mock:
        mock.post(TOKEN_URL).mock(return_value=_token_ok())
        route = mock.get(f"{API}/api/machines").mock(
            return_value=_machines(
                [{"id": "mid-123", "computerDnsName": "goanote2109.grupoalemana.dns"}]
            )
        )
        async with DefenderClient(settings) as dc:
            mid = await dc.resolve_machine_id("goanote2109.grupoalemana.dns")
    assert mid == "mid-123"
    assert route.called


@pytest.mark.asyncio
async def test_resolve_no_match_returns_none(settings) -> None:
    with respx.mock as mock:
        mock.post(TOKEN_URL).mock(return_value=_token_ok())
        mock.get(f"{API}/api/machines").mock(return_value=_machines([]))
        async with DefenderClient(settings) as dc:
            mid = await dc.resolve_machine_id("ghost-host")
    assert mid is None


@pytest.mark.asyncio
async def test_resolve_multiple_picks_most_recent(settings) -> None:
    with respx.mock as mock:
        mock.post(TOKEN_URL).mock(return_value=_token_ok())
        mock.get(f"{API}/api/machines").mock(
            return_value=_machines([
                {"id": "old", "computerDnsName": "h1", "lastSeen": "2026-01-01T00:00:00Z"},
                {"id": "new", "computerDnsName": "h1", "lastSeen": "2026-05-29T00:00:00Z"},
            ])
        )
        async with DefenderClient(settings) as dc:
            mid = await dc.resolve_machine_id("h1")
    assert mid == "new"


# ===== run_av_scan =====


@pytest.mark.asyncio
async def test_run_av_scan_happy_path(settings) -> None:
    with respx.mock as mock:
        mock.post(TOKEN_URL).mock(return_value=_token_ok())
        route = mock.post(f"{API}/api/machines/mid-123/runAntiVirusScan").mock(
            return_value=httpx.Response(201, json={"id": "action-abc", "type": "RunAntiVirusScan"})
        )
        async with DefenderClient(settings) as dc:
            r = await dc.run_av_scan("mid-123", comment="approved", host="goanote2109")

    assert route.called
    payload = json_mod.loads(route.calls.last.request.content)
    assert payload == {"Comment": "approved", "ScanType": "Quick"}
    assert r.ok is True
    assert r.action == "run_av_scan"
    assert r.action_id == "action-abc"
    assert r.machine_id == "mid-123"


@pytest.mark.asyncio
async def test_run_av_scan_403_returns_error(settings) -> None:
    with respx.mock as mock:
        mock.post(TOKEN_URL).mock(return_value=_token_ok())
        mock.post(f"{API}/api/machines/mid-123/runAntiVirusScan").mock(
            return_value=httpx.Response(403, text="forbidden")
        )
        async with DefenderClient(settings) as dc:
            r = await dc.run_av_scan("mid-123", comment="x")
    assert r.ok is False
    assert "permission denied" in r.message.lower()


# ===== isolate_machine =====


@pytest.mark.asyncio
async def test_isolate_machine_happy_path(settings) -> None:
    with respx.mock as mock:
        mock.post(TOKEN_URL).mock(return_value=_token_ok())
        route = mock.post(f"{API}/api/machines/mid-9/isolate").mock(
            return_value=httpx.Response(201, json={"id": "iso-1"})
        )
        async with DefenderClient(settings) as dc:
            r = await dc.isolate_machine("mid-9", comment="approved", host="pwned01")

    payload = json_mod.loads(route.calls.last.request.content)
    assert payload == {"Comment": "approved", "IsolationType": "Full"}
    assert r.ok is True
    assert r.action == "isolate_machine"
    assert r.action_id == "iso-1"
