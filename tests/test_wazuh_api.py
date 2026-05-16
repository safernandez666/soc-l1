"""Tests del WazuhApiClient con respx (sin pegarle al manager real)."""
from __future__ import annotations

import httpx
import pytest
import respx

from src.config import Settings
from src.tools.wazuh_api import WazuhApiClient, WazuhApiError


@pytest.fixture
def settings() -> Settings:
    return Settings(
        openai_api_key="test-key",
        wazuh_api_host="wazuh.test",
        wazuh_api_port=55000,
        wazuh_api_user="wazuh",
        wazuh_api_password="secret",
        wazuh_api_verify_ssl=False,
    )


@pytest.fixture
def base_url() -> str:
    return "https://wazuh.test:55000"


def _auth_response() -> httpx.Response:
    return httpx.Response(200, json={"data": {"token": "FAKE.JWT.TOKEN"}})


def _rule_response_full() -> httpx.Response:
    """Rule completa con MITRE y compliance (forma real del manager)."""
    return httpx.Response(
        200,
        json={
            "data": {
                "affected_items": [
                    {
                        "id": 60106,
                        "level": 9,
                        "description": "Defender: Hacktool detected",
                        "groups": ["windows", "defender", "malware"],
                        "mitre": {
                            "id": ["T1588.002"],
                            "tactic": ["Resource Development"],
                            "technique": ["Tool"],
                        },
                        "gdpr": ["IV_35.7.d"],
                        "pci_dss": ["10.6.1"],
                    }
                ],
                "total_affected_items": 1,
            }
        },
    )


def _rule_response_empty() -> httpx.Response:
    return httpx.Response(
        200, json={"data": {"affected_items": [], "total_affected_items": 0}}
    )


@pytest.mark.asyncio
async def test_get_rule_parses_full_response(settings, base_url) -> None:
    with respx.mock(base_url=base_url, assert_all_called=True) as mock:
        mock.post("/security/user/authenticate").mock(return_value=_auth_response())
        mock.get("/rules", params={"rule_ids": "60106"}).mock(
            return_value=_rule_response_full()
        )

        async with WazuhApiClient(settings) as client:
            rule = await client.get_rule("60106")

    assert rule is not None
    assert rule.rule_id == "60106"
    assert rule.level == 9
    assert rule.description == "Defender: Hacktool detected"
    assert "defender" in rule.groups
    assert rule.mitre_ids == ["T1588.002"]
    assert rule.mitre_tactics == ["Resource Development"]
    assert rule.gdpr == ["IV_35.7.d"]


@pytest.mark.asyncio
async def test_get_rule_returns_none_when_not_found(settings, base_url) -> None:
    with respx.mock(base_url=base_url, assert_all_called=True) as mock:
        mock.post("/security/user/authenticate").mock(return_value=_auth_response())
        mock.get("/rules", params={"rule_ids": "99999"}).mock(
            return_value=_rule_response_empty()
        )

        async with WazuhApiClient(settings) as client:
            rule = await client.get_rule("99999")

    assert rule is None


@pytest.mark.asyncio
async def test_jwt_is_cached_across_calls(settings, base_url) -> None:
    """Auth debe llamarse 1 vez aunque hagamos N get_rule consecutivos."""
    with respx.mock(base_url=base_url, assert_all_called=True) as mock:
        auth_route = mock.post("/security/user/authenticate").mock(
            return_value=_auth_response()
        )
        mock.get("/rules").mock(return_value=_rule_response_full())

        async with WazuhApiClient(settings) as client:
            await client.get_rule("60106")
            await client.get_rule("60106")
            await client.get_rule("60106")

    assert auth_route.call_count == 1


@pytest.mark.asyncio
async def test_auth_failure_raises_with_context(settings, base_url) -> None:
    """Si el manager devuelve 401 a la auth, error claro con status."""
    with respx.mock(base_url=base_url, assert_all_called=True) as mock:
        mock.post("/security/user/authenticate").mock(
            return_value=httpx.Response(401, json={"error": "bad creds"})
        )

        async with WazuhApiClient(settings) as client:
            with pytest.raises(WazuhApiError, match="auth failed"):
                await client.get_rule("60106")


@pytest.mark.asyncio
async def test_401_on_get_triggers_jwt_refresh(settings, base_url) -> None:
    """Si un GET vuelve 401 (JWT expirado pre-TTL), reintenta re-autenticando."""
    with respx.mock(base_url=base_url, assert_all_called=True) as mock:
        auth_route = mock.post("/security/user/authenticate").mock(
            return_value=_auth_response()
        )
        # Primer GET → 401, segundo → 200
        get_route = mock.get("/rules").mock(
            side_effect=[
                httpx.Response(401, json={"error": "token expired"}),
                _rule_response_full(),
            ]
        )

        async with WazuhApiClient(settings) as client:
            rule = await client.get_rule("60106")

    assert rule is not None
    assert rule.rule_id == "60106"
    assert auth_route.call_count == 2  # initial + refresh
    assert get_route.call_count == 2


@pytest.mark.asyncio
async def test_auth_response_without_token_raises(settings, base_url) -> None:
    """Manager devuelve 200 pero sin data.token → error claro, no crash."""
    with respx.mock(base_url=base_url, assert_all_called=True) as mock:
        mock.post("/security/user/authenticate").mock(
            return_value=httpx.Response(200, json={"data": {}})
        )

        async with WazuhApiClient(settings) as client:
            with pytest.raises(WazuhApiError, match="sin token"):
                await client.get_rule("60106")


@pytest.mark.asyncio
async def test_client_requires_context_manager(settings) -> None:
    """Usar el cliente sin async with debe fallar limpio."""
    client = WazuhApiClient(settings)
    with pytest.raises(WazuhApiError, match="not initialized"):
        await client.get_rule("60106")
