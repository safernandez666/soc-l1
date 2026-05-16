"""Tests del Enricher agent - build, schemas, y lógica de tools sin tocar LLM real."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
import respx
from agents.run_context import RunContextWrapper
from agents.tool_context import ToolContext

from src.agents.enricher import (
    EnricherContext,
    EnrichedUser,
    EnrichmentResult,
    SYSTEM_PROMPT,
    build_enricher_agent,
    ldap_search_user,
    wazuh_get_rule,
)
from src.config import LdapConfig, Settings
from src.models import ADUser
from src.normalize import normalize

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def keygen_alert():
    raw = json.loads((FIXTURES / "defender_keygen.json").read_text())
    return normalize(raw)


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
def ldap_cfg() -> LdapConfig:
    return LdapConfig(
        host="ad.test",
        port=389,
        base_dn="DC=test,DC=local",
        bind_dn="svc@test.local",
        bind_password="x",
        use_starttls=False,
        credentials_file="/nonexistent",
    )


def _ctx(
    settings: Settings,
    ldap_cfg: LdapConfig | None,
    *,
    tool_name: str = "test_tool",
    arguments: str = "{}",
) -> ToolContext[EnricherContext]:
    """Construye un ToolContext (subclase de RunContextWrapper que las tools necesitan
    cuando se invocan vía on_invoke_tool desde tests)."""
    return ToolContext(
        context=EnricherContext(settings=settings, ldap_cfg=ldap_cfg),
        tool_name=tool_name,
        tool_call_id="test-call-id",
        tool_arguments=arguments,
    )


# ===== Schemas =====


def test_enrichment_result_validates() -> None:
    """Schema acepta input mínimo válido."""
    r = EnrichmentResult(summary="vacío", flags=[])
    assert r.users == []
    assert r.rule is None


def test_enriched_user_rejects_unknown_field() -> None:
    """extra='forbid' - schema drift sí causa error."""
    with pytest.raises(Exception):  # ValidationError
        EnrichedUser(sam="x", found_in_ad=True, random_field="oops")


# ===== Build / config =====


def test_build_enricher_has_tools_and_output() -> None:
    """Sanity: agent armado con ambos tools y output_type correcto."""
    agent = build_enricher_agent()
    assert agent.name == "Enricher"
    assert agent.output_type is EnrichmentResult
    tool_names = {t.name for t in agent.tools}
    assert tool_names == {"ldap_search_user", "wazuh_get_rule"}


def test_system_prompt_demanda_uso_de_tools() -> None:
    """Verificación textual: el prompt obliga a llamar las tools cuando corresponde."""
    assert "ldap_search_user" in SYSTEM_PROMPT
    assert "wazuh_get_rule" in SYSTEM_PROMPT
    assert "PROCEDIMIENTO OBLIGATORIO" in SYSTEM_PROMPT


# ===== ldap_search_user tool =====


@pytest.mark.asyncio
async def test_ldap_search_user_returns_found_payload(settings, ldap_cfg) -> None:
    """Cuando AD devuelve un user, la tool mapea los campos clave para el LLM."""
    fake_user = ADUser(
        dn="CN=jdoe,DC=test,DC=local",
        sam="jdoe",
        display_name="John Doe",
        mail="jdoe@test.local",
        department="IT",
        title="Engineer",
        manager="CN=mgr,DC=test,DC=local",
        member_of=["CN=g1,DC=test,DC=local", "CN=g2,DC=test,DC=local"],
        account_enabled=True,
        locked_out=False,
        last_logon="2026-05-15T12:00:00+00:00",
        bad_pwd_count=0,
        pwd_last_set="2026-01-01T00:00:00+00:00",
        user_account_control=512,
    )
    with patch("src.agents.enricher.ldap_tools.search_user", return_value=fake_user):
        result = await ldap_search_user.on_invoke_tool(
            _ctx(settings, ldap_cfg),
            json.dumps({"sam_account_name": "jdoe"}),
        )

    payload = json.loads(result) if isinstance(result, str) else result
    assert payload["found"] is True
    assert payload["sam"] == "jdoe"
    assert payload["department"] == "IT"
    assert payload["account_enabled"] is True
    assert payload["member_of_count"] == 2


@pytest.mark.asyncio
async def test_ldap_search_user_returns_not_found(settings, ldap_cfg) -> None:
    """Usuario que no existe en AD → found=false (no crash)."""
    with patch("src.agents.enricher.ldap_tools.search_user", return_value=None):
        result = await ldap_search_user.on_invoke_tool(
            _ctx(settings, ldap_cfg),
            json.dumps({"sam_account_name": "ghost"}),
        )
    payload = json.loads(result) if isinstance(result, str) else result
    assert payload == {"found": False, "sam": "ghost"}


@pytest.mark.asyncio
async def test_ldap_search_user_handles_exception(settings, ldap_cfg) -> None:
    """Errores de LDAP (timeout, bind, etc.) llegan al LLM como found=false + error."""
    with patch(
        "src.agents.enricher.ldap_tools.search_user",
        side_effect=Exception("LDAP timeout"),
    ):
        result = await ldap_search_user.on_invoke_tool(
            _ctx(settings, ldap_cfg),
            json.dumps({"sam_account_name": "jdoe"}),
        )
    payload = json.loads(result) if isinstance(result, str) else result
    assert payload["found"] is False
    assert "LDAP timeout" in payload["error"]


@pytest.mark.asyncio
async def test_ldap_search_user_when_no_ldap_configured(settings) -> None:
    """En entornos sin LDAP (ldap_cfg=None), la tool responde sin crashear."""
    result = await ldap_search_user.on_invoke_tool(
        _ctx(settings, None),
        json.dumps({"sam_account_name": "jdoe"}),
    )
    payload = json.loads(result) if isinstance(result, str) else result
    assert payload["found"] is False
    assert "no configurado" in payload["error"]


# ===== wazuh_get_rule tool =====


def _auth_response() -> httpx.Response:
    return httpx.Response(200, json={"data": {"token": "FAKE.JWT"}})


def _rule_response() -> httpx.Response:
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
                        "gdpr": [],
                        "pci_dss": ["10.6.1"],
                    }
                ]
            }
        },
    )


@pytest.mark.asyncio
async def test_wazuh_get_rule_returns_full_detail(settings) -> None:
    with respx.mock(base_url="https://wazuh.test:55000") as mock:
        mock.post("/security/user/authenticate").mock(return_value=_auth_response())
        mock.get("/rules", params={"rule_ids": "60106"}).mock(
            return_value=_rule_response()
        )
        result = await wazuh_get_rule.on_invoke_tool(
            _ctx(settings, None),
            json.dumps({"rule_id": "60106"}),
        )
    payload = json.loads(result) if isinstance(result, str) else result
    assert payload["found"] is True
    assert payload["rule_id"] == "60106"
    assert payload["mitre_ids"] == ["T1588.002"]
    assert "defender" in payload["groups"]


@pytest.mark.asyncio
async def test_wazuh_get_rule_when_not_configured() -> None:
    """Si wazuh_api_password está vacío (entorno dev), tool responde sin crashear."""
    s = Settings(openai_api_key="test", wazuh_api_password="")
    result = await wazuh_get_rule.on_invoke_tool(
        _ctx(s, None),
        json.dumps({"rule_id": "60106"}),
    )
    payload = json.loads(result) if isinstance(result, str) else result
    assert payload["found"] is False
    assert "no configurado" in payload["error"]


@pytest.mark.asyncio
async def test_wazuh_get_rule_handles_api_error(settings) -> None:
    """Manager devuelve error → llega al LLM como found=false + error."""
    with respx.mock(base_url="https://wazuh.test:55000") as mock:
        mock.post("/security/user/authenticate").mock(
            return_value=httpx.Response(500, json={"error": "boom"})
        )
        result = await wazuh_get_rule.on_invoke_tool(
            _ctx(settings, None),
            json.dumps({"rule_id": "60106"}),
        )
    payload = json.loads(result) if isinstance(result, str) else result
    assert payload["found"] is False
    assert "auth failed" in payload["error"]
