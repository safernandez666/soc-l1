"""Tests del ThreatIntel agent - schemas + build + tools (sin tocar LLM real)."""
from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from agents.tool_context import ToolContext

from src.agents.threatintel import (
    SYSTEM_PROMPT,
    ThreatIntelContext,
    ThreatIntelResult,
    abuseipdb_check,
    build_threatintel_agent,
    vt_lookup_hash,
)
from src.config import Settings
from src.normalize import normalize

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def alert():
    raw = json.loads((FIXTURES / "defender_keygen.json").read_text())
    return normalize(raw)


@pytest.fixture
def settings_full() -> Settings:
    return Settings(
        openai_api_key="x",
        virustotal_api_key="VT-KEY",
        abuseipdb_api_key="AB-KEY",
    )


def _ctx(settings: Settings, *, tool_name: str = "test", args: str = "{}") -> ToolContext[ThreatIntelContext]:
    return ToolContext(
        context=ThreatIntelContext(settings=settings),
        tool_name=tool_name,
        tool_call_id="test-id",
        tool_arguments=args,
    )


# ===== Schemas =====


def test_threatintel_result_accepts_empty() -> None:
    r = ThreatIntelResult(summary="nada que consultar", flags=["no_ti_data"])
    assert r.file_reports == []
    assert r.ip_reports == []


def test_threatintel_result_rejects_unknown_field() -> None:
    with pytest.raises(Exception):
        ThreatIntelResult(summary="x", flags=[], unknown_field="bad")


# ===== Build / config =====


def test_build_threatintel_agent_has_all_tools() -> None:
    agent = build_threatintel_agent()
    assert agent.name == "ThreatIntel"
    assert agent.output_type is ThreatIntelResult
    tool_names = {t.name for t in agent.tools}
    assert tool_names == {"vt_lookup_hash", "abuseipdb_check", "fortigate_check_ip"}


def test_system_prompt_orienta_uso_correcto() -> None:
    """Prompt obliga skipear IPs RFC1918 (privadas no tienen sentido en AbuseIPDB)."""
    assert "vt_lookup_hash" in SYSTEM_PROMPT
    assert "abuseipdb_check" in SYSTEM_PROMPT
    assert "RFC1918" in SYSTEM_PROMPT
    assert "MÁXIMO 1 VEZ" in SYSTEM_PROMPT


# ===== vt_lookup_hash tool =====


@pytest.mark.asyncio
async def test_vt_lookup_hash_returns_full(settings_full) -> None:
    with respx.mock(base_url="https://www.virustotal.com/api/v3") as mock:
        mock.get("/files/abc").mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "sha256": "abc",
                            "last_analysis_stats": {
                                "malicious": 55, "suspicious": 0, "undetected": 15,
                                "harmless": 0, "timeout": 0,
                            },
                            "popular_threat_classification": {
                                "suggested_threat_label": "trojan.eicar"
                            },
                            "names": ["eicar.com"],
                        }
                    }
                },
            )
        )
        result = await vt_lookup_hash.on_invoke_tool(
            _ctx(settings_full), json.dumps({"sha256": "abc"})
        )

    payload = json.loads(result) if isinstance(result, str) else result
    assert payload["found"] is True
    assert payload["malicious_count"] == 55
    assert payload["family"] == "trojan.eicar"


@pytest.mark.asyncio
async def test_vt_lookup_hash_not_found(settings_full) -> None:
    with respx.mock(base_url="https://www.virustotal.com/api/v3") as mock:
        mock.get("/files/x").mock(return_value=httpx.Response(404))
        result = await vt_lookup_hash.on_invoke_tool(
            _ctx(settings_full), json.dumps({"sha256": "x"})
        )
    payload = json.loads(result) if isinstance(result, str) else result
    assert payload["found"] is False
    assert "VT no conoce" in payload["note"]


@pytest.mark.asyncio
async def test_vt_lookup_hash_when_no_key() -> None:
    s = Settings(openai_api_key="x", virustotal_api_key="")
    result = await vt_lookup_hash.on_invoke_tool(
        _ctx(s), json.dumps({"sha256": "abc"})
    )
    payload = json.loads(result) if isinstance(result, str) else result
    assert payload["found"] is False
    assert "no configurado" in payload["error"]


@pytest.mark.asyncio
async def test_vt_lookup_hash_handles_api_error(settings_full) -> None:
    with respx.mock(base_url="https://www.virustotal.com/api/v3") as mock:
        mock.get("/files/x").mock(return_value=httpx.Response(429))
        result = await vt_lookup_hash.on_invoke_tool(
            _ctx(settings_full), json.dumps({"sha256": "x"})
        )
    payload = json.loads(result) if isinstance(result, str) else result
    assert payload["found"] is False
    assert "rate limit" in payload["error"]


@pytest.mark.asyncio
async def test_vt_lookup_hash_caches_result(settings_full) -> None:
    """LLM repite la call con mismo hash → 2do call viene del cache."""
    ctx = _ctx(settings_full)
    with respx.mock(base_url="https://www.virustotal.com/api/v3") as mock:
        route = mock.get("/files/abc").mock(
            return_value=httpx.Response(
                200,
                json={"data": {"attributes": {"sha256": "abc", "last_analysis_stats": {}}}},
            )
        )
        r1 = await vt_lookup_hash.on_invoke_tool(ctx, json.dumps({"sha256": "abc"}))
        r2 = await vt_lookup_hash.on_invoke_tool(ctx, json.dumps({"sha256": "abc"}))

    assert route.call_count == 1
    p2 = json.loads(r2) if isinstance(r2, str) else r2
    assert p2["_cache_hit"] is True
    assert "Ya llamaste" in p2["_warning"]


# ===== abuseipdb_check tool =====


@pytest.mark.asyncio
async def test_abuseipdb_check_returns_score(settings_full) -> None:
    with respx.mock(base_url="https://api.abuseipdb.com/api/v2") as mock:
        mock.get("/check").mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "ipAddress": "1.2.3.4",
                        "abuseConfidenceScore": 92,
                        "countryCode": "RU",
                        "totalReports": 42,
                    }
                },
            )
        )
        result = await abuseipdb_check.on_invoke_tool(
            _ctx(settings_full), json.dumps({"ip": "1.2.3.4"})
        )

    payload = json.loads(result) if isinstance(result, str) else result
    assert payload["found"] is True
    assert payload["abuse_confidence_score"] == 92
    assert payload["country_code"] == "RU"


@pytest.mark.asyncio
async def test_abuseipdb_check_invalid_ip(settings_full) -> None:
    with respx.mock(base_url="https://api.abuseipdb.com/api/v2") as mock:
        mock.get("/check").mock(return_value=httpx.Response(422))
        result = await abuseipdb_check.on_invoke_tool(
            _ctx(settings_full), json.dumps({"ip": "not-an-ip"})
        )
    payload = json.loads(result) if isinstance(result, str) else result
    assert payload["found"] is False
    assert "inválida" in payload["note"]


@pytest.mark.asyncio
async def test_abuseipdb_check_when_no_key() -> None:
    s = Settings(openai_api_key="x", abuseipdb_api_key="")
    result = await abuseipdb_check.on_invoke_tool(
        _ctx(s), json.dumps({"ip": "1.2.3.4"})
    )
    payload = json.loads(result) if isinstance(result, str) else result
    assert payload["found"] is False
    assert "no configurado" in payload["error"]


@pytest.mark.asyncio
async def test_abuseipdb_check_caches_result(settings_full) -> None:
    ctx = _ctx(settings_full)
    with respx.mock(base_url="https://api.abuseipdb.com/api/v2") as mock:
        route = mock.get("/check").mock(
            return_value=httpx.Response(
                200, json={"data": {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 50}}
            )
        )
        await abuseipdb_check.on_invoke_tool(ctx, json.dumps({"ip": "1.2.3.4"}))
        r2 = await abuseipdb_check.on_invoke_tool(ctx, json.dumps({"ip": "1.2.3.4"}))

    assert route.call_count == 1
    p2 = json.loads(r2) if isinstance(r2, str) else r2
    assert p2["_cache_hit"] is True
