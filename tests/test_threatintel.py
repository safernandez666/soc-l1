"""Tests de VirusTotalClient y AbuseipdbClient (sin tocar APIs reales)."""
from __future__ import annotations

import httpx
import pytest
import respx

from src.config import Settings
from src.tools.threatintel import (
    AbuseipdbClient,
    ThreatIntelError,
    VirusTotalClient,
)


@pytest.fixture
def settings_full() -> Settings:
    return Settings(
        openai_api_key="x",
        virustotal_api_key="VT-TEST-KEY",
        abuseipdb_api_key="AB-TEST-KEY",
    )


# ===== VirusTotal =====

VT_URL = "https://www.virustotal.com/api/v3"


def _vt_file_response(sha256: str = "abc123") -> httpx.Response:
    """Response típico de /files/{sha256}: malicious=55/72 engines."""
    return httpx.Response(
        200,
        json={
            "data": {
                "id": sha256,
                "type": "file",
                "attributes": {
                    "sha256": sha256,
                    "size": 68,
                    "type_description": "Text",
                    "names": ["eicar.com", "test.txt"],
                    "first_submission_date": 1234567890,
                    "last_analysis_date": 1700000000,
                    "last_analysis_stats": {
                        "harmless": 0,
                        "malicious": 55,
                        "suspicious": 2,
                        "undetected": 15,
                        "timeout": 0,
                    },
                    "popular_threat_classification": {
                        "suggested_threat_label": "trojan.eicar/test",
                        "popular_threat_category": [
                            {"count": 50, "value": "trojan"},
                            {"count": 20, "value": "test-file"},
                        ],
                    },
                },
            }
        },
    )


@pytest.mark.asyncio
async def test_vt_get_file_report_parses_full_response(settings_full) -> None:
    with respx.mock(base_url=VT_URL, assert_all_called=True) as mock:
        mock.get("/files/abc123", headers={"x-apikey": "VT-TEST-KEY"}).mock(
            return_value=_vt_file_response("abc123")
        )
        async with VirusTotalClient(settings_full) as vt:
            report = await vt.get_file_report("abc123")

    assert report is not None
    assert report.sha256 == "abc123"
    assert report.malicious_count == 55
    assert report.suspicious_count == 2
    assert report.undetected_count == 15
    assert report.total_engines == 72  # 0+55+2+15+0
    assert report.family == "trojan.eicar/test"
    assert "trojan" in report.categories
    assert report.names == ["eicar.com", "test.txt"]
    assert report.type_description == "Text"
    assert report.size == 68


@pytest.mark.asyncio
async def test_vt_404_returns_none(settings_full) -> None:
    """File desconocido por VT → None (no es error)."""
    with respx.mock(base_url=VT_URL) as mock:
        mock.get("/files/unknown").mock(return_value=httpx.Response(404))
        async with VirusTotalClient(settings_full) as vt:
            report = await vt.get_file_report("unknown")
    assert report is None


@pytest.mark.asyncio
async def test_vt_401_raises_with_helpful_msg(settings_full) -> None:
    with respx.mock(base_url=VT_URL) as mock:
        mock.get("/files/x").mock(return_value=httpx.Response(401, json={}))
        async with VirusTotalClient(settings_full) as vt:
            with pytest.raises(ThreatIntelError, match="VIRUSTOTAL_API_KEY"):
                await vt.get_file_report("x")


@pytest.mark.asyncio
async def test_vt_429_rate_limit(settings_full) -> None:
    with respx.mock(base_url=VT_URL) as mock:
        mock.get("/files/x").mock(return_value=httpx.Response(429))
        async with VirusTotalClient(settings_full) as vt:
            with pytest.raises(ThreatIntelError, match="rate limit"):
                await vt.get_file_report("x")


@pytest.mark.asyncio
async def test_vt_missing_key_raises_on_enter() -> None:
    s = Settings(openai_api_key="x", virustotal_api_key="")
    with pytest.raises(ThreatIntelError, match="VIRUSTOTAL_API_KEY no configurada"):
        async with VirusTotalClient(s):
            pass


@pytest.mark.asyncio
async def test_vt_handles_minimal_response(settings_full) -> None:
    """Si VT devuelve un attrs casi vacío, parseamos sin crash."""
    minimal = httpx.Response(
        200,
        json={
            "data": {
                "id": "abc",
                "type": "file",
                "attributes": {"sha256": "abc"},
            }
        },
    )
    with respx.mock(base_url=VT_URL) as mock:
        mock.get("/files/abc").mock(return_value=minimal)
        async with VirusTotalClient(settings_full) as vt:
            r = await vt.get_file_report("abc")
    assert r is not None
    assert r.sha256 == "abc"
    assert r.malicious_count == 0
    assert r.family is None
    assert r.categories == []


# ===== AbuseIPDB =====

AB_URL = "https://api.abuseipdb.com/api/v2"


def _ab_response(ip: str = "1.2.3.4", score: int = 75) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "data": {
                "ipAddress": ip,
                "abuseConfidenceScore": score,
                "countryCode": "RU",
                "isp": "Bad ISP Ltd",
                "domain": "bad.example",
                "totalReports": 42,
                "numDistinctUsers": 15,
                "lastReportedAt": "2026-05-15T10:00:00+00:00",
                "isWhitelisted": False,
                "isTor": False,
                "usageType": "Data Center/Web Hosting/Transit",
            }
        },
    )


@pytest.mark.asyncio
async def test_ab_check_ip_parses_response(settings_full) -> None:
    with respx.mock(base_url=AB_URL, assert_all_called=True) as mock:
        mock.get(
            "/check",
            params={"ipAddress": "1.2.3.4", "maxAgeInDays": 90},
            headers={"Key": "AB-TEST-KEY", "Accept": "application/json"},
        ).mock(return_value=_ab_response("1.2.3.4", 75))

        async with AbuseipdbClient(settings_full) as ab:
            report = await ab.check_ip("1.2.3.4")

    assert report is not None
    assert report.ip == "1.2.3.4"
    assert report.abuse_confidence_score == 75
    assert report.country_code == "RU"
    assert report.total_reports == 42
    assert report.distinct_reporters == 15
    assert report.usage_type == "Data Center/Web Hosting/Transit"
    assert report.is_whitelisted is False


@pytest.mark.asyncio
async def test_ab_422_invalid_ip_returns_none(settings_full) -> None:
    with respx.mock(base_url=AB_URL) as mock:
        mock.get("/check").mock(return_value=httpx.Response(422, json={"errors": []}))
        async with AbuseipdbClient(settings_full) as ab:
            r = await ab.check_ip("not-an-ip")
    assert r is None


@pytest.mark.asyncio
async def test_ab_401_raises_with_helpful_msg(settings_full) -> None:
    with respx.mock(base_url=AB_URL) as mock:
        mock.get("/check").mock(return_value=httpx.Response(401))
        async with AbuseipdbClient(settings_full) as ab:
            with pytest.raises(ThreatIntelError, match="ABUSEIPDB_API_KEY"):
                await ab.check_ip("1.2.3.4")


@pytest.mark.asyncio
async def test_ab_429_rate_limit(settings_full) -> None:
    with respx.mock(base_url=AB_URL) as mock:
        mock.get("/check").mock(return_value=httpx.Response(429))
        async with AbuseipdbClient(settings_full) as ab:
            with pytest.raises(ThreatIntelError, match="rate limit"):
                await ab.check_ip("1.2.3.4")


@pytest.mark.asyncio
async def test_ab_missing_key_raises_on_enter() -> None:
    s = Settings(openai_api_key="x", abuseipdb_api_key="")
    with pytest.raises(ThreatIntelError, match="ABUSEIPDB_API_KEY no configurada"):
        async with AbuseipdbClient(s):
            pass


@pytest.mark.asyncio
async def test_ab_max_age_days_param_pasa(settings_full) -> None:
    """Cliente debe respetar max_age_days en el query string."""
    with respx.mock(base_url=AB_URL, assert_all_called=True) as mock:
        mock.get(
            "/check",
            params={"ipAddress": "1.2.3.4", "maxAgeInDays": 365},
        ).mock(return_value=_ab_response())
        async with AbuseipdbClient(settings_full) as ab:
            await ab.check_ip("1.2.3.4", max_age_days=365)


@pytest.mark.asyncio
async def test_ab_low_score_whitelisted_response(settings_full) -> None:
    """Sanity: IP buena (ej. Google DNS) debería devolver score bajo."""
    good = httpx.Response(
        200,
        json={
            "data": {
                "ipAddress": "8.8.8.8",
                "abuseConfidenceScore": 0,
                "countryCode": "US",
                "isp": "Google LLC",
                "totalReports": 1,
                "isWhitelisted": True,
            }
        },
    )
    with respx.mock(base_url=AB_URL) as mock:
        mock.get("/check").mock(return_value=good)
        async with AbuseipdbClient(settings_full) as ab:
            r = await ab.check_ip("8.8.8.8")
    assert r.abuse_confidence_score == 0
    assert r.is_whitelisted is True
    assert r.isp == "Google LLC"
