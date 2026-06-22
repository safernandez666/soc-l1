"""Fase 0 del auto-block FortiGate: evaluación de la decisión (sin ejecutar).

Ver docs/fortigate-autoblock-plan.md y src/fortigate_autoblock.py.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from src.config import Settings
from src.fortigate_autoblock import evaluate
from src.normalize import normalize

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fgt_alert() -> dict:
    return json.loads((FIXTURES / "fortigate_ips_critical.json").read_text())


def _settings() -> Settings:
    # Defaults: la regla 196201 está en la allowlist; protected_networks RFC1918.
    return Settings(
        fortigate_autoblock_enabled=False,
        protected_networks="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8",
    )


def test_normalize_extrae_srcip_y_rule(fgt_alert: dict) -> None:
    """Sanity: el normalizer (path nativo) saca srcip y rule.id de una alerta FGT IPS."""
    alert = normalize(fgt_alert)
    assert alert.wazuh_rule.id == "196201"
    assert alert.network.src_ip_external == "203.0.113.66"


def test_candidata_bloquearia_ip_publica(fgt_alert: dict) -> None:
    alert = normalize(fgt_alert)
    d = evaluate(alert, _settings())
    assert d.candidate is True
    assert d.should_block is True
    assert d.ip == "203.0.113.66"
    assert d.reason == "would_block"


def test_ip_protegida_no_bloquea(fgt_alert: dict) -> None:
    """Si el atacante cae en una red protegida (RFC1918), NO se bloquea."""
    raw = copy.deepcopy(fgt_alert)
    raw["data"]["srcip"] = "10.99.0.42"  # dentro de 10.0.0.0/8
    alert = normalize(raw)
    d = evaluate(alert, _settings())
    assert d.candidate is True
    assert d.should_block is False
    assert d.reason == "protected"
    assert d.ip is None
    assert d.protected_match == "10.0.0.0/8"


def test_regla_fuera_de_allowlist_no_es_candidata(fgt_alert: dict) -> None:
    """La regla base 196200 (level 3, solo 'evento detectado') no auto-bloquea."""
    raw = copy.deepcopy(fgt_alert)
    raw["rule"]["id"] = "196200"
    alert = normalize(raw)
    d = evaluate(alert, _settings())
    assert d.candidate is False
    assert d.should_block is False
    assert d.reason == "no_rule_match"


def test_sin_srcip_candidata_pero_no_bloquea(fgt_alert: dict) -> None:
    raw = copy.deepcopy(fgt_alert)
    raw["data"].pop("srcip")
    alert = normalize(raw)
    d = evaluate(alert, _settings())
    assert d.candidate is True
    assert d.should_block is False
    assert d.reason == "no_srcip"


def test_allowlist_configurable(fgt_alert: dict) -> None:
    """Si se saca 196201 de la allowlist, deja de ser candidata."""
    alert = normalize(fgt_alert)
    s = Settings(fortigate_auto_block_rules="196202,196203")
    d = evaluate(alert, s)
    assert d.candidate is False


def test_webhook_fase0_observa_y_corta(fgt_alert: dict) -> None:
    """En Fase 0, una alerta candidata se observa y corta: 202 'observed_fgt_autoblock',
    sin lanzar el pipeline (no email/ticket)."""
    import hashlib
    import hmac

    from fastapi.testclient import TestClient

    from src.config import get_settings
    from src.main import app

    TEST_SECRET = "test-secret-32-chars-or-more-abc"

    def _override() -> Settings:
        return Settings(
            wazuh_webhook_secret=TEST_SECRET,
            webhook_allowed_ips="127.0.0.1,testclient",
            fortigate_autoblock_enabled=False,  # Fase 0
        )

    app.dependency_overrides[get_settings] = _override
    get_settings.cache_clear()
    try:
        body = json.dumps(fgt_alert).encode()
        sig = "sha256=" + hmac.new(TEST_SECRET.encode(), body, hashlib.sha256).hexdigest()
        with TestClient(app) as c:
            r = c.post(
                "/webhook/wazuh-alert",
                content=body,
                headers={"X-Wazuh-Signature": sig, "Content-Type": "application/json"},
            )
        assert r.status_code == 202
        data = r.json()
        assert data["status"] == "observed_fgt_autoblock"
        assert data["would_block"] == "203.0.113.66"
        assert data["rule_id"] == "196201"
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()
