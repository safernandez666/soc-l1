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


# ===== Fase 1: enforce() ejecuta el quarantine real =====


def _mock_fgt_client(quarantine_result):
    """Devuelve (factory, client) para patchear FortigateClient como async ctx manager."""
    from unittest.mock import AsyncMock, MagicMock

    client = AsyncMock()
    client.quarantine_ip = AsyncMock(return_value=quarantine_result)
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=client)
    cm.__aexit__ = AsyncMock(return_value=False)
    factory = MagicMock(return_value=cm)
    return factory, client


def _enforce_settings(tmp_path: Path, **kw) -> Settings:
    base = dict(
        fortigate_autoblock_enabled=True,
        fortigate_host="fg.test",
        fortigate_token="t",
        protected_networks="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8",
        state_db_path=str(tmp_path / "state.db"),
    )
    base.update(kw)
    return Settings(**base)


@pytest.mark.asyncio
async def test_enforce_ejecuta_quarantine_real(fgt_alert: dict, tmp_path: Path) -> None:
    """should_block + no dry-run + configurado → llama quarantine_ip con ip+ttl correctos."""
    from unittest.mock import patch

    from src.fortigate_autoblock import enforce
    from src.models import FortigateActionResult

    alert = normalize(fgt_alert)
    settings = _enforce_settings(tmp_path)  # ttl default 1h
    result = FortigateActionResult(
        ok=True, ip="203.0.113.66", action="quarantine_ip",
        expires_at="2026-06-23T13:00:00+00:00", message="banned for 3600s",
    )
    factory, client = _mock_fgt_client(result)
    with patch("src.fortigate_autoblock.FortigateClient", factory):
        outcome = await enforce(alert, settings)

    client.quarantine_ip.assert_called_once_with("203.0.113.66", ttl_seconds=3600)
    assert outcome.executed is True
    assert outcome.ok is True
    assert outcome.expires_at == "2026-06-23T13:00:00+00:00"
    # registró en el JSONL con executed/block_ok
    rec = json.loads((tmp_path / "fgt_observations.jsonl").read_text().splitlines()[-1])
    assert rec["executed"] is True and rec["block_ok"] is True


@pytest.mark.asyncio
async def test_enforce_dry_run_fortigate_no_ejecuta(fgt_alert: dict, tmp_path: Path) -> None:
    """dry_run_fortigate=true (master off) → simula, NO toca FortiGate."""
    from unittest.mock import patch

    from src.fortigate_autoblock import enforce

    alert = normalize(fgt_alert)
    settings = _enforce_settings(tmp_path, dry_run_mode=False, dry_run_fortigate="true")
    factory, client = _mock_fgt_client(None)
    with patch("src.fortigate_autoblock.FortigateClient", factory):
        outcome = await enforce(alert, settings)

    factory.assert_not_called()
    client.quarantine_ip.assert_not_called()
    assert outcome.executed is False and outcome.ok is False
    assert "DRY_RUN" in (outcome.message or "")


@pytest.mark.asyncio
async def test_enforce_master_kill_switch_no_ejecuta(fgt_alert: dict, tmp_path: Path) -> None:
    """dry_run_mode=true (master) fuerza simulación aunque dry_run_fortigate=false."""
    from unittest.mock import patch

    from src.fortigate_autoblock import enforce

    alert = normalize(fgt_alert)
    settings = _enforce_settings(tmp_path, dry_run_mode=True, dry_run_fortigate="false")
    factory, client = _mock_fgt_client(None)
    with patch("src.fortigate_autoblock.FortigateClient", factory):
        outcome = await enforce(alert, settings)

    client.quarantine_ip.assert_not_called()
    assert outcome.executed is False and outcome.ok is False


@pytest.mark.asyncio
async def test_enforce_ip_protegida_no_ejecuta(fgt_alert: dict, tmp_path: Path) -> None:
    """IP del atacante en red protegida → candidata pero NO bloquea."""
    from unittest.mock import patch

    from src.fortigate_autoblock import enforce

    raw = copy.deepcopy(fgt_alert)
    raw["data"]["srcip"] = "10.99.0.42"
    alert = normalize(raw)
    settings = _enforce_settings(tmp_path)
    factory, client = _mock_fgt_client(None)
    with patch("src.fortigate_autoblock.FortigateClient", factory):
        outcome = await enforce(alert, settings)

    client.quarantine_ip.assert_not_called()
    assert outcome.executed is False and outcome.ok is False
    assert outcome.decision.reason == "protected"


@pytest.mark.asyncio
async def test_webhook_fase1_bloquea_y_corta(fgt_alert: dict, tmp_path: Path) -> None:
    """En Fase 1, una alerta candidata bloquea y corta: 202 'blocked_fgt_autoblock'."""
    import hashlib
    import hmac
    from unittest.mock import patch

    from fastapi.testclient import TestClient

    from src.config import get_settings
    from src.main import app
    from src.models import FortigateActionResult

    TEST_SECRET = "test-secret-32-chars-or-more-abc"

    def _override() -> Settings:
        return Settings(
            wazuh_webhook_secret=TEST_SECRET,
            webhook_allowed_ips="127.0.0.1,testclient",
            fortigate_autoblock_enabled=True,  # Fase 1
            fortigate_host="fg.test",
            fortigate_token="t",
            protected_networks="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8",
            state_db_path=str(tmp_path / "state.db"),
            smtp_host="",  # sin SMTP → no manda email, no rompe
        )

    result = FortigateActionResult(
        ok=True, ip="203.0.113.66", action="quarantine_ip",
        expires_at="2026-06-23T13:00:00+00:00", message="banned",
    )
    factory, client = _mock_fgt_client(result)

    app.dependency_overrides[get_settings] = _override
    get_settings.cache_clear()
    try:
        body = json.dumps(fgt_alert).encode()
        sig = "sha256=" + hmac.new(TEST_SECRET.encode(), body, hashlib.sha256).hexdigest()
        with patch("src.fortigate_autoblock.FortigateClient", factory):
            with TestClient(app) as c:
                r = c.post(
                    "/webhook/wazuh-alert",
                    content=body,
                    headers={"X-Wazuh-Signature": sig, "Content-Type": "application/json"},
                )
        assert r.status_code == 202
        data = r.json()
        assert data["status"] == "blocked_fgt_autoblock"
        assert data["blocked_ip"] == "203.0.113.66"
        assert data["ok"] is True
        client.quarantine_ip.assert_called_once_with("203.0.113.66", ttl_seconds=3600)
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()


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


# ===== Dedup por IP dentro de la ventana TTL =====


def test_observe_dedup_misma_ip_una_sola_observacion(fgt_alert: dict, tmp_path: Path) -> None:
    """Una ráfaga de la misma IP (Wazuh emite N alertas) se observa UNA sola vez:
    la 2ª vuelve duplicate=True y el JSONL queda con 1 sola fila (UI sin duplicados)."""
    from src.fortigate_autoblock import observe

    alert = normalize(fgt_alert)
    settings = _enforce_settings(tmp_path, fortigate_autoblock_enabled=False)

    d1 = observe(alert, settings)
    d2 = observe(alert, settings)

    assert d1.should_block is True and d1.duplicate is False
    assert d2.duplicate is True
    lines = (tmp_path / "fgt_observations.jsonl").read_text().splitlines()
    assert len(lines) == 1


@pytest.mark.asyncio
async def test_enforce_dedup_no_rebloquea(fgt_alert: dict, tmp_path: Path) -> None:
    """En Fase 1, la misma IP en ráfaga se bloquea UNA vez: el 2º enforce no llama a
    quarantine_ip (el ban TTL sigue activo) y devuelve duplicate=True."""
    from unittest.mock import patch

    from src.fortigate_autoblock import enforce
    from src.models import FortigateActionResult

    alert = normalize(fgt_alert)
    settings = _enforce_settings(tmp_path)
    result = FortigateActionResult(
        ok=True, ip="203.0.113.66", action="quarantine_ip",
        expires_at="2026-06-23T13:00:00+00:00", message="banned for 3600s",
    )
    factory, client = _mock_fgt_client(result)
    with patch("src.fortigate_autoblock.FortigateClient", factory):
        o1 = await enforce(alert, settings)
        o2 = await enforce(alert, settings)

    client.quarantine_ip.assert_called_once_with("203.0.113.66", ttl_seconds=3600)
    assert o1.ok is True and o1.decision.duplicate is False
    assert o2.executed is False and o2.decision.duplicate is True
    # JSONL: solo el primer bloqueo quedó registrado
    lines = (tmp_path / "fgt_observations.jsonl").read_text().splitlines()
    assert len(lines) == 1
