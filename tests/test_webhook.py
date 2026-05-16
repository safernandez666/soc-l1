"""Tests del FastAPI service - webhook ingest con HMAC."""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.config import Settings
from src.main import app, get_settings

FIXTURES = Path(__file__).parent / "fixtures"
TEST_SECRET = "test-secret-32-chars-or-more-abc"


def _sign(body: bytes, secret: str = TEST_SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


@pytest.fixture
def client() -> TestClient:
    """TestClient con settings overrideado a un secret de test."""

    def _settings_override() -> Settings:
        return Settings(wazuh_webhook_secret=TEST_SECRET)

    app.dependency_overrides[get_settings] = _settings_override
    # Limpiar el cache del lru_cache
    get_settings.cache_clear()
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
    get_settings.cache_clear()


@pytest.fixture
def defender_body() -> bytes:
    return (FIXTURES / "defender_keygen.json").read_bytes()


def test_health_endpoint(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "service": "soc-l1"}


def test_webhook_accepts_signed_defender_alert(client: TestClient, defender_body: bytes) -> None:
    """Happy path: alerta Defender firmada correctamente devuelve 202."""
    headers = {"X-Wazuh-Signature": _sign(defender_body), "Content-Type": "application/json"}
    r = client.post("/webhook/wazuh-alert", content=defender_body, headers=headers)
    assert r.status_code == 202
    data = r.json()
    assert data["status"] == "accepted"
    assert data["alert_id"] == "synthetic-alert-id-001"
    assert data["source"] == "defender_via_wazuh"


def test_webhook_rejects_missing_signature(client: TestClient, defender_body: bytes) -> None:
    """Sin header X-Wazuh-Signature → 401."""
    r = client.post(
        "/webhook/wazuh-alert",
        content=defender_body,
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 401


def test_webhook_rejects_wrong_signature(client: TestClient, defender_body: bytes) -> None:
    """Firma con secret distinto → 401."""
    wrong_sig = _sign(defender_body, secret="wrong-secret")
    r = client.post(
        "/webhook/wazuh-alert",
        content=defender_body,
        headers={"X-Wazuh-Signature": wrong_sig, "Content-Type": "application/json"},
    )
    assert r.status_code == 401


def test_webhook_rejects_tampered_body(client: TestClient, defender_body: bytes) -> None:
    """Firma OK para el body original, pero mandamos body distinto → 401."""
    original_sig = _sign(defender_body)
    tampered = defender_body + b"   "  # mismo contenido + trailing space
    r = client.post(
        "/webhook/wazuh-alert",
        content=tampered,
        headers={"X-Wazuh-Signature": original_sig, "Content-Type": "application/json"},
    )
    assert r.status_code == 401


def test_webhook_rejects_invalid_json(client: TestClient) -> None:
    """JSON inválido → 400."""
    body = b"{not valid json"
    r = client.post(
        "/webhook/wazuh-alert",
        content=body,
        headers={"X-Wazuh-Signature": _sign(body), "Content-Type": "application/json"},
    )
    assert r.status_code == 400


def test_webhook_accepts_native_wazuh_alert(client: TestClient) -> None:
    """Alerta Wazuh nativa (sin Defender) también va por el mismo endpoint."""
    payload = {
        "agent": {"name": "web-prod-01", "id": "001"},
        "data": {"srcip": "203.0.113.45", "srcuser": "admin"},
        "rule": {
            "id": "5712",
            "level": 10,
            "description": "SSH brute force",
            "groups": ["authentication_failed"],
        },
        "id": "native-test-001",
        "timestamp": "2026-05-15T10:00:00Z",
    }
    body = json.dumps(payload).encode()
    r = client.post(
        "/webhook/wazuh-alert",
        content=body,
        headers={"X-Wazuh-Signature": _sign(body), "Content-Type": "application/json"},
    )
    assert r.status_code == 202
    data = r.json()
    assert data["source"] == "wazuh_native"
    assert data["alert_id"] == "native-test-001"
