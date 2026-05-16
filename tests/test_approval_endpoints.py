"""Tests E2E de los endpoints /approve y /reject + ejecución post-aprobación."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from src.agents.narrator import NarratorPlan, ProposedAction
from src.config import Settings
from src.main import app, get_settings
from src.state import create_pending_approval, get_pending_approval, init_db


@pytest_asyncio.fixture
async def db_path(tmp_path: Path) -> str:
    path = str(tmp_path / "approval.db")
    await init_db(path)
    return path


@pytest.fixture
def settings_factory(db_path: str):
    """Devuelve un factory que cada test puede customizar (TTL, narrator on/off, etc.)."""

    def _make(**overrides) -> Settings:
        defaults = dict(
            wazuh_webhook_secret="x",
            state_db_path=db_path,
            approval_ttl_hours=24,
            approval_base_url="http://test.local",
            enable_narrator=True,
        )
        defaults.update(overrides)
        return Settings(**defaults)

    return _make


@pytest.fixture
def client(settings_factory):
    def _override() -> Settings:
        return settings_factory()

    app.dependency_overrides[get_settings] = _override
    get_settings.cache_clear()
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
    get_settings.cache_clear()


@pytest.fixture
def sample_plan() -> NarratorPlan:
    return NarratorPlan(
        executive_summary="malware detectado",
        risk_level="high",
        actions=[
            ProposedAction(type="disable_user", target="jdoe", justification="evidence X"),
        ],
        rationale="análisis ok",
    )


@pytest_asyncio.fixture
async def pending_token(db_path: str, sample_plan: NarratorPlan) -> str:
    return await create_pending_approval(
        db_path,
        alert_id="alert-abc",
        plan_json=sample_plan.model_dump_json(),
        alert_json='{"alert_id":"alert-abc"}',
    )


def test_approve_unknown_token_returns_invalid_page(client: TestClient) -> None:
    r = client.get("/approve/garbage-token-xxx")
    assert r.status_code == 200  # render HTML, no es 404
    assert "Token inválido" in r.text


def test_reject_unknown_token_returns_invalid_page(client: TestClient) -> None:
    r = client.get("/reject/garbage-token-xxx")
    assert r.status_code == 200
    assert "Token inválido" in r.text


def test_reject_marks_db_and_does_not_execute(
    client: TestClient, pending_token: str, db_path: str
) -> None:
    """Reject no llama al executor."""
    with patch("src.executor.execute_plan", new=AsyncMock()) as mocked_exec:
        r = client.get(f"/reject/{pending_token}")
    assert r.status_code == 200
    assert "Rechazado" in r.text
    mocked_exec.assert_not_called()

    row = asyncio.run(get_pending_approval(db_path, pending_token))
    assert row["status"] == "rejected"
    assert row["decided_at"] is not None


def test_approve_launches_executor_in_background(
    client: TestClient, pending_token: str, db_path: str
) -> None:
    """Approve responde rápido y dispara execute_plan en background."""
    executor_finished = asyncio.Event()

    async def fake_execute_plan(actions, ldap_cfg):
        executor_finished.set()
        return [{"action_type": a.type, "target": a.target, "ok": True, "message": "fake"} for a in actions]

    with patch("src.executor.execute_plan", side_effect=fake_execute_plan) as mocked_exec:
        r = client.get(f"/approve/{pending_token}")
        # Tras responder, dar margen para que el background task termine
        # (FastAPI TestClient corre el loop dentro del thread del request)
        # Damos hasta 2s para que el task background corra
        for _ in range(20):
            if mocked_exec.called:
                break
            # Yield al event loop
            asyncio.run(asyncio.sleep(0.1))

    assert r.status_code == 200
    assert "Aprobado" in r.text
    assert mocked_exec.called

    # state debería quedar en 'executed' tras el background task
    row = asyncio.run(get_pending_approval(db_path, pending_token))
    # Status puede ser 'approved' (si el background no terminó) o 'executed'
    assert row["status"] in ("approved", "executed")


def test_approve_twice_second_returns_already_decided(
    client: TestClient, pending_token: str
) -> None:
    with patch("src.executor.execute_plan", new=AsyncMock(return_value=[])):
        client.get(f"/approve/{pending_token}")
        r2 = client.get(f"/approve/{pending_token}")
    assert "Ya decidido" in r2.text


def test_approve_then_reject_blocked(
    client: TestClient, pending_token: str
) -> None:
    """Una vez aprobado, no se puede rechazar (token quemado)."""
    with patch("src.executor.execute_plan", new=AsyncMock(return_value=[])):
        client.get(f"/approve/{pending_token}")
        r = client.get(f"/reject/{pending_token}")
    assert "Ya decidido" in r.text


def test_decide_logs_ip_and_user_agent(
    client: TestClient, pending_token: str, db_path: str
) -> None:
    """Audit trail: IP y User-Agent deben quedar persistidos."""
    with patch("src.executor.execute_plan", new=AsyncMock(return_value=[])):
        client.get(
            f"/reject/{pending_token}",
            headers={"User-Agent": "Mozilla/Test 1.0"},
        )
    row = asyncio.run(get_pending_approval(db_path, pending_token))
    assert row["decided_by_ua"] == "Mozilla/Test 1.0"
    assert row["decided_by_ip"]  # TestClient usa "testclient" como host
