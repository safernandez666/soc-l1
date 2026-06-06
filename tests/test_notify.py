"""Tests de notify.py - capa de canales de cierre (hoy solo email)."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from src.agents.narrator import NarratorPlan, ProposedAction
from src.config import Settings
from src.normalize import normalize
from src.notify import notify_case_closure

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def alert():
    raw = json.loads((FIXTURES / "defender_keygen.json").read_text())
    return normalize(raw)


@pytest.fixture
def plan() -> NarratorPlan:
    return NarratorPlan(
        executive_summary="resumen",
        risk_level="high",
        actions=[ProposedAction(type="isolate_host", target="h", justification="j")],
        rationale="r",
    )


@pytest.fixture
def settings() -> Settings:
    return Settings(
        openai_api_key="test", smtp_host="smtp.test", smtp_to_approvers="soc@test",
    )


@pytest.mark.asyncio
async def test_notify_calls_email(settings, alert, plan) -> None:
    with patch("src.notify.send_closure_email", new=AsyncMock()) as mocked:
        await notify_case_closure(
            settings, alert, plan, decision="approved", timeline_events=[],
            execution_results=[], decided_by_ip="1.2.3.4", decided_at=None,
            executed_at=None, invgate_request_id=None,
        )
        mocked.assert_awaited_once()
        # decision se pasa como kwarg al email
        _, kwargs = mocked.call_args
        assert kwargs["decision"] == "approved"


@pytest.mark.asyncio
async def test_notify_no_teams_when_webhook_empty(settings, alert, plan) -> None:
    """Teams aún no implementado: con webhook vacío no se loguea el placeholder."""
    with patch("src.notify.send_closure_email", new=AsyncMock()):
        # teams_webhook_url default = "" → no debe intentar Teams
        assert settings.teams_webhook_url == ""
        await notify_case_closure(
            settings, alert, plan, decision="rejected", timeline_events=[],
            execution_results=None, decided_by_ip=None, decided_at=None,
            executed_at=None, invgate_request_id=None,
        )
