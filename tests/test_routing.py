"""Tests del routing/dispatch del Triage agent verdict."""
from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from src.agents.triage import TriageDecision
from src.config import Settings
from src.main import (
    _dispatch_by_verdict,
    _handle_analyze,
    _handle_auto_close,
    _handle_fast_track,
)
from src.normalize import normalize
from src.trace import PipelineTrace

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def alert():
    raw = json.loads((FIXTURES / "defender_keygen.json").read_text())
    return normalize(raw)


@pytest.fixture
def settings():
    return Settings(openai_api_key="test-key")


@pytest.fixture
def trace():
    return PipelineTrace("test-alert-id")


@pytest.mark.asyncio
async def test_handle_auto_close_logs_audit(
    alert, caplog: pytest.LogCaptureFixture
) -> None:
    decision = TriageDecision(
        verdict="auto_close_benign",
        reason="ruido conocido",
        confidence="high",
    )
    with caplog.at_level(logging.INFO, logger="soc-l1"):
        await _handle_auto_close(alert, decision)
    assert any("AUDIT auto_closed" in r.message for r in caplog.records)
    assert any("ruido conocido" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_handle_analyze_queues_for_pipeline(
    alert, settings, trace, caplog: pytest.LogCaptureFixture
) -> None:
    decision = TriageDecision(verdict="analyze", reason="needs context", confidence="medium")
    with caplog.at_level(logging.INFO, logger="soc-l1"):
        await _handle_analyze(alert, decision, settings, trace)
    assert any("PIPELINE_QUEUED analyze" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_handle_fast_track_queues_for_narrator(
    alert, settings, trace, caplog: pytest.LogCaptureFixture
) -> None:
    decision = TriageDecision(
        verdict="fast_track_critical",
        reason="malicious file detected",
        confidence="high",
    )
    with caplog.at_level(logging.WARNING, logger="soc-l1"):
        await _handle_fast_track(alert, decision, settings, trace)
    assert any("PIPELINE_QUEUED fast_track" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_dispatch_routes_to_auto_close(
    alert, settings, trace, caplog: pytest.LogCaptureFixture
) -> None:
    decision = TriageDecision(
        verdict="auto_close_benign", reason="r", confidence="high"
    )
    with caplog.at_level(logging.INFO, logger="soc-l1"):
        await _dispatch_by_verdict(alert, decision, settings, trace)
    assert any("AUDIT auto_closed" in r.message for r in caplog.records)
    assert not any("PIPELINE_QUEUED" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_dispatch_routes_to_analyze(
    alert, settings, trace, caplog: pytest.LogCaptureFixture
) -> None:
    decision = TriageDecision(verdict="analyze", reason="r", confidence="medium")
    with caplog.at_level(logging.INFO, logger="soc-l1"):
        await _dispatch_by_verdict(alert, decision, settings, trace)
    assert any("PIPELINE_QUEUED analyze" in r.message for r in caplog.records)
    assert not any("AUDIT auto_closed" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_dispatch_routes_to_fast_track(
    alert, settings, trace, caplog: pytest.LogCaptureFixture
) -> None:
    decision = TriageDecision(
        verdict="fast_track_critical", reason="r", confidence="high"
    )
    with caplog.at_level(logging.WARNING, logger="soc-l1"):
        await _dispatch_by_verdict(alert, decision, settings, trace)
    assert any("PIPELINE_QUEUED fast_track" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_dispatch_unknown_verdict_falls_back_to_analyze(
    alert, settings, trace, caplog: pytest.LogCaptureFixture
) -> None:
    """Si el LLM devolviera un verdict inválido (no debería con structured output, pero defensive)."""

    # Construir un decision con verdict-like que no matchea ningún case
    # Usamos un objeto duck-typed porque TriageDecision Pydantic lo rechazaría
    class FakeDecision:
        verdict = "weird_unknown_verdict"
        reason = "anomaly"
        confidence = "low"

    with caplog.at_level(logging.INFO, logger="soc-l1"):
        await _dispatch_by_verdict(alert, FakeDecision(), settings, trace)
    assert any("unknown verdict" in r.message for r in caplog.records)
    # Y debe haber caído al handler de analyze (que loggea a nivel INFO)
    assert any("PIPELINE_QUEUED analyze" in r.message for r in caplog.records)
