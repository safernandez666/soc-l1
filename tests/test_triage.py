"""Tests del Triage agent usando FakeModel - no consume tokens reales."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from agents import Runner
from agents.models.fake_id import FAKE_RESPONSES_ID

from src.agents.triage import (
    SYSTEM_PROMPT,
    TriageDecision,
    _alert_to_prompt_input,
    build_triage_agent,
    triage_alert,
)
from src.normalize import normalize

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def keygen_alert():
    raw = json.loads((FIXTURES / "defender_keygen.json").read_text())
    return normalize(raw)


def test_triage_decision_model_validates() -> None:
    """El TriageDecision Pydantic model acepta valores válidos."""
    d = TriageDecision(verdict="analyze", reason="test", confidence="medium")
    assert d.verdict == "analyze"


def test_triage_decision_rejects_invalid_verdict() -> None:
    """Verdicts fuera del enum son rechazados por Pydantic."""
    with pytest.raises(Exception):  # ValidationError
        TriageDecision(verdict="not_a_valid_verdict", reason="x", confidence="low")


def test_alert_to_prompt_input_excludes_raw(keygen_alert) -> None:
    """El prompt al LLM no incluye el campo raw (es muy grande)."""
    prompt = _alert_to_prompt_input(keygen_alert)
    parsed = json.loads(prompt)
    assert "raw" not in parsed
    # Pero sí los campos importantes
    assert parsed["source"] == "defender_via_wazuh"
    assert parsed["title"] == "'Keygen' hacktool was detected"
    assert len(parsed["users_involved"]) == 2
    assert parsed["files"][0]["sha256"].startswith("1111")


def test_build_triage_agent_has_structured_output() -> None:
    """El agent debe estar configurado con output_type=TriageDecision."""
    agent = build_triage_agent()
    assert agent.name == "Triage"
    assert agent.output_type == TriageDecision
    assert "TRIAGE" in agent.instructions


def test_system_prompt_mentions_conservative_default() -> None:
    """Sanity check: el prompt incluye la regla de seguridad anti-cierre falso."""
    assert "NUNCA cierres como benign" in SYSTEM_PROMPT
    assert "malicious" in SYSTEM_PROMPT.lower()
    assert "lateral_movement" in SYSTEM_PROMPT.lower()


def test_system_prompt_no_cierra_alertas_vpn() -> None:
    """Guard: las alertas VPN/identidad (fortigate_vpn_*, T1078) van a analyze,
    no auto_close_benign, aunque no tengan file evidence ni categoría crítica."""
    assert "fortigate_vpn_" in SYSTEM_PROMPT
    assert "T1078" in SYSTEM_PROMPT


# Nota: tests de integración real (que llaman al LLM) van en tests/integration/
# Se corren con OPENAI_API_KEY seteada. Por ahora ese path queda manual.
