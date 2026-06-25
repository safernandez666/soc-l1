"""Tests del Narrator: schemas + build (sin tocar LLM real)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.agents.enricher import EnrichedUser, EnrichmentResult
from src.agents.narrator import (
    NarratorPlan,
    ProposedAction,
    SYSTEM_PROMPT,
    _bundle_to_prompt,
    build_narrator_agent,
)
from src.agents.triage import TriageDecision
from src.normalize import normalize

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def keygen_alert():
    raw = json.loads((FIXTURES / "defender_keygen.json").read_text())
    return normalize(raw)


def test_proposed_action_validates() -> None:
    a = ProposedAction(type="disable_user", target="jdoe", justification="evidencia X")
    assert a.type == "disable_user"


def test_proposed_action_rejects_invalid_type() -> None:
    with pytest.raises(Exception):  # ValidationError
        ProposedAction(type="delete_user", target="jdoe", justification="x")


def test_narrator_plan_accepts_empty_actions() -> None:
    """Plan sin acciones (monitor only) es válido."""
    p = NarratorPlan(
        executive_summary="resumen", risk_level="low", actions=[], rationale="análisis"
    )
    assert p.actions == []


def test_narrator_plan_rejects_invalid_risk() -> None:
    with pytest.raises(Exception):
        NarratorPlan(
            executive_summary="x", risk_level="ultra", actions=[], rationale="x"
        )


def test_build_narrator_has_structured_output() -> None:
    agent = build_narrator_agent()
    assert agent.name == "Narrator"
    assert agent.output_type is NarratorPlan
    assert agent.tools == []  # Narrator no tiene tools


def test_system_prompt_demanda_approval_humano() -> None:
    """Sanity: el prompt explicita que no ejecuta sin aprobación."""
    assert "NO ejecutás acciones" in SYSTEM_PROMPT
    assert "found_in_ad" in SYSTEM_PROMPT
    assert "disable_user" in SYSTEM_PROMPT
    assert "force_password_change" in SYSTEM_PROMPT


def test_system_prompt_tiene_guia_vpn_identidad() -> None:
    """Guard: la guía de tratamiento VPN/identidad no debe perderse en refactors.
    Sin ella el Narrator (prompt Defender-céntrico) tiende a notify_only siempre."""
    assert "fortigate_vpn_" in SYSTEM_PROMPT
    # mapeo conservador: horario solo → notify_only; multi-país → disable_user
    assert "196104" in SYSTEM_PROMPT
    assert "fortigate_vpn_multiple_countries" in SYSTEM_PROMPT


def test_bundle_to_prompt_contains_all_inputs(keygen_alert) -> None:
    """El prompt enviado al LLM incluye alert + triage + enrichment + threat_intel."""
    from src.agents.threatintel import ThreatIntelResult
    from src.models import VtFileReport

    triage = TriageDecision(verdict="analyze", reason="r", confidence="medium")
    enrichment = EnrichmentResult(
        users=[EnrichedUser(sam="jdoe", found_in_ad=True, enabled=True)],
        rule=None,
        summary="s",
        flags=["mitre_T1059"],
    )
    ti = ThreatIntelResult(
        file_reports=[VtFileReport(sha256="abc", malicious_count=55, total_engines=72)],
        ip_reports=[],
        summary="vt summary",
        flags=["vt_highly_malicious"],
    )
    bundle = _bundle_to_prompt(keygen_alert, triage, enrichment, ti)
    parsed = json.loads(bundle)
    assert set(parsed.keys()) == {"alert", "triage", "enrichment", "threat_intel"}
    assert "raw" not in parsed["alert"]
    assert parsed["triage"]["verdict"] == "analyze"
    assert parsed["enrichment"]["users"][0]["sam"] == "jdoe"
    assert "mitre_T1059" in parsed["enrichment"]["flags"]
    assert parsed["threat_intel"]["file_reports"][0]["malicious_count"] == 55


def test_bundle_to_prompt_handles_no_threat_intel(keygen_alert) -> None:
    """Si threat_intel es None, se serializa como JSON null para que el LLM lo vea."""
    triage = TriageDecision(verdict="analyze", reason="r", confidence="medium")
    enrichment = EnrichmentResult(users=[], rule=None, summary="s", flags=[])
    bundle = _bundle_to_prompt(keygen_alert, triage, enrichment, None)
    parsed = json.loads(bundle)
    assert parsed["threat_intel"] is None
