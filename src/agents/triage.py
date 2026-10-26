"""Triage agent - primer filtro inteligente sobre alertas normalizadas.

Recibe una NormalizedAlert (post-normalize) y decide:
  - auto_close_benign:  alerta obviamente ruido/benigna, no consumir más tokens
  - analyze:            va al pipeline completo (Enricher → ThreatIntel → Narrator)
  - fast_track_critical: severidad crítica obvia, skip Enricher y va directo al Narrator

Sin tools externas. Solo LLM contra el JSON de la alerta normalizada.
Modelo: gpt-4o-mini (cheap, ~$0.0003 por triage).
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from agents import Agent
from src.agents import run_agent
from src.models import NormalizedAlert

TriageVerdict = Literal["auto_close_benign", "analyze", "fast_track_critical"]
Confidence = Literal["low", "medium", "high"]


class TriageDecision(BaseModel):
    """Output estructurado del Triage agent. El Agent SDK fuerza este schema."""

    verdict: TriageVerdict = Field(
        description="Decisión final: auto_close_benign | analyze | fast_track_critical"
    )
    reason: str = Field(
        description="Justificación clara, 1-2 frases. Citá qué señales pesaron en la decisión."
    )
    confidence: Confidence = Field(
        description="Cuán seguro estás de tu verdict: low | medium | high"
    )


SYSTEM_PROMPT = """Sos el agente TRIAGE de un SOC L1. Recibís una alerta normalizada y \
decidís rápido si vale la pena gastar análisis profundo o si se puede cerrar/escalar inmediato.

Devolvés EXACTAMENTE el JSON estructurado del schema TriageDecision.

REGLAS DE DECISIÓN:

**auto_close_benign** cuando:
- severity_source = low, regla conocida como ruidosa (Windows audit, sysmon noise)
- archivos con verdict != malicious (suspicious solo, sin file evidence fuerte)
- no hay correlación con otros usuarios o lateral movement
- categoría != Malware, Credential Access, Privilege Escalation, Lateral Movement, \
Initial Access, Persistence

**fast_track_critical** cuando:
- severity_source = critical
- O archivos con verdict = malicious EN máquina nueva o sin riesgo previo
- O múltiples evidencias en el mismo incident_id (incident_url no nulo + categoria \
Malware o crítica)
- O detection_source = antivirus + verdict = malicious

**analyze** (default): cualquier otro caso, especialmente:
- severity medium/high con file evidence
- múltiples usuarios involucrados (lateral movement potencial)
- IP externa pública sospechosa
- rule groups: privilege_escalation, credential_access, lateral_movement, exfiltration, persistence
- alertas de VPN/identidad (rule groups con prefijo `fortigate_vpn_`, o MITRE T1078 \
Valid Accounts): acceso de usuario monitoreado, fuera de horario, multi-IP o multi-país. \
El Narrator decide si amerita respuesta de identidad - vos NO las cierres.

NUNCA cierres como benign si:
- Hay hash de archivo con verdict = malicious
- Hay múltiples usuarios (logged_on + file_path_owner distintos)
- La regla pertenece a privilege_escalation, credential_access, lateral_movement, persistence
- La regla es de VPN/identidad (groups `fortigate_vpn_*`, o MITRE T1078): aunque la \
categoría no esté en la lista crítica y no haya file evidence, va a `analyze`
- categoría es "Malware" o "InitialAccess"

Sé conservador: ante la duda → `analyze`. El siguiente agente decide con más contexto."""


def build_triage_agent(model: str = "gpt-4o-mini") -> Agent:
    """Construye el Agent. Separado en función para facilitar override en tests."""
    return Agent(
        name="Triage",
        instructions=SYSTEM_PROMPT,
        model=model,
        output_type=TriageDecision,
    )


def _alert_to_prompt_input(alert: NormalizedAlert) -> str:
    """Compacta el NormalizedAlert a un prompt user-friendly para el LLM.

    No mandamos el `raw` original (es grande y ya está cubierto por los otros campos).
    """
    return alert.model_dump_json(exclude={"raw"}, indent=2)


async def triage_alert(
    alert: NormalizedAlert, model: str = "gpt-4o-mini"
) -> TriageDecision:
    """Corre el Triage agent contra una alerta. Devuelve la decisión estructurada."""
    agent = build_triage_agent(model=model)
    user_input = _alert_to_prompt_input(alert)
    result = await run_agent(agent, input=user_input, timeout=60.0, label="triage")
    return result.final_output_as(TriageDecision)
