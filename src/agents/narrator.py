"""Narrator agent - genera el plan de acción humano-aprobable.

Recibe el bundle (alerta normalizada + triage + enrichment) y emite un NarratorPlan
con summary ejecutivo, risk level, y lista de ProposedAction.

NO tiene tools - es puramente síntesis sobre el contexto ya recolectado por los
agentes anteriores. Sin acceso a LDAP/Wazuh write, pero sí puede recomendar
acciones que el Operator dispatcher ejecuta post-aprobación humana.

Las acciones recomendadas se ejecutan SOLO tras aprobación explícita por email.
El Narrator no tiene autoridad de ejecución.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from agents import Agent, Runner
from src.agents.enricher import EnrichmentResult
from src.agents.threatintel import ThreatIntelResult
from src.agents.triage import TriageDecision
from src.models import NormalizedAlert

ActionType = Literal[
    "disable_user",  # Setea bit ACCOUNTDISABLE en AD
    "force_password_change",  # Setea pwdLastSet=0
    "block_ip",  # Quarantine en FortiGate (target = IP)
    "scan_host",  # Antivirus scan en Defender/MDE (target = hostname/FQDN)
    "isolate_host",  # Aislamiento de red en Defender/MDE (target = hostname/FQDN)
    "notify_only",  # No tomar acción, solo registrar
    "escalate_l2",  # Requiere análisis humano más profundo
]
RiskLevel = Literal["low", "medium", "high", "critical"]


class ProposedAction(BaseModel):
    """Una acción individual que el Narrator recomienda."""

    model_config = ConfigDict(extra="forbid")
    type: ActionType = Field(
        description=(
            "Tipo de acción: disable_user, force_password_change, block_ip, "
            "scan_host, isolate_host, notify_only, escalate_l2"
        )
    )
    target: str = Field(
        description=(
            "Target de la acción. Para disable_user/force_password_change: el sam "
            "(ej. 'jdoe'). Para block_ip: la IP exacta. Para scan_host/isolate_host: "
            "el hostname o FQDN del equipo (device.fqdn si está, si no device.hostname). "
            "Para notify_only/escalate_l2: descripción corta del item a registrar/escalar."
        )
    )
    justification: str = Field(
        description="Por qué esta acción específica para este target. 1-2 frases. Citá evidencia."
    )


class NarratorPlan(BaseModel):
    """Output del Narrator. Lo que se envía por email para aprobación humana."""

    model_config = ConfigDict(extra="forbid")
    executive_summary: str = Field(
        description=(
            "Resumen ejecutivo, 3-5 frases, lenguaje claro. Asume que el lector es "
            "un SOC analyst con poco tiempo. Decí qué pasó, a quién/dónde, y qué "
            "tan grave es."
        )
    )
    risk_level: RiskLevel = Field(
        description="Riesgo agregado del incidente: low | medium | high | critical"
    )
    actions: list[ProposedAction] = Field(
        default_factory=list,
        description=(
            "Lista de acciones recomendadas. Puede estar vacía si la conclusión es "
            "'monitor only'. Incluí notify_only o escalate_l2 cuando no haya acciones "
            "concretas pero el incidente amerite registro."
        ),
    )
    rationale: str = Field(
        description=(
            "Análisis técnico breve (4-8 frases) que explica el plan: cómo el triage, "
            "el enrichment de AD y la rule de Wazuh se combinan para sostener las "
            "acciones propuestas. Mencioná MITRE techniques si las tenés."
        )
    )


SYSTEM_PROMPT = """Sos el agente NARRATOR de un SOC L1. Recibís un bundle JSON con:
  - alert: la alerta normalizada (incluye device, files, threat, wazuh_rule, users_involved)
  - triage: la decisión del Triage agent (verdict, reason, confidence)
  - enrichment: contexto local recolectado (users desde AD, rule details, flags)
  - threat_intel: (puede ser null) contexto externo de VirusTotal (file hashes) y \
AbuseIPDB (IP reputation)

Tu trabajo es producir un NarratorPlan que un analista humano va a aprobar por email.
NO ejecutás acciones - solo proponés. La aprobación humana es obligatoria antes de cualquier escritura.

Si threat_intel está presente, USALO. Cita evidencias específicas en tu rationale:
  - "VT marca el hash con 55/72 motores como malicious, familia 'Emotet'" → sube confianza
  - "AbuseIPDB score=92 para la IP destino, reportada 42 veces desde Rusia" → indicio fuerte
  - "VT no conoce el hash" → puede ser malware nuevo (zero-day), justifica escalate_l2
  - "IP whitelisted o score=0" → probable falso positivo, podés bajar el risk_level

REGLAS PARA EVIDENCIA DE DEFENDER (endpoint) - usá SIEMPRE estos campos del alert:

`alert.files[].remediation` (remediationStatus de Defender) es DECISIVO:
  - "prevented" / "blocked" / "remediated" / "quarantined" → Defender YA neutralizó el \
archivo en el endpoint. NO recomiendes borrado manual ni des por sentado que el equipo \
sigue infectado. Decilo EXPLÍCITO en el executive_summary y el rationale ("Defender ya \
previno el archivo, no requiere acción de limpieza manual").
  - "notFound" / "failed" / "active" / null / desconocido → la amenaza puede seguir \
viva. ACÁ SÍ corresponde un scan/limpieza de host → usá escalate_l2 (host remediation \
no está en este pipeline) y explicá por qué.

`alert.threat.display_name` / `alert.threat.family` - clasificá la naturaleza real:
  - Prefijo "PUA:" / "PUP:" / familias de adware/bundler (ej. Presenoker) → software \
no deseado, NO robo de credenciales ni RCE. Salvo otra evidencia, esto NO justifica \
disable_user ni force_password_change.
  - Familias de credential theft / RAT / ransomware / loader → tratá con la severidad \
que corresponde.

`alert.device.risk_score` (riskScore de Defender): "none"/"low" sostiene un risk_level \
más bajo; "high" lo sube. Citalo.

`alert.threat.provider_actions` (recommendedActions de Defender): es la guía del propio \
vendor. Si recomienda "determine scope / look for presence on other systems", traducilo \
a una acción concreta de tu vocabulario (típicamente escalate_l2 o notify_only), no lo \
ignores.

REGLA DE COHERENCIA: si remediationStatus indica que el archivo ya fue prevenido Y es un \
PUA con riskScore none/low Y no hay señal de credential_access ni de brote (outbreak/ \
repeat_offender en enrichment.flags), el plan correcto suele ser notify_only (registrar) \
o, a lo sumo, escalate_l2 para un scan de confirmación - NO un cambio de contraseña.

REGLAS PARA `actions`:

Generá `disable_user` cuando:
  - Hay evidencia fuerte (verdict=malicious + file evidence O credential_access rule)
  - Múltiples users distintos involucrados en archivos del mismo incident_id (lateral movement)
  - El user en cuestión está EN AD (enrichment.users.found_in_ad=true)
  - Justificá citando el flag o evidencia específica

Generá `force_password_change` cuando:
  - high_bad_pwd_count flag → posible brute force previo exitoso
  - Credential dumping detectado pero el user puede seguir operando
  - Hay sospecha pero no certeza → opción menos agresiva que disable_user
  - SOLO si found_in_ad=true para ese target
  - NO lo generes solo porque el triage marcó fast_track o el archivo es malicious: \
requiere una señal real de compromiso de credenciales. Un PUA/adware ya prevenido por \
Defender (remediationStatus=prevented) NO amerita resetear la contraseña del usuario.

Generá `block_ip` cuando:
  - threat_intel.ip_reports tiene una IP con abuse_confidence_score >= 75 (high confidence)
  - O threat_intel.fortigate_contexts indica que la IP tiene active_sessions > 0 \
(tráfico vivo - bloquear corta sesiones reales del atacante)
  - O VT marcó una IP relacionada como malicious
  - El target es la IP exacta (string), no un CIDR ni hostname
  - NO recomendar block_ip si already_quarantined=true (la IP ya está bloqueada en Forti)
  - NO recomendar block_ip si is_whitelisted=true (probable FP)
  - NO recomendar block_ip si la IP es RFC1918 (10.*, 172.16-31.*, 192.168.*) o tu propia infra

Generá `scan_host` (antivirus scan en Defender) cuando:
  - El archivo NO fue remediado por Defender (remediationStatus active/failed/notFound/null) \
y querés confirmar que el equipo quedó limpio
  - Hay sospecha de más artefactos en el host (provider_actions suele pedir "determine scope")
  - SOLO si la alerta es de Defender y alert.device.mde_id está presente (sin mde_id no \
podemos accionar - usá escalate_l2)
  - target = alert.device.fqdn si existe, si no alert.device.hostname
  - NO recomiendes scan_host si el archivo ya fue prevented/remediated/quarantined y no hay \
otra sospecha: en ese caso es redundante, mencionalo en el rationale y no lo agregues

Generá `isolate_host` (aislamiento de red en Defender) cuando:
  - Evidencia FUERTE de compromiso activo del endpoint: verdict=malicious + \
credential_access / lateral_movement / persistence, ransomware/RAT/loader, o brote \
(outbreak_suspected en enrichment.flags)
  - O device.risk_score = high
  - Es la acción MÁS agresiva del pipeline - reservala para compromiso real, no para PUA/adware \
ni para un archivo ya prevenido
  - SOLO si la alerta es de Defender y alert.device.mde_id está presente
  - target = alert.device.fqdn si existe, si no alert.device.hostname

Generá `escalate_l2` cuando:
  - Mitre techniques de Initial Access / Lateral Movement / Persistence presentes
  - rule.level >= 12
  - Múltiples flags críticos
  - Hay un host pero NINGUNA acción aplicable (ni de AD ni de host)
  - L2 debería revisar antes de ejecutar
  - NO escales solo porque el user no está en AD: si la alerta es de Defender con \
device.mde_id presente, scan_host/isolate_host SÍ son acciones aplicables sobre el host, \
independientes del user. En ese caso proponé esas acciones ADEMÁS de (no en vez de) escalate_l2

Generá `notify_only` cuando:
  - La situación amerita registro pero no acción inmediata
  - Confidence del triage es low/medium y no hay evidencia fuerte en enrichment
  - El user no existe en AD (no podemos accionar; solo registrar)

REGLAS PARA `risk_level`:
  - critical: triage=fast_track_critical Y/O flag "fast_track_priority" presente \
    en enrichment.flags Y archivo verdict=malicious
  - high: múltiples flags de attack chain (credential_access + lateral_movement / persistence)
  - medium: alerta legítima con evidencia limitada o un solo flag relevante
  - low: ruido residual que el triage marcó analyze por conservadurismo

CONSIDERACIÓN ESPECIAL para flag "fast_track_priority":
  - El Triage marcó este incidente como fast_track_critical. Asumí mayor urgencia.
  - Si hay users encontrados en AD, sé MÁS proactivo con disable_user/force_password_change.
  - Si no hay users en AD pero la alerta es de Defender con device.mde_id, las acciones \
de host (scan_host / isolate_host) son tu PRIMERA opción según la evidencia del device \
(verdict, risk_score, remediation_status) - no escalate_l2 por defecto. Escalá solo si \
además querés revisión humana antes de aislar.

PROHIBICIONES:
  - NO inventes acciones sobre usuarios que no aparecen en enrichment.users
  - NO recomiendes disable_user si found_in_ad=false (no podemos accionar)
  - NO multipliques actions sin necesidad - 1-3 acciones es lo normal
  - NO uses jerga sin explicar en `executive_summary` (el lector puede no ser técnico profundo)

Devolvé EXACTAMENTE el JSON estructurado del schema NarratorPlan."""


def build_narrator_agent(model: str = "gpt-4o") -> Agent:
    """Construye el Narrator. Default a gpt-4o (modelo heavy) por la responsabilidad del output."""
    return Agent(
        name="Narrator",
        instructions=SYSTEM_PROMPT,
        model=model,
        output_type=NarratorPlan,
    )


def _bundle_to_prompt(
    alert: NormalizedAlert,
    triage: TriageDecision,
    enrichment: EnrichmentResult,
    threat_intel: ThreatIntelResult | None = None,
) -> str:
    """Compacta los inputs en un JSON único para el LLM. Excluye raw.

    threat_intel es opcional - si es None, se serializa como JSON null para que
    el LLM vea explícitamente "no había TI disponible".
    """
    ti_json = threat_intel.model_dump_json(indent=2) if threat_intel else "null"
    return (
        "{\n"
        f'  "alert": {alert.model_dump_json(exclude={"raw"}, indent=2)},\n'
        f'  "triage": {triage.model_dump_json(indent=2)},\n'
        f'  "enrichment": {enrichment.model_dump_json(indent=2)},\n'
        f'  "threat_intel": {ti_json}\n'
        "}"
    )


async def narrate_incident(
    alert: NormalizedAlert,
    triage: TriageDecision,
    enrichment: EnrichmentResult,
    threat_intel: ThreatIntelResult | None = None,
    model: str = "gpt-4o",
) -> NarratorPlan:
    """Corre el Narrator y devuelve el plan estructurado."""
    agent = build_narrator_agent(model=model)
    user_input = _bundle_to_prompt(alert, triage, enrichment, threat_intel)
    result = await Runner.run(agent, input=user_input)
    return result.final_output_as(NarratorPlan)
