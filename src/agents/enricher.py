"""Enricher agent - segundo paso después del Triage cuando el verdict es `analyze`.

Tiene acceso a 2 tools:
  - ldap_search_user(sam):    consulta AD (read-only). Devuelve dn, enabled, locked_out, dept, manager, last_logon, etc.
  - wazuh_get_rule(rule_id):  detalle de la rule de Wazuh: descripción, groups, mitre tactics/techniques.

Estrategia esperada del LLM (forzada por el system prompt):
  1. Para cada user en users_involved → llamar ldap_search_user.
  2. Si la alerta tiene wazuh_rule.id → llamar wazuh_get_rule.
  3. Sintetizar todo en EnrichmentResult.

El output structured deja el resultado listo para que el siguiente agente (ThreatIntel
o Narrator) trabaje sobre un JSON limpio sin tener que re-leer la alerta cruda.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from agents import Agent, RunContextWrapper, Runner, function_tool
from pydantic import BaseModel, ConfigDict, Field

from src.config import LdapConfig, Settings
from src.models import ADUser, NormalizedAlert, WazuhRuleInfo
from src.tools import ldap as ldap_tools
from src.tools.wazuh_api import WazuhApiClient, WazuhApiError

logger = logging.getLogger("soc-l1")


@dataclass
class EnricherContext:
    """Inyectado vía RunContextWrapper a las tool functions.

    Las tools no pueden recibir el LdapConfig directo desde el LLM (no es serializable
    y no queremos exponerlo en el schema). Lo pasamos vía contexto.
    """

    settings: Settings
    ldap_cfg: LdapConfig | None  # None si LDAP no está configurado (skip search_user)


class EnrichedUser(BaseModel):
    """Snapshot por usuario tras consultar AD. Subset relevante de ADUser + lookup status."""

    model_config = ConfigDict(extra="forbid")
    sam: str
    found_in_ad: bool
    enabled: bool | None = None
    locked_out: bool | None = None
    department: str | None = None
    title: str | None = None
    manager: str | None = None
    mail: str | None = None
    last_logon: str | None = None
    bad_pwd_count: int | None = None
    member_of_count: int | None = None
    lookup_error: str | None = None


class EnrichmentResult(BaseModel):
    """Output estructurado del Enricher. Consumido por el próximo agente del pipeline."""

    model_config = ConfigDict(extra="forbid")
    users: list[EnrichedUser] = Field(default_factory=list)
    rule: WazuhRuleInfo | None = None
    summary: str = Field(
        description=(
            "Resumen ejecutivo 2-3 líneas: qué encontró el Enricher, qué se ve normal "
            "vs raro (cuenta deshabilitada, depto inesperado, regla de high-severity, etc.)"
        )
    )
    flags: list[str] = Field(
        default_factory=list,
        description=(
            "Lista corta de señales que el próximo agente debe priorizar. Ejemplos: "
            "'user_disabled', 'lateral_movement_indicator', 'mitre_T1059', 'no_ad_match'."
        ),
    )


# ===== Tools expuestas al LLM =====


@function_tool
async def ldap_search_user(
    ctx: RunContextWrapper[EnricherContext], sam_account_name: str
) -> dict[str, Any]:
    """Busca un usuario en AD por sAMAccountName.

    Devuelve atributos relevantes para SOC: estado de cuenta (enabled, locked_out),
    departamento, manager, último logon, bad password count. Si no existe, found=false.

    Args:
        sam_account_name: El sam (sin dominio). Ejemplo: "jdoe", no "jdoe@example.com".
    """
    cfg = ctx.context.ldap_cfg
    if cfg is None:
        return {
            "found": False,
            "sam": sam_account_name,
            "error": "LDAP no configurado en este entorno",
        }

    try:
        user: ADUser | None = ldap_tools.search_user(cfg, sam_account_name)
    except Exception as e:  # noqa: BLE001 - el LLM necesita un string, no un raise
        logger.warning("ldap_search_user failed for %s: %s", sam_account_name, e)
        return {"found": False, "sam": sam_account_name, "error": str(e)}

    if user is None:
        return {"found": False, "sam": sam_account_name}

    return {
        "found": True,
        "sam": user.sam,
        "dn": user.dn,
        "display_name": user.display_name,
        "mail": user.mail,
        "department": user.department,
        "title": user.title,
        "manager": user.manager,
        "account_enabled": user.account_enabled,
        "locked_out": user.locked_out,
        "last_logon": user.last_logon,
        "bad_pwd_count": user.bad_pwd_count,
        "pwd_last_set": user.pwd_last_set,
        "member_of_count": len(user.member_of),
    }


@function_tool
async def wazuh_get_rule(
    ctx: RunContextWrapper[EnricherContext], rule_id: str
) -> dict[str, Any]:
    """Trae el detalle de una Wazuh rule por ID.

    Útil para entender por qué disparó la alerta y qué MITRE tactic/technique asocia.

    Args:
        rule_id: ID numérico de la rule. Ejemplo: "60106".
    """
    settings = ctx.context.settings
    if not settings.wazuh_api_password:
        return {"found": False, "rule_id": rule_id, "error": "Wazuh API no configurado"}

    try:
        async with WazuhApiClient(settings) as client:
            rule = await client.get_rule(rule_id)
    except WazuhApiError as e:
        logger.warning("wazuh_get_rule failed for %s: %s", rule_id, e)
        return {"found": False, "rule_id": rule_id, "error": str(e)}

    if rule is None:
        return {"found": False, "rule_id": rule_id}

    return {
        "found": True,
        "rule_id": rule.rule_id,
        "level": rule.level,
        "description": rule.description,
        "groups": rule.groups,
        "mitre_ids": rule.mitre_ids,
        "mitre_tactics": rule.mitre_tactics,
        "mitre_techniques": rule.mitre_techniques,
        "gdpr": rule.gdpr,
        "pci_dss": rule.pci_dss,
    }


# ===== System prompt =====

SYSTEM_PROMPT = """Sos el agente ENRICHER de un SOC L1. Recibís una alerta ya triada \
(verdict=analyze) y tu trabajo es enriquecerla con contexto antes de que el siguiente \
agente decida acción.

Tenés 2 tools:
  - ldap_search_user(sam_account_name): mirá AD para cada usuario involucrado.
  - wazuh_get_rule(rule_id): detalle de la rule de Wazuh.

PROCEDIMIENTO OBLIGATORIO:
1. Para CADA usuario en users_involved del input, llamá ldap_search_user con su `sam`.
   Si la lista está vacía, no llames.
2. Si la alerta tiene wazuh_rule.id, llamá wazuh_get_rule.
3. Devolvé EXACTAMENTE el JSON de EnrichmentResult.

CRITERIO PARA `flags` (priorización para el próximo agente):
- "user_disabled" → si encontraste un user con account_enabled=false.
- "user_locked_out" → si locked_out=true.
- "no_ad_match" → si un sam involucrado no existe en AD (puede ser ataque con cuenta inexistente).
- "high_bad_pwd_count" → bad_pwd_count >= 5 (posible brute force previo).
- "multiple_users_distinct_departments" → si los users tienen departments distintos en la misma alerta.
- "mitre_<technique_id>" → uno por cada technique reportada por la rule (ej. "mitre_T1059").
- "rule_high_severity" → si rule.level >= 10.
- "rule_group_<group>" → para grupos críticos: lateral_movement, credential_access, \
privilege_escalation, persistence, exfiltration. Ej "rule_group_lateral_movement".

CRITERIO PARA `summary`:
- 2-3 líneas, claras, sin jerga. Mencioná: cuántos users, si alguno está raro, qué dice la rule.
- Ejemplo: "2 usuarios involucrados, ambos activos en AD. jdoe (IT) y asmith (Finance) - \
departamentos distintos, sospechoso. Rule 60106 = malware detection con MITRE T1588.002."

Si una tool falla (error en la respuesta), no la repitas: anotalo en el campo correspondiente \
(lookup_error en el user, o seguí sin la rule) y continuá."""


def build_enricher_agent(model: str = "gpt-4o-mini") -> Agent[EnricherContext]:
    """Construye el Enricher Agent. Modelo separado para tests y override."""
    return Agent[EnricherContext](
        name="Enricher",
        instructions=SYSTEM_PROMPT,
        model=model,
        tools=[ldap_search_user, wazuh_get_rule],
        output_type=EnrichmentResult,
    )


def _alert_to_prompt_input(alert: NormalizedAlert) -> str:
    """Compacta la alerta al JSON que ve el LLM. Excluye `raw` (mucho ruido)."""
    return alert.model_dump_json(exclude={"raw"}, indent=2)


async def enrich_alert(
    alert: NormalizedAlert,
    settings: Settings,
    ldap_cfg: LdapConfig | None,
    model: str = "gpt-4o-mini",
) -> EnrichmentResult:
    """Corre el Enricher contra una alerta. Devuelve el resultado estructurado."""
    agent = build_enricher_agent(model=model)
    ctx = EnricherContext(settings=settings, ldap_cfg=ldap_cfg)
    user_input = _alert_to_prompt_input(alert)
    result = await Runner.run(agent, input=user_input, context=ctx)
    return result.final_output_as(EnrichmentResult)
