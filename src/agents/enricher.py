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
from dataclasses import dataclass, field
from typing import Any

from agents import Agent, RunContextWrapper, Runner, function_tool
from pydantic import BaseModel, ConfigDict, Field

from src.config import LdapConfig, Settings
from src.models import ADUser, NormalizedAlert, WazuhRuleInfo
from src.tools import ldap as ldap_tools
from src.tools import wazuh_alerts
from src.tools.wazuh_api import WazuhApiClient, WazuhApiError

logger = logging.getLogger("soc-l1")


@dataclass
class EnricherContext:
    """Inyectado vía RunContextWrapper a las tool functions.

    Cache + hit counter por (tool, args). Después de N hits sobre la misma key,
    devolvemos un error estructurado en lugar del payload normal - empíricamente
    gpt-4o-mini sigue llamando a las tools aunque el response diga "stop". El error
    estructurado fuerza el cambio de estado mental del LLM.
    """

    settings: Settings
    ldap_cfg: LdapConfig | None  # None si LDAP no está configurado (skip search_user)
    _call_cache: dict[str, dict[str, Any]] = field(default_factory=dict)
    _call_hits: dict[str, int] = field(default_factory=dict)


# Después de cuántos cache hits devolvemos hard error en vez del payload normal.
# 0 = primer call (real), 1+ = cached. A partir del 2do hit (3 calls totales) devolvemos error.
_MAX_REPEAT_HITS = 2


def _cache_get(ctx: EnricherContext, key: str) -> dict[str, Any] | None:
    return ctx._call_cache.get(key)


def _cache_set(ctx: EnricherContext, key: str, value: dict[str, Any]) -> None:
    ctx._call_cache[key] = value


def _track_hit(ctx: EnricherContext, key: str) -> int:
    """Incrementa el contador de hits para una key y devuelve el nuevo valor."""
    ctx._call_hits[key] = ctx._call_hits.get(key, 0) + 1
    return ctx._call_hits[key]


def _cached_reply(
    prev: dict[str, Any], tool_name: str, key: str, hit_count: int
) -> dict[str, Any]:
    """Devuelve la respuesta cacheada con marca + warning."""
    out = dict(prev)
    out["_cache_hit"] = True
    out["_hit_count"] = hit_count
    out["_warning"] = (
        f"Ya llamaste {tool_name}({key}) antes (hit #{hit_count}). "
        f"NO vuelvas a llamar a esta tool con los mismos argumentos. "
        f"Producí el JSON final ahora."
    )
    return out


def _hard_stop_reply(tool_name: str, key: str, hit_count: int) -> dict[str, Any]:
    """Respuesta agresiva tras >=N hits: el LLM tiene que parar de llamar tools.

    Cambiamos el shape de la respuesta a algo que parece error. La idea es romper
    el patrón mental del LLM que cree que llamando otra vez va a obtener data nueva.
    """
    return {
        "_error": "MAX_RETRIES_EXCEEDED",
        "_tool": tool_name,
        "_key": key,
        "_hit_count": hit_count + 1,
        "_critical_instruction": (
            f"STOP. Llamaste {tool_name}({key}) {hit_count + 1} veces seguidas. "
            f"Esta es la ÚLTIMA RESPUESTA que vas a recibir de tools. "
            f"Componé el JSON EnrichmentResult AHORA con la data que ya tenés. "
            f"Si no tenés data suficiente, devolvé un EnrichmentResult con "
            f"flags=['enricher_loop_aborted'] y summary explicando que el agent "
            f"se atascó. NO llames más tools."
        ),
    }


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
    cache_key = f"ldap:{sam_account_name}"
    cached = _cache_get(ctx.context, cache_key)
    if cached is not None:
        hit_count = _track_hit(ctx.context, cache_key)
        if hit_count >= _MAX_REPEAT_HITS:
            logger.error(
                "🛑 TOOL ldap_search_user(sam=%r) → HARD STOP (hit #%d, forzando salida)",
                sam_account_name, hit_count,
            )
            return _hard_stop_reply("ldap_search_user", f"'{sam_account_name}'", hit_count)
        logger.warning(
            "⚠️  TOOL ldap_search_user(sam=%r) → CACHED (hit #%d)",
            sam_account_name, hit_count,
        )
        return _cached_reply(cached, "ldap_search_user", f"'{sam_account_name}'", hit_count)

    cfg = ctx.context.ldap_cfg
    logger.info("🔎 TOOL ldap_search_user(sam=%r) [agent=Enricher]", sam_account_name)

    if cfg is None:
        logger.warning(
            "↳ ldap_search_user(sam=%r) → SKIP: LDAP no configurado", sam_account_name
        )
        result = {
            "found": False,
            "sam": sam_account_name,
            "error": "LDAP no configurado en este entorno",
        }
        _cache_set(ctx.context, cache_key, result)
        return result

    try:
        user: ADUser | None = ldap_tools.search_user(cfg, sam_account_name)
    except Exception as e:  # noqa: BLE001 - el LLM necesita un string, no un raise
        logger.warning(
            "↳ ldap_search_user(sam=%r) → ERROR: %s", sam_account_name, e
        )
        result = {"found": False, "sam": sam_account_name, "error": str(e)}
        _cache_set(ctx.context, cache_key, result)
        return result

    if user is None:
        logger.info("↳ ldap_search_user(sam=%r) → NOT FOUND in AD", sam_account_name)
        result = {"found": False, "sam": sam_account_name}
        _cache_set(ctx.context, cache_key, result)
        return result

    # Visibilidad: la línea más importante del Enricher. Acá ves QUÉ aprendió el agent.
    logger.info(
        "↳ ldap_search_user(sam=%r) → FOUND: enabled=%s locked=%s "
        "dept=%r title=%r mgr=%s groups=%d bad_pwd=%d last_logon=%s",
        sam_account_name,
        user.account_enabled,
        user.locked_out,
        user.department,
        user.title,
        (user.manager.split(",")[0] if user.manager else None),
        len(user.member_of),
        user.bad_pwd_count,
        user.last_logon,
    )
    result = {
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
    _cache_set(ctx.context, cache_key, result)
    return result


@function_tool
async def wazuh_get_rule(
    ctx: RunContextWrapper[EnricherContext], rule_id: str
) -> dict[str, Any]:
    """Trae el detalle de una Wazuh rule por ID.

    Útil para entender por qué disparó la alerta y qué MITRE tactic/technique asocia.

    Args:
        rule_id: ID numérico de la rule. Ejemplo: "60106".
    """
    cache_key = f"rule:{rule_id}"
    cached = _cache_get(ctx.context, cache_key)
    if cached is not None:
        hit_count = _track_hit(ctx.context, cache_key)
        if hit_count >= _MAX_REPEAT_HITS:
            logger.error(
                "🛑 TOOL wazuh_get_rule(rule_id=%r) → HARD STOP (hit #%d, forzando salida)",
                rule_id, hit_count,
            )
            return _hard_stop_reply("wazuh_get_rule", f"'{rule_id}'", hit_count)
        logger.warning(
            "⚠️  TOOL wazuh_get_rule(rule_id=%r) → CACHED (hit #%d)",
            rule_id, hit_count,
        )
        return _cached_reply(cached, "wazuh_get_rule", f"'{rule_id}'", hit_count)

    settings = ctx.context.settings
    logger.info("🔎 TOOL wazuh_get_rule(rule_id=%r) [agent=Enricher]", rule_id)

    if not settings.wazuh_api_password:
        logger.warning(
            "↳ wazuh_get_rule(rule_id=%r) → SKIP: Wazuh API no configurado", rule_id
        )
        result = {"found": False, "rule_id": rule_id, "error": "Wazuh API no configurado"}
        _cache_set(ctx.context, cache_key, result)
        return result

    try:
        async with WazuhApiClient(settings) as client:
            rule = await client.get_rule(rule_id)
    except WazuhApiError as e:
        logger.warning("↳ wazuh_get_rule(rule_id=%r) → ERROR: %s", rule_id, e)
        result = {"found": False, "rule_id": rule_id, "error": str(e)}
        _cache_set(ctx.context, cache_key, result)
        return result

    if rule is None:
        logger.info("↳ wazuh_get_rule(rule_id=%r) → NOT FOUND", rule_id)
        result = {"found": False, "rule_id": rule_id}
        _cache_set(ctx.context, cache_key, result)
        return result

    logger.info(
        "↳ wazuh_get_rule(rule_id=%r) → FOUND: level=%d desc=%r groups=%s mitre=%s",
        rule_id,
        rule.level,
        rule.description[:80],
        rule.groups,
        rule.mitre_ids,
    )
    result = {
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
    _cache_set(ctx.context, cache_key, result)
    return result


@function_tool
async def wazuh_recent_alerts(
    ctx: RunContextWrapper[EnricherContext],
    sha256: str | None = None,
    host: str | None = None,
    user: str | None = None,
    rule_id: str | None = None,
    minutes: int = 30,
) -> dict[str, Any]:
    """Busca alertas recientes de Wazuh para detectar correlación / brote.

    Pasá al menos uno: sha256, host, user, rule_id. El match es OR. Devuelve
    las alertas que matchean dentro de los últimos `minutes` (default 30, max 1440).

    Usar cuando: hay archivo con sha256 (¿está en otros endpoints?), o un host con
    múltiples eventos en serie, o un user que repite alertas.

    Args:
        sha256: hash del archivo a correlar.
        host: hostname (agent name o device hostname).
        user: sam del usuario.
        rule_id: ID de regla para contar disparos.
        minutes: ventana hacia atrás (default 30).
    """
    minutes = max(1, min(minutes, 1440))
    filters_key = f"sha={sha256}|host={host}|user={user}|rule={rule_id}|min={minutes}"
    cache_key = f"recent:{filters_key}"

    cached = _cache_get(ctx.context, cache_key)
    if cached is not None:
        hit_count = _track_hit(ctx.context, cache_key)
        if hit_count >= _MAX_REPEAT_HITS:
            logger.error(
                "🛑 TOOL wazuh_recent_alerts(%s) → HARD STOP (hit #%d)",
                filters_key, hit_count,
            )
            return _hard_stop_reply("wazuh_recent_alerts", filters_key, hit_count)
        logger.warning(
            "⚠️  TOOL wazuh_recent_alerts(%s) → CACHED (hit #%d)",
            filters_key, hit_count,
        )
        return _cached_reply(cached, "wazuh_recent_alerts", filters_key, hit_count)

    logger.info("🔎 TOOL wazuh_recent_alerts(%s) [agent=Enricher]", filters_key)

    if not any((sha256, host, user, rule_id)):
        result = {
            "found": False,
            "count": 0,
            "matches": [],
            "error": "Debe proveer al menos un filtro (sha256, host, user, rule_id).",
        }
        _cache_set(ctx.context, cache_key, result)
        return result

    try:
        matches = wazuh_alerts.query_recent_alerts(
            sha256=sha256, host=host, user=user, rule_id=rule_id, minutes=minutes,
        )
    except Exception as e:  # noqa: BLE001
        logger.warning("↳ wazuh_recent_alerts(%s) → ERROR: %s", filters_key, e)
        result = {"found": False, "count": 0, "matches": [], "error": str(e)}
        _cache_set(ctx.context, cache_key, result)
        return result

    distinct_hosts = len({m.host for m in matches if m.host})
    distinct_users = len({m.user for m in matches if m.user})
    distinct_sha256 = len({m.sha256 for m in matches if m.sha256})

    logger.info(
        "↳ wazuh_recent_alerts(%s) → FOUND %d alerts (hosts=%d users=%d shas=%d, window=%dm)",
        filters_key, len(matches), distinct_hosts, distinct_users, distinct_sha256, minutes,
    )

    result = {
        "found": len(matches) > 0,
        "count": len(matches),
        "distinct_hosts": distinct_hosts,
        "distinct_users": distinct_users,
        "distinct_sha256": distinct_sha256,
        "window_minutes": minutes,
        "matches": [m.model_dump() for m in matches],
    }
    _cache_set(ctx.context, cache_key, result)
    return result


# ===== System prompt =====

SYSTEM_PROMPT = """Sos el agente ENRICHER de un SOC L1. Recibís una alerta ya triada \
(verdict=analyze) y tu trabajo es enriquecerla con contexto antes de que el siguiente \
agente decida acción.

Tenés 3 tools:
  - ldap_search_user(sam_account_name): mirá AD para cada usuario involucrado.
  - wazuh_get_rule(rule_id): detalle de la rule de Wazuh.
  - wazuh_recent_alerts(sha256?, host?, user?, rule_id?, minutes?): correlación / brote. \
Busca alertas recientes con esos filtros (OR-match).

REGLAS CRÍTICAS (anti-loop):
  - Cada tool se llama **MÁXIMO 1 VEZ por argumento**. Si ya llamaste \
ldap_search_user('jdoe'), NO la vuelvas a llamar. Si ya llamaste wazuh_get_rule('200002'), \
NO la repitas.
  - Si una tool ya devolvió found=false o un error, ACEPTÁ ese resultado y seguí. \
NO reintentes con el mismo argumento.
  - Después de juntar los datos de las tools, escribí el JSON FINAL sin más tool calls.

RESULTADOS VÁLIDOS QUE NO REQUIEREN REINTENTAR:
  - **found=false en ldap_search_user**: el user no existe en AD. Es un dato útil \
(flag "no_ad_match"). NO sigas buscando ese sam, no existe.
  - **rule.description con placeholders** como '$(title)' o '${var}': es así por como \
Wazuh devuelve el template (no se resuelve hasta que la alerta dispara). Usá lo que \
TENÉS (level, groups, mitre) y componé el JSON. NO sigas llamando tools para "resolver" el template.
  - **mitre=[] (vacío)**: la rule no tiene mapping MITRE asociado. NO es un error, \
seguí con esa info.

SI RECIBÍS `{"_error": "MAX_RETRIES_EXCEEDED", ...}` en una tool response:
  - Es la señal de que YA llamaste esa tool varias veces. PARÁ COMPLETAMENTE de llamar tools.
  - Componé el JSON EnrichmentResult con la data que TENGAS, aunque sea parcial.
  - Si te falta info, devolvé flags=['enricher_loop_aborted'] y describí en summary qué pasó.

PROCEDIMIENTO OBLIGATORIO (en este orden):
1. Para CADA usuario en users_involved del input, llamá ldap_search_user con su `sam` \
(idealmente en paralelo - una llamada por user). Si la lista está vacía, no llames.
2. Si la alerta tiene wazuh_rule.id, llamá wazuh_get_rule UNA SOLA VEZ con ese id.
3. Si la alerta tiene file con sha256, llamá wazuh_recent_alerts(sha256=..., minutes=30) \
UNA SOLA VEZ. Si NO hay sha256 pero hay host afectado, llamá wazuh_recent_alerts(host=..., minutes=30). \
Si NO hay sha256 ni host pero hay user, llamá wazuh_recent_alerts(user=..., minutes=30). \
Esta tool es para detectar brote/correlación: si vuelve count>=3 o distinct_hosts>=2, hay señal \
de evento múltiple, no un caso aislado.
4. Componé y devolvé EXACTAMENTE el JSON de EnrichmentResult. NO más tool calls después \
de este punto.

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
- "outbreak_suspected" → wazuh_recent_alerts devolvió count>=3 o distinct_hosts>=2 con \
el mismo sha256/host (mismo binario / mismo evento en múltiples endpoints).
- "repeat_offender_user" → wazuh_recent_alerts(user=...) devolvió count>=3 dentro de la ventana \
(usuario con eventos múltiples).

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
        tools=[ldap_search_user, wazuh_get_rule, wazuh_recent_alerts],
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
    max_turns: int = 20,
) -> EnrichmentResult:
    """Corre el Enricher contra una alerta. Devuelve el resultado estructurado.

    max_turns=20: en producción vimos al LLM repetir tool calls (6x get_rule sobre
    el mismo rule_id) y agotar el default de 10 turns del SDK. 20 deja margen para
    2-3 users LDAP + 1 rule + síntesis sin perderse.
    """
    agent = build_enricher_agent(model=model)
    ctx = EnricherContext(settings=settings, ldap_cfg=ldap_cfg)
    user_input = _alert_to_prompt_input(alert)
    result = await Runner.run(agent, input=user_input, context=ctx, max_turns=max_turns)
    return result.final_output_as(EnrichmentResult)
