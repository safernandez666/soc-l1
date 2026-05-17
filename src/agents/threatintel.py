"""ThreatIntel agent - corre en paralelo al Enricher.

Mientras el Enricher mira AD + Wazuh rule (local), el ThreatIntel mira fuentes
EXTERNAS: VirusTotal para hashes, AbuseIPDB para IPs. Le da al Narrator un
segundo opinion sobre los IOCs de la alerta.

Tools:
  - vt_lookup_hash(sha256): VT v3 file report → detection rate, family, names
  - abuseipdb_check(ip): IP reputation → confidence score 0-100, ISP, country

Cache anti-loop por (tool, args) en el contexto (mismo patrón que Enricher).

PROCEDIMIENTO esperado del LLM (forzado en system prompt):
  1. Por cada file en alert.files con SHA256 → vt_lookup_hash
  2. Por cada IP en alert.network (src/dst) → abuseipdb_check
  3. Sintetizar en ThreatIntelResult

El Narrator final recibe alert + triage + enrichment + threat_intel.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from agents import Agent, RunContextWrapper, Runner, function_tool
from pydantic import BaseModel, ConfigDict, Field

from src.config import Settings
from src.models import AbuseipdbReport, NormalizedAlert, VtFileReport
from src.tools.threatintel import (
    AbuseipdbClient,
    ThreatIntelError,
    VirusTotalClient,
)

logger = logging.getLogger("soc-l1")


@dataclass
class ThreatIntelContext:
    """Inyectado vía RunContextWrapper. Cache + hit counter anti-loop.

    Mismo patrón que EnricherContext: cache devuelve resultado anterior; tras
    _MAX_REPEAT_HITS hits, hard-stop con error structure que fuerza al LLM a parar.
    """

    settings: Settings
    _call_cache: dict[str, dict[str, Any]] = field(default_factory=dict)
    _call_hits: dict[str, int] = field(default_factory=dict)


_MAX_REPEAT_HITS = 2


def _cache_get(ctx: ThreatIntelContext, key: str) -> dict[str, Any] | None:
    return ctx._call_cache.get(key)


def _cache_set(ctx: ThreatIntelContext, key: str, value: dict[str, Any]) -> None:
    ctx._call_cache[key] = value


def _track_hit(ctx: ThreatIntelContext, key: str) -> int:
    ctx._call_hits[key] = ctx._call_hits.get(key, 0) + 1
    return ctx._call_hits[key]


def _cached_reply(
    prev: dict[str, Any], tool_name: str, key: str, hit_count: int
) -> dict[str, Any]:
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
    return {
        "_error": "MAX_RETRIES_EXCEEDED",
        "_tool": tool_name,
        "_key": key,
        "_hit_count": hit_count + 1,
        "_critical_instruction": (
            f"STOP. Llamaste {tool_name}({key}) {hit_count + 1} veces seguidas. "
            f"Esta es la ÚLTIMA RESPUESTA. Componé el JSON ThreatIntelResult AHORA "
            f"con la data que ya tenés. Si te falta, devolvé flags=['threatintel_loop_aborted'] "
            f"y explicalo en summary. NO llames más tools."
        ),
    }


# ===== Output schema =====


class ThreatIntelResult(BaseModel):
    """Output estructurado del ThreatIntel. Lo consume el Narrator."""

    model_config = ConfigDict(extra="forbid")
    file_reports: list[VtFileReport] = Field(default_factory=list)
    ip_reports: list[AbuseipdbReport] = Field(default_factory=list)
    summary: str = Field(
        description=(
            "Resumen ejecutivo 2-3 líneas. Qué dice cada fuente externa. "
            "Si VT/AbuseIPDB no encontró un IOC, decirlo explícito."
        )
    )
    flags: list[str] = Field(
        default_factory=list,
        description=(
            "Señales para el Narrator. Ejemplos: 'vt_highly_malicious' (>50% engines), "
            "'vt_known_family_<name>', 'abuseipdb_high_confidence' (score >=75), "
            "'ip_tor_exit', 'ip_whitelisted', 'no_ti_data' (ningún IOC encontrado)."
        ),
    )


# ===== Tools =====


@function_tool
async def vt_lookup_hash(
    ctx: RunContextWrapper[ThreatIntelContext], sha256: str
) -> dict[str, Any]:
    """Consulta VirusTotal por un hash SHA256 de archivo.

    Devuelve detection rate (cuántos motores AV lo marcan malicious), familia de
    malware si se conoce, primera vez visto en VT, nombres de archivos vistos.

    Si el hash NO está en VT, devuelve found=false (no es error - VT no lo vio aún).

    Args:
        sha256: Hash SHA256 del archivo. Hex lowercase de 64 chars.
    """
    cache_key = f"vt:{sha256}"
    cached = _cache_get(ctx.context, cache_key)
    if cached is not None:
        hit_count = _track_hit(ctx.context, cache_key)
        if hit_count >= _MAX_REPEAT_HITS:
            logger.error(
                "🛑 TOOL vt_lookup_hash(sha256=%r) → HARD STOP (hit #%d)",
                sha256, hit_count,
            )
            return _hard_stop_reply("vt_lookup_hash", f"'{sha256}'", hit_count)
        logger.warning(
            "⚠️  TOOL vt_lookup_hash(sha256=%r) → CACHED (hit #%d)", sha256, hit_count,
        )
        return _cached_reply(cached, "vt_lookup_hash", f"'{sha256}'", hit_count)

    settings = ctx.context.settings
    logger.info("🔎 TOOL vt_lookup_hash(sha256=%r) [agent=ThreatIntel]", sha256)

    if not settings.virustotal_api_key:
        logger.warning("↳ vt_lookup_hash → SKIP: VT no configurado")
        result = {"found": False, "sha256": sha256, "error": "VirusTotal no configurado"}
        _cache_set(ctx.context, cache_key, result)
        return result

    try:
        async with VirusTotalClient(settings) as vt:
            report = await vt.get_file_report(sha256)
    except ThreatIntelError as e:
        logger.warning("↳ vt_lookup_hash(sha256=%r) → ERROR: %s", sha256, e)
        result = {"found": False, "sha256": sha256, "error": str(e)}
        _cache_set(ctx.context, cache_key, result)
        return result

    if report is None:
        logger.info("↳ vt_lookup_hash(sha256=%r) → NOT FOUND in VT", sha256)
        result = {"found": False, "sha256": sha256, "note": "VT no conoce este hash"}
        _cache_set(ctx.context, cache_key, result)
        return result

    logger.info(
        "↳ vt_lookup_hash(sha256=%r) → FOUND: %d/%d malicious family=%r names=%s",
        sha256,
        report.malicious_count,
        report.total_engines,
        report.family,
        report.names[:3],
    )
    result = {
        "found": True,
        "sha256": report.sha256,
        "malicious_count": report.malicious_count,
        "suspicious_count": report.suspicious_count,
        "undetected_count": report.undetected_count,
        "total_engines": report.total_engines,
        "family": report.family,
        "categories": report.categories,
        "first_submission": report.first_submission,
        "last_analysis": report.last_analysis,
        "names": report.names,
        "type_description": report.type_description,
        "size": report.size,
    }
    _cache_set(ctx.context, cache_key, result)
    return result


@function_tool
async def abuseipdb_check(
    ctx: RunContextWrapper[ThreatIntelContext], ip: str
) -> dict[str, Any]:
    """Consulta AbuseIPDB por la reputation de una IP.

    Devuelve confidence score 0-100 (crowdsourced - mayor = más reportada como
    abuso), país, ISP, cantidad de reports, si es Tor exit, si está whitelisted.

    Si la IP es inválida (no parseable), devuelve found=false.

    Args:
        ip: Dirección IPv4 o IPv6 en string. NO meter CIDR ni hostname.
    """
    cache_key = f"abuseipdb:{ip}"
    cached = _cache_get(ctx.context, cache_key)
    if cached is not None:
        hit_count = _track_hit(ctx.context, cache_key)
        if hit_count >= _MAX_REPEAT_HITS:
            logger.error(
                "🛑 TOOL abuseipdb_check(ip=%r) → HARD STOP (hit #%d)", ip, hit_count,
            )
            return _hard_stop_reply("abuseipdb_check", f"'{ip}'", hit_count)
        logger.warning(
            "⚠️  TOOL abuseipdb_check(ip=%r) → CACHED (hit #%d)", ip, hit_count,
        )
        return _cached_reply(cached, "abuseipdb_check", f"'{ip}'", hit_count)

    settings = ctx.context.settings
    logger.info("🔎 TOOL abuseipdb_check(ip=%r) [agent=ThreatIntel]", ip)

    if not settings.abuseipdb_api_key:
        logger.warning("↳ abuseipdb_check → SKIP: AbuseIPDB no configurado")
        result = {"found": False, "ip": ip, "error": "AbuseIPDB no configurado"}
        _cache_set(ctx.context, cache_key, result)
        return result

    try:
        async with AbuseipdbClient(settings) as ab:
            report = await ab.check_ip(ip)
    except ThreatIntelError as e:
        logger.warning("↳ abuseipdb_check(ip=%r) → ERROR: %s", ip, e)
        result = {"found": False, "ip": ip, "error": str(e)}
        _cache_set(ctx.context, cache_key, result)
        return result

    if report is None:
        logger.info("↳ abuseipdb_check(ip=%r) → INVALID IP", ip)
        result = {"found": False, "ip": ip, "note": "IP inválida según AbuseIPDB"}
        _cache_set(ctx.context, cache_key, result)
        return result

    logger.info(
        "↳ abuseipdb_check(ip=%r) → FOUND: score=%d country=%s isp=%r reports=%d "
        "whitelisted=%s tor=%s",
        ip,
        report.abuse_confidence_score,
        report.country_code,
        report.isp,
        report.total_reports,
        report.is_whitelisted,
        report.is_tor,
    )
    result = {
        "found": True,
        "ip": report.ip,
        "abuse_confidence_score": report.abuse_confidence_score,
        "country_code": report.country_code,
        "isp": report.isp,
        "domain": report.domain,
        "total_reports": report.total_reports,
        "distinct_reporters": report.distinct_reporters,
        "last_reported_at": report.last_reported_at,
        "is_whitelisted": report.is_whitelisted,
        "is_tor": report.is_tor,
        "usage_type": report.usage_type,
    }
    _cache_set(ctx.context, cache_key, result)
    return result


# ===== System prompt =====

SYSTEM_PROMPT = """Sos el agente THREAT_INTEL de un SOC L1. Tu trabajo es enriquecer una \
alerta normalizada con datos de fuentes externas de threat intelligence: VirusTotal \
(reputation de archivos por hash) y AbuseIPDB (reputation de IPs).

Tenés 2 tools:
  - vt_lookup_hash(sha256): VT v3 file report
  - abuseipdb_check(ip): IP reputation crowdsourced

REGLAS CRÍTICAS (anti-loop):
  - Cada tool se llama MÁXIMO 1 VEZ por argumento. NO repitas con los mismos args.
  - Si una tool devolvió found=false / error, ACEPTÁ y seguí. NO reintentes.
  - Después de juntar los datos, escribí el JSON FINAL sin más tool calls.

PROCEDIMIENTO OBLIGATORIO:
1. Por cada file en alert.files que tenga sha256 (no None, no vacío) → vt_lookup_hash.
   Si la lista está vacía o ningún file tiene SHA256, no llames.
2. Por cada IP en alert.network (src_ip_internal, src_ip_external, dst_ip) que NO sea \
None ni RFC1918 (10.*, 172.16-31.*, 192.168.*) → abuseipdb_check.
   IPs privadas no tiene sentido consultarlas (AbuseIPDB es para IPs públicas).
3. Componé y devolvé EXACTAMENTE el JSON de ThreatIntelResult.

CRITERIO PARA `flags`:
- "vt_highly_malicious" → algún file con malicious_count >= 50% de total_engines
- "vt_known_family_<name>" → uno por cada family distinta encontrada (ej. "vt_known_family_emotet")
- "vt_unknown_hash" → al menos un SHA256 no estaba en VT (puede ser malware nuevo)
- "abuseipdb_high_confidence" → alguna IP con score >= 75
- "abuseipdb_medium_confidence" → alguna IP con score entre 25 y 74
- "ip_tor_exit" → alguna IP es Tor
- "ip_whitelisted" → alguna IP está whitelisted (probablemente FP)
- "no_ti_data" → no se pudo obtener data de ninguna fuente (ej. no había hashes ni IPs públicas)

CRITERIO PARA `summary`:
- 2-3 líneas, claras. Mencioná: cuántos files chequeados (y cuántos malicious según VT), \
cuántas IPs chequeadas (y la peor según AbuseIPDB).
- Ejemplo: "1 archivo chequeado: SHA256 abc... = 55/72 malicious (trojan.eicar). \
1 IP externa: 1.2.3.4 score=92 (RU, reportada 42 veces). Sin Tor, sin whitelisted."

Si NO había hashes ni IPs públicas que consultar, devolvé el JSON con file_reports=[], \
ip_reports=[], flags=["no_ti_data"], summary="Alerta sin IOCs externos para consultar."."""


# ===== Build + run =====


def build_threatintel_agent(model: str = "gpt-4o-mini") -> Agent[ThreatIntelContext]:
    return Agent[ThreatIntelContext](
        name="ThreatIntel",
        instructions=SYSTEM_PROMPT,
        model=model,
        tools=[vt_lookup_hash, abuseipdb_check],
        output_type=ThreatIntelResult,
    )


def _alert_to_prompt_input(alert: NormalizedAlert) -> str:
    """Compacta la alerta al JSON que ve el LLM. Excluye `raw`."""
    return alert.model_dump_json(exclude={"raw"}, indent=2)


async def threat_intel_alert(
    alert: NormalizedAlert,
    settings: Settings,
    model: str = "gpt-4o-mini",
    max_turns: int = 20,
) -> ThreatIntelResult:
    """Corre el ThreatIntel agent contra una alerta. Devuelve ThreatIntelResult."""
    agent = build_threatintel_agent(model=model)
    ctx = ThreatIntelContext(settings=settings)
    user_input = _alert_to_prompt_input(alert)
    result = await Runner.run(agent, input=user_input, context=ctx, max_turns=max_turns)
    return result.final_output_as(ThreatIntelResult)
