"""FastAPI service - ingesta de alertas Wazuh + Defender + approval workflow.

Endpoints:
  POST /webhook/wazuh-alert     - recibe alerta, verifica HMAC, normaliza, lanza pipeline
  GET  /health                  - healthcheck simple
  GET  /approve/{token}         - aprobar plan del Narrator (click desde email)
  GET  /reject/{token}          - rechazar plan del Narrator (click desde email)

Pipeline (background, post-202):
  normalize → Triage → routing
    ├─ auto_close_benign  → log audit
    ├─ analyze            → Enricher → Narrator → email approval → executor (post-approve)
    └─ fast_track_critical→ Narrator → email approval → executor (post-approve)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from src.config import Settings
from src.models import NormalizedAlert
from src.normalize import normalize
from src.security import verify_wazuh_signature
from src.trace import PipelineTrace

logger = logging.getLogger("soc-l1")

# Background tasks fire-and-forget: guardamos referencia fuerte para que el GC de
# CPython no las recolecte (y cancele silenciosamente) antes de que terminen.
_background_tasks: set[asyncio.Task] = set()


def _spawn(coro) -> asyncio.Task:
    """create_task anclado: retiene la referencia hasta que la task termina."""
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cache singleton de settings (lee .env una sola vez)."""
    return Settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    # Silenciar el ruido de las libs HTTP - nos quedamos con los logs del pipeline.
    # Cada llamada a OpenAI / Wazuh API se loggea explícitamente en nuestros tools.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)
    # openai.agents emite ERROR 429 cada vez que el tracing endpoint nos limita
    # (telemetría interna del SDK, no afecta el pipeline). Lo silenciamos por
    # completo deshabilitando el tracing - no usamos esos traces para nada.
    logging.getLogger("openai.agents").setLevel(logging.CRITICAL)
    try:
        from agents import set_tracing_disabled

        set_tracing_disabled(True)
    except ImportError:
        # SDK viejo sin esta API - el setLevel ya es suficiente
        pass

    logger.info("SOC L1 service starting up - log level=%s", settings.log_level)

    if settings.openai_api_key and not os.environ.get("OPENAI_API_KEY"):
        os.environ["OPENAI_API_KEY"] = settings.openai_api_key
        logger.info("OPENAI_API_KEY exported to environment (from .env)")

    if settings.enable_triage and not settings.openai_api_key:
        logger.warning(
            "ENABLE_TRIAGE=true pero OPENAI_API_KEY no está seteada. "
            "El triage va a fallar. Agregá OPENAI_API_KEY=sk-... al .env"
        )

    # Init SQLite si Narrator está habilitado (es lo único que la usa)
    sweeper: asyncio.Task | None = None
    if settings.enable_narrator:
        from src.state import init_db

        await init_db(settings.state_db_path)
        sweeper = asyncio.create_task(_purge_sweeper(settings))

    yield
    if sweeper is not None:
        sweeper.cancel()
    logger.info("SOC L1 service shutting down")


async def _purge_sweeper(settings: Settings) -> None:
    """Housekeeping periódico: purga approvals viejos cada 6h (y una vez al boot)."""
    from src.state import purge_old_approvals

    while True:
        try:
            await purge_old_approvals(
                settings.state_db_path, settings.approval_retention_days
            )
        except Exception:  # noqa: BLE001 - el sweeper nunca debe tumbar el servicio
            logger.exception("purge sweeper falló (reintenta en el próximo ciclo)")
        await asyncio.sleep(6 * 3600)


app = FastAPI(
    title="SOC L1 - Wazuh + Defender",
    version="0.2.0",
    description="Multi-agent SOAR for Wazuh alerts (Defender via Wazuh + native) with email approval",
    lifespan=lifespan,
)


SettingsDep = Annotated[Settings, Depends(get_settings)]


# ===== Health & ingest =====


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "soc-l1"}


@app.post("/webhook/wazuh-alert", status_code=status.HTTP_202_ACCEPTED)
async def wazuh_webhook(
    request: Request,
    settings: SettingsDep,
    x_wazuh_signature: Annotated[str | None, Header(alias="X-Wazuh-Signature")] = None,
) -> JSONResponse:
    """Recibe alerta Wazuh. Verifica IP source + HMAC, normaliza, lanza pipeline."""
    # Guardrail #1: source IP allowlist (default: localhost only).
    # Reduce surface attack - aunque alguien tenga el HMAC secret, solo puede
    # mandar desde IPs autorizadas.
    client_ip = request.client.host if request.client else None
    allowed_ips = settings.webhook_allowed_ips_set()
    if client_ip not in allowed_ips:
        logger.warning(
            "Wazuh webhook: source IP %s NOT in allowlist %s - rejecting",
            client_ip, sorted(allowed_ips),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"webhook source IP not allowed",
        )

    body = await request.body()

    if not verify_wazuh_signature(settings.wazuh_webhook_secret, body, x_wazuh_signature):
        logger.warning("Wazuh webhook: invalid or missing HMAC signature")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid signature")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as e:
        logger.error("Wazuh webhook: invalid JSON body: %s", e)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid JSON") from e

    try:
        alert = normalize(payload)
    except Exception as e:
        logger.exception("Wazuh webhook: normalize failed")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"normalize error: {e}"
        ) from e

    logger.info(
        "alert accepted | id=%s source=%s severity=%s host=%s users=%s files=%s",
        alert.alert_id,
        alert.source,
        alert.severity_source,
        alert.device.hostname,
        len(alert.users_involved),
        len(alert.files),
    )

    # Dedup: si Wazuh reenvía la misma alerta y ya tiene un approval pending,
    # no relanzamos el pipeline (evita emails + tickets InvGate duplicados).
    if settings.enable_narrator:
        from src.state import has_pending_for_alert

        try:
            if await has_pending_for_alert(settings.state_db_path, alert.alert_id):
                logger.info(
                    "alert deduplicada | id=%s ya tiene un approval pending - skip pipeline",
                    alert.alert_id,
                )
                return JSONResponse(
                    status_code=status.HTTP_202_ACCEPTED,
                    content={
                        "status": "deduplicated",
                        "alert_id": alert.alert_id,
                        "source": alert.source,
                    },
                )
        except Exception:  # noqa: BLE001 - dedup es best-effort, no bloquea el ingest
            logger.exception("dedup check falló para alert id=%s (sigo)", alert.alert_id)

    if settings.enable_triage:
        _spawn(_run_triage_in_background(alert, settings))

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={
            "status": "accepted",
            "alert_id": alert.alert_id,
            "source": alert.source,
        },
    )


# ===== Pipeline =====


async def _run_triage_in_background(alert: NormalizedAlert, settings: Settings) -> None:
    """Corre el Triage agent en background y rutea según el verdict."""
    try:
        from src.agents.triage import triage_alert

        logger.info(
            "🤖 AGENT Triage.run | id=%s model=%s host=%s severity=%s",
            alert.alert_id,
            settings.openai_model_light,
            alert.device.hostname,
            alert.severity_source,
        )
        decision = await triage_alert(alert, model=settings.openai_model_light)
        logger.info(
            "✅ TRIAGE | id=%s verdict=%s confidence=%s\n  reason: %s",
            alert.alert_id,
            decision.verdict,
            decision.confidence,
            decision.reason,
        )
        trace = PipelineTrace(alert.alert_id)
        trace.add(
            "triage", decision.reason,
            detail=f"verdict={decision.verdict} confidence={decision.confidence}",
        )
        await _dispatch_by_verdict(alert, decision, settings, trace)
    except Exception:
        logger.exception("triage failed for alert id=%s", alert.alert_id)


async def _dispatch_by_verdict(
    alert: NormalizedAlert, decision, settings: Settings, trace: PipelineTrace
) -> None:
    if decision.verdict == "auto_close_benign":
        await _handle_auto_close(alert, decision)
    elif decision.verdict == "analyze":
        await _handle_analyze(alert, decision, settings, trace)
    elif decision.verdict == "fast_track_critical":
        await _handle_fast_track(alert, decision, settings, trace)
    else:
        logger.warning(
            "unknown verdict | id=%s verdict=%s (treating as analyze)",
            alert.alert_id,
            decision.verdict,
        )
        await _handle_analyze(alert, decision, settings, trace)


async def _handle_auto_close(alert: NormalizedAlert, decision) -> None:
    """Verdict auto_close_benign: log audit y termina."""
    logger.info(
        "AUDIT auto_closed | id=%s wazuh_rule=%s host=%s reason=%r confidence=%s",
        alert.alert_id,
        alert.wazuh_rule.id,
        alert.device.hostname,
        decision.reason,
        decision.confidence,
    )


async def _handle_analyze(
    alert: NormalizedAlert, decision, settings: Settings, trace: PipelineTrace
) -> None:
    """analyze: Enricher → Narrator → email approval."""
    logger.info(
        "PIPELINE_QUEUED analyze | id=%s host=%s users=%s files=%s",
        alert.alert_id,
        alert.device.hostname,
        len(alert.users_involved),
        len(alert.files),
    )
    await _enrich_and_request_approval(alert, decision, settings, trace, priority="normal")


async def _handle_fast_track(
    alert: NormalizedAlert, decision, settings: Settings, trace: PipelineTrace
) -> None:
    """fast_track_critical: misma pipeline que analyze pero con priority=critical.

    El Enricher SÍ se ejecuta (a diferencia del diseño v1) - para incidentes críticos
    queremos MÁS contexto, no menos. La diferencia entre analyze/fast_track queda
    como hint para el Narrator vía priority + el triage.verdict que ya recibe.
    """
    logger.warning(
        "PIPELINE_QUEUED fast_track | id=%s host=%s severity=%s (running full enrichment)",
        alert.alert_id,
        alert.device.hostname,
        alert.severity_source,
    )
    await _enrich_and_request_approval(alert, decision, settings, trace, priority="critical")


async def _enrich_and_request_approval(
    alert: NormalizedAlert,
    decision,
    settings: Settings,
    trace: PipelineTrace,
    priority: str = "normal",
) -> None:
    """Pipeline compartido: Enricher + ThreatIntel (paralelo) → Narrator → email.

    priority: "normal" (de analyze) o "critical" (de fast_track). Se traduce en
    un flag extra en el enrichment para que el Narrator lo considere.

    Enricher (LDAP + Wazuh API) y ThreatIntel (VT + AbuseIPDB) son INDEPENDIENTES
    - los corremos en paralelo con asyncio.gather. Ahorra ~5-10s vs secuencial.
    """
    if not settings.enable_enricher:
        logger.info("enricher_skipped | id=%s ENABLE_ENRICHER=false", alert.alert_id)
        return

    # Lanzamos Enricher y ThreatIntel en paralelo (comparten la referencia al trace)
    enrichment_task = asyncio.create_task(_run_enricher_safely(alert, settings, priority, trace))

    ti_task = None
    if settings.enable_threat_intel:
        ti_task = asyncio.create_task(_run_threatintel_safely(alert, settings, trace))

    enrichment = await enrichment_task
    if enrichment is None:
        # Si el Enricher falló, abortamos el pipeline (no tenemos contexto suficiente)
        if ti_task is not None:
            ti_task.cancel()
        return

    threat_intel = None
    if ti_task is not None:
        threat_intel = await ti_task

    await _run_narrator_and_request_approval(
        alert, decision, settings, enrichment, threat_intel, trace
    )


async def _run_enricher_safely(
    alert: NormalizedAlert, settings: Settings, priority: str, trace: PipelineTrace
):
    """Wrapper del Enricher con logging + manejo de errores. Devuelve None si falló."""
    try:
        from src.agents.enricher import enrich_alert

        ldap_cfg = _build_ldap_cfg_safely()
        logger.info(
            "🤖 AGENT Enricher.run | id=%s priority=%s users_to_lookup=%d rule_id=%s",
            alert.alert_id,
            priority,
            len(alert.users_involved),
            alert.wazuh_rule.id,
        )
        # Usamos modelo HEAVY (gpt-4o) - en pruebas con gpt-4o-mini el LLM ignoraba
        # las instrucciones anti-loop y machacaba la misma tool decenas de veces.
        enrichment = await enrich_alert(
            alert, settings=settings, ldap_cfg=ldap_cfg, model=settings.openai_model_heavy
        )
        if priority == "critical" and "fast_track_priority" not in enrichment.flags:
            enrichment.flags.append("fast_track_priority")

        user_lines = []
        for u in enrichment.users:
            if u.found_in_ad:
                user_lines.append(
                    f"  - {u.sam}: enabled={u.enabled} locked={u.locked_out} "
                    f"dept={u.department!r} bad_pwd={u.bad_pwd_count}"
                )
            else:
                err = f" ({u.lookup_error})" if u.lookup_error else ""
                user_lines.append(f"  - {u.sam}: NOT FOUND in AD{err}")

        rule_line = "rule=NOT_FETCHED"
        if enrichment.rule:
            rule_line = (
                f"rule={enrichment.rule.rule_id} level={enrichment.rule.level} "
                f"mitre={enrichment.rule.mitre_ids} groups={enrichment.rule.groups}"
            )

        logger.info(
            "✅ ENRICHED | id=%s users=%d rule_found=%s flags=[%s]\n"
            "  summary: %s\n"
            "%s\n  %s",
            alert.alert_id,
            len(enrichment.users),
            enrichment.rule is not None,
            ", ".join(enrichment.flags) if enrichment.flags else "none",
            enrichment.summary,
            "\n".join(user_lines) if user_lines else "  (no users en enrichment)",
            rule_line,
        )
        trace.add(
            "enricher", enrichment.summary,
            detail=f"users={len(enrichment.users)} flags=[{', '.join(enrichment.flags)}]",
        )
        return enrichment
    except Exception:
        logger.exception("enricher failed for alert id=%s", alert.alert_id)
        return None


async def _run_threatintel_safely(
    alert: NormalizedAlert, settings: Settings, trace: PipelineTrace
):
    """Wrapper del ThreatIntel. Si falla, devuelve None (no aborta el pipeline)."""
    try:
        from src.agents.threatintel import threat_intel_alert

        # Skip silencioso si no hay keys (no spamea log de WARN cada alerta)
        if not settings.virustotal_api_key and not settings.abuseipdb_api_key:
            logger.info(
                "threatintel_skipped | id=%s VT y AbuseIPDB keys vacías",
                alert.alert_id,
            )
            return None

        logger.info(
            "🤖 AGENT ThreatIntel.run | id=%s files=%d ips=[src_int=%s, src_ext=%s, dst=%s]",
            alert.alert_id,
            len(alert.files),
            alert.network.src_ip_internal,
            alert.network.src_ip_external,
            alert.network.dst_ip,
        )
        # Mismo razonamiento que en Enricher: gpt-4o sigue las instrucciones anti-loop
        ti = await threat_intel_alert(
            alert, settings=settings, model=settings.openai_model_heavy
        )

        # Resumen estructurado: qué encontró por hash y por IP
        file_lines = []
        for fr in ti.file_reports:
            file_lines.append(
                f"  - {fr.sha256[:16]}...: {fr.malicious_count}/{fr.total_engines} "
                f"malicious family={fr.family!r}"
            )
        ip_lines = []
        for ir in ti.ip_reports:
            ip_lines.append(
                f"  - {ir.ip}: score={ir.abuse_confidence_score} country={ir.country_code} "
                f"reports={ir.total_reports} whitelisted={ir.is_whitelisted}"
            )

        logger.info(
            "✅ THREAT_INTEL | id=%s files=%d ips=%d flags=[%s]\n"
            "  summary: %s\n"
            "%s\n%s",
            alert.alert_id,
            len(ti.file_reports),
            len(ti.ip_reports),
            ", ".join(ti.flags) if ti.flags else "none",
            ti.summary,
            "\n".join(file_lines) if file_lines else "  (no file reports)",
            "\n".join(ip_lines) if ip_lines else "  (no ip reports)",
        )
        trace.add(
            "threat_intel", ti.summary,
            detail=f"files={len(ti.file_reports)} ips={len(ti.ip_reports)} "
                   f"flags=[{', '.join(ti.flags)}]",
        )
        return ti
    except Exception:
        logger.exception("threatintel failed for alert id=%s", alert.alert_id)
        return None


async def _run_narrator_and_request_approval(
    alert: NormalizedAlert, decision, settings: Settings, enrichment, threat_intel=None,
    trace: PipelineTrace | None = None,
) -> None:
    """Narrator → guardar plan en SQLite → enviar email de approval.

    threat_intel: ThreatIntelResult opcional (puede ser None si ENABLE_THREAT_INTEL=false
    o si el ThreatIntel agent falló - el Narrator igual produce un plan sin TI).
    """
    if not settings.enable_narrator:
        logger.info("narrator_skipped | id=%s ENABLE_NARRATOR=false", alert.alert_id)
        return

    try:
        from src.agents.narrator import narrate_incident
        from src.mailer import send_approval_email
        from src.state import create_pending_approval

        logger.info(
            "🤖 AGENT Narrator.run | id=%s model=%s triage_verdict=%s "
            "enrichment_flags=%d ti_flags=%d",
            alert.alert_id,
            settings.openai_model_heavy,
            decision.verdict,
            len(enrichment.flags),
            len(threat_intel.flags) if threat_intel else 0,
        )
        plan = await narrate_incident(
            alert,
            triage=decision,
            enrichment=enrichment,
            threat_intel=threat_intel,
            model=settings.openai_model_heavy,
        )

        # Detalle de cada acción propuesta (lo que va a aprobar/rechazar el humano)
        action_lines = []
        for a in plan.actions:
            action_lines.append(f"  - {a.type} → {a.target}: {a.justification}")

        logger.info(
            "✅ NARRATED | id=%s risk=%s actions=%d\n"
            "  summary: %s\n"
            "%s",
            alert.alert_id,
            plan.risk_level,
            len(plan.actions),
            plan.executive_summary,
            "\n".join(action_lines) if action_lines else "  (no actions - monitor only)",
        )

        if trace is not None:
            trace.add(
                "narrator", plan.executive_summary,
                detail=f"risk={plan.risk_level} actions={len(plan.actions)}",
            )

        invgate_request_id = await _create_invgate_ticket_safely(
            settings, alert, plan
        )

        if trace is not None and invgate_request_id:
            trace.add(
                "invgate", f"Ticket #{invgate_request_id} creado en InvGate",
                detail=f"prioridad por risk={plan.risk_level}",
            )

        token = await create_pending_approval(
            settings.state_db_path,
            alert_id=alert.alert_id,
            plan_json=plan.model_dump_json(),
            alert_json=alert.model_dump_json(),
            invgate_request_id=invgate_request_id,
            timeline_json=trace.to_json() if trace is not None else None,
        )
        review_url = f"{settings.approval_base_url.rstrip('/')}/review/{token}"
        logger.info(
            "📬 APPROVAL_PENDING | id=%s risk=%s actions=%d ticket=%s\n  review: %s",
            alert.alert_id,
            plan.risk_level,
            len(plan.actions),
            invgate_request_id or "n/a",
            review_url,
        )

        await send_approval_email(
            settings, alert, plan, token,
            invgate_request_id=invgate_request_id,
            enrichment=enrichment,
            threat_intel=threat_intel,
        )
    except Exception:
        logger.exception("narrator/approval failed for alert id=%s", alert.alert_id)


def _build_ldap_cfg_safely():
    """Intenta construir LdapConfig. Si falta config, devuelve None."""
    try:
        from src.config import LdapConfig

        return LdapConfig()
    except Exception as e:  # noqa: BLE001
        logger.warning("LDAP no disponible (%s) - pipeline correrá sin AD writes", e)
        return None


# ===== InvGate ticket helpers =====


async def _create_invgate_ticket_safely(
    settings: Settings, alert: NormalizedAlert, plan,
) -> int | None:
    """Crea ticket InvGate post-Narrator. Devuelve request_id o None (nunca aborta)."""
    try:
        from src.tools.invgate import InvgateClient, is_configured, priority_id_from_risk

        if not is_configured(settings):
            return None

        priority = priority_id_from_risk(plan.risk_level)
        title = f"[SOC-L1] {alert.title} — {alert.device.hostname or 'unknown'}"

        action_lines = []
        for a in plan.actions:
            action_lines.append(f"  - {a.type} → {a.target}: {a.justification}")

        description = (
            f"Resumen ejecutivo:\n{plan.executive_summary}\n\n"
            f"Risk level: {plan.risk_level.upper()}\n\n"
            f"Acciones propuestas ({len(plan.actions)}):\n"
            + ("\n".join(action_lines) if action_lines else "  (ninguna)")
            + f"\n\nAnálisis:\n{plan.rationale}\n\n"
            f"---\n"
            f"Alert ID: {alert.alert_id}\n"
            f"Host: {alert.device.hostname}\n"
            f"Wazuh rule: {alert.wazuh_rule.id} (level {alert.wazuh_rule.level})\n"
            f"Source: {alert.source}\n"
            f"Timestamp: {alert.timestamp}\n"
        )

        async with InvgateClient(settings) as client:
            result = await client.create_incident(
                title=title,
                description=description,
                priority_id=priority,
            )

        if result.ok and result.request_id is not None:
            return result.request_id
        logger.warning(
            "🎫 INVGATE create FAILED | alert=%s error=%s",
            alert.alert_id, result.error,
        )
        return None
    except Exception:
        logger.exception("invgate: create_ticket failed for alert=%s", alert.alert_id)
        return None


async def _update_invgate_on_decision(
    settings: Settings,
    request_id: int,
    decision: str,
    alert_id: str,
    ip: str | None,
) -> None:
    """Agrega comentario al ticket InvGate reflejando la decisión (fire-and-forget)."""
    try:
        from src.tools.invgate import InvgateClient

        if decision == "approved":
            body = f"Plan APROBADO por {ip or 'unknown'}. Ejecutando acciones."
        else:
            body = f"Plan RECHAZADO por {ip or 'unknown'}. No se ejecutan acciones."

        async with InvgateClient(settings) as client:
            await client.add_comment(request_id, body)
    except Exception:
        logger.exception(
            "invgate: decision comment failed | ticket=%s alert=%s",
            request_id, alert_id,
        )


async def _update_invgate_post_execution(
    settings: Settings,
    request_id: int,
    alert_id: str,
    results: list[dict],
) -> None:
    """Agrega comentario post-ejecución al ticket InvGate (fire-and-forget)."""
    try:
        from src.tools.invgate import InvgateClient

        ok_count = sum(1 for r in results if r.get("ok"))
        fail_count = len(results) - ok_count

        lines = [f"Ejecución completada: {ok_count} OK, {fail_count} FAIL."]
        for r in results:
            tag = "OK" if r.get("ok") else "FAIL"
            lines.append(
                f"  [{tag}] {r.get('action_type', '?')} → {r.get('target', '?')}: "
                f"{r.get('message', '')}"
            )

        async with InvgateClient(settings) as client:
            await client.add_comment(request_id, "\n".join(lines))
    except Exception:
        logger.exception(
            "invgate: post_execution comment failed | ticket=%s alert=%s",
            request_id, alert_id,
        )


# ===== Approval endpoints =====


# Design tokens alineados con src/mailer.py (mismo system del integrator Wazuh).
# Cada estado tiene icono + color banner + color de acento.
_PAGE_STATES = {
    "approved":    {"banner": "#15803d", "accent": "#16a34a", "icon": "✅", "title": "Aprobado"},
    "rejected":    {"banner": "#9a3412", "accent": "#ea580c", "icon": "❌", "title": "Rechazado"},
    "already":     {"banner": "#475569", "accent": "#94a3b8", "icon": "ℹ️",  "title": "Ya decidido"},
    "expired":     {"banner": "#7f1d1d", "accent": "#991b1b", "icon": "⏱️",  "title": "Expirado"},
    "not_found":   {"banner": "#7f1d1d", "accent": "#991b1b", "icon": "🚫", "title": "Token inválido"},
    "error":       {"banner": "#7f1d1d", "accent": "#991b1b", "icon": "⚠️",  "title": "Error"},
}


def _decision_meta_html(alert_id: str) -> str:
    """Bloque prominente (alert_id + hora local) para el banner de la confirmación.

    Permite que el operador distinga la decisión recién tomada de una pestaña vieja
    de otra alerta que pueda haber quedado abierta.
    """
    import html as _h

    when = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return (
        '<div style="margin-top:12px; font-size:13px; line-height:1.5; opacity:0.96;">'
        f'Alerta <strong style="font-family:monospace;">{_h.escape(alert_id)}</strong><br>'
        f'<span style="font-size:12px; opacity:0.85;">🕐 {when}</span>'
        "</div>"
    )


def _render_decision_page(
    state_key: str, body_html: str, meta_html: str = ""
) -> HTMLResponse:
    """Render página de decisión con el design system de soc-l1.

    state_key: approved | rejected | already | expired | not_found | error
    body_html: contenido del cuerpo (puede contener <code>, <strong>, etc.)
    meta_html: bloque opcional (alert_id + hora) que se muestra prominente en el
        banner, para que el operador distinga ESTA decisión de una pestaña vieja.
    """
    s = _PAGE_STATES.get(state_key, _PAGE_STATES["error"])
    page = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark light">
  <title>SOC L1 · {s["title"]}</title>
  <style>
    :root {{ color-scheme: dark light; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background-color:#0b0d10; margin:0; padding:40px 20px; color:#f3f4f6; }}
    .container {{ max-width:560px; margin:0 auto; background-color:#14171c;
                  border:1px solid #23272f; border-radius:12px; overflow:hidden;
                  box-shadow:0 1px 3px rgba(0,0,0,0.4); }}
    .banner {{ background:{s["banner"]}; color:white; padding:32px 24px; text-align:center; }}
    .icon {{ font-size:48px; line-height:1; margin-bottom:12px; }}
    .heading {{ font-size:22px; font-weight:bold; margin:0; }}
    .body {{ padding:28px 24px; font-size:14px; line-height:1.6; color:#cbd5e1;
             text-align:center; border-left:4px solid {s["accent"]}; margin:0 24px;
             background-color:#1b1f26; border-radius:6px; }}
    .footer {{ padding:16px; background-color:#0b0d10; text-align:center;
               font-size:12px; color:#94a3b8; }}
    code {{ background-color:#23272f; padding:2px 6px; border-radius:3px;
            font-family:'SF Mono',Monaco,monospace; font-size:12px; color:#cbd5e1; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="banner">
      <div class="icon">{s["icon"]}</div>
      <h1 class="heading">{s["title"]}</h1>
      {meta_html}
    </div>
    <div style="padding: 28px 24px 16px;">
      <div class="body">{body_html}</div>
    </div>
    <div style="text-align:center; padding: 4px 24px 20px;">
      <button onclick="cerrarPestana()"
              style="padding:12px 28px; border:none; border-radius:6px; cursor:pointer;
                     background:{s["accent"]}; color:white; font:bold 14px sans-serif;">
        ✕ Cerrar pestaña
      </button>
      <p id="cerrar-hint" style="display:none; margin:12px 0 0; font-size:13px; color:#94a3b8;">
        Esta pestaña ya cumplió su función — podés cerrarla cuando quieras.
      </p>
    </div>
    <div class="footer">
      <strong>SOC L1 · Wazuh + Defender</strong><br>
      pipeline multi-agente
    </div>
  </div>
  <script>
    function cerrarPestana() {{
      // window.close() solo funciona en pestañas abiertas por script; el browser
      // puede ignorarlo (Safari iOS siempre lo bloquea). Intentamos y, si la pestaña
      // sigue viva, mostramos el hint para que el operador la cierre a mano.
      window.open('', '_self');
      window.close();
      setTimeout(function() {{
        var h = document.getElementById('cerrar-hint');
        if (h) h.style.display = 'block';
      }}, 250);
    }}
  </script>
</body>
</html>
"""
    return HTMLResponse(content=page)


async def _send_closure_safely(
    settings: Settings,
    row: dict,
    *,
    decision: str,
    execution_results: list[dict] | None,
) -> None:
    """Reconstruye alert/plan/timeline desde el row del approval y notifica el cierre.

    Fire-and-forget: cualquier fallo se loguea, nunca propaga. execution_results None
    = rechazo (sin bloque ejecución); [] = aprobado sin acciones; lista = ejecutado.
    """
    try:
        from src.agents.narrator import NarratorPlan
        from src.notify import notify_case_closure

        alert = NormalizedAlert.model_validate_json(row["alert_json"])
        plan = NarratorPlan.model_validate_json(row["plan_json"])
    except Exception:
        logger.exception(
            "closure: no se pudo reconstruir alert/plan | alert=%s",
            row.get("alert_id"),
        )
        return

    await notify_case_closure(
        settings, alert, plan,
        decision=decision,
        timeline_events=PipelineTrace.events_from_json(row.get("timeline_json")),
        execution_results=execution_results,
        decided_by_ip=row.get("decided_by_ip"),
        decided_at=row.get("decided_at"),
        executed_at=row.get("executed_at"),
        invgate_request_id=row.get("invgate_request_id"),
    )


async def _handle_decision(
    request: Request,
    settings: Settings,
    token: str,
    decision: str,
    selected_action_indices: list[int] | None = None,
) -> HTMLResponse:
    """Lógica común para /approve, /reject y /decide.

    selected_action_indices: si viene (desde /decide), solo esas acciones se ejecutan.
    Si None y decision='approved', se ejecutan TODAS (compat con /approve clásico).
    """
    from src.state import decide_approval, mark_executed

    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")

    result, row = await decide_approval(
        settings.state_db_path,
        token=token,
        decision=decision,
        ip=ip,
        user_agent=ua,
        ttl_hours=settings.approval_ttl_hours,
        selected_action_indices=selected_action_indices,
    )

    if result == "not_found":
        logger.warning("APPROVAL_NOT_FOUND | token=%s ip=%s", token[:12], ip)
        return _render_decision_page(
            "not_found",
            "Este link no corresponde a ningún approval pendiente. "
            "Puede haber sido manipulado o pertenecer a otro entorno.",
        )

    if result == "expired":
        logger.warning(
            "APPROVAL_EXPIRED | alert=%s token=%s ip=%s",
            row["alert_id"] if row else "?",
            token[:12],
            ip,
        )
        return _render_decision_page(
            "expired",
            f"Este approval excedió el TTL de <strong>{settings.approval_ttl_hours}h</strong> "
            "y no puede ser decidido. Si la alerta sigue siendo relevante, esperá la próxima "
            "iteración del pipeline.",
        )

    if result == "already_decided":
        prev = row["status"] if row else "?"
        logger.info(
            "APPROVAL_REPLAY | alert=%s token=%s prev_status=%s ip=%s",
            row["alert_id"] if row else "?",
            token[:12],
            prev,
            ip,
        )
        return _render_decision_page(
            "already",
            f"Este approval ya fue resuelto previamente (estado: <strong>{prev}</strong>). "
            "Cada link es single-use y no admite cambios.",
            meta_html=_decision_meta_html(row["alert_id"]) if row else "",
        )

    # result == "ok"
    assert row is not None
    alert_id = row["alert_id"]
    logger.info(
        "APPROVAL_DECISION | alert=%s decision=%s ip=%s ua=%r",
        alert_id,
        decision,
        ip,
        ua,
    )

    invgate_rid = row.get("invgate_request_id")
    if invgate_rid:
        _spawn(
            _update_invgate_on_decision(settings, invgate_rid, decision, alert_id, ip)
        )

    if decision == "rejected":
        # row ya trae decided_at/decided_by_ip actualizados; sin ejecución.
        _spawn(
            _send_closure_safely(settings, row, decision="rejected", execution_results=None)
        )
        return _render_decision_page(
            "rejected",
            f"El plan de acción fue rechazado. <strong>No se ejecutará ninguna acción</strong> "
            f"para la alerta <code>{alert_id}</code>. Quedó registrada la decisión con tu IP "
            "y timestamp para audit.",
            meta_html=_decision_meta_html(alert_id),
        )

    # approved → ejecutar plan
    from src.agents.narrator import NarratorPlan

    try:
        plan = NarratorPlan.model_validate_json(row["plan_json"])
    except Exception:
        logger.exception("APPROVAL_PLAN_PARSE_FAILED | alert=%s", alert_id)
        return _render_decision_page(
            "error",
            "Aprobaste, pero el plan guardado no pudo deserializarse. "
            "Las acciones <strong>no se ejecutaron</strong>. Revisar logs del servicio.",
        )

    # Filtrar por acciones seleccionadas (si vinieron de /decide).
    # Si selected_action_indices es None, se ejecutan todas (modo /approve clásico).
    total_actions = len(plan.actions)
    if selected_action_indices is not None:
        valid_indices = set(selected_action_indices) & set(range(total_actions))
        actions_to_run = [plan.actions[i] for i in sorted(valid_indices)]
        skipped = total_actions - len(actions_to_run)
    else:
        actions_to_run = plan.actions
        skipped = 0

    # Lanzamos el executor en background para responder rápido al humano que clickeó
    _spawn(
        _execute_approved_plan_in_background(
            settings, token, alert_id, plan, actions_to_run, invgate_rid
        )
    )

    import html as _h

    n = len(actions_to_run)
    if n == 0:
        body = (
            f"Approval registrado para la alerta <code>{alert_id}</code>, "
            f"pero <strong>ninguna acción fue seleccionada</strong>. "
            f"No se ejecutó nada. Quedó registrado en SQLite para audit."
        )
    else:
        actions_list = "".join(
            f'<li style="margin:4px 0;"><strong style="font-family:monospace;">'
            f"{_h.escape(a.type)}</strong> → <code>{_h.escape(a.target)}</code></li>"
            for a in actions_to_run
        )
        body = (
            f"Plan aprobado para la alerta <code>{alert_id}</code>.<br><br>"
            f"Se {'está' if n == 1 else 'están'} ejecutando <strong>{n} "
            f"acción{'' if n == 1 else 'es'}</strong> en background:"
            f'<ul style="text-align:left; display:inline-block; margin:10px 0 0; '
            f'padding-left:20px;">{actions_list}</ul>'
        )
        if skipped > 0:
            body += (
                f"<br><br>({skipped} acción{'es' if skipped > 1 else ''} "
                f"<strong>descartada{'s' if skipped > 1 else ''}</strong> por tu selección)"
            )
        body += '<br><br><span style="font-size:12px;color:#94a3b8;">El resultado queda en logs y SQLite.</span>'
    return _render_decision_page("approved", body, meta_html=_decision_meta_html(alert_id))


async def _execute_approved_plan_in_background(
    settings: Settings, token: str, alert_id: str, plan, actions_to_run,
    invgate_request_id: int | None = None,
) -> None:
    """actions_to_run puede ser un subset del plan original (filtrado en /decide)."""
    from src.executor import execute_plan
    from src.state import get_pending_approval, mark_executed

    if not actions_to_run:
        await mark_executed(settings.state_db_path, token, [])
        logger.info("EXECUTED | alert=%s actions=0 (nothing selected)", alert_id)
        # Cierre: aprobado sin acciones → execution_results=[] (no None)
        row = await get_pending_approval(settings.state_db_path, token)
        if row:
            _spawn(
                _send_closure_safely(settings, row, decision="approved", execution_results=[])
            )
        return

    try:
        ldap_cfg = _build_ldap_cfg_safely()
        results = await execute_plan(actions_to_run, ldap_cfg=ldap_cfg, settings=settings)
        await mark_executed(settings.state_db_path, token, results)
        ok_count = sum(1 for r in results if r.get("ok"))
        logger.info(
            "EXECUTED | alert=%s actions=%d ok=%d fail=%d",
            alert_id,
            len(results),
            ok_count,
            len(results) - ok_count,
        )
        if invgate_request_id:
            _spawn(
                _update_invgate_post_execution(
                    settings, invgate_request_id, alert_id, results
                )
            )
        # Cierre: re-leemos el row para tener executed_at + decided_at actualizados
        row = await get_pending_approval(settings.state_db_path, token)
        if row:
            _spawn(
                _send_closure_safely(
                    settings, row, decision="approved", execution_results=results
                )
            )
    except Exception:
        logger.exception("executor failed | alert=%s token=%s", alert_id, token[:12])


@app.get("/approve/{token}")
async def approve_plan(request: Request, settings: SettingsDep, token: str) -> HTMLResponse:
    """Backwards compat: aprueba TODAS las acciones del plan (legacy email links)."""
    return await _handle_decision(request, settings, token, "approved")


@app.get("/reject/{token}")
async def reject_plan(request: Request, settings: SettingsDep, token: str) -> HTMLResponse:
    return await _handle_decision(request, settings, token, "rejected")


# ===== Review (granular approval) =====


def _render_review_page(
    token: str,
    plan,
    alert_id: str,
    risk_color: str,
    risk_label: str,
) -> HTMLResponse:
    """Página HTML con form: 1 checkbox por acción + 2 botones (Aprobar selección, Rechazar todo)."""
    import html as _h

    if not plan.actions:
        # Plan vacío: solo botón rechazar (no hay nada que aprobar)
        actions_html = (
            "<p style='color:#94a3b8;font-style:italic;'>El plan no incluye acciones "
            "automatizadas. Solo podés cerrar el incidente como rechazado.</p>"
        )
    else:
        rows_html = []
        for i, a in enumerate(plan.actions):
            action_color = {
                "disable_user": "#dc2626",
                "force_password_change": "#ea580c",
                "block_ip": "#7f1d1d",
                "scan_host": "#0891b2",
                "isolate_host": "#9333ea",
                "notify_only": "#38bdf8",
                "escalate_l2": "#a16207",
            }.get(a.type, "#475569")
            rows_html.append(
                f"""<label style="display:block;padding:14px 16px;margin-bottom:8px;
                                  background-color:#1b1f26;border-radius:6px;border-left:4px solid {action_color};
                                  cursor:pointer;">
                  <input type="checkbox" name="action_idx" value="{i}" checked
                         style="margin-right:10px;transform:scale(1.3);vertical-align:middle;">
                  <strong style="font-family:monospace;color:{action_color};">{_h.escape(a.type)}</strong>
                  → <code style="background-color:#1b2b3a;padding:2px 6px;border-radius:3px;">{_h.escape(a.target)}</code>
                  <div style="margin:6px 0 0 30px;font-size:12px;color:#94a3b8;line-height:1.5;">
                    {_h.escape(a.justification)}
                  </div>
                </label>"""
            )
        actions_html = "\n".join(rows_html)

    page = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark light">
  <title>SOC L1 · Revisar plan {alert_id}</title>
  <style>
    :root {{ color-scheme: dark light; }}
    body {{ font-family: sans-serif; background-color:#0b0d10; margin:0; padding:20px; color:#f3f4f6; }}
    .container {{ max-width:760px; margin:0 auto; background-color:#14171c; border:1px solid #23272f;
                  border-radius:12px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,0.4); }}
    .header {{ padding:24px; border-left:8px solid {risk_color}; background-color:#0b0d10; }}
    h1 {{ font-size:20px; margin:0 0 8px 0; color:#f3f4f6; }}
    .meta {{ font-size:13px; color:#94a3b8; }}
    .badge {{ display:inline-block; padding:4px 12px; border-radius:16px;
              background:{risk_color}; color:white; font:bold 11px sans-serif;
              text-transform:uppercase; margin-top:8px; }}
    .summary {{ padding:16px 24px; font-size:14px; line-height:1.6; color:#cbd5e1;
                background-color:#241c10; margin:20px; border-radius:8px;
                border-left:4px solid #f59e0b; }}
    .form-section {{ padding:0 24px 16px; }}
    .form-section h2 {{ font-size:16px; margin:16px 0 12px; color:#f3f4f6; }}
    .buttons {{ padding:16px 24px 24px; display:flex; gap:12px; flex-wrap:wrap; }}
    .btn {{ padding:14px 28px; border:none; border-radius:6px; font-weight:bold;
            font-size:14px; cursor:pointer; }}
    .btn-approve {{ background:#16a34a; color:white; }}
    .btn-approve:hover {{ background:#15803d; }}
    .btn-reject {{ background:#dc2626; color:white; }}
    .btn-reject:hover {{ background:#b91c1c; }}
    .footer {{ padding:16px; background-color:#0b0d10; text-align:center; font-size:12px; color:#94a3b8; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>📋 Revisar plan de acción</h1>
      <div class="meta">Alerta <code>{_h.escape(alert_id)}</code></div>
      <span class="badge">RISK: {_h.escape(risk_label)}</span>
    </div>

    <div class="summary">
      <strong style="color:#fbbf78;">📝 Resumen ejecutivo:</strong><br>
      {_h.escape(plan.executive_summary)}
    </div>

    <form method="post" action="/decide/{token}">
      <div class="form-section">
        <h2>Acciones propuestas ({len(plan.actions)})</h2>
        <p style="font-size:12px;color:#94a3b8;margin:0 0 12px;">
          Desmarcá las que NO querés ejecutar y clickeá <strong>Aprobar selección</strong>.
          O clickeá <strong>Rechazar todo</strong> si ninguna debe correr.
        </p>
        {actions_html}
      </div>

      <div class="buttons">
        <button type="submit" name="decision" value="approve" class="btn btn-approve">
          ✅ Aprobar selección
        </button>
        <button type="submit" name="decision" value="reject" class="btn btn-reject">
          ❌ Rechazar todo
        </button>
      </div>
    </form>

    <div class="footer">
      <strong>SOC L1 · Wazuh + Defender</strong><br>
      Link single-use, válido por 24h. Primer click decide.
    </div>
  </div>
</body>
</html>
"""
    return HTMLResponse(content=page)


@app.get("/review/{token}")
async def review_plan(
    request: Request, settings: SettingsDep, token: str
) -> HTMLResponse:
    """Página intermedia con form de checkboxes per-action.
    Si el token ya fue decidido / expiró / no existe → renderiza la misma página de error
    que /approve y /reject (consistencia visual).
    """
    from src.state import get_pending_approval

    row = await get_pending_approval(settings.state_db_path, token)
    if row is None:
        return _render_decision_page(
            "not_found",
            "Este link no corresponde a ningún approval pendiente.",
        )
    if row["status"] != "pending":
        return _render_decision_page(
            "already",
            f"Este approval ya fue resuelto previamente (estado: <strong>{row['status']}</strong>).",
        )

    # Render del form
    from src.agents.narrator import NarratorPlan

    try:
        plan = NarratorPlan.model_validate_json(row["plan_json"])
    except Exception:
        logger.exception("review: plan corrupto | alert=%s", row["alert_id"])
        return _render_decision_page(
            "error",
            "El plan guardado no pudo deserializarse. Revisar logs del servicio.",
        )

    # Color del banner por risk_level (mismo system que el email)
    risk_color_map = {
        "critical": "#7f1d1d",
        "high":     "#991b1b",
        "medium":   "#b45309",
        "low":      "#a16207",
    }
    risk_color = risk_color_map.get(plan.risk_level, "#475569")

    return _render_review_page(
        token=token,
        plan=plan,
        alert_id=row["alert_id"],
        risk_color=risk_color,
        risk_label=plan.risk_level,
    )


@app.post("/decide/{token}")
async def decide_plan(
    request: Request,
    settings: SettingsDep,
    token: str,
    decision: Annotated[str, Form()],
    action_idx: Annotated[list[int] | None, Form()] = None,
) -> HTMLResponse:
    """Procesa el form del /review.

    decision: "approve" o "reject" (vino del button name=decision)
    action_idx: lista de índices checkeados (0-based). Si vacío y approve → ejecuta 0 acciones.
    """
    if decision == "reject":
        # Rechazo total - ignoramos action_idx
        return await _handle_decision(request, settings, token, "rejected")

    if decision == "approve":
        indices = action_idx or []
        return await _handle_decision(
            request, settings, token, "approved", selected_action_indices=indices
        )

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"decision inválida: {decision!r} (debe ser 'approve' o 'reject')",
    )


# ===== Dashboard: cola de approvals =====


_STATUS_BADGES = {
    "pending":  {"bg": "#fef3c7", "fg": "#92400e"},  # amarillo
    "approved": {"bg": "#dcfce7", "fg": "#166534"},  # verde
    "rejected": {"bg": "#fee2e2", "fg": "#7f1d1d"},  # rojo
    "expired":  {"bg": "#23272f", "fg": "#334155"},  # gris
    "executed": {"bg": "#dbeafe", "fg": "#1e40af"},  # azul
}


def _render_approvals_page(
    rows: list[dict], total: int, status_filter: str | None, limit: int, offset: int
) -> HTMLResponse:
    """Renderiza la cola de approvals como HTML table con paginación + filtros."""
    import html as _h
    import json as _json

    if not rows:
        empty_msg = (
            "<p style='color:#94a3b8;font-style:italic;text-align:center;padding:40px;'>"
            "No hay approvals que mostrar"
            + (f" con status='{_h.escape(status_filter)}'" if status_filter else "")
            + ".</p>"
        )
        rows_html = empty_msg
    else:
        row_lines = []
        for row in rows:
            # Parsear plan_json para extraer risk + action types (resumen visual)
            risk = "?"
            action_types: list[str] = []
            try:
                plan = _json.loads(row.get("plan_json", "{}"))
                risk = plan.get("risk_level", "?")
                action_types = [a.get("type", "?") for a in plan.get("actions", [])]
            except (TypeError, ValueError):
                pass

            risk_color = {
                "critical": "#7f1d1d",
                "high":     "#991b1b",
                "medium":   "#b45309",
                "low":      "#a16207",
            }.get(risk, "#475569")

            status = row.get("status", "?")
            badge = _STATUS_BADGES.get(status, {"bg": "#23272f", "fg": "#334155"})

            decided = row.get("decided_at") or "—"
            decided_by = row.get("decided_by_ip") or "—"

            actions_summary = ", ".join(action_types[:4])
            if len(action_types) > 4:
                actions_summary += f" +{len(action_types) - 4}"
            if not actions_summary:
                actions_summary = "—"

            # Link a /review solo si pending; si no, sin link (decided ya)
            alert_id = _h.escape(row.get("alert_id", "?"))
            token = _h.escape(row.get("token", ""))
            if status == "pending":
                alert_cell = (
                    f"<a href='/review/{token}' "
                    f"style='color:#38bdf8;text-decoration:none;'>{alert_id}</a>"
                )
            else:
                alert_cell = alert_id

            row_lines.append(
                f"""<tr>
                  <td><code style='font-size:12px;'>{alert_cell}</code></td>
                  <td><span style='background:{risk_color};color:white;padding:3px 10px;
                                    border-radius:12px;font:bold 10px sans-serif;
                                    text-transform:uppercase;'>{_h.escape(risk)}</span></td>
                  <td><span style='background:{badge["bg"]};color:{badge["fg"]};
                                    padding:3px 10px;border-radius:12px;
                                    font:bold 10px sans-serif;text-transform:uppercase;'>{_h.escape(status)}</span></td>
                  <td style='font-size:12px;color:#cbd5e1;'>{_h.escape(actions_summary)}</td>
                  <td style='font-size:11px;color:#94a3b8;'>{_h.escape(row.get("created_at", "")[:19])}</td>
                  <td style='font-size:11px;color:#94a3b8;'>{_h.escape(decided[:19] if decided != "—" else "—")}</td>
                  <td style='font-size:11px;color:#94a3b8;'>{_h.escape(decided_by)}</td>
                </tr>"""
            )
        rows_html = (
            "<table style='width:100%;border-collapse:collapse;'>"
            "<thead><tr style='background:#0b0d10;text-align:left;'>"
            "<th style='padding:10px;border-bottom:2px solid #23272f;font-size:12px;color:#94a3b8;'>Alert ID</th>"
            "<th style='padding:10px;border-bottom:2px solid #23272f;font-size:12px;color:#94a3b8;'>Risk</th>"
            "<th style='padding:10px;border-bottom:2px solid #23272f;font-size:12px;color:#94a3b8;'>Status</th>"
            "<th style='padding:10px;border-bottom:2px solid #23272f;font-size:12px;color:#94a3b8;'>Acciones</th>"
            "<th style='padding:10px;border-bottom:2px solid #23272f;font-size:12px;color:#94a3b8;'>Creado</th>"
            "<th style='padding:10px;border-bottom:2px solid #23272f;font-size:12px;color:#94a3b8;'>Decidido</th>"
            "<th style='padding:10px;border-bottom:2px solid #23272f;font-size:12px;color:#94a3b8;'>Por IP</th>"
            "</tr></thead>"
            "<tbody>"
            + "\n".join(
                f"<tr style='border-bottom:1px solid #23272f;'>{r[4:]}"
                for r in row_lines
            )
            + "</tbody></table>"
        )
        # Hack visual: agregar padding a cada td
        rows_html = rows_html.replace(
            "<td>", "<td style='padding:10px;'>"
        ).replace("<td style='padding:10px;'><td", "<td")

    # Filtros (links arriba)
    def _filter_link(label: str, st: str | None) -> str:
        url = "/approvals" if st is None else f"/approvals?status={st}"
        active = (st == status_filter) or (st is None and not status_filter)
        bg = "#38bdf8" if active else "#23272f"
        fg = "white" if active else "#cbd5e1"
        return (
            f"<a href='{url}' style='display:inline-block;padding:6px 14px;"
            f"background:{bg};color:{fg};border-radius:4px;text-decoration:none;"
            f"font:bold 12px sans-serif;text-transform:uppercase;margin-right:6px;'>"
            f"{label}</a>"
        )

    filters_html = (
        _filter_link("Todos", None)
        + _filter_link("Pending", "pending")
        + _filter_link("Approved", "approved")
        + _filter_link("Rejected", "rejected")
        + _filter_link("Executed", "executed")
        + _filter_link("Expired", "expired")
    )

    # Paginación
    showing_from = offset + 1 if rows else 0
    showing_to = offset + len(rows)
    pag_parts = []
    if offset > 0:
        prev_offset = max(0, offset - limit)
        url = f"/approvals?limit={limit}&offset={prev_offset}"
        if status_filter:
            url += f"&status={status_filter}"
        pag_parts.append(
            f"<a href='{url}' style='padding:6px 14px;background:#23272f;"
            f"color:#94a3b8;border-radius:4px;text-decoration:none;font-size:12px;'>"
            f"← Anteriores</a>"
        )
    if showing_to < total:
        next_offset = offset + limit
        url = f"/approvals?limit={limit}&offset={next_offset}"
        if status_filter:
            url += f"&status={status_filter}"
        pag_parts.append(
            f"<a href='{url}' style='padding:6px 14px;background:#23272f;"
            f"color:#94a3b8;border-radius:4px;text-decoration:none;font-size:12px;margin-left:6px;'>"
            f"Siguientes →</a>"
        )
    pag_html = " ".join(pag_parts)

    page = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark light">
  <title>SOC L1 · Approvals</title>
  <style>
    :root {{ color-scheme: dark light; }}
    body {{ font-family: sans-serif; background-color:#0b0d10; margin:0; padding:20px; color:#f3f4f6; }}
    .container {{ max-width:1280px; margin:0 auto; background-color:#14171c; border:1px solid #23272f;
                  border-radius:12px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,0.4); }}
    .header {{ padding:20px 24px; border-left:8px solid #38bdf8; background-color:#0b0d10; }}
    .header h1 {{ font-size:20px; margin:0 0 4px 0; color:#f3f4f6; }}
    .meta {{ font-size:13px; color:#94a3b8; }}
    .filters {{ padding:16px 24px; border-bottom:1px solid #23272f; }}
    .table-wrap {{ padding:16px 24px; overflow-x:auto; }}
    .pagination {{ padding:16px 24px; text-align:center; border-top:1px solid #23272f; }}
    .footer {{ padding:16px; background-color:#0b0d10; text-align:center; font-size:12px; color:#94a3b8; }}
    code {{ font-family:'SF Mono',Monaco,monospace; color:#cbd5e1; }}
    a:hover {{ opacity:0.85; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>📋 Cola de approvals</h1>
      <div class="meta">
        Mostrando <strong>{showing_from}-{showing_to}</strong> de <strong>{total}</strong>
        {f"(filtro: {_h.escape(status_filter)})" if status_filter else "(sin filtro)"}
      </div>
    </div>
    <div class="filters">{filters_html}</div>
    <div class="table-wrap">{rows_html}</div>
    <div class="pagination">{pag_html or '&nbsp;'}</div>
    <div class="footer">
      <strong>SOC L1 · Wazuh + Defender</strong> · pipeline multi-agente<br>
      Para datos en JSON: <code>/approvals?format=json</code>
    </div>
  </div>
</body>
</html>
"""
    return HTMLResponse(content=page)


@app.get("/approvals")
async def list_approvals_endpoint(
    request: Request,
    settings: SettingsDep,
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
    format: str = "html",
):
    """Cola de approvals (last N, paginada, filtrable por status).

    Detrás del mismo login que /ui: expone tokens de approval y planes, así que
    no puede ser anónimo (un token pending filtrado permitiría aprobar acciones).

    Query params:
      - status: pending | approved | rejected | expired | executed (opcional)
      - limit: 1-500 (default 50)
      - offset: 0+ (default 0)
      - format: html (default) | json
    """
    from src.state import list_approvals
    from src.web import auth

    if not auth.session_valid(settings, request.cookies.get(auth.COOKIE_NAME)):
        if format == "json":
            return JSONResponse(content={"error": "unauthorized"}, status_code=401)
        return RedirectResponse(url="/ui/login", status_code=303)

    rows, total = await list_approvals(
        settings.state_db_path, status=status, limit=limit, offset=offset
    )

    if format == "json":
        # JSON: stripeamos plan_json (objetos masivos) y token (credencial de
        # aprobación single-use — nunca debe salir en la lista).
        clean_rows = []
        for r in rows:
            r = dict(r)
            r.pop("plan_json", None)
            r.pop("token", None)
            clean_rows.append(r)
        return JSONResponse(content={
            "total": total,
            "limit": limit,
            "offset": offset,
            "status_filter": status,
            "rows": clean_rows,
        })

    return _render_approvals_page(rows, total, status, limit, offset)


# ===== GUI / Dashboard (ZebraSecurity) =====
# Panel de revisión solo-lectura en /ui, detrás de login. Import al final para
# evitar import circular (src.web define su propio get_settings).
from src.web import router as _web_router  # noqa: E402

app.include_router(_web_router)
