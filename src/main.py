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
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse

from src.config import Settings
from src.models import NormalizedAlert
from src.normalize import normalize
from src.security import verify_wazuh_signature

logger = logging.getLogger("soc-l1")


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
    if settings.enable_narrator:
        from src.state import init_db

        await init_db(settings.state_db_path)

    yield
    logger.info("SOC L1 service shutting down")


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
    """Recibe alerta Wazuh. Verifica HMAC, normaliza, lanza pipeline en background."""
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

    if settings.enable_triage:
        asyncio.create_task(_run_triage_in_background(alert, settings))

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

        decision = await triage_alert(alert, model=settings.openai_model_light)
        logger.info(
            "triage | id=%s verdict=%s confidence=%s reason=%r",
            alert.alert_id,
            decision.verdict,
            decision.confidence,
            decision.reason,
        )
        await _dispatch_by_verdict(alert, decision, settings)
    except Exception:
        logger.exception("triage failed for alert id=%s", alert.alert_id)


async def _dispatch_by_verdict(
    alert: NormalizedAlert, decision, settings: Settings
) -> None:
    if decision.verdict == "auto_close_benign":
        await _handle_auto_close(alert, decision)
    elif decision.verdict == "analyze":
        await _handle_analyze(alert, decision, settings)
    elif decision.verdict == "fast_track_critical":
        await _handle_fast_track(alert, decision, settings)
    else:
        logger.warning(
            "unknown verdict | id=%s verdict=%s (treating as analyze)",
            alert.alert_id,
            decision.verdict,
        )
        await _handle_analyze(alert, decision, settings)


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


async def _handle_analyze(alert: NormalizedAlert, decision, settings: Settings) -> None:
    """analyze: Enricher → (si enable_narrator) Narrator + email approval."""
    logger.info(
        "PIPELINE_QUEUED analyze | id=%s host=%s users=%s files=%s",
        alert.alert_id,
        alert.device.hostname,
        len(alert.users_involved),
        len(alert.files),
    )

    if not settings.enable_enricher:
        logger.info("enricher_skipped | id=%s ENABLE_ENRICHER=false", alert.alert_id)
        return

    try:
        from src.agents.enricher import EnrichmentResult, enrich_alert

        ldap_cfg = _build_ldap_cfg_safely()
        enrichment = await enrich_alert(
            alert, settings=settings, ldap_cfg=ldap_cfg, model=settings.openai_model_light
        )
        logger.info(
            "ENRICHED | id=%s users=%d rule_found=%s flags=%s | %s",
            alert.alert_id,
            len(enrichment.users),
            enrichment.rule is not None,
            ",".join(enrichment.flags) if enrichment.flags else "none",
            enrichment.summary,
        )
    except Exception:
        logger.exception("enricher failed for alert id=%s", alert.alert_id)
        return

    await _run_narrator_and_request_approval(alert, decision, settings, enrichment)


async def _handle_fast_track(alert: NormalizedAlert, decision, settings: Settings) -> None:
    """fast_track_critical: skip Enricher, va directo a Narrator con enrichment vacío."""
    logger.warning(
        "PIPELINE_QUEUED fast_track | id=%s host=%s severity=%s",
        alert.alert_id,
        alert.device.hostname,
        alert.severity_source,
    )
    from src.agents.enricher import EnrichmentResult

    empty_enrichment = EnrichmentResult(
        users=[],
        rule=None,
        summary="(fast_track: enrichment skipped por criticidad)",
        flags=["fast_track_skip_enrichment"],
    )
    await _run_narrator_and_request_approval(
        alert, decision, settings, empty_enrichment
    )


async def _run_narrator_and_request_approval(
    alert: NormalizedAlert, decision, settings: Settings, enrichment
) -> None:
    """Narrator → guardar plan en SQLite → enviar email de approval."""
    if not settings.enable_narrator:
        logger.info("narrator_skipped | id=%s ENABLE_NARRATOR=false", alert.alert_id)
        return

    try:
        from src.agents.narrator import narrate_incident
        from src.mailer import send_approval_email
        from src.state import create_pending_approval

        plan = await narrate_incident(
            alert, triage=decision, enrichment=enrichment, model=settings.openai_model_heavy
        )
        logger.info(
            "NARRATED | id=%s risk=%s actions=%d | %s",
            alert.alert_id,
            plan.risk_level,
            len(plan.actions),
            plan.executive_summary,
        )

        token = await create_pending_approval(
            settings.state_db_path,
            alert_id=alert.alert_id,
            plan_json=plan.model_dump_json(),
            alert_json=alert.model_dump_json(),
        )
        logger.info("APPROVAL_PENDING | id=%s token=%s", alert.alert_id, token[:12] + "…")

        await send_approval_email(settings, alert, plan, token)
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


# ===== Approval endpoints =====


# Design tokens alineados con src/mailer.py (mismo system del integrator Wazuh).
# Cada estado tiene icono + color banner + color de acento.
_PAGE_STATES = {
    "approved":    {"banner": "#15803d", "accent": "#16a34a", "icon": "✅", "title": "Aprobado"},
    "rejected":    {"banner": "#9a3412", "accent": "#ea580c", "icon": "❌", "title": "Rechazado"},
    "already":     {"banner": "#475569", "accent": "#64748b", "icon": "ℹ️",  "title": "Ya decidido"},
    "expired":     {"banner": "#7f1d1d", "accent": "#991b1b", "icon": "⏱️",  "title": "Expirado"},
    "not_found":   {"banner": "#7f1d1d", "accent": "#991b1b", "icon": "🚫", "title": "Token inválido"},
    "error":       {"banner": "#7f1d1d", "accent": "#991b1b", "icon": "⚠️",  "title": "Error"},
}


def _render_decision_page(state_key: str, body_html: str) -> HTMLResponse:
    """Render página de decisión con el design system de soc-l1.

    state_key: approved | rejected | already | expired | not_found | error
    body_html: contenido del cuerpo (puede contener <code>, <strong>, etc.)
    """
    s = _PAGE_STATES.get(state_key, _PAGE_STATES["error"])
    page = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>SOC L1 · {s["title"]}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #f8fafc; margin: 0; padding: 40px 20px; color: #0f172a; }}
    .container {{ max-width: 560px; margin: 0 auto; background: white;
                  border-radius: 12px; overflow: hidden;
                  box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
    .banner {{ background: {s["banner"]}; color: white; padding: 32px 24px; text-align: center; }}
    .icon {{ font-size: 48px; line-height: 1; margin-bottom: 12px; }}
    .heading {{ font-size: 22px; font-weight: bold; margin: 0; }}
    .body {{ padding: 28px 24px; font-size: 14px; line-height: 1.6; color: #334155;
             text-align: center; border-left: 4px solid {s["accent"]}; margin: 0 24px;
             background: #f9fafb; border-radius: 6px; }}
    .footer {{ padding: 16px; background: #f8fafc; text-align: center;
               font-size: 12px; color: #64748b; }}
    code {{ background: #f1f5f9; padding: 2px 6px; border-radius: 3px;
            font-family: 'SF Mono', Monaco, monospace; font-size: 12px; color: #0f172a; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="banner">
      <div class="icon">{s["icon"]}</div>
      <h1 class="heading">{s["title"]}</h1>
    </div>
    <div style="padding: 28px 24px 16px;">
      <div class="body">{body_html}</div>
    </div>
    <div class="footer">
      <strong>SOC L1 · Wazuh + Defender</strong><br>
      Example Corp — pipeline multi-agente
    </div>
  </div>
</body>
</html>
"""
    return HTMLResponse(content=page)


async def _handle_decision(
    request: Request, settings: Settings, token: str, decision: str
) -> HTMLResponse:
    """Lógica común para /approve y /reject."""
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

    if decision == "rejected":
        return _render_decision_page(
            "rejected",
            f"El plan de acción fue rechazado. <strong>No se ejecutará ninguna acción</strong> "
            f"para la alerta <code>{alert_id}</code>. Quedó registrada la decisión con tu IP "
            "y timestamp para audit.",
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

    # Lanzamos el executor en background para responder rápido al humano que clickeó
    asyncio.create_task(
        _execute_approved_plan_in_background(settings, token, alert_id, plan)
    )

    n = len(plan.actions)
    return _render_decision_page(
        "approved",
        f"Plan aprobado para la alerta <code>{alert_id}</code>.<br><br>"
        f"Se {'está' if n == 1 else 'están'} ejecutando <strong>{n} "
        f"acción{'' if n == 1 else 'es'}</strong> en background. "
        "El resultado queda en los logs del servicio y en SQLite.",
    )


async def _execute_approved_plan_in_background(
    settings: Settings, token: str, alert_id: str, plan
) -> None:
    from src.executor import execute_plan
    from src.state import mark_executed

    try:
        ldap_cfg = _build_ldap_cfg_safely()
        results = await execute_plan(plan.actions, ldap_cfg=ldap_cfg)
        await mark_executed(settings.state_db_path, token, results)
        ok_count = sum(1 for r in results if r.get("ok"))
        logger.info(
            "EXECUTED | alert=%s actions=%d ok=%d fail=%d",
            alert_id,
            len(results),
            ok_count,
            len(results) - ok_count,
        )
    except Exception:
        logger.exception("executor failed | alert=%s token=%s", alert_id, token[:12])


@app.get("/approve/{token}")
async def approve_plan(request: Request, settings: SettingsDep, token: str) -> HTMLResponse:
    return await _handle_decision(request, settings, token, "approved")


@app.get("/reject/{token}")
async def reject_plan(request: Request, settings: SettingsDep, token: str) -> HTMLResponse:
    return await _handle_decision(request, settings, token, "rejected")
