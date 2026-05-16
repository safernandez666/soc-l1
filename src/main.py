"""FastAPI service - ingesta de alertas Wazuh + Defender.

Endpoints actuales:
  POST /webhook/wazuh-alert    - recibe alerta, verifica HMAC, normaliza, loggea, 202
  GET  /health                 - healthcheck simple

Próximo:
  - Pipeline de agentes (triage → enricher → ti → narrator)
  - POST /approve/{token} para resume desde email
  - SQLite state para alertas pendientes
"""
from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

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
    yield
    logger.info("SOC L1 service shutting down")


app = FastAPI(
    title="SOC L1 - Wazuh + Defender",
    version="0.1.0",
    description="Multi-agent SOAR for Wazuh alerts (Defender via Wazuh + native)",
    lifespan=lifespan,
)


SettingsDep = Annotated[Settings, Depends(get_settings)]


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "soc-l1"}


@app.post("/webhook/wazuh-alert", status_code=status.HTTP_202_ACCEPTED)
async def wazuh_webhook(
    request: Request,
    settings: SettingsDep,
    x_wazuh_signature: Annotated[str | None, Header(alias="X-Wazuh-Signature")] = None,
) -> JSONResponse:
    """Recibe alerta Wazuh (nativa o Defender-via-Wazuh).

    Verifica HMAC, normaliza al schema interno, loggea (próximamente: lanza pipeline).
    Devuelve 202 inmediato para no bloquear el integrator.
    """
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

    # Si Triage está habilitado, lanzamos pipeline en background y respondemos 202 ya.
    # El integrator de Wazuh no debería esperar el análisis completo.
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


async def _run_triage_in_background(alert: NormalizedAlert, settings: Settings) -> None:
    """Corre el Triage agent en background y loggea el resultado.

    Errores aquí NO afectan al webhook (ya respondió 202). Solo se loggean.
    Próximo: según verdict, encolar para Enricher/TI/Narrator o auto-close.
    """
    try:
        # Import diferido para no requerir openai-agents si triage está deshabilitado
        from src.agents.triage import triage_alert

        decision = await triage_alert(alert, model=settings.openai_model_light)
        logger.info(
            "triage | id=%s verdict=%s confidence=%s reason=%r",
            alert.alert_id,
            decision.verdict,
            decision.confidence,
            decision.reason,
        )
    except Exception:
        logger.exception("triage failed for alert id=%s", alert.alert_id)
