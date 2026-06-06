"""Capa de notificación de cierre de caso (post-decisión).

Único punto que conoce los CANALES de salida. Hoy: solo email
([[mailer]].send_closure_email). Mañana: + Teams, sin tocar a los callers en main.py.

Enchufar Teams después = setear settings.teams_webhook_url + crear src/teams.py con
send_teams_closure() + descomentar la línea de abajo. Cero cambios en el pipeline.
"""
from __future__ import annotations

import logging

from src.agents.narrator import NarratorPlan
from src.config import Settings
from src.mailer import send_closure_email
from src.models import NormalizedAlert

logger = logging.getLogger("soc-l1")


async def notify_case_closure(
    settings: Settings,
    alert: NormalizedAlert,
    plan: NarratorPlan,
    *,
    decision: str,
    timeline_events: list[dict],
    execution_results: list[dict] | None,
    decided_by_ip: str | None,
    decided_at: str | None,
    executed_at: str | None,
    invgate_request_id: int | None = None,
) -> None:
    """Notifica el cierre del caso por todos los canales habilitados.

    Fire-and-forget: cada canal maneja sus propios errores y no propaga (el cierre
    ya ocurrió, la notificación no debe romper nada).

    decision: "approved" | "rejected".
    execution_results: None en rechazo, [] en aprobación sin acciones, lista si hubo ejecución.
    """
    await send_closure_email(
        settings, alert, plan,
        decision=decision,
        timeline_events=timeline_events,
        execution_results=execution_results,
        decided_by_ip=decided_by_ip,
        decided_at=decided_at,
        executed_at=executed_at,
        invgate_request_id=invgate_request_id,
    )

    # FUTURO (hook Teams): cuando exista src/teams.py y el webhook esté configurado:
    # if settings.teams_webhook_url:
    #     from src.teams import send_teams_closure
    #     await send_teams_closure(
    #         settings, alert, plan, decision=decision,
    #         timeline_events=timeline_events, execution_results=execution_results,
    #     )
    if settings.teams_webhook_url:
        logger.info(
            "notify: teams_webhook_url configurado pero Teams aún no implementado "
            "(alert=%s) - solo email enviado",
            alert.alert_id,
        )
