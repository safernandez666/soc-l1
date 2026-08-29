"""Reconciliación InvGate → state.db: InvGate es la fuente de verdad.

Relee en InvGate el estado real de los tickets de los casos que todavía no
sabemos resueltos y lo persiste en state.db (`invgate_status_id`,
`invgate_resolved`, `invgate_checked_at`). El dashboard lee ese snapshot, así que
muestra el estado REAL del ticket, no nuestra suposición optimista.

Corre periódicamente desde el sweeper del lifespan (`main.py`). Best-effort: un
ticket ilegible (permiso/HTTP) se saltea y se reintenta el próximo ciclo; nunca
tumba el servicio.
"""
from __future__ import annotations

import logging

from src.config import Settings
from src.state import cases_needing_invgate_check, update_invgate_status
from src.tools.invgate import InvgateClient, is_configured

logger = logging.getLogger("soc-l1")


async def reconcile_invgate(settings: Settings, limit: int = 100) -> dict[str, int]:
    """Relee InvGate para los casos no-resueltos y actualiza state.db.

    Devuelve un resumen {checked, resolved, still_open, unreadable}.
    """
    summary = {"checked": 0, "resolved": 0, "still_open": 0, "unreadable": 0}
    if not is_configured(settings):
        return summary

    cases = await cases_needing_invgate_check(settings.state_db_path, limit=limit)
    if not cases:
        return summary

    async with InvgateClient(settings) as client:
        for case in cases:
            rid = case["invgate_request_id"]
            ticket = await client.get_incident(rid)
            summary["checked"] += 1
            if ticket is None:
                summary["unreadable"] += 1
                continue
            resolved = client._ticket_is_resolved(ticket)  # noqa: SLF001
            status_id = ticket.get("status_id")
            try:
                status_id = int(status_id) if status_id is not None else None
            except (TypeError, ValueError):
                status_id = None
            await update_invgate_status(
                settings.state_db_path, case["rowid"], status_id, resolved
            )
            summary["resolved" if resolved else "still_open"] += 1

    logger.info(
        "invgate reconcile | chequeados=%d resueltos=%d abiertos=%d ilegibles=%d",
        summary["checked"], summary["resolved"],
        summary["still_open"], summary["unreadable"],
    )
    return summary
