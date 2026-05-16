"""Executor - dispatcher determinístico de ProposedAction post-aprobación.

NO usa LLM. Solo mapea action.type → función concreta de tools/ldap.py.
Esto es DELIBERADO: una vez que el humano aprobó el plan, no queremos que un
LLM decida qué ejecutar; eso sería un vector de prompt injection con efecto
side-effect en AD.

Acciones soportadas:
  - disable_user           → tools.ldap.disable_user
  - force_password_change  → tools.ldap.force_password_change
  - notify_only            → no-op (registra "noted")
  - escalate_l2            → no-op (registra "escalated", futuro: ticket/Slack)

Cada acción retorna ExecutionResult con ok + message + target.
La lista completa va al state.mark_executed para audit trail permanente.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from pydantic import BaseModel, ConfigDict

from src.agents.narrator import ProposedAction
from src.config import LdapConfig
from src.tools import ldap as ldap_tools

logger = logging.getLogger("soc-l1")


class ExecutionResult(BaseModel):
    """Resultado de ejecutar una ProposedAction individual."""

    model_config = ConfigDict(extra="forbid")
    action_type: str
    target: str
    ok: bool
    message: str | None = None


def _exec_disable_user_sync(cfg: LdapConfig, sam: str) -> ExecutionResult:
    try:
        r = ldap_tools.disable_user(cfg, sam)
        return ExecutionResult(
            action_type="disable_user",
            target=sam,
            ok=r.ok,
            message=r.message or (f"DN={r.target_dn}" if r.target_dn else None),
        )
    except Exception as e:  # noqa: BLE001
        logger.exception("disable_user failed for %s", sam)
        return ExecutionResult(
            action_type="disable_user", target=sam, ok=False, message=str(e)
        )


def _exec_force_password_sync(cfg: LdapConfig, sam: str) -> ExecutionResult:
    try:
        r = ldap_tools.force_password_change(cfg, sam)
        return ExecutionResult(
            action_type="force_password_change",
            target=sam,
            ok=r.ok,
            message=r.message or (f"DN={r.target_dn}" if r.target_dn else None),
        )
    except Exception as e:  # noqa: BLE001
        logger.exception("force_password_change failed for %s", sam)
        return ExecutionResult(
            action_type="force_password_change", target=sam, ok=False, message=str(e)
        )


async def _execute_one(action: ProposedAction, ldap_cfg: LdapConfig | None) -> ExecutionResult:
    """Ejecuta una sola action según su type. Acciones AD requieren ldap_cfg != None."""
    if action.type == "notify_only":
        return ExecutionResult(
            action_type=action.type, target=action.target, ok=True, message="noted"
        )

    if action.type == "escalate_l2":
        # v1: solo log. Futuro: crear ticket / mandar a Slack / etc.
        logger.warning(
            "ESCALATE_L2 | target=%s justification=%s",
            action.target,
            action.justification,
        )
        return ExecutionResult(
            action_type=action.type,
            target=action.target,
            ok=True,
            message="escalated to L2 (log only - no ticket system wired)",
        )

    if action.type in ("disable_user", "force_password_change"):
        if ldap_cfg is None:
            return ExecutionResult(
                action_type=action.type,
                target=action.target,
                ok=False,
                message="LDAP no configurado - acción no ejecutada",
            )
        if action.type == "disable_user":
            return await asyncio.to_thread(_exec_disable_user_sync, ldap_cfg, action.target)
        return await asyncio.to_thread(_exec_force_password_sync, ldap_cfg, action.target)

    return ExecutionResult(
        action_type=action.type,
        target=action.target,
        ok=False,
        message=f"unknown action type: {action.type}",
    )


async def execute_plan(
    actions: list[ProposedAction], ldap_cfg: LdapConfig | None
) -> list[dict[str, Any]]:
    """Ejecuta cada acción del plan secuencialmente y devuelve audit trail.

    Secuencial (no paralelo) a propósito: las acciones sobre el mismo user podrían
    pisarse (ej. disable + force_password sobre el mismo target). Volumen esperado
    es chico (1-3 acciones), no vale la pena paralelizar.
    """
    results: list[ExecutionResult] = []
    for action in actions:
        r = await _execute_one(action, ldap_cfg)
        logger.info(
            "EXEC | type=%s target=%s ok=%s msg=%s",
            r.action_type,
            r.target,
            r.ok,
            r.message,
        )
        results.append(r)
    return [r.model_dump() for r in results]
