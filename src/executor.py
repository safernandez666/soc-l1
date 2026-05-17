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

Guardrails de seguridad (defensa en profundidad post-approval):
  - PROTECTED_USERS: lista de sams que el executor refusa tocar. Aunque el Narrator
    recomiende disable_user y el humano apruebe, los users protegidos quedan intactos.
    Útil para cuentas de admin, ejecutivos, service accounts.
  - DRY_RUN_MODE: flag global que convierte todas las acciones AD en no-op (solo log).
    Útil para validar el comportamiento del Narrator antes de habilitar ejecución real.

Cada acción retorna ExecutionResult con ok + message + target.
La lista completa va al state.mark_executed para audit trail permanente.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from pydantic import BaseModel, ConfigDict

from src.agents.narrator import ProposedAction
from src.config import LdapConfig, Settings
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


async def _execute_one(
    action: ProposedAction,
    ldap_cfg: LdapConfig | None,
    protected_users: set[str],
    dry_run: bool,
) -> ExecutionResult:
    """Ejecuta una sola action según su type. Acciones AD requieren ldap_cfg != None.

    Antes de tocar AD, pasa por dos guardrails:
      1. PROTECTED_USERS: si action.target está en la lista (case-insensitive), refusa.
      2. DRY_RUN: si está activo, devuelve ok=True sin ejecutar (audit pero no impacto).
    """
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
        # Guardrail #1: PROTECTED_USERS (defensa permanente)
        target_lower = action.target.strip().lower()
        if target_lower in protected_users:
            logger.warning(
                "🛡️  PROTECTED USER | refused %s on target=%r (in PROTECTED_USERS list)",
                action.type, action.target,
            )
            return ExecutionResult(
                action_type=action.type,
                target=action.target,
                ok=False,
                message=(
                    f"REFUSED: '{action.target}' está en PROTECTED_USERS. "
                    f"AD intacto. Si querés ejecutar esta acción, sacá el sam de la lista."
                ),
            )

        # Guardrail #2: DRY_RUN_MODE (toggle de testing)
        if dry_run:
            logger.warning(
                "🧪 DRY_RUN | would have executed %s on target=%r (no-op)",
                action.type, action.target,
            )
            return ExecutionResult(
                action_type=action.type,
                target=action.target,
                ok=True,
                message=f"DRY_RUN: acción simulada (no se ejecutó en AD)",
            )

        # Ejecución real
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
    actions: list[ProposedAction],
    ldap_cfg: LdapConfig | None,
    settings: Settings | None = None,
) -> list[dict[str, Any]]:
    """Ejecuta cada acción del plan secuencialmente y devuelve audit trail.

    Secuencial (no paralelo) a propósito: las acciones sobre el mismo user podrían
    pisarse (ej. disable + force_password sobre el mismo target). Volumen esperado
    es chico (1-3 acciones), no vale la pena paralelizar.

    settings: si None, sin guardrails (uso de tests). En producción siempre pasarlo.
    """
    protected_users: set[str] = set()
    dry_run = False
    if settings is not None:
        protected_users = settings.protected_users_set()
        dry_run = settings.dry_run_mode

    if protected_users:
        logger.info(
            "executor: PROTECTED_USERS activo (%d cuentas): %s",
            len(protected_users), sorted(protected_users),
        )
    if dry_run:
        logger.warning("executor: DRY_RUN_MODE=true - ninguna acción AD se ejecuta de verdad")

    results: list[ExecutionResult] = []
    for action in actions:
        r = await _execute_one(action, ldap_cfg, protected_users, dry_run)
        logger.info(
            "EXEC | type=%s target=%s ok=%s msg=%s",
            r.action_type,
            r.target,
            r.ok,
            r.message,
        )
        results.append(r)
    return [r.model_dump() for r in results]
