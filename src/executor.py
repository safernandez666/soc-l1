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
import ipaddress
import logging
from typing import Any

from pydantic import BaseModel, ConfigDict

from src.agents.narrator import ProposedAction
from src.config import LdapConfig, Settings
from src.tools import ldap as ldap_tools
from src.tools.fortigate import FortigateClient, FortigateError

logger = logging.getLogger("soc-l1")


def _ip_in_protected_networks(ip: str, networks: list[str]) -> str | None:
    """Si la IP está en alguno de los CIDRs protegidos, devuelve el match. None si no.

    Soporta IPv4 e IPv6. Si la IP es inválida, retorna 'invalid_ip'.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid_ip"
    for net in networks:
        try:
            if ip_obj in ipaddress.ip_network(net.strip(), strict=False):
                return net.strip()
        except ValueError:
            continue
    return None


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


async def _exec_block_ip(settings: Settings, ip: str) -> ExecutionResult:
    """Quarantine de una IP en FortiGate. Default TTL 1h."""
    try:
        async with FortigateClient(settings) as fg:
            r = await fg.quarantine_ip(ip, ttl_seconds=3600)
        return ExecutionResult(
            action_type="block_ip",
            target=ip,
            ok=r.ok,
            message=r.message,
        )
    except FortigateError as e:
        logger.exception("block_ip failed for %s", ip)
        return ExecutionResult(
            action_type="block_ip", target=ip, ok=False, message=str(e)
        )


async def _execute_one(
    action: ProposedAction,
    ldap_cfg: LdapConfig | None,
    protected_users: set[str],
    protected_networks: list[str],
    dry_run: bool,
    settings: Settings | None,
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

    if action.type == "block_ip":
        ip = action.target.strip()
        # Guardrail PROTECTED_NETWORKS: nunca bloquear redes propias
        match = _ip_in_protected_networks(ip, protected_networks)
        if match == "invalid_ip":
            logger.warning("🛡️  block_ip target=%r es IP inválida, refused", ip)
            return ExecutionResult(
                action_type="block_ip", target=ip, ok=False,
                message=f"REFUSED: '{ip}' no es una IP válida",
            )
        if match is not None:
            logger.warning(
                "🛡️  PROTECTED NETWORK | refused block_ip on target=%r (matches %s)",
                ip, match,
            )
            return ExecutionResult(
                action_type="block_ip", target=ip, ok=False,
                message=(
                    f"REFUSED: '{ip}' está en PROTECTED_NETWORKS (matches {match}). "
                    f"FortiGate intacto. Si querés bloquear, sacá el CIDR de la lista."
                ),
            )
        if dry_run:
            logger.warning("🧪 DRY_RUN | would have block_ip on target=%r", ip)
            return ExecutionResult(
                action_type="block_ip", target=ip, ok=True,
                message="DRY_RUN: block_ip simulado (FortiGate intacto)",
            )
        if settings is None or not settings.fortigate_host or not settings.fortigate_token:
            return ExecutionResult(
                action_type="block_ip", target=ip, ok=False,
                message="FortiGate no configurado - acción no ejecutada",
            )
        return await _exec_block_ip(settings, ip)

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
    protected_networks: list[str] = []
    dry_run = False
    if settings is not None:
        protected_users = settings.protected_users_set()
        protected_networks = settings.protected_networks_list()
        dry_run = settings.dry_run_mode

    if protected_users:
        logger.info(
            "executor: PROTECTED_USERS activo (%d cuentas): %s",
            len(protected_users), sorted(protected_users),
        )
    if protected_networks:
        logger.info(
            "executor: PROTECTED_NETWORKS activo (%d CIDRs): %s",
            len(protected_networks), protected_networks,
        )
    if dry_run:
        logger.warning("executor: DRY_RUN_MODE=true - ninguna acción AD/FortiGate se ejecuta de verdad")

    results: list[ExecutionResult] = []
    for action in actions:
        r = await _execute_one(
            action, ldap_cfg, protected_users, protected_networks, dry_run, settings
        )
        logger.info(
            "EXEC | type=%s target=%s ok=%s msg=%s",
            r.action_type,
            r.target,
            r.ok,
            r.message,
        )
        results.append(r)
    return [r.model_dump() for r in results]
