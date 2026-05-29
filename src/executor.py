"""Executor - dispatcher determinístico de ProposedAction post-aprobación.

NO usa LLM. Solo mapea action.type → función concreta de tools/ldap.py.
Esto es DELIBERADO: una vez que el humano aprobó el plan, no queremos que un
LLM decida qué ejecutar; eso sería un vector de prompt injection con efecto
side-effect en AD.

Acciones soportadas:
  - disable_user           → tools.ldap.disable_user
  - force_password_change  → tools.ldap.force_password_change
  - block_ip               → tools.fortigate.quarantine_ip
  - scan_host              → tools.defender.run_av_scan (MDE)
  - isolate_host           → tools.defender.isolate_machine (MDE)
  - notify_only            → no-op (registra "noted")
  - escalate_l2            → no-op (registra "escalated", futuro: ticket/Slack)

Guardrails de seguridad (defensa en profundidad post-approval):
  - PROTECTED_USERS: lista de sams que el executor refusa tocar. Aunque el Narrator
    recomiende disable_user y el humano apruebe, los users protegidos quedan intactos.
    Útil para cuentas de admin, ejecutivos, service accounts.
  - PROTECTED_NETWORKS: CIDRs que nunca se bloquean en FortiGate (block_ip).
  - PROTECTED_HOSTS: hostnames que el executor refusa escanear/aislar (scan_host/
    isolate_host). Pensado para DCs, Exchange, hipervisores.
  - DRY_RUN_MODE: flag global que convierte todas las acciones AD/FortiGate/Defender
    en no-op (solo log). Útil para validar el Narrator antes de habilitar ejecución real.

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
from src.tools.defender import DefenderClient, DefenderError
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
    except Exception as e:
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
    except Exception as e:
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


async def _exec_defender_action(
    settings: Settings, action_type: str, host: str
) -> ExecutionResult:
    """scan_host / isolate_host vía MDE. Resuelve hostname → machineId y acciona."""
    comment = f"SOC-L1 automated {action_type} (human-approved) on {host}"
    try:
        async with DefenderClient(settings) as dc:
            machine_id = await dc.resolve_machine_id(host)
            if not machine_id:
                return ExecutionResult(
                    action_type=action_type, target=host, ok=False,
                    message=f"no se encontró machineId en MDE para host '{host}'",
                )
            if action_type == "scan_host":
                r = await dc.run_av_scan(machine_id, comment=comment, host=host)
            else:  # isolate_host
                r = await dc.isolate_machine(machine_id, comment=comment, host=host)
        return ExecutionResult(
            action_type=action_type, target=host, ok=r.ok, message=r.message,
        )
    except DefenderError as e:
        logger.exception("%s failed for %s", action_type, host)
        return ExecutionResult(
            action_type=action_type, target=host, ok=False, message=str(e)
        )


async def _execute_one(
    action: ProposedAction,
    ldap_cfg: LdapConfig | None,
    protected_users: set[str],
    protected_networks: list[str],
    protected_hosts: set[str],
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

    if action.type in ("scan_host", "isolate_host"):
        host = action.target.strip()
        # Guardrail PROTECTED_HOSTS: nunca escanear/aislar infra crítica
        if host.lower() in protected_hosts:
            logger.warning(
                "🛡️  PROTECTED HOST | refused %s on target=%r (in PROTECTED_HOSTS list)",
                action.type, host,
            )
            return ExecutionResult(
                action_type=action.type, target=host, ok=False,
                message=(
                    f"REFUSED: '{host}' está en PROTECTED_HOSTS. Defender intacto. "
                    f"Si querés ejecutar, sacá el host de la lista."
                ),
            )
        if dry_run:
            logger.warning("🧪 DRY_RUN | would have %s on target=%r", action.type, host)
            return ExecutionResult(
                action_type=action.type, target=host, ok=True,
                message=f"DRY_RUN: {action.type} simulado (Defender intacto)",
            )
        if settings is None or not settings.defender_configured():
            return ExecutionResult(
                action_type=action.type, target=host, ok=False,
                message="Defender (MDE) no configurado - acción no ejecutada",
            )
        return await _exec_defender_action(settings, action.type, host)

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
                message="DRY_RUN: acción simulada (no se ejecutó en AD)",
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
    protected_hosts: set[str] = set()
    dry_run = False
    if settings is not None:
        protected_users = settings.protected_users_set()
        protected_networks = settings.protected_networks_list()
        protected_hosts = settings.protected_hosts_set()
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
    if protected_hosts:
        logger.info(
            "executor: PROTECTED_HOSTS activo (%d hosts): %s",
            len(protected_hosts), sorted(protected_hosts),
        )
    if dry_run:
        logger.warning("executor: DRY_RUN_MODE=true - ninguna acción AD/FortiGate se ejecuta de verdad")

    results: list[ExecutionResult] = []
    for action in actions:
        r = await _execute_one(
            action, ldap_cfg, protected_users, protected_networks,
            protected_hosts, dry_run, settings,
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
