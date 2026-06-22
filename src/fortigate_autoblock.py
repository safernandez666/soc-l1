"""Auto-block FortiGate migrado desde el integration `custom-email-unified` de Wazuh.

Ver `docs/fortigate-autoblock-plan.md`. Este módulo decide, a partir de una alerta ya
normalizada, si corresponde un auto-block (regla IPS de alta confianza en la allowlist)
y cuál IP se bloquearía, respetando el guardrail `PROTECTED_NETWORKS`.

- **Fase 0 (`fortigate_autoblock_enabled=False`):** solo OBSERVA — `observe()` loguea qué
  bloquearía, sin ejecutar nada. Sirve para comparar contra lo que hace el script actual.
- **Fase 1 (`=True`):** el caller ejecuta el quarantine (fast-path en el ingest).

El primitivo de bloqueo elegido es `quarantine_ip` (monitor/user/banned con TTL), no el
addrgrp permanente del script viejo (decisión 2026-06-22).
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from src.config import Settings
from src.executor import _ip_in_protected_networks
from src.models import NormalizedAlert

logger = logging.getLogger("soc-l1")


def _observation_path(settings: Settings) -> Path:
    """JSONL de observaciones, junto a la state.db (gitignored)."""
    return Path(settings.state_db_path).with_name("fgt_observations.jsonl")


def _notify_state_path(settings: Settings) -> Path:
    """JSON {ip: last_notified_iso} para deduplicar el email de observación por IP."""
    return Path(settings.state_db_path).with_name("fgt_notified.json")


def _load_notify_state(settings: Settings) -> dict[str, str]:
    path = _notify_state_path(settings)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001 - best-effort, archivo corrupto = sin dedup
        return {}


def recently_notified(settings: Settings, ip: str) -> bool:
    """True si ya mandamos email de observación para esta IP dentro de la ventana TTL."""
    last = _load_notify_state(settings).get(ip)
    if not last:
        return False
    try:
        last_dt = datetime.fromisoformat(last)
    except ValueError:
        return False
    return datetime.now(tz=UTC) - last_dt < timedelta(hours=settings.fortigate_block_ttl_hours)


def mark_notified(settings: Settings, ip: str) -> None:
    """Registra que ya notificamos esta IP. Best-effort; poda entradas viejas."""
    try:
        data = _load_notify_state(settings)
        now = datetime.now(tz=UTC)
        data[ip] = now.isoformat()
        # Poda: descarta IPs cuyo último aviso excede 2× el TTL (ya no deduplican).
        horizon = now - timedelta(hours=2 * settings.fortigate_block_ttl_hours)
        pruned = {}
        for k, v in data.items():
            try:
                if datetime.fromisoformat(v) >= horizon:
                    pruned[k] = v
            except ValueError:
                continue
        _notify_state_path(settings).write_text(
            json.dumps(pruned, ensure_ascii=False), encoding="utf-8"
        )
    except Exception:  # noqa: BLE001 - nunca rompe el ingest
        logger.exception("fgt-autoblock: no pude registrar la notificación")


@dataclass(frozen=True)
class AutoBlockDecision:
    """Resultado de evaluar una alerta contra la política de auto-block."""

    candidate: bool  # la regla está en la allowlist de auto-block
    ip: str | None  # IP que se bloquearía; None si no aplica o está protegida
    rule_id: str | None
    reason: str  # would_block | no_rule_match | no_srcip | protected | invalid_ip
    protected_match: str | None = None  # CIDR protegido que matcheó (si reason=protected)

    @property
    def should_block(self) -> bool:
        return self.candidate and self.ip is not None and self.reason == "would_block"


def evaluate(alert: NormalizedAlert, settings: Settings) -> AutoBlockDecision:
    """Decide si la alerta dispara auto-block y cuál IP, aplicando PROTECTED_NETWORKS."""
    rule_id = alert.wazuh_rule.id
    if not rule_id or rule_id not in settings.fortigate_auto_block_rules_set():
        return AutoBlockDecision(False, None, rule_id, "no_rule_match")

    # En las alertas FortiGate IPS el atacante es el srcip (path nativo del normalizer).
    ip = alert.network.src_ip_external or alert.network.src_ip_internal
    if not ip or ip == "-":
        return AutoBlockDecision(True, None, rule_id, "no_srcip")

    match = _ip_in_protected_networks(ip, settings.protected_networks_list())
    if match == "invalid_ip":
        return AutoBlockDecision(True, None, rule_id, "invalid_ip")
    if match is not None:
        return AutoBlockDecision(True, None, rule_id, "protected", protected_match=match)

    return AutoBlockDecision(True, ip, rule_id, "would_block")


def _record(alert: NormalizedAlert, decision: AutoBlockDecision, settings: Settings) -> None:
    """Append best-effort de la decisión a un JSONL, para resumir la observación."""
    try:
        rec = {
            "ts": datetime.now(tz=UTC).isoformat(),
            "alert_id": alert.alert_id,
            "rule_id": decision.rule_id,
            "ip": alert.network.src_ip_external or alert.network.src_ip_internal,
            "reason": decision.reason,
            "would_block": decision.should_block,
            "protected_match": decision.protected_match,
            "host": alert.device.hostname,
        }
        path = _observation_path(settings)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001 - registro best-effort, nunca rompe el ingest
        logger.exception("fgt-autoblock: no pude registrar la observación")


def observe(alert: NormalizedAlert, settings: Settings) -> AutoBlockDecision:
    """Fase 0: evalúa, loguea y registra la decisión sin ejecutar. Devuelve la decisión.

    Solo actúa cuando la regla es candidata (evita ruido en alertas no-FortiGate-IPS).
    """
    decision = evaluate(alert, settings)
    if not decision.candidate:
        return decision

    _record(alert, decision, settings)
    ttl_h = settings.fortigate_block_ttl_hours
    if decision.should_block:
        logger.info(
            "🔭 FGT-AUTOBLOCK OBSERVE | WOULD quarantine ip=%s rule=%s ttl=%sh "
            "alert=%s (Fase 0: no ejecutado)",
            decision.ip, decision.rule_id, ttl_h, alert.alert_id,
        )
    elif decision.reason == "protected":
        logger.info(
            "🛡️ FGT-AUTOBLOCK OBSERVE | candidata pero IP PROTEGIDA, NO bloquearía | "
            "ip=%s matchea=%s rule=%s alert=%s",
            alert.network.src_ip_external or alert.network.src_ip_internal,
            decision.protected_match, decision.rule_id, alert.alert_id,
        )
    else:
        logger.info(
            "🔭 FGT-AUTOBLOCK OBSERVE | candidata sin acción (%s) | rule=%s alert=%s",
            decision.reason, decision.rule_id, alert.alert_id,
        )
    return decision


def summarize(path: Path) -> dict:
    """Resumen de la observación (Fase 0) a partir del JSONL."""
    from collections import Counter

    total = 0
    would_block = 0
    by_reason: Counter[str] = Counter()
    by_rule: Counter[str] = Counter()
    block_ips: set[str] = set()
    protected_ips: set[str] = set()
    first_ts = last_ts = None
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            total += 1
            by_reason[r.get("reason") or "?"] += 1
            by_rule[str(r.get("rule_id"))] += 1
            ts = r.get("ts")
            if ts:
                first_ts = min(first_ts or ts, ts)
                last_ts = max(last_ts or ts, ts)
            if r.get("would_block"):
                would_block += 1
                if r.get("ip"):
                    block_ips.add(r["ip"])
            elif r.get("reason") == "protected" and r.get("ip"):
                protected_ips.add(r["ip"])
    return {
        "total_observaciones": total,
        "would_block": would_block,
        "ips_distintas_que_bloquearia": len(block_ips),
        "ips_protegidas_evitadas": sorted(protected_ips),
        "por_reason": dict(by_reason),
        "por_regla": dict(by_rule),
        "ventana": {"desde": first_ts, "hasta": last_ts},
    }


def load_recent(path: Path, limit: int = 50) -> list[dict]:
    """Últimas `limit` observaciones (más recientes primero)."""
    if not path.exists():
        return []
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return list(reversed(out[-limit:]))


if __name__ == "__main__":  # python -m src.fortigate_autoblock [--summary]
    from src.config import get_settings

    p = _observation_path(get_settings())
    print(f"# Observación FortiGate auto-block (Fase 0)\n# fuente: {p}\n")
    print(json.dumps(summarize(p), ensure_ascii=False, indent=2))
