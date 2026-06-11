"""Read-only coverage tools."""
from __future__ import annotations

from typing import Any

from src.wazuh_health.store.audit_store import AuditStore


def get_agent_list(*, audit: AuditStore) -> list[dict[str, Any]]:
    pr = audit.latest_probe_run("coverage")
    if pr is None:
        return []
    return pr.artifacts.get("agents", [])


def get_disconnected_agents(*, audit: AuditStore) -> list[dict[str, Any]]:
    return [a for a in get_agent_list(audit=audit) if a.get("status") == "disconnected"]


def get_rule_hit_counts(*, audit: AuditStore, days: int = 30) -> dict[str, int]:
    pr = audit.latest_probe_run("coverage")
    if pr is None:
        return {}
    return pr.artifacts.get("rule_hits_by_id", {})


def get_decoder_errors(*, audit: AuditStore) -> int:
    pr = audit.latest_probe_run("coverage")
    if pr is None:
        return 0
    return int(pr.metrics.get("decoders.errors", 0))
