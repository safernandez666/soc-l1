"""Read-only capacity tools."""
from __future__ import annotations

from typing import Any

from src.wazuh_health.store.audit_store import AuditStore


def get_disk_stats(*, audit: AuditStore) -> dict[str, float | int]:
    pr = audit.latest_probe_run("capacity")
    if pr is None:
        return {}
    return {k: v for k, v in pr.metrics.items() if k.startswith("disk.")}


def get_indexer_stats(*, audit: AuditStore) -> dict[str, float | int]:
    pr = audit.latest_probe_run("capacity")
    if pr is None:
        return {}
    return {k: v for k, v in pr.metrics.items() if k.startswith("indexer.")}


def get_manager_stats(*, audit: AuditStore) -> dict[str, float | int]:
    pr = audit.latest_probe_run("capacity")
    if pr is None:
        return {}
    return {k: v for k, v in pr.metrics.items() if k.startswith("manager.")}


def list_recent_alerts(
    *, audit: AuditStore, rule_groups: list[str] | None = None, hours: int = 1
) -> list[dict[str, Any]]:
    """Returns alert signatures from the hygiene run, not raw alerts."""
    pr = audit.latest_probe_run("hygiene")
    if pr is None:
        return []
    buckets = pr.artifacts.get("top_buckets", [])
    if rule_groups:
        wanted = set(rule_groups)
        buckets = [b for b in buckets if wanted.intersection(b.get("rule_groups", []))]
    return [{k: v for k, v in b.items() if k != "noise_score_breakdown"}
            for b in buckets[:20]]
