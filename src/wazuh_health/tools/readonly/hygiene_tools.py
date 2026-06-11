"""Read-only hygiene tools. Each tool reads from the latest ProbeResult."""
from __future__ import annotations

from typing import Any

from src.wazuh_health.store.audit_store import AuditStore


def get_top_buckets(*, audit: AuditStore, limit: int = 10) -> list[dict[str, Any]]:
    pr = audit.latest_probe_run("hygiene")
    if pr is None:
        return []
    buckets = pr.artifacts.get("top_buckets", [])
    return buckets[:limit]


def get_recommendations(*, audit: AuditStore, limit: int = 10) -> list[dict[str, Any]]:
    pr = audit.latest_probe_run("hygiene")
    if pr is None:
        return []
    return pr.artifacts.get("recommendations", [])[:limit]


def simulate(*, audit: AuditStore, recommendation_id: str) -> dict[str, Any] | None:
    pr = audit.latest_probe_run("hygiene")
    if pr is None:
        return None
    for sim in pr.artifacts.get("simulations", []):
        if sim.get("recommendation_id") == recommendation_id:
            return sim
    return None


def query_rule_history(
    *, audit: AuditStore, rule_id: str, days: int = 7
) -> dict[str, Any]:
    """Approximation: counts the rule_id presence across the recent hygiene runs."""
    pr = audit.latest_probe_run("hygiene")
    if pr is None:
        return {"rule_id": rule_id, "count": 0, "first_seen": None, "last_seen": None}
    matching = [
        b for b in pr.artifacts.get("top_buckets", [])
        if str(b.get("rule_id")) == rule_id
    ]
    if not matching:
        return {"rule_id": rule_id, "count": 0, "first_seen": None, "last_seen": None}
    b = matching[0]
    return {
        "rule_id": rule_id,
        "count": b.get("count", 0),
        "first_seen": b.get("first_seen"),
        "last_seen": b.get("last_seen"),
    }
