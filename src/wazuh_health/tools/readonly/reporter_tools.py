"""Read-only reporter tools."""
from __future__ import annotations

from typing import Any

from src.wazuh_health.store.findings_store import FindingsStore


def query_findings(
    *, store: FindingsStore, since_iso: str | None = None
) -> list[dict[str, Any]]:
    return [f.model_dump() for f in store.list_open(since_iso=since_iso)]


def get_metric_trend(*, audit, metric: str, hours: int = 24) -> list[dict[str, Any]]:
    """Reads the last N probe_runs and extracts the requested metric."""
    pr = audit.latest_probe_run("capacity")
    if pr is None or metric not in pr.metrics:
        return []
    return [{"run_at": pr.run_at.isoformat(), "value": pr.metrics[metric]}]
