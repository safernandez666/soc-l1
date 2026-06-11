"""Capacity probe — disk, indexer heap, alerts.json growth."""
from __future__ import annotations

from typing import Any

from src.wazuh_health.contracts.probes import ProbeName
from src.wazuh_health.probes.base import Probe
from src.wazuh_health.source.base import WazuhSource


class CapacityProbe(Probe):
    name: ProbeName = "capacity"

    def __init__(
        self,
        *,
        source: WazuhSource,
        previous_size: int | None = None,
        hours_between: float | None = None,
    ) -> None:
        self._source = source
        self._previous_size = previous_size
        self._hours_between = hours_between

    def collect(self) -> dict[str, Any]:
        metrics: dict[str, float | int] = {}
        errors: list[str] = []

        try:
            disk = self._source.disk_stats()
            for name, fs in disk.filesystems.items():
                metrics[f"disk.{name}.free_pct"] = fs.free_pct
                metrics[f"disk.{name}.free_bytes"] = fs.free_bytes
            metrics["alerts_json.size_bytes"] = disk.alerts_json_size_bytes
            if self._previous_size is not None and self._hours_between:
                delta_mb = (
                    disk.alerts_json_size_bytes - self._previous_size
                ) / 1_000_000
                metrics["alerts_json.growth_mb_per_h"] = round(
                    delta_mb / self._hours_between, 2
                )
        except Exception as exc:
            errors.append(f"disk_stats: {exc!r}")

        try:
            mgr = self._source.manager_stats()
            if mgr.cpu_pct is not None:
                metrics["manager.cpu_pct"] = mgr.cpu_pct
            if mgr.mem_pct is not None:
                metrics["manager.mem_pct"] = mgr.mem_pct
        except Exception as exc:
            errors.append(f"manager_stats: {exc!r}")

        try:
            idx = self._source.indexer_stats()
            if idx.heap_pct is not None:
                metrics["indexer.heap_pct"] = idx.heap_pct
            metrics["indexer.red_shards"] = idx.red_shards
            metrics["indexer.yellow_shards"] = idx.yellow_shards
            metrics["indexer.pending_tasks"] = idx.pending_tasks
        except Exception as exc:
            errors.append(f"indexer_stats: {exc!r}")

        return {"metrics": metrics, "artifacts": {}, "errors": errors}
