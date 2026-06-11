"""Hygiene probe — wraps the CleanSwarm-derived analyzer/recommender/simulator."""
from __future__ import annotations

from typing import Any, Protocol

from src.wazuh_health.contracts import CleanAlert
from src.wazuh_health.contracts.probes import ProbeName
from src.wazuh_health.hygiene.analyzer import build_noise_buckets
from src.wazuh_health.hygiene.recommender import recommend_from_buckets
from src.wazuh_health.hygiene.simulator import (
    simulate_combined, simulate_recommendations,
)
from src.wazuh_health.probes.base import Probe


class _AlertSource(Protocol):
    def iter_alerts(self, *, since_days: int | None = None): ...


class HygieneProbe(Probe):
    name: ProbeName = "hygiene"

    def __init__(
        self,
        *,
        source: _AlertSource,
        window_hours: int = 1,
        min_count: int = 50,
        top: int = 20,
        max_recommendations: int = 10,
    ) -> None:
        self._source = source
        self._window_hours = window_hours
        self._min_count = min_count
        self._top = top
        self._max_recs = max_recommendations

    def collect(self) -> dict[str, Any]:
        alerts: list[CleanAlert] = list(self._source.iter_alerts(since_days=None))
        total = len(alerts)
        buckets = build_noise_buckets(alerts, min_count=self._min_count, top=self._top)
        recs = recommend_from_buckets(
            buckets, total_alerts=total, max_recommendations=self._max_recs
        )
        sims = simulate_recommendations(alerts, recs)
        combined = simulate_combined(alerts, sims) if sims else None

        metrics: dict[str, float | int] = {
            "noise.total_alerts": total,
            "noise.bucket_count": len(buckets),
            "noise.recommendations_count": len(recs),
            "noise.combined_reduction_pct": (
                round(combined.union_reduction_ratio * 100, 2) if combined else 0.0
            ),
        }
        artifacts = {
            "top_buckets": [b.model_dump() for b in buckets],
            "recommendations": [r.model_dump() for r in recs],
            "simulations": [s.model_dump() for s in sims],
            "combined_simulation": combined.model_dump() if combined else None,
        }
        return {"metrics": metrics, "artifacts": artifacts, "errors": []}
