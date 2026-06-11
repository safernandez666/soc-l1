"""Coverage probe — agent health, decoder errors, zero-hit rules."""
from __future__ import annotations

from typing import Any, Protocol

from src.wazuh_health.contracts.probes import ProbeName
from src.wazuh_health.probes.base import Probe


class _Source(Protocol):
    def list_agents(self): ...
    def manager_stats(self): ...


class CoverageProbe(Probe):
    name: ProbeName = "coverage"

    def __init__(self, *, source: _Source) -> None:
        self._source = source

    def collect(self) -> dict[str, Any]:
        errors: list[str] = []
        metrics: dict[str, float | int] = {}
        agents_artifact: list[dict] = []
        try:
            agents = self._source.list_agents()
            metrics["agents.total"] = len(agents)
            metrics["agents.active"] = sum(1 for a in agents if a.status == "active")
            metrics["agents.disconnected"] = sum(
                1 for a in agents if a.status == "disconnected"
            )
            metrics["agents.never_connected"] = sum(
                1 for a in agents if a.status == "never_connected"
            )
            agents_artifact = [a.model_dump(mode="json") for a in agents]
        except Exception as exc:
            errors.append(f"list_agents: {exc!r}")

        try:
            mgr = self._source.manager_stats()
            metrics["decoders.errors"] = mgr.decoder_errors
            metrics["rules.zero_hit"] = sum(
                1 for hits in mgr.rule_hits_by_id.values() if hits == 0
            )
        except Exception as exc:
            errors.append(f"manager_stats: {exc!r}")

        return {
            "metrics": metrics,
            "artifacts": {"agents": agents_artifact},
            "errors": errors,
        }
