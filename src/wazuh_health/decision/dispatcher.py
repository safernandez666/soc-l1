"""WakeDispatcher: invoke at most one domain agent per dispatch, respecting cooldowns + cap."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Callable, Protocol

from src.wazuh_health.contracts import ThresholdHit
from src.wazuh_health.contracts.probes import ProbeName


_DOMAIN_OF: dict[ProbeName, str] = {
    "capacity": "capacity",
    "hygiene": "hygiene",
    "coverage": "coverage",
}

_AGENT_OF_DOMAIN: dict[str, str] = {
    "capacity": "CapacityAgent",
    "hygiene": "HygieneAgent",
    "coverage": "CoverageAgent",
}


class _AuditLike(Protocol):
    def count_agent_runs_today(self, agent: str, *, now: datetime) -> int: ...
    def record_agent_run(self, **kw) -> int: ...


class WakeDispatcher:
    def __init__(
        self,
        *,
        cooldown,
        agent_runs: _AuditLike,
        invoke_by_domain: dict[str, Callable[..., None]],
        daily_cap: int = 50,
    ) -> None:
        self._cooldown = cooldown
        self._audit = agent_runs
        self._invokers = invoke_by_domain
        self._daily_cap = daily_cap

    def dispatch(self, hits: list[ThresholdHit], *, now: datetime) -> None:
        eligible: dict[str, list[ThresholdHit]] = defaultdict(list)
        for h in hits:
            if not self._cooldown.can_wake(h.probe, h.metric, now=now):
                continue
            eligible[_DOMAIN_OF[h.probe]].append(h)

        for domain, dom_hits in eligible.items():
            agent_name = _AGENT_OF_DOMAIN[domain]
            if self._audit.count_agent_runs_today(agent_name, now=now) >= self._daily_cap:
                for h in dom_hits:
                    self._cooldown.mark_woken(h.probe, h.metric, at=now)
                continue
            invoker = self._invokers.get(domain)
            if invoker is None:
                continue
            invoker(dom_hits, audit_store=self._audit)
            for h in dom_hits:
                self._cooldown.mark_woken(h.probe, h.metric, at=now)
