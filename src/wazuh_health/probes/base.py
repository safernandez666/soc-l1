"""Probe abstract base class."""
from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, ClassVar

from src.wazuh_health.contracts import ProbeResult
from src.wazuh_health.contracts.probes import ProbeName


class Probe(ABC):
    name: ClassVar[ProbeName]

    @abstractmethod
    def collect(self) -> dict[str, Any]:
        """Return a dict with 'metrics', 'artifacts', 'errors'."""
        raise NotImplementedError

    def run(self) -> ProbeResult:
        try:
            payload = self.collect()
        except Exception as exc:
            payload = {"metrics": {}, "artifacts": {}, "errors": [repr(exc)]}
        return ProbeResult(
            probe=self.name,
            run_at=datetime.now(tz=timezone.utc),
            metrics=payload.get("metrics", {}),
            artifacts=payload.get("artifacts", {}),
            errors=payload.get("errors", []),
        )
