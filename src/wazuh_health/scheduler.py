"""Tiny scheduler with injectable clock — no third-party dep."""
from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Job:
    name: str
    interval_seconds: float
    callback: Callable[[], None]
    last_run: float | None = None


class _RealClock:
    @staticmethod
    def time() -> float: return time.monotonic()


class Scheduler:
    def __init__(self, *, clock=None, jitter_seconds: float = 0.0) -> None:
        self._clock = clock or _RealClock()
        self._jitter = jitter_seconds
        self._jobs: list[Job] = []

    def add(self, job: Job) -> None:
        self._jobs.append(job)

    def tick(self) -> int:
        """Run any jobs that are due. Returns number of jobs invoked."""
        now = self._clock.time()
        ran = 0
        for job in self._jobs:
            jitter = random.uniform(0, self._jitter) if self._jitter else 0
            if job.last_run is None or now - job.last_run >= job.interval_seconds + jitter:
                try:
                    job.callback()
                finally:
                    job.last_run = now
                    ran += 1
        return ran
