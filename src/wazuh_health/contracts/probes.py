"""Probe and threshold contracts."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ProbeName = Literal["capacity", "hygiene", "coverage"]
Severity = Literal["info", "warning", "critical"]


class ProbeResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    probe: ProbeName
    run_at: datetime
    metrics: dict[str, float | int]
    artifacts: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)


class ThresholdHit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    probe: ProbeName
    metric: str
    value: float | int
    rule: str
    severity: Severity
