"""Finding and report contracts (LLM agent outputs)."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Domain = Literal["hygiene", "capacity", "coverage"]
Severity = Literal["info", "warning", "critical"]


class DomainFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain: Domain
    severity: Severity
    title: str = Field(max_length=120)
    body_md: str = Field(max_length=4000)
    evidence: dict[str, str | int | float] = Field(default_factory=dict)
    suggested_action: str
    proposed_artifact: str | None = None
    hash_key: str = ""  # filled by daemon, never trusted from LLM


class WazuhHealthReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    generated_at: datetime
    window_hours: int
    summary: str
    by_domain: dict[Domain, list[DomainFinding]] = Field(default_factory=dict)
    top_priorities: list[DomainFinding] = Field(default_factory=list)
