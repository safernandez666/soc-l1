"""Finding and report contracts (LLM agent outputs)."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Domain = Literal["hygiene", "capacity", "coverage"]
Severity = Literal["info", "warning", "critical"]


class DomainFinding(BaseModel):
    """Single LLM-emitted finding.

    Length limits (title, body_md) and evidence value shape are intentionally
    NOT enforced at the contract layer; the ``sanitize_finding`` agent is the
    single enforcement point (defense-in-depth: contract is permissive,
    sanitizer narrows). Downstream consumers should treat sanitized findings
    as having ``dict[str, str | int | float]`` evidence.
    """

    model_config = ConfigDict(extra="forbid")
    domain: Domain
    severity: Severity
    title: str
    body_md: str
    evidence: dict[str, Any] = Field(default_factory=dict)
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
