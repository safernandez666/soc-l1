"""Typed models for CleanSwarm reports.

CleanSwarm stays read-only by design for the MVP: it produces recommendations and
simulation data, but it does not modify Wazuh configuration.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

RecommendationType = Literal[
    "suppress_conditionally",
    "tune_frequency",
    "investigate_source",
    "leave_visible",
]
RiskLevel = Literal["low", "medium", "high"]


class CleanAlert(BaseModel):
    """Compact Wazuh alert shape used for hygiene analysis."""

    model_config = ConfigDict(extra="forbid")

    timestamp: str
    rule_id: str
    rule_level: int = 0
    rule_description: str = "Unknown"
    rule_groups: list[str] = Field(default_factory=list)
    agent_id: str | None = None
    agent_name: str | None = None
    srcip: str | None = None
    dstip: str | None = None
    user: str | None = None
    decoder_name: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class NoiseBucket(BaseModel):
    """Aggregate of repeated alerts sharing a stable signature."""

    model_config = ConfigDict(extra="forbid")

    key: str
    dimensions: dict[str, str]
    count: int
    rule_id: str | None = None
    rule_level: int = 0
    rule_description: str = "Unknown"
    first_seen: str | None = None
    last_seen: str | None = None
    affected_agents: list[str] = Field(default_factory=list)
    affected_srcips: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    noise_score: float = 0.0


class Recommendation(BaseModel):
    """Human-reviewable tuning recommendation."""

    model_config = ConfigDict(extra="forbid")

    id: str
    type: RecommendationType
    title: str
    rule_id: str
    condition: dict[str, str] = Field(default_factory=dict)
    reason: str
    risk: RiskLevel
    expected_reduction_count: int
    expected_reduction_ratio: float
    proposed_wazuh_rule: str | None = None
    rollback: str


class SimulationResult(BaseModel):
    """Historical impact estimate for a recommendation."""

    model_config = ConfigDict(extra="forbid")

    recommendation_id: str
    matched_alerts: int
    total_alerts: int
    reduction_ratio: float
    max_level_hidden: int
    high_or_critical_hidden: int
    affected_rules: list[str] = Field(default_factory=list)
    sample_hidden_alerts: list[CleanAlert] = Field(default_factory=list)
    verdict: RiskLevel


class CleanSwarmReport(BaseModel):
    """Top-level CleanSwarm analysis output."""

    model_config = ConfigDict(extra="forbid")

    generated_at: str
    source: str
    total_alerts: int
    analyzed_days: int | None = None
    top_buckets: list[NoiseBucket] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)
    simulations: list[SimulationResult] = Field(default_factory=list)
