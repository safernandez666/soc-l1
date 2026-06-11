"""Noise hygiene aggregates and recommendations (moved from cleanswarm)."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

RecommendationType = Literal[
    "suppress_conditionally",
    "tune_frequency",
    "investigate_source",
    "leave_visible",
]
RiskLevel = Literal["low", "medium", "high"]


class NoiseBucket(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str
    dimensions: dict[str, str]
    count: int
    rule_id: str | None = None
    rule_level: int = 0
    rule_description: str = "Unknown"
    rule_groups: list[str] = Field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    affected_agents: list[str] = Field(default_factory=list)
    affected_srcips: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    noise_score: float = 0.0
    noise_score_breakdown: dict[str, float] = Field(default_factory=dict)


class Recommendation(BaseModel):
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
    model_config = ConfigDict(extra="forbid")
    recommendation_id: str
    matched_alerts: int
    total_alerts: int
    reduction_ratio: float
    max_level_hidden: int
    high_or_critical_hidden: int
    affected_rules: list[str] = Field(default_factory=list)
    sample_hidden_alert_ids: list[str] = Field(default_factory=list)
    verdict: RiskLevel


class CombinedSimulation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    total_alerts: int
    union_matched: int
    union_reduction_ratio: float
    overlap_alerts: int
    max_level_hidden: int
    high_or_critical_hidden: int


class CleanSwarmReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    generated_at: str
    source: str
    total_alerts: int
    analyzed_days: int | None = None
    top_buckets: list[NoiseBucket] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)
    simulations: list[SimulationResult] = Field(default_factory=list)
    combined_simulation: CombinedSimulation | None = None
