"""Simulate CleanSwarm recommendations against historical alerts."""
from __future__ import annotations

from src.cleanswarm.models import CleanAlert, Recommendation, SimulationResult


def _matches_condition(alert: CleanAlert, recommendation: Recommendation) -> bool:
    if alert.rule_id != recommendation.rule_id:
        return False
    for key, expected in recommendation.condition.items():
        actual = {
            "agent.name": alert.agent_name,
            "srcip": alert.srcip,
            "user": alert.user,
        }.get(key)
        if actual != expected:
            return False
    return True


def simulate_recommendation(
    alerts: list[CleanAlert], recommendation: Recommendation, *, sample_size: int = 5
) -> SimulationResult:
    matched = [alert for alert in alerts if _matches_condition(alert, recommendation)]
    max_level = max((alert.rule_level for alert in matched), default=0)
    high_count = sum(1 for alert in matched if alert.rule_level >= 10)

    if high_count:
        verdict = "high"
    elif max_level >= 7:
        verdict = "medium"
    else:
        verdict = recommendation.risk

    return SimulationResult(
        recommendation_id=recommendation.id,
        matched_alerts=len(matched),
        total_alerts=len(alerts),
        reduction_ratio=round(len(matched) / max(len(alerts), 1), 4),
        max_level_hidden=max_level,
        high_or_critical_hidden=high_count,
        affected_rules=sorted({alert.rule_id for alert in matched}),
        sample_hidden_alerts=matched[:sample_size],
        verdict=verdict,
    )


def simulate_recommendations(
    alerts: list[CleanAlert], recommendations: list[Recommendation]
) -> list[SimulationResult]:
    return [simulate_recommendation(alerts, rec) for rec in recommendations]
