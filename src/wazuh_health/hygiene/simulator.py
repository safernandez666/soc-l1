"""Simulate hygiene recommendations against historical alerts."""
from __future__ import annotations

from src.wazuh_health.contracts import (
    CleanAlert,
    CombinedSimulation,
    Recommendation,
    SimulationResult,
)


def _matches_condition(alert: CleanAlert, rec: Recommendation) -> bool:
    if alert.rule_id != rec.rule_id:
        return False
    table = {
        "agent.name": alert.agent_name,
        "srcip": alert.srcip,
        "user": alert.user,
    }
    for key, expected in rec.condition.items():
        if table.get(key) != expected:
            return False
    return True


def simulate_recommendation(
    alerts: list[CleanAlert], rec: Recommendation, *, sample_size: int = 5
) -> SimulationResult:
    matched: list[CleanAlert] = [a for a in alerts if _matches_condition(a, rec)]
    max_level = max((a.rule_level for a in matched), default=0)
    high_count = sum(1 for a in matched if a.rule_level >= 10)

    if high_count:
        verdict = "high"
    elif max_level >= 7:
        verdict = "medium"
    elif matched:
        verdict = rec.risk
    else:
        verdict = "low"

    return SimulationResult(
        recommendation_id=rec.id,
        matched_alerts=len(matched),
        total_alerts=len(alerts),
        reduction_ratio=round(len(matched) / max(len(alerts), 1), 4),
        max_level_hidden=max_level,
        high_or_critical_hidden=high_count,
        affected_rules=sorted({a.rule_id for a in matched}),
        sample_hidden_alert_ids=[
            f"{a.rule_id}@{a.timestamp}" for a in matched[:sample_size]
        ],
        verdict=verdict,
    )


def simulate_recommendations(
    alerts: list[CleanAlert], recs: list[Recommendation]
) -> list[SimulationResult]:
    return [simulate_recommendation(alerts, r) for r in recs]


def simulate_combined(
    alerts: list[CleanAlert], sims: list[SimulationResult]
) -> CombinedSimulation:
    """Compute union/overlap of alerts that would be hidden by all sims together.

    Identifies alerts by (rule_id, timestamp, agent_name, srcip, user) tuple.
    """
    matched_sets: list[set[tuple]] = []
    by_id = {
        (idx, f"{a.rule_id}@{a.timestamp}@{a.agent_name}@{a.srcip}@{a.user}"): a
        for idx, a in enumerate(alerts)
    }
    for sim in sims:
        # Recompute the matched set from the original alert pool using affected_rules.
        s: set[tuple] = set()
        for key, a in by_id.items():
            if a.rule_id in sim.affected_rules:
                s.add(key)
        matched_sets.append(s)

    union: set[tuple] = set().union(*matched_sets) if matched_sets else set()
    counts: dict[tuple, int] = {}
    for s in matched_sets:
        for k in s:
            counts[k] = counts.get(k, 0) + 1
    overlap = sum(1 for v in counts.values() if v >= 2)

    union_alerts = [by_id[k] for k in union]
    max_level = max((a.rule_level for a in union_alerts), default=0)
    high_count = sum(1 for a in union_alerts if a.rule_level >= 10)

    return CombinedSimulation(
        total_alerts=len(alerts),
        union_matched=len(union),
        union_reduction_ratio=round(len(union) / max(len(alerts), 1), 4),
        overlap_alerts=overlap,
        max_level_hidden=max_level,
        high_or_critical_hidden=high_count,
    )
