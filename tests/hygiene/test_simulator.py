from src.wazuh_health.contracts import CleanAlert, Recommendation
from src.wazuh_health.hygiene.simulator import (
    simulate_combined,
    simulate_recommendation,
    simulate_recommendations,
)


def _alert(rule_id, level, srcip=None, agent="vpn01"):
    return CleanAlert(
        timestamp="2026-06-11T10:00:00Z",
        rule_id=rule_id, rule_level=level, agent_name=agent, srcip=srcip,
    )


def _rec(rec_id, rule_id, condition):
    return Recommendation(
        id=rec_id, type="suppress_conditionally",
        title="t", rule_id=rule_id, condition=condition,
        reason="r", risk="low",
        expected_reduction_count=0, expected_reduction_ratio=0.0,
        rollback="rb",
    )


def test_simulator_counts_only_exact_condition_match():
    alerts = [
        _alert("5710", 5, srcip="10.0.0.1"),
        _alert("5710", 5, srcip="10.0.0.2"),
    ]
    rec = _rec("r1", "5710", {"srcip": "10.0.0.1"})
    sim = simulate_recommendation(alerts, rec)
    assert sim.matched_alerts == 1


def test_verdict_high_if_any_high_severity_hidden():
    alerts = [_alert("100100", 12, srcip="10.0.0.1")]
    rec = _rec("r1", "100100", {"srcip": "10.0.0.1"})
    sim = simulate_recommendation(alerts, rec)
    assert sim.verdict == "high"


def test_simulate_recommendations_returns_one_per_rec():
    alerts = [_alert("5710", 5, srcip="10.0.0.1")]
    sims = simulate_recommendations(alerts, [_rec("r1", "5710", {"srcip": "10.0.0.1"})])
    assert [s.recommendation_id for s in sims] == ["r1"]


def test_combined_simulation_dedupes_overlapping_recommendations():
    alerts = [_alert("5710", 5, srcip="10.0.0.1") for _ in range(5)]
    r1 = _rec("r1", "5710", {"srcip": "10.0.0.1"})
    r2 = _rec("r2", "5710", {})  # matches all 5710 too
    sims = simulate_recommendations(alerts, [r1, r2])
    combined = simulate_combined(alerts, sims)
    # Each hides 5 separately, but union is still 5 alerts, overlap=5.
    assert combined.union_matched == 5
    assert combined.overlap_alerts == 5
