from datetime import datetime, timezone

from src.wazuh_health.contracts import ProbeResult
from src.wazuh_health.decision.threshold import (
    ThresholdEngine, ThresholdRule,
)


def _result(metrics):
    return ProbeResult(
        probe="capacity", run_at=datetime.now(tz=timezone.utc),
        metrics=metrics, artifacts={}, errors=[],
    )


def test_simple_lt_rule_hits():
    eng = ThresholdEngine(rules={"capacity": [
        ThresholdRule(metric="disk.free_pct", rule="value < 15", severity="warning"),
    ]})
    hits = eng.evaluate(_result({"disk.free_pct": 10}))
    assert len(hits) == 1
    assert hits[0].severity == "warning"


def test_missing_metric_does_not_hit():
    eng = ThresholdEngine(rules={"capacity": [
        ThresholdRule(metric="disk.free_pct", rule="value < 15", severity="warning"),
    ]})
    assert eng.evaluate(_result({"other": 1})) == []


def test_streak_requires_history():
    eng = ThresholdEngine(rules={"capacity": [
        ThresholdRule(metric="agents.disconnected", rule="value >= 3 streak >= 2", severity="warning"),
    ]})
    # First tick — no hit even though value matches.
    hits = eng.evaluate(_result({"agents.disconnected": 5}))
    assert hits == []
    # Second tick — streak reached.
    hits = eng.evaluate(_result({"agents.disconnected": 5}))
    assert len(hits) == 1
