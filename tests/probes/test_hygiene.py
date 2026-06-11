from src.wazuh_health.contracts import CleanAlert
from src.wazuh_health.probes.hygiene import HygieneProbe


class _FakeSource:
    def __init__(self, alerts: list[CleanAlert]):
        self._alerts = alerts

    def iter_alerts(self, *, since_days=None):
        return iter(self._alerts)


def _alert(rid="5710", level=5):
    return CleanAlert(
        timestamp="2026-06-11T10:00:00Z", rule_id=rid, rule_level=level,
        agent_name="vpn01", srcip="10.0.5.20",
    )


def test_hygiene_probe_emits_bucket_count_and_combined_reduction():
    probe = HygieneProbe(source=_FakeSource([_alert() for _ in range(40)]), min_count=10)
    result = probe.run()
    assert result.metrics["noise.recommendations_count"] >= 1
    assert "noise.combined_reduction_pct" in result.metrics
    assert "top_buckets" in result.artifacts
    assert "recommendations" in result.artifacts


def test_hygiene_probe_with_no_noise_returns_zeros():
    probe = HygieneProbe(source=_FakeSource([]), min_count=10)
    result = probe.run()
    assert result.metrics["noise.recommendations_count"] == 0
    assert result.metrics["noise.combined_reduction_pct"] == 0.0
