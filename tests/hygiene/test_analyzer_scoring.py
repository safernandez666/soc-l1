from src.wazuh_health.contracts import CleanAlert
from src.wazuh_health.hygiene.analyzer import build_noise_buckets


def _alert(rule_id="5710", level=5, agent="vpn01", srcip="10.0.5.20"):
    return CleanAlert(
        timestamp="2026-06-11T10:00:00Z",
        rule_id=rule_id,
        rule_level=level,
        agent_name=agent,
        srcip=srcip,
    )


def test_bucket_score_includes_breakdown():
    alerts = [_alert() for _ in range(20)]
    buckets = build_noise_buckets(alerts, min_count=5)
    assert buckets
    b = buckets[0]
    assert {"volume", "repetition", "severity_penalty", "spread_penalty"} <= set(
        b.noise_score_breakdown
    )


def test_severity_penalty_dampens_high_level_buckets():
    low = [_alert(level=3) for _ in range(50)]
    high = [_alert(rule_id="100100", level=12, agent="win01", srcip="203.0.113.99") for _ in range(50)]
    buckets = build_noise_buckets(low + high, min_count=5)
    by_rule = {b.rule_id: b for b in buckets}
    assert by_rule["100100"].noise_score < by_rule["5710"].noise_score


def test_user_spread_penalty_applied():
    base = []
    for i in range(40):
        base.append(_alert(rule_id="5402", level=4, agent="srv01", srcip=None))
        base[-1].user = f"user{i}"  # 40 distinct users
    buckets = build_noise_buckets(base, min_count=10)
    # Same rule grouped by (rule_id, agent.name) since no srcip/user dim wins...
    # The spread by user should drop the score below the same rule with 1 user
    assert buckets[0].noise_score_breakdown["spread_penalty"] > 0
