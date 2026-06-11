from src.wazuh_health.contracts import NoiseBucket
from src.wazuh_health.hygiene.recommender import (
    SENSITIVE_RULE_GROUPS,
    recommend_from_buckets,
)


def _bucket(level=5, groups=None, count=100, dims=None):
    return NoiseBucket(
        key="rule_id=5710|agent.name=vpn01",
        dimensions=dims or {"rule_id": "5710", "agent.name": "vpn01"},
        count=count,
        rule_id="5710",
        rule_level=level,
        rule_description="ssh fail",
        rule_groups=groups or [],
    )


def test_level_ge_7_without_sensitive_groups_goes_to_tune_frequency():
    recs = recommend_from_buckets([_bucket(level=7)], total_alerts=200)
    assert recs[0].type == "tune_frequency"


def test_level_ge_10_always_investigate_source():
    recs = recommend_from_buckets([_bucket(level=11)], total_alerts=200)
    assert recs[0].type == "investigate_source"


def test_sensitive_rule_groups_degrade_to_investigate():
    for g in SENSITIVE_RULE_GROUPS:
        recs = recommend_from_buckets(
            [_bucket(level=4, groups=[g])], total_alerts=200
        )
        assert recs[0].type == "investigate_source", g


def test_no_dimensions_yields_tune_frequency():
    recs = recommend_from_buckets(
        [_bucket(level=3, dims={"rule_id": "5710"})], total_alerts=200
    )
    assert recs[0].type == "tune_frequency"


def test_low_severity_with_dimensions_is_suppress_candidate():
    recs = recommend_from_buckets([_bucket(level=4, count=50)], total_alerts=500)
    assert recs[0].type == "suppress_conditionally"
    assert recs[0].risk == "low"


def test_high_ratio_bumps_risk():
    recs = recommend_from_buckets([_bucket(level=4, count=400)], total_alerts=500)
    assert recs[0].risk == "medium"
