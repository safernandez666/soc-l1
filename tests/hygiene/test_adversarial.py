import json
from pathlib import Path

from src.wazuh_health.contracts import CleanAlert
from src.wazuh_health.hygiene.analyzer import build_noise_buckets
from src.wazuh_health.hygiene.recommender import recommend_from_buckets
from src.wazuh_health.hygiene.report import analyze_file


def test_sensitive_group_with_high_volume_does_not_recommend_suppression(tmp_path):
    alerts = []
    for _ in range(100):
        alerts.append(CleanAlert(
            timestamp="2026-06-11T10:00:00Z",
            rule_id="5712", rule_level=5,
            rule_groups=["authentication_failures"],
            agent_name="vpn01", srcip="10.0.5.20",
        ))
    buckets = build_noise_buckets(alerts, min_count=10)
    recs = recommend_from_buckets(buckets, total_alerts=len(alerts))
    assert all(r.type == "investigate_source" for r in recs)


def test_full_pipeline_handles_corrupt_and_high_level_alerts(tmp_path):
    p = tmp_path / "alerts.json"
    with p.open("w") as f:
        f.write("not json\n")
        f.write("\n")
        for _ in range(15):
            f.write(json.dumps({
                "timestamp": "2026-06-11T10:00:00Z",
                "rule": {"id": "5712", "level": 12,
                         "description": "scan", "groups": ["attacks"]},
                "agent": {"id": "1", "name": "vpn01"},
                "data": {"srcip": "10.0.5.20"},
                "decoder": {"name": "sshd"},
            }) + "\n")
    report = analyze_file(str(p), days=None, min_count=5)
    assert report.total_alerts == 15
    assert all(r.type == "investigate_source" for r in report.recommendations)
    # No suppression XML emitted for high-severity rules.
    assert all(r.proposed_wazuh_rule is None for r in report.recommendations)
