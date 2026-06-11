from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from src.cleanswarm.analyzer import build_noise_buckets
from src.cleanswarm.collector import compact_alert, load_alerts
from src.cleanswarm.recommender import recommend_from_buckets
from src.cleanswarm.report import analyze_file, render_markdown
from src.cleanswarm.simulator import simulate_recommendations

FIXTURE = Path("tests/fixtures/cleanswarm/alerts.json")


def test_compact_alert_extracts_common_wazuh_fields() -> None:
    raw = json.loads(FIXTURE.read_text().splitlines()[0])
    alert = compact_alert(raw)

    assert alert is not None
    assert alert.rule_id == "5710"
    assert alert.rule_level == 5
    assert alert.agent_name == "vpn01"
    assert alert.srcip == "10.0.5.20"
    assert alert.user == "scanner"


def test_noise_bucket_recommendation_and_simulation_are_conditional() -> None:
    alerts = load_alerts(FIXTURE)
    buckets = build_noise_buckets(alerts, min_count=5)

    assert buckets
    bucket = buckets[0]
    assert bucket.rule_id == "5710"
    assert bucket.dimensions == {
        "rule_id": "5710",
        "agent.name": "vpn01",
        "srcip": "10.0.5.20",
    }

    recommendations = recommend_from_buckets(buckets, total_alerts=len(alerts))
    assert recommendations[0].type == "suppress_conditionally"
    assert recommendations[0].risk in {"low", "medium"}
    assert "<if_sid>5710</if_sid>" in (recommendations[0].proposed_wazuh_rule or "")
    assert "agent.name" in (recommendations[0].proposed_wazuh_rule or "")

    simulations = simulate_recommendations(alerts, recommendations)
    assert simulations[0].matched_alerts == 10
    assert simulations[0].max_level_hidden == 5
    assert simulations[0].high_or_critical_hidden == 0


def test_report_can_render_json_and_markdown() -> None:
    report = analyze_file(str(FIXTURE), days=None, min_count=5)
    assert report.total_alerts == 11
    assert report.recommendations

    markdown = render_markdown(report)
    assert "CleanSwarm Wazuh Hygiene Report" in markdown
    assert "Recommendations" in markdown


def test_cli_analyze_writes_json(tmp_path: Path) -> None:
    out = tmp_path / "cleanswarm.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.cleanswarm",
            "analyze",
            "--alerts-path",
            str(FIXTURE),
            "--days",
            "9999",
            "--min-count",
            "5",
            "--out",
            str(out),
        ],
        check=True,
        text=True,
        capture_output=True,
    )

    assert result.stdout == ""
    payload = json.loads(out.read_text())
    assert payload["total_alerts"] == 11
    assert payload["recommendations"][0]["type"] == "suppress_conditionally"
