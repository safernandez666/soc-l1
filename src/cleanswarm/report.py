"""CleanSwarm report orchestration and rendering."""
from __future__ import annotations

from datetime import datetime, timezone

from src.cleanswarm.analyzer import build_noise_buckets
from src.cleanswarm.collector import load_alerts
from src.cleanswarm.models import CleanSwarmReport
from src.cleanswarm.recommender import recommend_from_buckets
from src.cleanswarm.simulator import simulate_recommendations


def analyze_file(
    alerts_path: str,
    *,
    days: int | None = 7,
    min_count: int = 10,
    top: int = 20,
    max_recommendations: int = 10,
    limit: int | None = None,
) -> CleanSwarmReport:
    alerts = load_alerts(alerts_path, days=days, limit=limit)
    buckets = build_noise_buckets(alerts, min_count=min_count, top=top)
    recommendations = recommend_from_buckets(
        buckets,
        total_alerts=len(alerts),
        max_recommendations=max_recommendations,
    )
    simulations = simulate_recommendations(alerts, recommendations)
    return CleanSwarmReport(
        generated_at=datetime.now(tz=timezone.utc).isoformat(),
        source=alerts_path,
        total_alerts=len(alerts),
        analyzed_days=days,
        top_buckets=buckets,
        recommendations=recommendations,
        simulations=simulations,
    )


def render_markdown(report: CleanSwarmReport) -> str:
    lines = [
        "# CleanSwarm Wazuh Hygiene Report",
        "",
        f"- Generated: `{report.generated_at}`",
        f"- Source: `{report.source}`",
        f"- Total alerts analyzed: **{report.total_alerts}**",
        f"- Window days: **{report.analyzed_days if report.analyzed_days is not None else 'all'}**",
        "",
        "## Top noisy buckets",
        "",
    ]

    if not report.top_buckets:
        lines.append("No noisy buckets found with the current thresholds.")
    else:
        for bucket in report.top_buckets:
            lines.extend(
                [
                    f"### {bucket.rule_id} — {bucket.rule_description}",
                    f"- Count: **{bucket.count}** | Level: **{bucket.rule_level}** | Noise score: **{bucket.noise_score}**",
                    f"- Dimensions: `{bucket.dimensions}`",
                    f"- Agents: `{bucket.affected_agents[:5]}`",
                    f"- Src IPs: `{bucket.affected_srcips[:5]}`",
                    "",
                ]
            )

    lines.extend(["", "## Recommendations", ""])
    if not report.recommendations:
        lines.append("No recommendations generated.")
    else:
        simulations = {sim.recommendation_id: sim for sim in report.simulations}
        for rec in report.recommendations:
            sim = simulations.get(rec.id)
            lines.extend(
                [
                    f"### {rec.id}: {rec.title}",
                    f"- Type: `{rec.type}` | Risk: **{rec.risk}**",
                    f"- Condition: `{rec.condition}`",
                    f"- Expected reduction: **{rec.expected_reduction_count}** alerts ({rec.expected_reduction_ratio:.1%})",
                    f"- Reason: {rec.reason}",
                ]
            )
            if sim:
                lines.append(
                    f"- Simulation: hides **{sim.matched_alerts}**/{sim.total_alerts}; "
                    f"max hidden level **{sim.max_level_hidden}**; verdict **{sim.verdict}**"
                )
            if rec.proposed_wazuh_rule:
                lines.extend(["", "```xml", rec.proposed_wazuh_rule, "```"])
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"
