"""High-level orchestration of the hygiene pipeline (used by CleanSwarm CLI)."""
from __future__ import annotations

from datetime import datetime, timezone

from src.wazuh_health.contracts import CleanSwarmReport
from src.wazuh_health.hygiene.analyzer import build_noise_buckets
from src.wazuh_health.hygiene.recommender import recommend_from_buckets
from src.wazuh_health.hygiene.simulator import (
    simulate_combined,
    simulate_recommendations,
)
from src.wazuh_health.source.local_fs import load_alerts


def analyze_file(
    alerts_path: str,
    *,
    days: int | None = 7,
    min_count: int = 10,
    top: int = 20,
    max_recommendations: int = 10,
    limit: int | None = None,
    rotated_glob: str | None = None,
    first_local_rule_id: int = 110000,
) -> CleanSwarmReport:
    alerts = load_alerts(
        alerts_path, days=days, limit=limit, rotated_glob=rotated_glob
    )
    buckets = build_noise_buckets(alerts, min_count=min_count, top=top)
    recs = recommend_from_buckets(
        buckets,
        total_alerts=len(alerts),
        max_recommendations=max_recommendations,
        first_local_rule_id=first_local_rule_id,
    )
    sims = simulate_recommendations(alerts, recs)
    combined = simulate_combined(alerts, sims) if sims else None

    return CleanSwarmReport(
        generated_at=datetime.now(tz=timezone.utc).isoformat(),
        source=alerts_path,
        total_alerts=len(alerts),
        analyzed_days=days,
        top_buckets=buckets,
        recommendations=recs,
        simulations=sims,
        combined_simulation=combined,
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
        for b in report.top_buckets:
            lines += [
                f"### {b.rule_id} — {b.rule_description}",
                f"- Count: **{b.count}** | Level: **{b.rule_level}** | Score: **{b.noise_score}**",
                f"- Breakdown: `{b.noise_score_breakdown}`",
                f"- Dimensions: `{b.dimensions}`",
                "",
            ]

    lines += ["", "## Recommendations", ""]
    sims = {s.recommendation_id: s for s in report.simulations}
    for rec in report.recommendations:
        sim = sims.get(rec.id)
        lines += [
            f"### {rec.id}: {rec.title}",
            f"- Type: `{rec.type}` | Risk: **{rec.risk}**",
            f"- Condition: `{rec.condition}`",
            f"- Expected reduction: **{rec.expected_reduction_count}** alerts ({rec.expected_reduction_ratio:.1%})",
            f"- Reason: {rec.reason}",
        ]
        if sim:
            lines.append(
                f"- Simulation: hides **{sim.matched_alerts}**/{sim.total_alerts}; "
                f"max hidden level **{sim.max_level_hidden}**; verdict **{sim.verdict}**"
            )
        if rec.proposed_wazuh_rule:
            lines += ["", "```xml", rec.proposed_wazuh_rule, "```"]
        lines.append("")

    if report.combined_simulation:
        c = report.combined_simulation
        lines += [
            "## Combined impact",
            "",
            f"- Union of hidden alerts: **{c.union_matched}** ({c.union_reduction_ratio:.1%})",
            f"- Overlap (covered by 2+ recs): **{c.overlap_alerts}**",
            f"- Max hidden level: **{c.max_level_hidden}**, high/critical hidden: **{c.high_or_critical_hidden}**",
            "",
        ]

    return "\n".join(lines).rstrip() + "\n"
