"""Deterministic email digest of probe results (no LLM, plain template).

Used by `wazuh-health once --email` so the operator gets a quick read of the
last hygiene/capacity/coverage run without spending OpenAI tokens.
"""
from __future__ import annotations

from datetime import datetime, timezone

from src.wazuh_health.contracts import ProbeResult
from src.wazuh_health.store.audit_store import AuditStore


def _format_metrics(metrics: dict[str, float | int]) -> list[str]:
    if not metrics:
        return ["- (no metrics)"]
    return [f"- `{k}`: **{v}**" for k, v in sorted(metrics.items())]


def _format_top_buckets(buckets: list[dict]) -> list[str]:
    if not buckets:
        return ["_(no noisy buckets above threshold)_"]
    lines = []
    for b in buckets[:5]:
        lines.append(
            f"- **{b.get('rule_id')}** ({b.get('rule_description', '')[:60]}) — "
            f"count: {b.get('count')}, level: {b.get('rule_level')}, "
            f"score: {b.get('noise_score')}"
        )
    return lines


def _format_recommendations(recs: list[dict]) -> list[str]:
    if not recs:
        return ["_(no recommendations)_"]
    lines = []
    for r in recs[:10]:
        lines.append(
            f"- `{r.get('type')}` [{r.get('risk')}] — **rule {r.get('rule_id')}**: "
            f"{r.get('title', '')[:80]}"
        )
        if reason := r.get("reason"):
            lines.append(f"  - {reason}")
    return lines


def build_email_digest(audit: AuditStore) -> tuple[str, str]:
    """Compose (subject, markdown_body) from the latest probe runs.

    Reads the most recent run of each probe (capacity, hygiene, coverage) and
    summarises metrics + hygiene recommendations. Returns plain Markdown.
    """
    now_iso = datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
    capacity: ProbeResult | None = audit.latest_probe_run("capacity")
    hygiene: ProbeResult | None = audit.latest_probe_run("hygiene")
    coverage: ProbeResult | None = audit.latest_probe_run("coverage")

    bucket_count = 0
    rec_count = 0
    if hygiene:
        bucket_count = int(hygiene.metrics.get("noise.bucket_count", 0))
        rec_count = int(hygiene.metrics.get("noise.recommendations_count", 0))
    disk_free_pct = None
    if capacity:
        disk_free_pct = capacity.metrics.get("disk.var_ossec.free_pct")
    disconnected_agents = None
    if coverage:
        disconnected_agents = int(coverage.metrics.get("agents.disconnected", 0))

    subject_bits = []
    if disk_free_pct is not None and disk_free_pct < 15:
        subject_bits.append(f"⚠ disk {disk_free_pct}%")
    if rec_count:
        subject_bits.append(f"{rec_count} hygiene recs")
    if disconnected_agents:
        subject_bits.append(f"{disconnected_agents} agents disconnected")
    if not subject_bits:
        subject_bits.append("nominal")
    subject = "Wazuh Health digest — " + ", ".join(subject_bits)

    lines: list[str] = [
        "# Wazuh Health digest",
        "",
        f"_Generated at {now_iso}_",
        "",
        "## Capacity",
        "",
    ]
    if capacity:
        lines += _format_metrics(capacity.metrics)
        if capacity.errors:
            lines += ["", "**Probe errors:**", *[f"- `{e}`" for e in capacity.errors]]
    else:
        lines.append("_(no capacity probe results)_")

    lines += ["", "## Hygiene", ""]
    if hygiene:
        lines += [f"- Total alerts analysed: **{hygiene.metrics.get('noise.total_alerts', 0)}**"]
        lines += [f"- Bucket count: **{bucket_count}** | recommendations: **{rec_count}**"]
        lines += [
            "- Combined reduction (if applied): "
            f"**{hygiene.metrics.get('noise.combined_reduction_pct', 0)}%**"
        ]
        lines += ["", "### Top noisy buckets", ""]
        lines += _format_top_buckets(hygiene.artifacts.get("top_buckets", []))
        lines += ["", "### Conservative recommendations", ""]
        lines += _format_recommendations(hygiene.artifacts.get("recommendations", []))
    else:
        lines.append("_(no hygiene probe results)_")

    lines += ["", "## Coverage", ""]
    if coverage:
        lines += _format_metrics(coverage.metrics)
        if coverage.errors:
            lines += ["", "**Probe errors:**", *[f"- `{e}`" for e in coverage.errors]]
    else:
        lines.append("_(no coverage probe results)_")

    lines += [
        "",
        "---",
        "",
        "This digest is template-generated (no LLM). For the narrated report run "
        "`wazuh-health report` (uses the heavy model).",
        "",
    ]

    return subject, "\n".join(lines)
