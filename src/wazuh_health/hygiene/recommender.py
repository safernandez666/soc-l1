"""Conservative tuning recommendations from noise buckets."""
from __future__ import annotations

import re

from src.wazuh_health.contracts import NoiseBucket, Recommendation
from src.wazuh_health.hygiene.xml_render import render_local_rule

SENSITIVE_RULE_GROUPS = frozenset(
    {
        "authentication_failures",
        "attacks",
        "attack",
        "intrusion_attempt",
        "web_attack",
        "malware",
        "virus",
        "rootkit",
        "audit_logon_invalid",
    }
)


def _safe_id(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", value).strip("-")[:80]


def _is_sensitive(bucket: NoiseBucket) -> bool:
    return any(g in SENSITIVE_RULE_GROUPS for g in bucket.rule_groups)


def recommend_from_buckets(
    buckets: list[NoiseBucket],
    *,
    total_alerts: int,
    max_recommendations: int = 10,
    first_local_rule_id: int = 110000,
) -> list[Recommendation]:
    recommendations: list[Recommendation] = []

    for idx, bucket in enumerate(buckets[:max_recommendations]):
        if not bucket.rule_id:
            continue
        condition = {k: v for k, v in bucket.dimensions.items() if k != "rule_id"}
        ratio = bucket.count / max(total_alerts, 1)

        if bucket.rule_level >= 10 or (_is_sensitive(bucket) and bucket.rule_level >= 4):
            rec_type = "investigate_source"
            risk = "high"
            reason = (
                "Severity or rule group is sensitive (auth/attack/malware-class). "
                "Do not silence; review source or replace with tighter correlation."
            )
        elif bucket.rule_level >= 7:
            rec_type = "tune_frequency"
            risk = "medium"
            reason = (
                "Mid-high severity. Prefer frequency/threshold tuning over suppression."
            )
        elif not condition:
            rec_type = "tune_frequency"
            risk = "medium"
            reason = (
                "Globally noisy rule with no specific dimensions. Tune threshold or "
                "split the rule before silencing."
            )
        else:
            rec_type = "suppress_conditionally"
            risk = "low" if bucket.rule_level <= 5 and ratio <= 0.3 else "medium"
            reason = (
                "Repeated low-severity pattern with specific dimensions. Candidate "
                "for reversible conditional suppression."
            )

        rec_id = f"cs-{_safe_id(bucket.key)}"
        proposed_rule: str | None = None
        if rec_type == "suppress_conditionally":
            try:
                proposed_rule = render_local_rule(
                    bucket,
                    local_rule_id=first_local_rule_id + idx,
                    bucket_hash=rec_id,
                    count=bucket.count,
                )
            except ValueError:
                proposed_rule = None

        recommendations.append(
            Recommendation(
                id=rec_id,
                type=rec_type,
                title=f"Reduce noise of rule {bucket.rule_id}: {bucket.rule_description[:80]}",
                rule_id=str(bucket.rule_id),
                condition=condition,
                reason=reason,
                risk=risk,
                expected_reduction_count=bucket.count,
                expected_reduction_ratio=round(ratio, 4),
                proposed_wazuh_rule=proposed_rule,
                rollback=(
                    "Not applied automatically. If approved and added to "
                    f"local_rules.xml, rollback = remove the CleanSwarm rule for {bucket.rule_id}."
                ),
            )
        )

    return recommendations
