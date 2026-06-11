"""Noise aggregation with calibrated scoring + breakdown."""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from src.wazuh_health.contracts import CleanAlert, NoiseBucket


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _signature(alert: CleanAlert) -> tuple[str, dict[str, str]]:
    dims = {"rule_id": alert.rule_id}
    if alert.agent_name:
        dims["agent.name"] = alert.agent_name
    if alert.srcip:
        dims["srcip"] = alert.srcip
    return ("|".join(f"{k}={v}" for k, v in dims.items()), dims)


def _noise_score_components(
    *, count: int, level: int, unique_agents: int,
    unique_srcips: int, unique_users: int, total: int,
) -> dict[str, float]:
    safe_total = max(total, 1)
    volume = min(count / safe_total, 1.0) * 70.0
    repetition = min(math.log10(max(count, 1)) / math.log10(max(safe_total, 10)) * 20.0, 20.0)
    severity_penalty = max(level - 5, 0) * 5.0
    spread_penalty = (
        max(unique_agents - 1, 0) * 2.0
        + max(unique_srcips - 1, 0)
        + max(unique_users - 1, 0)
    )
    return {
        "volume": round(volume, 2),
        "repetition": round(repetition, 2),
        "severity_penalty": round(severity_penalty, 2),
        "spread_penalty": round(spread_penalty, 2),
    }


def build_noise_buckets(
    alerts: list[CleanAlert], *, min_count: int = 10, top: int = 20
) -> list[NoiseBucket]:
    grouped: dict[str, list[CleanAlert]] = defaultdict(list)
    dimensions_by_key: dict[str, dict[str, str]] = {}

    for alert in alerts:
        key, dims = _signature(alert)
        grouped[key].append(alert)
        dimensions_by_key[key] = dims

    buckets: list[NoiseBucket] = []
    total = len(alerts)
    for key, items in grouped.items():
        if len(items) < min_count:
            continue
        timestamps = [parse_timestamp(a.timestamp) for a in items]
        valid_ts = [ts for ts in timestamps if ts is not None]
        first_seen = min(valid_ts).isoformat() if valid_ts else None
        last_seen = max(valid_ts).isoformat() if valid_ts else None

        agent_counts = Counter(a.agent_name for a in items if a.agent_name)
        srcip_counts = Counter(a.srcip for a in items if a.srcip)
        user_counts = Counter(a.user for a in items if a.user)
        exemplar = items[0]
        breakdown = _noise_score_components(
            count=len(items),
            level=exemplar.rule_level,
            unique_agents=len(agent_counts),
            unique_srcips=len(srcip_counts),
            unique_users=len(user_counts),
            total=total,
        )
        score = round(
            max(
                breakdown["volume"]
                + breakdown["repetition"]
                - breakdown["severity_penalty"]
                - breakdown["spread_penalty"],
                0.0,
            ),
            2,
        )
        buckets.append(
            NoiseBucket(
                key=key,
                dimensions=dimensions_by_key[key],
                count=len(items),
                rule_id=exemplar.rule_id,
                rule_level=exemplar.rule_level,
                rule_description=exemplar.rule_description,
                rule_groups=list(exemplar.rule_groups),
                first_seen=first_seen,
                last_seen=last_seen,
                affected_agents=[k for k, _ in agent_counts.most_common(10)],
                affected_srcips=[k for k, _ in srcip_counts.most_common(10)],
                affected_users=[k for k, _ in user_counts.most_common(10)],
                noise_score=score,
                noise_score_breakdown=breakdown,
            )
        )

    return sorted(buckets, key=lambda b: (b.noise_score, b.count), reverse=True)[:top]
