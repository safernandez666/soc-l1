"""Noise aggregation for CleanSwarm."""
from __future__ import annotations

from collections import Counter, defaultdict

from src.cleanswarm.collector import parse_timestamp
from src.cleanswarm.models import CleanAlert, NoiseBucket


def _signature(alert: CleanAlert) -> tuple[str, dict[str, str]]:
    """Prefer specific, reversible dimensions for safe conditional tuning."""
    dims = {"rule_id": alert.rule_id}
    if alert.agent_name:
        dims["agent.name"] = alert.agent_name
    if alert.srcip:
        dims["srcip"] = alert.srcip
    elif alert.user:
        dims["user"] = alert.user
    return ("|".join(f"{k}={v}" for k, v in dims.items()), dims)


def _noise_score(count: int, level: int, unique_agents: int, unique_srcips: int, total: int) -> float:
    volume_score = min(count / max(total, 1), 1.0) * 70
    repetition_score = min(count / 100, 1.0) * 20
    severity_penalty = max(level - 5, 0) * 5
    spread_penalty = max(unique_agents - 1, 0) * 2 + max(unique_srcips - 1, 0)
    return round(max(volume_score + repetition_score - severity_penalty - spread_penalty, 0), 2)


def build_noise_buckets(alerts: list[CleanAlert], *, min_count: int = 10, top: int = 20) -> list[NoiseBucket]:
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
        first_seen = None
        last_seen = None
        timestamps = [parse_timestamp(a.timestamp) for a in items]
        valid_ts = [ts for ts in timestamps if ts is not None]
        if valid_ts:
            first_seen = min(valid_ts).isoformat()
            last_seen = max(valid_ts).isoformat()

        agent_counts = Counter(a.agent_name for a in items if a.agent_name)
        srcip_counts = Counter(a.srcip for a in items if a.srcip)
        user_counts = Counter(a.user for a in items if a.user)
        exemplar = items[0]
        buckets.append(
            NoiseBucket(
                key=key,
                dimensions=dimensions_by_key[key],
                count=len(items),
                rule_id=exemplar.rule_id,
                rule_level=exemplar.rule_level,
                rule_description=exemplar.rule_description,
                first_seen=first_seen,
                last_seen=last_seen,
                affected_agents=[k for k, _ in agent_counts.most_common(10)],
                affected_srcips=[k for k, _ in srcip_counts.most_common(10)],
                affected_users=[k for k, _ in user_counts.most_common(10)],
                noise_score=_noise_score(
                    len(items),
                    exemplar.rule_level,
                    len(agent_counts),
                    len(srcip_counts),
                    total,
                ),
            )
        )

    return sorted(buckets, key=lambda b: (b.noise_score, b.count), reverse=True)[:top]
