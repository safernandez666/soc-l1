"""Read Wazuh alerts from NDJSON files.

The collector intentionally avoids Wazuh writes and avoids the indexer/API for the MVP.
It can run against /var/ossec/logs/alerts/alerts.json, rotated samples, or exported NDJSON.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from src.cleanswarm.models import CleanAlert


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


def _first_string(*values: Any) -> str | None:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _extract_user(data: dict[str, Any]) -> str | None:
    return _first_string(
        data.get("srcuser"),
        data.get("dstuser"),
        data.get("user"),
        data.get("win", {}).get("eventdata", {}).get("targetUserName"),
        data.get("win", {}).get("eventdata", {}).get("subjectUserName"),
    )


def compact_alert(raw: dict[str, Any]) -> CleanAlert | None:
    """Convert a raw Wazuh alert into CleanSwarm's compact shape."""
    rule = raw.get("rule") or {}
    agent = raw.get("agent") or {}
    data = raw.get("data") or {}
    decoder = raw.get("decoder") or {}

    rule_id = str(rule.get("id") or "").strip()
    if not rule_id:
        return None

    try:
        level = int(rule.get("level") or 0)
    except (TypeError, ValueError):
        level = 0

    return CleanAlert(
        timestamp=str(raw.get("timestamp") or ""),
        rule_id=rule_id,
        rule_level=level,
        rule_description=str(rule.get("description") or "Unknown")[:300],
        rule_groups=[str(g) for g in (rule.get("groups") or []) if str(g).strip()],
        agent_id=str(agent.get("id")) if agent.get("id") is not None else None,
        agent_name=_first_string(agent.get("name")),
        srcip=_first_string(data.get("srcip"), data.get("src_ip"), data.get("sourceIp")),
        dstip=_first_string(data.get("dstip"), data.get("dst_ip"), data.get("destinationIp")),
        user=_extract_user(data),
        decoder_name=_first_string(decoder.get("name")),
        raw=raw,
    )


def iter_alerts(path: str | Path, *, days: int | None = None) -> Iterable[CleanAlert]:
    """Yield compact alerts from a Wazuh NDJSON file.

    Invalid JSON lines and malformed alerts are skipped. When `days` is provided,
    alerts older than now-days are ignored.
    """
    cutoff: datetime | None = None
    if days is not None:
        cutoff = datetime.now(tz=timezone.utc) - timedelta(days=days)

    with Path(path).open(encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            alert = compact_alert(raw)
            if alert is None:
                continue
            if cutoff is not None:
                ts = parse_timestamp(alert.timestamp)
                if ts is not None and ts < cutoff:
                    continue
            yield alert


def load_alerts(path: str | Path, *, days: int | None = None, limit: int | None = None) -> list[CleanAlert]:
    alerts: list[CleanAlert] = []
    for alert in iter_alerts(path, days=days):
        alerts.append(alert)
        if limit is not None and len(alerts) >= limit:
            break
    return alerts
