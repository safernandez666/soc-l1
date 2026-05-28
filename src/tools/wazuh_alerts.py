"""Tail-based reader for /var/ossec/logs/alerts/alerts.json.

Wazuh writes alerts as NDJSON (one JSON per line) to this file. To detect
correlation (same hash on multiple hosts, same user across multiple alerts)
we scan the tail of the file backwards in time until we fall out of the
configured window.

This avoids the indexer entirely - no new credentials, no network call.
Trade-off: only sees the current alerts.json (typically <=24h, depending on
log rotation). For longer windows, query the indexer.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from src.models import WazuhRecentAlert

logger = logging.getLogger("soc-l1")

ALERTS_PATH = "/var/ossec/logs/alerts/alerts.json"
_READ_CHUNK = 64 * 1024
_DEFAULT_MAX_SCAN_LINES = 20_000


def _reverse_line_reader(path: Path, max_lines: int) -> Iterator[bytes]:
    """Yield lines from `path` in reverse order. Bounded by `max_lines`."""
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        pos = f.tell()
        buffer = b""
        yielded = 0
        while pos > 0 and yielded < max_lines:
            chunk_size = min(_READ_CHUNK, pos)
            pos -= chunk_size
            f.seek(pos)
            chunk = f.read(chunk_size) + buffer
            lines = chunk.split(b"\n")
            # First piece is partial - belongs to previous chunk read
            buffer = lines[0]
            for line in reversed(lines[1:]):
                if line.strip():
                    yield line
                    yielded += 1
                    if yielded >= max_lines:
                        return
        if pos == 0 and buffer.strip() and yielded < max_lines:
            yield buffer


def _parse_timestamp(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _alert_matches(
    alert: dict[str, Any],
    sha256: str | None,
    host: str | None,
    user: str | None,
    rule_id: str | None,
) -> bool:
    """OR-match: returns True if any provided filter matches."""
    if rule_id and str((alert.get("rule") or {}).get("id")) == rule_id:
        return True

    data = alert.get("data") or {}
    agent = alert.get("agent") or {}
    evidence = data.get("evidence") or []

    if host:
        h = host.lower()
        if (agent.get("name") or "").lower() == h:
            return True
        for ev in evidence:
            if (ev.get("hostName") or "").lower() == h:
                return True
            if (ev.get("deviceDnsName") or "").lower() == h:
                return True

    if user:
        u = user.lower()
        if (data.get("srcuser") or "").lower() == u:
            return True
        for ev in evidence:
            for logged in (ev.get("loggedOnUsers") or []):
                if (logged.get("accountName") or "").lower() == u:
                    return True

    if sha256:
        s = sha256.lower()
        for ev in evidence:
            fd = ev.get("fileDetails") or {}
            if (fd.get("sha256") or "").lower() == s:
                return True

    return False


def _extract_summary(alert: dict[str, Any]) -> WazuhRecentAlert | None:
    """Compact a raw alert into the model. Returns None if shape is broken."""
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    data = alert.get("data") or {}
    evidence = data.get("evidence") or []

    host = agent.get("name")
    user_sam: str | None = None
    sha256_hash: str | None = None

    for ev in evidence:
        if not user_sam:
            for u in (ev.get("loggedOnUsers") or []):
                if u.get("accountName"):
                    user_sam = u["accountName"]
                    break
        if not host:
            host = ev.get("hostName") or ev.get("deviceDnsName")
        if not sha256_hash:
            fd = ev.get("fileDetails") or {}
            if fd.get("sha256"):
                sha256_hash = fd["sha256"]

    if not user_sam:
        user_sam = data.get("srcuser")

    try:
        return WazuhRecentAlert(
            timestamp=str(alert.get("timestamp") or ""),
            rule_id=str(rule.get("id") or ""),
            level=int(rule.get("level") or 0),
            description=str(rule.get("description") or "")[:200],
            agent_name=agent.get("name"),
            agent_id=str(agent.get("id")) if agent.get("id") is not None else None,
            host=host,
            user=user_sam,
            sha256=sha256_hash,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("alerts: skipping malformed alert: %s", e)
        return None


def query_recent_alerts(
    *,
    sha256: str | None = None,
    host: str | None = None,
    user: str | None = None,
    rule_id: str | None = None,
    minutes: int = 30,
    limit: int = 50,
    alerts_path: str = ALERTS_PATH,
    max_scan_lines: int = _DEFAULT_MAX_SCAN_LINES,
) -> list[WazuhRecentAlert]:
    """Tail alerts.json for matches within `minutes` window. OR-match across filters.

    Requires at least one filter. Returns newest-first, capped at `limit`.
    """
    if not any((sha256, host, user, rule_id)):
        raise ValueError("at least one filter (sha256/host/user/rule_id) is required")

    path = Path(alerts_path)
    if not path.exists():
        logger.warning("alerts: %s not found, returning empty", alerts_path)
        return []

    cutoff = datetime.now(tz=timezone.utc) - timedelta(minutes=minutes)
    matches: list[WazuhRecentAlert] = []
    scanned = 0

    for line in _reverse_line_reader(path, max_lines=max_scan_lines):
        scanned += 1
        try:
            alert = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            # alerts.json may contain windows event content in latin-1 - skip undecodable
            continue

        ts = _parse_timestamp(alert.get("timestamp") or "")
        if ts is not None and ts < cutoff:
            # alerts.json is chronological; older lines won't match the window either
            break

        if not _alert_matches(alert, sha256, host, user, rule_id):
            continue

        summary = _extract_summary(alert)
        if summary is not None:
            matches.append(summary)
            if len(matches) >= limit:
                break

    logger.debug(
        "alerts: scanned=%d matched=%d (sha256=%s host=%s user=%s rule=%s window=%dm)",
        scanned, len(matches), sha256, host, user, rule_id, minutes,
    )
    return matches
