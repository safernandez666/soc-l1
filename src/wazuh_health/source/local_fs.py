"""Local filesystem helpers for reading Wazuh alerts (NDJSON, gzip, rotated)."""
from __future__ import annotations

import gzip
import json
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from src.wazuh_health.contracts import CleanAlert


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


def _safe_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _extract_user(data: dict[str, Any]) -> str | None:
    win = _safe_dict(data.get("win"))
    eventdata = _safe_dict(win.get("eventdata"))
    aws_identity = _safe_dict(_safe_dict(data.get("aws")).get("userIdentity"))
    return _first_string(
        data.get("srcuser"),
        data.get("dstuser"),
        data.get("user") if isinstance(data.get("user"), str) else None,
        eventdata.get("targetUserName"),
        eventdata.get("subjectUserName"),
        aws_identity.get("userName"),
        _safe_dict(data.get("office365")).get("UserId"),
    )


def compact_alert(raw: dict[str, Any]) -> CleanAlert | None:
    rule = _safe_dict(raw.get("rule"))
    agent = _safe_dict(raw.get("agent"))
    data = _safe_dict(raw.get("data"))
    decoder = _safe_dict(raw.get("decoder"))

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


def _open_text(path: Path):
    if path.suffix == ".gz" or path.name.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open(encoding="utf-8", errors="replace")


def _iter_one_file(
    path: Path, *, cutoff: datetime | None
) -> Iterator[CleanAlert]:
    with _open_text(path) as f:
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
                # Drop alerts whose timestamp is unparseable when a cutoff is set.
                if ts is None or ts < cutoff:
                    continue
            yield alert


def iter_alerts(
    path: str | Path,
    *,
    days: int | None = None,
    rotated_glob: str | None = None,
) -> Iterable[CleanAlert]:
    cutoff = (
        datetime.now(tz=timezone.utc) - timedelta(days=days)
        if days is not None
        else None
    )
    main = Path(path)
    files: list[Path] = [main] if main.exists() else []
    if rotated_glob is not None:
        files += sorted(
            (p for p in Path(rotated_glob).parent.glob(Path(rotated_glob).name)),
            key=lambda p: p.name,
        )
        # Avoid double-yielding the main file if the glob also matches it.
        files = list({p.resolve(): p for p in files}.values())

    for fpath in files:
        yield from _iter_one_file(fpath, cutoff=cutoff)


def load_alerts(
    path: str | Path,
    *,
    days: int | None = None,
    limit: int | None = None,
    rotated_glob: str | None = None,
) -> list[CleanAlert]:
    out: list[CleanAlert] = []
    for alert in iter_alerts(path, days=days, rotated_glob=rotated_glob):
        out.append(alert)
        if limit is not None and len(out) >= limit:
            break
    return out


# --- LocalFSSource ------------------------------------------------------

import os
import re
from collections.abc import Iterable as _Iterable
from pathlib import Path as _Path

from src.wazuh_health.source.base import (
    AgentInfo,
    DiskStats,
    FilesystemStat,
    IndexerStats,
    ManagerStats,
)


_CLIENT_KEY_LINE = re.compile(
    r"^\s*(?P<id>\d+)\s+(?P<name>\S+)\s+(?P<ip>\S+)\s+\S+\s*$"
)


def _filesystem_stat(path: _Path) -> FilesystemStat:
    s = os.statvfs(path)
    total = s.f_frsize * s.f_blocks
    free = s.f_frsize * s.f_bavail
    pct = (free / total * 100.0) if total else 0.0
    return FilesystemStat(
        path=str(path),
        total_bytes=total,
        free_bytes=free,
        free_pct=round(pct, 2),
    )


class LocalFSSource:
    """Filesystem-backed WazuhSource.

    Reads from /var/ossec/* paths. Never writes.
    """

    def __init__(
        self,
        *,
        alerts_path: _Path,
        rotated_glob: str | None,
        ossec_conf: _Path,
        client_keys: _Path,
        var_ossec_path: _Path | None = None,
        indexer_path: _Path | None = None,
    ) -> None:
        self.alerts_path = _Path(alerts_path)
        self.rotated_glob = rotated_glob
        self.ossec_conf = _Path(ossec_conf)
        self.client_keys = _Path(client_keys)
        self.var_ossec_path = _Path(var_ossec_path or "/var/ossec")
        self.indexer_path = _Path(indexer_path or "/var/lib/wazuh-indexer")

    def iter_alerts(self, *, since_days: int | None = None) -> _Iterable[CleanAlert]:
        return iter_alerts(
            self.alerts_path,
            days=since_days,
            rotated_glob=self.rotated_glob,
        )

    def disk_stats(self) -> DiskStats:
        fs: dict[str, FilesystemStat] = {}
        if self.var_ossec_path.exists():
            fs["var_ossec"] = _filesystem_stat(self.var_ossec_path)
        if self.indexer_path.exists():
            fs["indexer"] = _filesystem_stat(self.indexer_path)
        size = self.alerts_path.stat().st_size if self.alerts_path.exists() else 0
        return DiskStats(filesystems=fs, alerts_json_size_bytes=size)

    def list_agents(self) -> list[AgentInfo]:
        if not self.client_keys.exists():
            return []
        out: list[AgentInfo] = []
        for line in self.client_keys.read_text(errors="replace").splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            m = _CLIENT_KEY_LINE.match(line)
            if not m:
                continue
            out.append(AgentInfo(
                agent_id=m.group("id"),
                name=m.group("name"),
                ip=m.group("ip") if m.group("ip") != "any" else None,
                status="unknown",
            ))
        return out

    def manager_stats(self) -> ManagerStats:
        # Local FS does not have manager stats readily available without parsing
        # ossec-control output. v1: return empty.
        return ManagerStats()

    def indexer_stats(self) -> IndexerStats:
        # Same as above — without the API we cannot get heap; return empty.
        return IndexerStats()
