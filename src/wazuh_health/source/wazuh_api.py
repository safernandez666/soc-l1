"""Wazuh API source (read-only except for the JWT login POST)."""
from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any

import httpx

from src.wazuh_health.contracts import CleanAlert
from src.wazuh_health.source.base import (
    AgentInfo, DiskStats, IndexerStats, ManagerStats,
)


class WazuhAPISource:
    """HTTP-based WazuhSource. Authenticates via JWT and uses GET-only afterwards."""

    def __init__(
        self,
        *,
        host: str,
        port: int = 55000,
        user: str,
        password: str,
        verify_ssl: bool = True,
        timeout_s: float = 10.0,
    ) -> None:
        self._base = f"https://{host}:{port}"
        self._user = user
        self._password = password
        self._verify = verify_ssl
        self._timeout = timeout_s
        self._token: str | None = None

    def _login(self) -> str:
        if self._token:
            return self._token
        # The only POST allowed in this package — boundary test whitelists this file.
        with httpx.Client(verify=self._verify, timeout=self._timeout) as c:
            r = c.post(
                f"{self._base}/security/user/authenticate",
                auth=(self._user, self._password),
            )
            r.raise_for_status()
            self._token = r.json()["data"]["token"]
        assert self._token is not None
        return self._token

    def _get(self, path: str) -> dict[str, Any]:
        token = self._login()
        with httpx.Client(
            verify=self._verify,
            timeout=self._timeout,
            headers={"Authorization": f"Bearer {token}"},
        ) as c:
            r = c.get(f"{self._base}{path}")
            r.raise_for_status()
            return r.json()

    def iter_alerts(self, *, since_days: int | None = None) -> Iterable[CleanAlert]:
        # API-based alert streaming is out of MVP scope. Probes that need
        # historical alerts must use LocalFSSource.
        return iter(())

    def disk_stats(self) -> DiskStats:
        # The Manager API exposes /manager/info with disk usage on some versions;
        # left empty in v1.
        return DiskStats()

    def list_agents(self) -> list[AgentInfo]:
        payload = self._get("/agents")
        items = payload.get("data", {}).get("affected_items", [])
        out: list[AgentInfo] = []
        for item in items:
            lka = item.get("last_keep_alive")
            try:
                ts = datetime.fromisoformat(lka.replace("Z", "+00:00")) if lka else None
            except Exception:
                ts = None
            out.append(AgentInfo(
                agent_id=str(item.get("id", "")),
                name=item.get("name", ""),
                ip=item.get("ip"),
                status=item.get("status", "unknown"),
                last_keep_alive=ts,
            ))
        return out

    def manager_stats(self) -> ManagerStats:
        # /manager/stats varies per version; v1 returns empty.
        return ManagerStats()

    def indexer_stats(self) -> IndexerStats:
        payload = self._get("/cluster/health")
        d = payload.get("data", {}) or {}
        return IndexerStats(
            heap_pct=d.get("heap_pct"),
            red_shards=int(d.get("red_shards", 0)),
            yellow_shards=int(d.get("yellow_shards", 0)),
            pending_tasks=int(d.get("pending_tasks", 0)),
        )
