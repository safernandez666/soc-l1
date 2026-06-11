"""WazuhSource Protocol and DTOs.

All methods are read-only. Implementations must not expose any setter
or write call. This is enforced by `tests/test_boundaries.py`.
"""
from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from src.wazuh_health.contracts import CleanAlert


class FilesystemStat(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    total_bytes: int
    free_bytes: int
    free_pct: float


class DiskStats(BaseModel):
    model_config = ConfigDict(extra="forbid")
    filesystems: dict[str, FilesystemStat] = Field(default_factory=dict)
    alerts_json_size_bytes: int = 0


class AgentInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str
    name: str
    ip: str | None = None
    status: str = "unknown"
    last_keep_alive: datetime | None = None


class ManagerStats(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cpu_pct: float | None = None
    mem_pct: float | None = None
    decoder_errors: int = 0
    rule_hits_by_id: dict[str, int] = Field(default_factory=dict)


class IndexerStats(BaseModel):
    model_config = ConfigDict(extra="forbid")
    heap_pct: float | None = None
    red_shards: int = 0
    yellow_shards: int = 0
    pending_tasks: int = 0


@runtime_checkable
class WazuhSource(Protocol):
    """Read-only data source for Wazuh metrics."""

    def iter_alerts(
        self, *, since_days: int | None = None
    ) -> Iterable[CleanAlert]: ...

    def disk_stats(self) -> DiskStats: ...

    def list_agents(self) -> list[AgentInfo]: ...

    def manager_stats(self) -> ManagerStats: ...

    def indexer_stats(self) -> IndexerStats: ...
