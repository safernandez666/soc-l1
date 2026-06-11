"""Per-metric cooldown table stored in SQLite."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta


class CooldownTable:
    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        default_minutes: int = 360,
        per_metric: dict[str, int] | None = None,
    ) -> None:
        self._conn = conn
        self._default = default_minutes
        self._per_metric = per_metric or {}

    def _window(self, metric: str) -> timedelta:
        return timedelta(minutes=self._per_metric.get(metric, self._default))

    def can_wake(self, probe: str, metric: str, *, now: datetime) -> bool:
        row = self._conn.execute(
            "SELECT last_woken_at FROM cooldowns WHERE probe = ? AND metric = ?",
            (probe, metric),
        ).fetchone()
        if row is None:
            return True
        last = datetime.fromisoformat(row["last_woken_at"])
        return now - last >= self._window(metric)

    def mark_woken(self, probe: str, metric: str, *, at: datetime) -> None:
        self._conn.execute(
            "INSERT INTO cooldowns(probe, metric, last_woken_at) VALUES (?, ?, ?) "
            "ON CONFLICT(probe, metric) DO UPDATE SET last_woken_at=excluded.last_woken_at",
            (probe, metric, at.isoformat()),
        )
        self._conn.commit()
