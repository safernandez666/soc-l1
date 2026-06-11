"""AuditStore — probe_runs + agent_runs persistence."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime

from src.wazuh_health.contracts import ProbeResult
from src.wazuh_health.contracts.probes import ProbeName


class AuditStore:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def record_probe_run(self, result: ProbeResult) -> int:
        cur = self._conn.execute(
            "INSERT INTO probe_runs(probe, run_at, metrics_json, artifacts_json, errors_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                result.probe, result.run_at.isoformat(),
                json.dumps(result.metrics, sort_keys=True, default=str),
                json.dumps(result.artifacts, sort_keys=True, default=str),
                json.dumps(result.errors),
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def latest_probe_run(self, probe: ProbeName) -> ProbeResult | None:
        row = self._conn.execute(
            "SELECT * FROM probe_runs WHERE probe = ? ORDER BY id DESC LIMIT 1",
            (probe,),
        ).fetchone()
        if row is None:
            return None
        return ProbeResult(
            probe=row["probe"],
            run_at=datetime.fromisoformat(row["run_at"]),
            metrics=json.loads(row["metrics_json"]),
            artifacts=json.loads(row["artifacts_json"]),
            errors=json.loads(row["errors_json"]),
        )

    def record_agent_run(
        self,
        *,
        agent: str,
        started_at: datetime,
        ended_at: datetime | None,
        status: str,
        input_tokens: int = 0,
        output_tokens: int = 0,
        tool_calls: list[dict] | None = None,
        output_hash: str | None = None,
        finding_ids: list[int] | None = None,
    ) -> int:
        cur = self._conn.execute(
            "INSERT INTO agent_runs(agent, started_at, ended_at, status, "
            "input_tokens, output_tokens, tool_calls_json, output_hash, finding_ids_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                agent, started_at.isoformat(),
                ended_at.isoformat() if ended_at else None,
                status, input_tokens, output_tokens,
                json.dumps(tool_calls or []),
                output_hash,
                json.dumps(finding_ids or []),
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def count_agent_runs_today(self, agent: str, *, now: datetime) -> int:
        day_start = now.date().isoformat()
        return int(self._conn.execute(
            "SELECT count(*) FROM agent_runs WHERE agent = ? AND started_at >= ?",
            (agent, day_start),
        ).fetchone()[0])
