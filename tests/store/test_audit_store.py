from datetime import datetime, timezone

from src.wazuh_health.contracts import ProbeResult
from src.wazuh_health.store.audit_store import AuditStore
from src.wazuh_health.store.db import connect, migrate


def test_record_probe_run_then_latest_returns_it():
    conn = connect(":memory:"); migrate(conn)
    audit = AuditStore(conn)
    pr = ProbeResult(
        probe="capacity",
        run_at=datetime.now(tz=timezone.utc),
        metrics={"x": 1}, artifacts={"a": 1}, errors=[],
    )
    audit.record_probe_run(pr)
    latest = audit.latest_probe_run("capacity")
    assert latest is not None
    assert latest.metrics["x"] == 1


def test_record_agent_run_persists_token_counts():
    conn = connect(":memory:"); migrate(conn)
    audit = AuditStore(conn)
    audit.record_agent_run(
        agent="HygieneAgent",
        started_at=datetime.now(tz=timezone.utc),
        ended_at=datetime.now(tz=timezone.utc),
        status="ok", input_tokens=120, output_tokens=80,
        tool_calls=[{"name": "get_top_buckets", "args": {}}],
        output_hash="h", finding_ids=[1, 2],
    )
    row = conn.execute("SELECT input_tokens, output_tokens FROM agent_runs").fetchone()
    assert row[0] == 120 and row[1] == 80
