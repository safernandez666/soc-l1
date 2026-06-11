"""Tests for the deterministic email digest."""
from datetime import datetime, timezone

from src.wazuh_health.contracts import ProbeResult
from src.wazuh_health.digest import build_email_digest
from src.wazuh_health.store.audit_store import AuditStore
from src.wazuh_health.store.db import connect, migrate


def _seed(audit: AuditStore):
    audit.record_probe_run(ProbeResult(
        probe="capacity", run_at=datetime.now(tz=timezone.utc),
        metrics={"disk.var_ossec.free_pct": 12.5,
                 "indexer.heap_pct": 78.3},
        artifacts={}, errors=[],
    ))
    audit.record_probe_run(ProbeResult(
        probe="hygiene", run_at=datetime.now(tz=timezone.utc),
        metrics={"noise.total_alerts": 1234,
                 "noise.bucket_count": 5,
                 "noise.recommendations_count": 3,
                 "noise.combined_reduction_pct": 18.5},
        artifacts={
            "top_buckets": [
                {"rule_id": "5710", "rule_description": "ssh fail",
                 "count": 200, "rule_level": 5, "noise_score": 65.4},
            ],
            "recommendations": [
                {"type": "suppress_conditionally", "risk": "low",
                 "rule_id": "5710", "title": "Reduce noise of rule 5710",
                 "reason": "Repeated low-severity pattern."},
            ],
        },
        errors=[],
    ))
    audit.record_probe_run(ProbeResult(
        probe="coverage", run_at=datetime.now(tz=timezone.utc),
        metrics={"agents.total": 10, "agents.active": 7,
                 "agents.disconnected": 3, "agents.never_connected": 0,
                 "decoders.errors": 0, "rules.zero_hit": 2},
        artifacts={}, errors=[],
    ))


def test_digest_subject_signals_problems():
    conn = connect(":memory:"); migrate(conn)
    audit = AuditStore(conn)
    _seed(audit)
    subject, body = build_email_digest(audit)
    # Has disk<15, recs>0, disconnected>0 — all three should appear in subject.
    assert "disk 12.5%" in subject
    assert "3 hygiene recs" in subject
    assert "3 agents disconnected" in subject


def test_digest_body_includes_three_sections():
    conn = connect(":memory:"); migrate(conn)
    audit = AuditStore(conn)
    _seed(audit)
    _, body = build_email_digest(audit)
    assert "## Capacity" in body
    assert "## Hygiene" in body
    assert "## Coverage" in body
    assert "5710" in body  # top bucket appears
    assert "Reduce noise" in body  # recommendation title


def test_digest_with_no_probe_runs_is_nominal():
    conn = connect(":memory:"); migrate(conn)
    audit = AuditStore(conn)
    subject, body = build_email_digest(audit)
    assert "nominal" in subject
    assert "no capacity probe results" in body
    assert "no hygiene probe results" in body
    assert "no coverage probe results" in body
