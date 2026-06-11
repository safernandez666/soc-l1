from datetime import datetime, timezone

from src.wazuh_health.contracts import ProbeResult
from src.wazuh_health.store.audit_store import AuditStore
from src.wazuh_health.store.db import connect, migrate
from src.wazuh_health.tools.readonly import (
    CAPACITY_TOOL_NAMES, COVERAGE_TOOL_NAMES, HYGIENE_TOOL_NAMES,
    REPORTER_TOOL_NAMES,
)
from src.wazuh_health.tools.readonly.hygiene_tools import get_top_buckets


def _seed_hygiene(conn):
    audit = AuditStore(conn)
    audit.record_probe_run(ProbeResult(
        probe="hygiene",
        run_at=datetime.now(tz=timezone.utc),
        metrics={"noise.recommendations_count": 1},
        artifacts={"top_buckets": [
            {"key": "k", "dimensions": {"rule_id": "5710"}, "count": 100,
             "rule_id": "5710", "rule_level": 5, "rule_description": "x",
             "rule_groups": [], "first_seen": None, "last_seen": None,
             "affected_agents": [], "affected_srcips": [], "affected_users": [],
             "noise_score": 50.0, "noise_score_breakdown": {}},
        ]},
        errors=[],
    ))


def test_get_top_buckets_reads_latest_probe_run():
    conn = connect(":memory:"); migrate(conn)
    _seed_hygiene(conn)
    audit = AuditStore(conn)
    buckets = get_top_buckets(audit=audit, limit=5)
    assert len(buckets) == 1
    assert buckets[0]["rule_id"] == "5710"


def test_each_domain_tool_set_is_disjoint():
    domains = [HYGIENE_TOOL_NAMES, CAPACITY_TOOL_NAMES,
               COVERAGE_TOOL_NAMES, REPORTER_TOOL_NAMES]
    seen = set()
    for s in domains:
        assert seen.isdisjoint(s), f"overlap: {seen & s}"
        seen |= s
