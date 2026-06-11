"""Captures the input_payload sent to the agent runner and asserts no raw IPs."""
import re
from datetime import datetime, timezone

from src.wazuh_health.agents.hygiene import invoke_hygiene_agent
from src.wazuh_health.agents.runner import AgentInvocation, set_runner
from src.wazuh_health.contracts import (
    CleanAlert, DomainFinding, ThresholdHit,
)
from src.wazuh_health.probes.hygiene import HygieneProbe
from src.wazuh_health.pseudonymize import Pseudonymizer
from src.wazuh_health.store.audit_store import AuditStore
from src.wazuh_health.store.db import connect, migrate
from src.wazuh_health.store.findings_store import FindingsStore


_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


class _CapturingRunner:
    def __init__(self):
        self.captured: AgentInvocation | None = None

    def run(self, invocation):
        self.captured = invocation
        return [], {"input": 0, "output": 0}


def test_pseudonymized_buckets_contain_no_raw_ips():
    p = Pseudonymizer(salt="s")
    masked_buckets = [
        p.mask({"rule_id": "5710", "srcip": "10.0.5.20", "agent.name": "vpn01"},
               fields=["srcip", "agent.name"])
    ]
    runner = _CapturingRunner()
    set_runner(runner)
    conn = connect(":memory:"); migrate(conn)
    audit = AuditStore(conn); store = FindingsStore(conn)

    from src.wazuh_health.contracts import ProbeResult
    audit.record_probe_run(ProbeResult(
        probe="hygiene",
        run_at=datetime.now(tz=timezone.utc),
        metrics={"noise.recommendations_count": 1},
        artifacts={"top_buckets": masked_buckets, "recommendations": [], "simulations": []},
        errors=[],
    ))

    invoke_hygiene_agent(
        hits=[ThresholdHit(probe="hygiene", metric="m", value=1,
                            rule="value >= 1", severity="warning")],
        audit_store=audit, findings_store=store,
        light_model="gpt-4o-mini", now=datetime.now(tz=timezone.utc),
    )
    payload_str = str(runner.captured.input_payload)
    assert not _IP_RE.search(payload_str), f"raw IP leaked: {payload_str}"
