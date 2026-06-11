from datetime import datetime, timezone

from src.wazuh_health.contracts import DomainFinding, ThresholdHit
from src.wazuh_health.agents.hygiene import invoke_hygiene_agent
from src.wazuh_health.agents.runner import FakeAgentRunner, set_runner
from src.wazuh_health.store.audit_store import AuditStore
from src.wazuh_health.store.db import connect, migrate
from src.wazuh_health.store.findings_store import FindingsStore


def test_invoke_hygiene_writes_findings_through_sanitizer():
    canned = [DomainFinding(
        domain="hygiene", severity="warning",
        title="t", body_md="b", evidence={"rule_id": "5710"},
        suggested_action="Review the rule",
    )]
    set_runner(FakeAgentRunner({"HygieneAgent": canned}))
    conn = connect(":memory:"); migrate(conn)
    audit = AuditStore(conn)
    store = FindingsStore(conn)

    invoke_hygiene_agent(
        hits=[ThresholdHit(probe="hygiene", metric="noise.bucket_count",
                            value=1, rule="value >= 1", severity="warning")],
        audit_store=audit, findings_store=store,
        light_model="gpt-4o-mini", now=datetime.now(tz=timezone.utc),
    )
    assert len(store.list_open()) == 1


def test_rejected_finding_is_not_persisted():
    canned = [DomainFinding(
        domain="hygiene", severity="warning",
        title="t", body_md="b", evidence={"rule_id": "5710"},
        suggested_action="rm -rf /",  # blocked by sanitizer
    )]
    set_runner(FakeAgentRunner({"HygieneAgent": canned}))
    conn = connect(":memory:"); migrate(conn)
    audit = AuditStore(conn)
    store = FindingsStore(conn)

    invoke_hygiene_agent(
        hits=[ThresholdHit(probe="hygiene", metric="noise.bucket_count",
                            value=1, rule="value >= 1", severity="warning")],
        audit_store=audit, findings_store=store,
        light_model="gpt-4o-mini", now=datetime.now(tz=timezone.utc),
    )
    assert store.list_open() == []
