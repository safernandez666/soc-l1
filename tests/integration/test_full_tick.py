"""End-to-end: probe → threshold → dispatch → fake agent → finding → reporter."""
from datetime import datetime, timezone

from src.wazuh_health.agents.hygiene import invoke_hygiene_agent
from src.wazuh_health.agents.reporter import invoke_reporter_agent
from src.wazuh_health.agents.runner import FakeAgentRunner, set_runner
from src.wazuh_health.contracts import (
    CleanAlert, DomainFinding, WazuhHealthReport,
)
from src.wazuh_health.decision.cooldown import CooldownTable
from src.wazuh_health.decision.dispatcher import WakeDispatcher
from src.wazuh_health.decision.threshold import ThresholdEngine, ThresholdRule
from src.wazuh_health.probes.hygiene import HygieneProbe
from src.wazuh_health.store.audit_store import AuditStore
from src.wazuh_health.store.db import connect, migrate
from src.wazuh_health.store.findings_store import FindingsStore


class _FakeAlertSource:
    def __init__(self, alerts):
        self._alerts = alerts
    def iter_alerts(self, *, since_days=None):
        return iter(self._alerts)


def test_full_tick_creates_finding_and_report():
    now = datetime.now(tz=timezone.utc)
    alerts = [
        CleanAlert(
            timestamp="2026-06-11T10:00:00Z",
            rule_id="5710", rule_level=5,
            agent_name="vpn01", srcip="10.0.5.20",
        )
        for _ in range(60)
    ]
    canned_findings = [DomainFinding(
        domain="hygiene", severity="warning",
        title="Noisy 5710 from 10.0.5.20",
        body_md="Suppress conditionally; matches CleanSwarm recommendation.",
        evidence={"rule_id": "5710", "matched": 60},
        suggested_action="Review the rule",
    )]
    canned_report = WazuhHealthReport(
        generated_at=now, window_hours=6, summary="one open finding",
        by_domain={"hygiene": canned_findings, "capacity": [], "coverage": []},
        top_priorities=canned_findings,
    )
    set_runner(FakeAgentRunner({
        "HygieneAgent": canned_findings,
        "ReporterAgent": canned_report,
    }))

    conn = connect(":memory:"); migrate(conn)
    audit = AuditStore(conn)
    store = FindingsStore(conn)
    cooldown = CooldownTable(conn)

    # 1. Probe runs
    probe = HygieneProbe(source=_FakeAlertSource(alerts), min_count=10)
    result = probe.run()
    audit.record_probe_run(result)

    # 2. Threshold engine
    engine = ThresholdEngine(rules={"hygiene": [
        ThresholdRule(metric="noise.recommendations_count",
                      rule="value >= 1", severity="warning"),
    ]})
    hits = engine.evaluate(result)
    assert hits

    # 3. Dispatcher invokes the hygiene agent
    def _inv(hits, *, audit_store):
        invoke_hygiene_agent(
            hits=hits, audit_store=audit, findings_store=store,
            light_model="gpt-4o-mini", now=now,
        )

    dispatcher = WakeDispatcher(
        cooldown=cooldown, agent_runs=audit,
        invoke_by_domain={"hygiene": _inv}, daily_cap=50,
    )
    dispatcher.dispatch(hits, now=now)

    # 4. One open finding exists
    open_findings = store.list_open()
    assert len(open_findings) == 1
    assert open_findings[0].title.startswith("Noisy 5710")

    # 5. Reporter consolidates
    rep = invoke_reporter_agent(
        audit_store=audit, findings_store=store,
        heavy_model="gpt-4o", window_hours=6, now=now,
    )
    assert rep.summary == "one open finding"
