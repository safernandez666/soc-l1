from datetime import datetime, timezone

from src.wazuh_health.agents.reporter import invoke_reporter_agent
from src.wazuh_health.agents.runner import FakeAgentRunner, set_runner
from src.wazuh_health.contracts import DomainFinding, WazuhHealthReport
from src.wazuh_health.store.audit_store import AuditStore
from src.wazuh_health.store.db import connect, migrate
from src.wazuh_health.store.findings_store import FindingsStore


def test_reporter_returns_canned_report():
    canned = WazuhHealthReport(
        generated_at=datetime.now(tz=timezone.utc),
        window_hours=6, summary="ok",
        by_domain={"hygiene": [], "capacity": [], "coverage": []},
        top_priorities=[],
    )
    set_runner(FakeAgentRunner({"ReporterAgent": canned}))
    conn = connect(":memory:"); migrate(conn)
    audit = AuditStore(conn)
    store = FindingsStore(conn)
    rep = invoke_reporter_agent(
        audit_store=audit, findings_store=store,
        heavy_model="gpt-4o", window_hours=6, now=datetime.now(tz=timezone.utc),
    )
    assert rep.window_hours == 6
