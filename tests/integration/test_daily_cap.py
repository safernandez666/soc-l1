from datetime import datetime, timezone

from src.wazuh_health.contracts import ThresholdHit
from src.wazuh_health.decision.cooldown import CooldownTable
from src.wazuh_health.decision.dispatcher import WakeDispatcher
from src.wazuh_health.store.audit_store import AuditStore
from src.wazuh_health.store.db import connect, migrate


def test_dispatcher_stops_invoking_after_daily_cap():
    conn = connect(":memory:"); migrate(conn)
    audit = AuditStore(conn)
    calls = {"n": 0}

    def _inv(hits, *, audit_store):
        calls["n"] += 1
        audit_store.record_agent_run(
            agent="HygieneAgent",
            started_at=datetime.now(tz=timezone.utc),
            ended_at=datetime.now(tz=timezone.utc),
            status="ok",
        )

    dispatcher = WakeDispatcher(
        cooldown=CooldownTable(conn, default_minutes=0),  # no cooldown
        agent_runs=audit,
        invoke_by_domain={"hygiene": _inv},
        daily_cap=3,
    )
    now = datetime.now(tz=timezone.utc)
    for i in range(5):
        dispatcher.dispatch([ThresholdHit(
            probe="hygiene", metric=f"m{i}", value=1,
            rule="value >= 1", severity="warning",
        )], now=now)

    assert calls["n"] == 3
