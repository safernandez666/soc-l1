from datetime import datetime, timezone

from src.wazuh_health.contracts import ThresholdHit
from src.wazuh_health.decision.cooldown import CooldownTable
from src.wazuh_health.decision.dispatcher import WakeDispatcher
from src.wazuh_health.store.db import connect, migrate


class _Counting:
    def __init__(self):
        self.calls = 0
        self.hits_seen = []

    def __call__(self, hits, *, audit_store=None):
        self.calls += 1
        self.hits_seen.extend(hits)


def _hit(metric, severity="warning"):
    return ThresholdHit(
        probe="capacity", metric=metric, value=1,
        rule="value < 1", severity=severity,
    )


class _FakeAuditStore:
    def __init__(self):
        self._counts = {}
    def count_agent_runs_today(self, agent, *, now): return self._counts.get(agent, 0)
    def record_agent_run(self, **kw): self._counts[kw["agent"]] = self._counts.get(kw["agent"], 0) + 1


def _disp():
    conn = connect(":memory:"); migrate(conn)
    return WakeDispatcher(
        cooldown=CooldownTable(conn, default_minutes=360),
        agent_runs=_FakeAuditStore(),
        invoke_by_domain={"capacity": _Counting(), "hygiene": _Counting(),
                          "coverage": _Counting()},
        daily_cap=50,
    )


def test_dispatch_invokes_each_domain_once_per_dispatch():
    d = _disp()
    d.dispatch([_hit("disk.free_pct"), _hit("indexer.heap_pct")],
               now=datetime.now(tz=timezone.utc))
    cap = d._invokers["capacity"]
    assert cap.calls == 1
    assert len(cap.hits_seen) == 2


def test_dispatch_skips_metric_in_cooldown():
    d = _disp()
    now = datetime.now(tz=timezone.utc)
    d._cooldown.mark_woken("capacity", "disk.free_pct", at=now)
    d.dispatch([_hit("disk.free_pct")], now=now)
    assert d._invokers["capacity"].calls == 0


def test_dispatch_respects_daily_cap():
    d = _disp()
    d._daily_cap = 0  # already over cap
    d.dispatch([_hit("disk.free_pct")], now=datetime.now(tz=timezone.utc))
    assert d._invokers["capacity"].calls == 0
