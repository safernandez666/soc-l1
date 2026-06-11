from datetime import datetime, timedelta, timezone

from src.wazuh_health.decision.cooldown import CooldownTable
from src.wazuh_health.store.db import connect, migrate


def test_can_wake_when_no_history():
    conn = connect(":memory:"); migrate(conn)
    c = CooldownTable(conn, default_minutes=360)
    assert c.can_wake("capacity", "disk.free_pct", now=datetime.now(tz=timezone.utc))


def test_cooldown_blocks_within_window():
    conn = connect(":memory:"); migrate(conn)
    c = CooldownTable(conn, default_minutes=360)
    now = datetime.now(tz=timezone.utc)
    c.mark_woken("capacity", "disk.free_pct", at=now)
    assert not c.can_wake("capacity", "disk.free_pct", now=now + timedelta(minutes=10))


def test_per_metric_override_used():
    conn = connect(":memory:"); migrate(conn)
    c = CooldownTable(conn, default_minutes=360,
                      per_metric={"indexer.heap_pct": 60})
    now = datetime.now(tz=timezone.utc)
    c.mark_woken("capacity", "indexer.heap_pct", at=now)
    assert c.can_wake("capacity", "indexer.heap_pct", now=now + timedelta(minutes=61))
    assert not c.can_wake("capacity", "indexer.heap_pct", now=now + timedelta(minutes=10))
