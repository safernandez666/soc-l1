import sqlite3

from src.wazuh_health.store.db import connect, migrate


def test_migrate_creates_all_tables():
    conn = connect(":memory:")
    migrate(conn)
    tables = {
        r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    assert {"probe_runs", "findings", "notifications", "agent_runs", "cooldowns",
            "schema_version"} <= tables


def test_migrate_is_idempotent():
    conn = connect(":memory:")
    migrate(conn)
    migrate(conn)  # second call must not raise
    v = conn.execute("SELECT max(version) FROM schema_version").fetchone()[0]
    assert v == 1
