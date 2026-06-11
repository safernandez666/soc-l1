from src.wazuh_health.contracts import DomainFinding
from src.wazuh_health.store.db import connect, migrate
from src.wazuh_health.store.findings_store import FindingsStore, compute_hash_key


def _finding(title="t", domain="hygiene", severity="warning",
             evidence=None, suggested_action="a"):
    return DomainFinding(
        domain=domain, severity=severity, title=title, body_md="b",
        evidence=evidence or {"rule_id": "5710"},
        suggested_action=suggested_action,
    )


def test_hash_key_is_deterministic_and_order_independent():
    h1 = compute_hash_key("hygiene", "rule_id", {"rule_id": "5710", "agent": "x"})
    h2 = compute_hash_key("hygiene", "rule_id", {"agent": "x", "rule_id": "5710"})
    assert h1 == h2


def test_insert_then_same_hash_updates_last_seen_only():
    conn = connect(":memory:"); migrate(conn)
    store = FindingsStore(conn)
    f = _finding()
    fid1 = store.upsert(f, hash_key="abc")
    fid2 = store.upsert(f, hash_key="abc")
    assert fid1 == fid2
    rows = conn.execute("SELECT count(*) FROM findings").fetchone()
    assert rows[0] == 1


def test_query_open_findings_returns_only_open():
    conn = connect(":memory:"); migrate(conn)
    store = FindingsStore(conn)
    store.upsert(_finding(title="a"), hash_key="h1")
    fid = store.upsert(_finding(title="b"), hash_key="h2")
    store.mark_resolved(fid)
    titles = [f.title for f in store.list_open()]
    assert titles == ["a"]
