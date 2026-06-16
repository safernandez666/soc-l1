"""Tests de state.py - SQLite pending approvals."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
import pytest_asyncio

from src.state import (
    create_pending_approval,
    decide_approval,
    get_pending_approval,
    init_db,
    mark_executed,
)


@pytest_asyncio.fixture
async def db(tmp_path: Path) -> str:
    path = str(tmp_path / "test.db")
    await init_db(path)
    return path


@pytest.mark.asyncio
async def test_init_db_creates_table(tmp_path: Path) -> None:
    path = str(tmp_path / "init.db")
    await init_db(path)
    with sqlite3.connect(path) as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    table_names = {r[0] for r in rows}
    assert "pending_approvals" in table_names


@pytest.mark.asyncio
async def test_init_db_is_idempotent(tmp_path: Path) -> None:
    """Llamar init_db dos veces no rompe ni borra datos."""
    path = str(tmp_path / "idemp.db")
    await init_db(path)
    token = await create_pending_approval(path, "a1", '{"plan":1}', '{"alert":1}')
    await init_db(path)
    row = await get_pending_approval(path, token)
    assert row is not None


@pytest.mark.asyncio
async def test_create_and_get(db: str) -> None:
    token = await create_pending_approval(db, "alert-123", '{"x":1}', '{"y":2}')
    assert len(token) > 30  # secrets.token_urlsafe(32) → ~43 chars
    row = await get_pending_approval(db, token)
    assert row is not None
    assert row["alert_id"] == "alert-123"
    assert row["status"] == "pending"
    assert row["plan_json"] == '{"x":1}'
    assert row["alert_json"] == '{"y":2}'


@pytest.mark.asyncio
async def test_get_unknown_token_returns_none(db: str) -> None:
    assert await get_pending_approval(db, "garbage-token") is None


@pytest.mark.asyncio
async def test_tokens_are_unique(db: str) -> None:
    """Sanity: 100 tokens consecutivos no colisionan."""
    tokens = set()
    for i in range(100):
        t = await create_pending_approval(db, f"id-{i}", "{}", "{}")
        tokens.add(t)
    assert len(tokens) == 100


@pytest.mark.asyncio
async def test_decide_approve_happy_path(db: str) -> None:
    token = await create_pending_approval(db, "a", "{}", "{}")
    status, row = await decide_approval(db, token, "approved", ip="10.0.0.1", user_agent="UA")
    assert status == "ok"
    assert row is not None
    assert row["status"] == "approved"
    assert row["decided_by_ip"] == "10.0.0.1"
    assert row["decided_by_ua"] == "UA"
    assert row["decided_at"] is not None


@pytest.mark.asyncio
async def test_decide_reject_happy_path(db: str) -> None:
    token = await create_pending_approval(db, "a", "{}", "{}")
    status, row = await decide_approval(db, token, "rejected")
    assert status == "ok"
    assert row["status"] == "rejected"


@pytest.mark.asyncio
async def test_decide_unknown_token(db: str) -> None:
    status, row = await decide_approval(db, "garbage", "approved")
    assert status == "not_found"
    assert row is None


@pytest.mark.asyncio
async def test_decide_twice_is_idempotent(db: str) -> None:
    """Segunda decisión sobre el mismo token → already_decided, no sobrescribe."""
    token = await create_pending_approval(db, "a", "{}", "{}")
    await decide_approval(db, token, "approved")
    status, row = await decide_approval(db, token, "rejected")
    assert status == "already_decided"
    assert row["status"] == "approved"  # quedó la primera


@pytest.mark.asyncio
async def test_decide_expired_is_marked_in_db(tmp_path: Path) -> None:
    """Si el token excedió TTL, se marca 'expired' en DB y no se puede aprobar."""
    db = str(tmp_path / "exp.db")
    await init_db(db)
    token = await create_pending_approval(db, "a", "{}", "{}")

    # Forzamos created_at viejo
    with sqlite3.connect(db) as conn:
        conn.execute(
            "UPDATE pending_approvals SET created_at='2020-01-01T00:00:00+00:00' "
            "WHERE token=?",
            (token,),
        )
        conn.commit()

    status, row = await decide_approval(db, token, "approved", ttl_hours=24)
    assert status == "expired"
    assert row["status"] == "expired"

    # Re-intentar: ya no está pending → already_decided
    status2, _ = await decide_approval(db, token, "approved", ttl_hours=24)
    assert status2 == "already_decided"


@pytest.mark.asyncio
async def test_decide_rejects_invalid_decision(db: str) -> None:
    token = await create_pending_approval(db, "a", "{}", "{}")
    with pytest.raises(AssertionError):
        await decide_approval(db, token, "maybe")


@pytest.mark.asyncio
async def test_mark_executed_updates_status_and_result(db: str) -> None:
    token = await create_pending_approval(db, "a", "{}", "{}")
    await decide_approval(db, token, "approved")
    result = [{"action": "disable_user", "target": "jdoe", "ok": True}]
    await mark_executed(db, token, result)

    row = await get_pending_approval(db, token)
    assert row["status"] == "executed"
    assert row["executed_at"] is not None
    assert json.loads(row["execution_result"]) == result


@pytest.mark.asyncio
async def test_mark_executed_returns_true_when_approved(db: str) -> None:
    token = await create_pending_approval(db, "a", "{}", "{}")
    await decide_approval(db, token, "approved")
    assert await mark_executed(db, token, [{"ok": True}]) is True


@pytest.mark.asyncio
async def test_mark_executed_noop_when_not_approved(db: str) -> None:
    """Si el approval no está 'approved' (p.ej. un reject entró antes), mark_executed
    no pisa el estado terminal y devuelve False."""
    token = await create_pending_approval(db, "a", "{}", "{}")
    await decide_approval(db, token, "rejected")
    assert await mark_executed(db, token, [{"ok": True}]) is False

    row = await get_pending_approval(db, token)
    assert row["status"] == "rejected"  # intacto
    assert row["executed_at"] is None


@pytest.mark.asyncio
async def test_timeline_json_persisted_and_read(db: str) -> None:
    timeline = '[{"stage":"triage","ts":"2026-06-06T00:00:00+00:00","summary":"x"}]'
    token = await create_pending_approval(
        db, "a", "{}", "{}", timeline_json=timeline
    )
    row = await get_pending_approval(db, token)
    assert row["timeline_json"] == timeline
    # decide_approval también devuelve la columna nueva
    _, decided = await decide_approval(db, token, "approved")
    assert decided["timeline_json"] == timeline


@pytest.mark.asyncio
async def test_timeline_json_defaults_to_null(db: str) -> None:
    """Backwards-compat: crear sin timeline_json deja la columna NULL."""
    token = await create_pending_approval(db, "a", "{}", "{}")
    row = await get_pending_approval(db, token)
    assert row["timeline_json"] is None


@pytest.mark.asyncio
async def test_migration_idempotent_on_existing_db(tmp_path: Path) -> None:
    """init_db sobre una DB que ya tiene la columna timeline_json no rompe."""
    path = str(tmp_path / "mig.db")
    await init_db(path)
    await init_db(path)  # segunda corrida: ALTER TABLE ya aplicado → no debe fallar
    token = await create_pending_approval(path, "a", "{}", "{}", timeline_json="[]")
    row = await get_pending_approval(path, token)
    assert row["timeline_json"] == "[]"
