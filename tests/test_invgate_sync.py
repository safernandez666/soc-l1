"""Tests de la reconciliación InvGate → state.db (fuente de verdad).

Usa una state.db temporal + InvGate mockeado con respx. Verifica que el snapshot
del estado real del ticket se persiste y que la vista de reconciliación lista los
casos con ticket abierto.
"""
from __future__ import annotations

import json

import httpx
import pytest
import pytest_asyncio
import respx

from src.config import Settings
from src.invgate_sync import reconcile_invgate
from src.state import (
    _connect,
    create_pending_approval,
    init_db,
)
from src.web import queries

BASE = "https://invgate.test/api/v1"


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        openai_api_key="x",
        HOST_INVGATE=BASE,
        USER_INVGATE="api",
        PASS_INVGATE="secret",
        CREATOR_ID_INVGATE=1,
        INVGATE_VERIFY_SSL=False,
        state_db_path=str(tmp_path / "state.db"),
    )


async def _seed_case(db_path: str, alert_id: str, request_id: int) -> int:
    """Crea un caso con ticket y devuelve su rowid."""
    await create_pending_approval(
        db_path,
        alert_id,
        json.dumps({"risk_level": "high", "actions": []}),
        json.dumps({"title": "t", "device": {"hostname": "h"}}),
        invgate_request_id=request_id,
    )
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT rowid FROM pending_approvals WHERE invgate_request_id=?",
            (request_id,),
        ).fetchone()
    return row["rowid"]


def _ticket(status_id: int, *, solved: bool = False):
    return httpx.Response(
        200,
        json={
            "id": 1, "status_id": status_id,
            "solved_at": "2026-07-24T10:00:00Z" if solved else None,
            "closed_at": None,
        },
    )


@pytest_asyncio.fixture
async def db(settings: Settings) -> str:
    await init_db(settings.state_db_path)
    return settings.state_db_path


@pytest.mark.asyncio
async def test_reconcile_persists_real_status(settings: Settings, db: str) -> None:
    await _seed_case(db, "a-open", 100)   # seguirá abierto (status 7)
    await _seed_case(db, "a-solved", 200)  # resuelto (status 5)

    def _route(request):
        tid = request.url.params.get("id")
        return _ticket(5, solved=True) if tid == "200" else _ticket(7)

    with respx.mock as mock:
        mock.get(f"{BASE}/incident").mock(side_effect=_route)
        summary = await reconcile_invgate(settings)

    assert summary["checked"] == 2
    assert summary["resolved"] == 1
    assert summary["still_open"] == 1

    view = await queries.invgate_reconcile_view(db)
    assert view["counts"]["resuelto"] == 1
    assert view["counts"]["abierto"] == 1
    # el abierto aparece en la lista, el resuelto no
    open_ids = {c["invgate_request_id"] for c in view["open_cases"]}
    assert open_ids == {100}


@pytest.mark.asyncio
async def test_resolved_case_not_rechecked(settings: Settings, db: str) -> None:
    await _seed_case(db, "a", 300)
    with respx.mock as mock:
        mock.get(f"{BASE}/incident").mock(return_value=_ticket(5, solved=True))
        await reconcile_invgate(settings)
        # segunda pasada: ya resuelto → no hay casos por chequear
        summary2 = await reconcile_invgate(settings)
    assert summary2["checked"] == 0


@pytest.mark.asyncio
async def test_unreadable_ticket_counts_and_retries(settings: Settings, db: str) -> None:
    await _seed_case(db, "a", 400)
    with respx.mock as mock:
        mock.get(f"{BASE}/incident").mock(return_value=httpx.Response(403))
        summary = await reconcile_invgate(settings)
    assert summary["unreadable"] == 1
    # sigue no-resuelto → vuelve a aparecer para chequear
    view = await queries.invgate_reconcile_view(db)
    assert view["counts"]["sin_verificar"] == 1
