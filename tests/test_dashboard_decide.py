"""Tests de la decisión desde el panel: POST /ui/api/case/{rowid}/decide.

El panel era solo-lectura y la única forma de decidir era el link del correo. Este
endpoint reusa la misma ruta (_decide_and_apply), así que lo que se verifica acá es
que no se haya abierto un segundo camino con reglas distintas: mismo single-use,
misma auth, y el token de approval nunca sale al browser.
"""
from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from src.agents.narrator import NarratorPlan, ProposedAction
from src.config import Settings
from src.main import app, get_settings
from src.state import create_pending_approval, get_pending_approval, init_db


@pytest_asyncio.fixture
async def db_path(tmp_path: Path) -> str:
    path = str(tmp_path / "decide.db")
    await init_db(path)
    return path


@pytest.fixture
def settings_factory(db_path: str):
    def _make(**overrides) -> Settings:
        defaults = dict(
            wazuh_webhook_secret="x",
            state_db_path=db_path,
            approval_ttl_hours=24,
            approval_base_url="http://test.local",
            enable_narrator=True,
            dashboard_enabled=True,
            dashboard_password="test-pass",
            dashboard_session_secret="0" * 64,
        )
        defaults.update(overrides)
        return Settings(**defaults)

    return _make


@pytest.fixture
def client(settings_factory):
    app.dependency_overrides[get_settings] = lambda: settings_factory()
    get_settings.cache_clear()
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
    get_settings.cache_clear()


@pytest.fixture
def auth_client(client: TestClient, settings_factory):
    from src.web import auth

    client.cookies.set(auth.COOKIE_NAME, auth.issue_session(settings_factory()))
    return client


@pytest.fixture
def plan() -> NarratorPlan:
    return NarratorPlan(
        executive_summary="url maliciosa en correo",
        risk_level="critical",
        actions=[
            ProposedAction(type="block_ip", target="142.67.249.79", justification="origen"),
            ProposedAction(type="disable_user", target="jdoe", justification="buzón tocado"),
        ],
        rationale="análisis ok",
    )


@pytest_asyncio.fixture
async def case(db_path: str, plan: NarratorPlan) -> dict:
    token = await create_pending_approval(
        db_path,
        alert_id="alert-o365",
        plan_json=plan.model_dump_json(),
        alert_json='{"alert_id":"alert-o365"}',
    )
    with sqlite3.connect(db_path) as conn:
        rowid = conn.execute(
            "SELECT rowid FROM pending_approvals WHERE token=?", (token,)
        ).fetchone()[0]
    return {"token": token, "rowid": rowid}


def test_decide_requires_session(client: TestClient, case: dict) -> None:
    r = client.post(f"/ui/api/case/{case['rowid']}/decide", json={"decision": "rejected"})
    assert r.status_code == 401


def test_decide_rejects_unknown_decision(auth_client: TestClient, case: dict) -> None:
    r = auth_client.post(
        f"/ui/api/case/{case['rowid']}/decide", json={"decision": "maybe"}
    )
    assert r.status_code == 400
    assert r.json()["error"] == "bad_decision"


def test_decide_rejects_bad_selection(auth_client: TestClient, case: dict) -> None:
    r = auth_client.post(
        f"/ui/api/case/{case['rowid']}/decide",
        json={"decision": "approved", "selected_action_indices": ["0"]},
    )
    assert r.status_code == 400
    assert r.json()["error"] == "bad_selection"


def test_decide_unknown_case_is_404(auth_client: TestClient) -> None:
    r = auth_client.post("/ui/api/case/999999/decide", json={"decision": "rejected"})
    assert r.status_code == 404


def test_reject_from_dashboard_marks_db_without_executing(
    auth_client: TestClient, case: dict, db_path: str
) -> None:
    with patch("src.executor.execute_plan", new=AsyncMock()) as mocked_exec:
        r = auth_client.post(
            f"/ui/api/case/{case['rowid']}/decide", json={"decision": "rejected"}
        )
    assert r.status_code == 200, r.text
    assert r.json()["decision"] == "rejected"
    mocked_exec.assert_not_called()

    row = asyncio.run(get_pending_approval(db_path, case["token"]))
    assert row["status"] == "rejected"
    assert row["decided_at"] is not None


def test_approve_from_dashboard_runs_only_selected_actions(
    auth_client: TestClient, case: dict, db_path: str
) -> None:
    """La selección del panel llega al executor igual que la de /decide."""
    with patch("src.main._execute_approved_plan_in_background", new=AsyncMock()) as bg:
        r = auth_client.post(
            f"/ui/api/case/{case['rowid']}/decide",
            json={"decision": "approved", "selected_action_indices": [0]},
        )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["n_actions"] == 1
    assert body["skipped"] == 1

    actions_to_run = bg.call_args.args[4]
    assert [a.type for a in actions_to_run] == ["block_ip"]

    row = asyncio.run(get_pending_approval(db_path, case["token"]))
    assert row["status"] == "approved"


def test_second_decision_is_rejected_as_already_decided(
    auth_client: TestClient, case: dict
) -> None:
    """El single-use del token vale igual viniendo del panel."""
    with patch("src.main._execute_approved_plan_in_background", new=AsyncMock()):
        first = auth_client.post(
            f"/ui/api/case/{case['rowid']}/decide", json={"decision": "approved"}
        )
    assert first.status_code == 200

    second = auth_client.post(
        f"/ui/api/case/{case['rowid']}/decide", json={"decision": "rejected"}
    )
    assert second.status_code == 409
    assert second.json()["error"] == "already"


def test_case_payload_never_exposes_the_token(
    auth_client: TestClient, case: dict
) -> None:
    r = auth_client.get(f"/ui/api/case/{case['rowid']}")
    assert r.status_code == 200
    assert case["token"] not in r.text


def test_session_reports_execution_mode(auth_client: TestClient) -> None:
    """La UI necesita saber si contiene de verdad o simula."""
    r = auth_client.get("/ui/api/session")
    assert r.status_code == 200
    body = r.json()
    assert body["authed"] is True
    assert body["mode"] in ("live", "dry_run", "mixed")
    assert set(body["dry_run_families"]) == {"ad", "fortigate", "defender"}


def test_session_hides_mode_when_not_authed(client: TestClient) -> None:
    r = client.get("/ui/api/session")
    assert r.status_code == 200
    assert r.json() == {"authed": False}


def test_execution_results_are_flagged_as_simulated(
    auth_client: TestClient, case: dict, db_path: str
) -> None:
    """Un resultado con prefijo DRY_RUN se marca como simulado en el payload."""
    from src.state import mark_executed

    asyncio.run(
        get_pending_approval(db_path, case["token"])
    )
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE pending_approvals SET status='approved' WHERE token=?",
            (case["token"],),
        )
    asyncio.run(
        mark_executed(
            db_path,
            case["token"],
            [
                {
                    "action_type": "block_ip",
                    "target": "142.67.249.79",
                    "ok": True,
                    "message": "DRY_RUN: block_ip simulado (FortiGate intacto)",
                },
                {
                    "action_type": "block_ip",
                    "target": "10.0.0.9",
                    "ok": True,
                    "message": "quarantine ok",
                },
            ],
        )
    )
    r = auth_client.get(f"/ui/api/case/{case['rowid']}")
    results = r.json()["execution_result"]
    assert [er["simulated"] for er in results] == [True, False]
