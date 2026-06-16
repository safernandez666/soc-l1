"""Tests E2E de los endpoints /approve y /reject + ejecución post-aprobación."""
from __future__ import annotations

import asyncio
import json
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
    path = str(tmp_path / "approval.db")
    await init_db(path)
    return path


@pytest.fixture
def settings_factory(db_path: str):
    """Devuelve un factory que cada test puede customizar (TTL, narrator on/off, etc.)."""

    def _make(**overrides) -> Settings:
        defaults = dict(
            wazuh_webhook_secret="x",
            state_db_path=db_path,
            approval_ttl_hours=24,
            approval_base_url="http://test.local",
            enable_narrator=True,
        )
        defaults.update(overrides)
        return Settings(**defaults)

    return _make


@pytest.fixture
def client(settings_factory):
    def _override() -> Settings:
        return settings_factory()

    app.dependency_overrides[get_settings] = _override
    get_settings.cache_clear()
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
    get_settings.cache_clear()


@pytest.fixture
def auth_client(client: TestClient, settings_factory):
    """client con una sesión de dashboard válida.

    /approvals está detrás del mismo login que /ui (expone tokens/planes), así que
    requiere la cookie firmada. La emitimos con las mismas settings que usa la app.
    """
    from src.web import auth

    cookie = auth.issue_session(settings_factory())
    client.cookies.set(auth.COOKIE_NAME, cookie)
    return client


@pytest.fixture
def sample_plan() -> NarratorPlan:
    return NarratorPlan(
        executive_summary="malware detectado",
        risk_level="high",
        actions=[
            ProposedAction(type="disable_user", target="jdoe", justification="evidence X"),
        ],
        rationale="análisis ok",
    )


@pytest_asyncio.fixture
async def pending_token(db_path: str, sample_plan: NarratorPlan) -> str:
    return await create_pending_approval(
        db_path,
        alert_id="alert-abc",
        plan_json=sample_plan.model_dump_json(),
        alert_json='{"alert_id":"alert-abc"}',
    )


def test_approve_unknown_token_returns_invalid_page(client: TestClient) -> None:
    r = client.get("/approve/garbage-token-xxx")
    assert r.status_code == 200  # render HTML, no es 404
    assert "Token inválido" in r.text


def test_reject_unknown_token_returns_invalid_page(client: TestClient) -> None:
    r = client.get("/reject/garbage-token-xxx")
    assert r.status_code == 200
    assert "Token inválido" in r.text


def test_reject_marks_db_and_does_not_execute(
    client: TestClient, pending_token: str, db_path: str
) -> None:
    """Reject no llama al executor."""
    with patch("src.executor.execute_plan", new=AsyncMock()) as mocked_exec:
        r = client.get(f"/reject/{pending_token}")
    assert r.status_code == 200
    assert "Rechazado" in r.text
    mocked_exec.assert_not_called()

    row = asyncio.run(get_pending_approval(db_path, pending_token))
    assert row["status"] == "rejected"
    assert row["decided_at"] is not None


def test_approve_launches_executor_in_background(
    client: TestClient, pending_token: str, db_path: str
) -> None:
    """Approve responde rápido y dispara execute_plan en background."""
    executor_finished = asyncio.Event()

    async def fake_execute_plan(actions, ldap_cfg):
        executor_finished.set()
        return [{"action_type": a.type, "target": a.target, "ok": True, "message": "fake"} for a in actions]

    with patch("src.executor.execute_plan", side_effect=fake_execute_plan) as mocked_exec:
        r = client.get(f"/approve/{pending_token}")
        # Tras responder, dar margen para que el background task termine
        # (FastAPI TestClient corre el loop dentro del thread del request)
        # Damos hasta 2s para que el task background corra
        for _ in range(20):
            if mocked_exec.called:
                break
            # Yield al event loop
            asyncio.run(asyncio.sleep(0.1))

    assert r.status_code == 200
    assert "Aprobado" in r.text
    assert mocked_exec.called

    # state debería quedar en 'executed' tras el background task
    row = asyncio.run(get_pending_approval(db_path, pending_token))
    # Status puede ser 'approved' (si el background no terminó) o 'executed'
    assert row["status"] in ("approved", "executed")


def test_approve_twice_second_returns_already_decided(
    client: TestClient, pending_token: str
) -> None:
    with patch("src.executor.execute_plan", new=AsyncMock(return_value=[])):
        client.get(f"/approve/{pending_token}")
        r2 = client.get(f"/approve/{pending_token}")
    assert "Ya decidido" in r2.text


def test_approve_then_reject_blocked(
    client: TestClient, pending_token: str
) -> None:
    """Una vez aprobado, no se puede rechazar (token quemado)."""
    with patch("src.executor.execute_plan", new=AsyncMock(return_value=[])):
        client.get(f"/approve/{pending_token}")
        r = client.get(f"/reject/{pending_token}")
    assert "Ya decidido" in r.text


def test_decide_logs_ip_and_user_agent(
    client: TestClient, pending_token: str, db_path: str
) -> None:
    """Audit trail: IP y User-Agent deben quedar persistidos."""
    with patch("src.executor.execute_plan", new=AsyncMock(return_value=[])):
        client.get(
            f"/reject/{pending_token}",
            headers={"User-Agent": "Mozilla/Test 1.0"},
        )
    row = asyncio.run(get_pending_approval(db_path, pending_token))
    assert row["decided_by_ua"] == "Mozilla/Test 1.0"
    assert row["decided_by_ip"]  # TestClient usa "testclient" como host


# ===== /review (granular approval form) =====


def test_review_renders_form_with_checkboxes(
    client: TestClient, pending_token: str, sample_plan
) -> None:
    """GET /review/{token} renderiza un form con 1 checkbox por acción."""
    r = client.get(f"/review/{pending_token}")
    assert r.status_code == 200
    assert "Revisar plan de acción" in r.text
    # Para cada acción del plan, debe haber un input checkbox
    for i, action in enumerate(sample_plan.actions):
        assert f'value="{i}"' in r.text
        assert action.type in r.text
        assert action.target in r.text
    # Botones de submit
    assert 'value="approve"' in r.text
    assert 'value="reject"' in r.text


def test_review_unknown_token(client: TestClient) -> None:
    r = client.get("/review/garbage-token-xxx")
    assert r.status_code == 200
    assert "Token inválido" in r.text


def test_review_already_decided(client: TestClient, pending_token: str) -> None:
    """Si el token ya se decidió, /review muestra "ya decidido" en vez del form."""
    with patch("src.executor.execute_plan", new=AsyncMock(return_value=[])):
        client.get(f"/reject/{pending_token}")
    r = client.get(f"/review/{pending_token}")
    assert "Ya decidido" in r.text
    # No debe renderizar el form
    assert 'value="approve"' not in r.text


# ===== /decide (form POST handler) =====


def test_decide_approve_with_all_selected_runs_all(
    client: TestClient, pending_token: str, sample_plan
) -> None:
    """POST /decide con todas las acciones checkeadas → executor recibe todo el plan."""
    captured_actions = []

    async def capture(actions, ldap_cfg, settings):
        captured_actions.append(list(actions))
        return [{"action_type": a.type, "target": a.target, "ok": True, "message": "ok"} for a in actions]

    with patch("src.executor.execute_plan", side_effect=capture) as mocked:
        r = client.post(
            f"/decide/{pending_token}",
            data={
                "decision": "approve",
                "action_idx": [str(i) for i in range(len(sample_plan.actions))],
            },
        )
        # Esperar background task
        for _ in range(20):
            if mocked.called:
                break
            asyncio.run(asyncio.sleep(0.05))

    assert r.status_code == 200
    assert "Aprobado" in r.text
    assert len(captured_actions[0]) == len(sample_plan.actions)


def test_decide_approve_with_subset_runs_only_selected(
    client: TestClient, db_path: str, sample_plan
) -> None:
    """POST /decide con solo algunos action_idx → executor recibe el subset."""
    # Crear un plan con 3 acciones para probar selección
    from src.agents.narrator import NarratorPlan, ProposedAction
    multi_plan = NarratorPlan(
        executive_summary="x",
        risk_level="high",
        actions=[
            ProposedAction(type="disable_user", target="userA", justification="x"),
            ProposedAction(type="block_ip", target="1.2.3.4", justification="x"),
            ProposedAction(type="escalate_l2", target="incident-z", justification="x"),
        ],
        rationale="x",
    )
    token = asyncio.run(create_pending_approval(
        db_path, alert_id="alert-multi",
        plan_json=multi_plan.model_dump_json(),
        alert_json='{"alert_id":"alert-multi"}',
    ))

    captured = []

    async def capture(actions, ldap_cfg, settings):
        captured.append(list(actions))
        return [{"action_type": a.type, "target": a.target, "ok": True, "message": "ok"} for a in actions]

    with patch("src.executor.execute_plan", side_effect=capture) as mocked:
        r = client.post(
            f"/decide/{token}",
            data={"decision": "approve", "action_idx": ["0", "2"]},
        )
        for _ in range(20):
            if mocked.called:
                break
            asyncio.run(asyncio.sleep(0.05))

    assert r.status_code == 200
    assert "Aprobado" in r.text
    assert "descartada" in r.text  # mensaje de que 1 quedó afuera
    # Solo 2 acciones fueron al executor: índices 0 y 2 (disable_user + escalate_l2)
    assert len(captured[0]) == 2
    assert captured[0][0].type == "disable_user"
    assert captured[0][1].type == "escalate_l2"


def test_decide_approve_with_zero_selected_runs_nothing(
    client: TestClient, pending_token: str
) -> None:
    """POST /decide con decision=approve pero ningún checkbox → ejecuta 0 acciones."""
    with patch("src.executor.execute_plan", new=AsyncMock()) as mocked:
        r = client.post(
            f"/decide/{pending_token}",
            data={"decision": "approve"},  # sin action_idx
        )
    assert r.status_code == 200
    assert "ninguna acción fue seleccionada" in r.text
    mocked.assert_not_called()


def test_decide_reject_ignores_selected_actions(
    client: TestClient, pending_token: str
) -> None:
    """POST /decide con decision=reject ignora action_idx y rechaza todo."""
    with patch("src.executor.execute_plan", new=AsyncMock()) as mocked:
        r = client.post(
            f"/decide/{pending_token}",
            data={"decision": "reject", "action_idx": ["0"]},
        )
    assert r.status_code == 200
    assert "Rechazado" in r.text
    mocked.assert_not_called()


def test_decide_invalid_decision_returns_400(
    client: TestClient, pending_token: str
) -> None:
    r = client.post(
        f"/decide/{pending_token}",
        data={"decision": "maybe"},
    )
    assert r.status_code == 400
    assert "decision inválida" in r.json()["detail"]


# ===== /approvals dashboard =====


def test_approvals_html_empty_when_no_data(auth_client: TestClient, db_path: str) -> None:
    """DB vacía (en este test todavía no creamos approvals) → mensaje "No hay approvals"."""
    r = auth_client.get("/approvals")
    assert r.status_code == 200
    assert "Cola de approvals" in r.text
    assert "No hay approvals" in r.text


def test_approvals_html_lists_pending_with_review_link(
    auth_client: TestClient, pending_token: str
) -> None:
    """Approval pending debe aparecer en la tabla con link a /review/{token}."""
    r = auth_client.get("/approvals")
    assert r.status_code == 200
    assert "alert-abc" in r.text  # alert_id del fixture pending_token
    assert f"/review/{pending_token}" in r.text  # link clickeable a la página
    assert "PENDING" in r.text.upper()


def test_approvals_filter_by_status(auth_client: TestClient, pending_token: str) -> None:
    """?status=approved no debería mostrar el pending."""
    r = auth_client.get("/approvals?status=approved")
    assert r.status_code == 200
    assert "alert-abc" not in r.text
    assert "No hay approvals" in r.text


def test_approvals_json_format(auth_client: TestClient, pending_token: str) -> None:
    """?format=json devuelve JSON con total + rows + paginación."""
    r = auth_client.get("/approvals?format=json")
    assert r.status_code == 200
    data = r.json()
    assert "total" in data
    assert "rows" in data
    assert data["total"] >= 1
    assert any(row["alert_id"] == "alert-abc" for row in data["rows"])
    # plan_json no debe venir en el JSON (lo strippeamos para no inflar)
    assert all("plan_json" not in row for row in data["rows"])
    # token NUNCA debe salir en la lista (es la credencial single-use de aprobación)
    assert all("token" not in row for row in data["rows"])


def test_approvals_pagination(auth_client: TestClient, db_path: str) -> None:
    """Limit + offset funcionan correctamente."""
    # Crear 5 approvals para testear paginación
    for i in range(5):
        asyncio.run(create_pending_approval(
            db_path, alert_id=f"alert-{i}",
            plan_json='{"risk_level":"medium","actions":[]}',
            alert_json="{}",
        ))

    r1 = auth_client.get("/approvals?limit=2&offset=0&format=json")
    assert r1.json()["total"] == 5
    assert len(r1.json()["rows"]) == 2

    r2 = auth_client.get("/approvals?limit=2&offset=2&format=json")
    assert len(r2.json()["rows"]) == 2

    # No deben repetirse entre páginas
    ids_1 = {r["alert_id"] for r in r1.json()["rows"]}
    ids_2 = {r["alert_id"] for r in r2.json()["rows"]}
    assert not (ids_1 & ids_2)


def test_approvals_limit_capped_at_500(auth_client: TestClient, db_path: str) -> None:
    """Defensa anti-DoS: limit>500 se capea a 500 internamente (no rompe)."""
    r = auth_client.get("/approvals?limit=10000&format=json")
    assert r.status_code == 200
    # Aunque devuelva 0 rows (no hay data en este test), la response no falla


# ===== /approvals auth (Fase 1: el endpoint expone tokens, exige login) =====


def test_approvals_json_without_session_is_401(client: TestClient, pending_token: str) -> None:
    """Sin cookie de sesión, /approvals?format=json devuelve 401 (no filtra tokens)."""
    r = client.get("/approvals?format=json")
    assert r.status_code == 401
    assert "alert-abc" not in r.text


def test_approvals_html_without_session_redirects_to_login(client: TestClient) -> None:
    """Sin sesión, la vista HTML redirige al login en vez de mostrar la cola."""
    r = client.get("/approvals", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/ui/login"
