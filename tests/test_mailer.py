"""Tests del mailer - construcción del mensaje + skip si no hay SMTP configurado."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from src.agents.narrator import NarratorPlan, ProposedAction
from src.config import Settings
from src.mailer import (
    _build_html_body,
    _build_message,
    _build_text_body,
    send_approval_email,
)
from src.normalize import normalize

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def alert():
    raw = json.loads((FIXTURES / "defender_keygen.json").read_text())
    return normalize(raw)


@pytest.fixture
def plan() -> NarratorPlan:
    return NarratorPlan(
        executive_summary="Hacktool detectado en desktop-1234 afectando jdoe.",
        risk_level="high",
        actions=[
            ProposedAction(
                type="disable_user",
                target="jdoe",
                justification="Owner del archivo malicioso con verdict=malicious",
            ),
            ProposedAction(
                type="force_password_change",
                target="asmith",
                justification="Logged on en el mismo evento - sospechoso",
            ),
        ],
        rationale="Triage marcó fast_track. Enrichment confirmó users activos en AD.",
    )


@pytest.fixture
def settings() -> Settings:
    return Settings(
        openai_api_key="test",
        smtp_host="smtp.test",
        smtp_port=587,
        smtp_user="svc@test",
        smtp_password="pwd",
        smtp_from="soc-l1@test",
        smtp_to_approvers="soc@test,oncall@test",
        smtp_use_starttls=True,
        smtp_ssl_verify=False,
        approval_base_url="https://soc.test",
    )


def test_text_body_contains_essentials(alert, plan) -> None:
    body = _build_text_body(
        alert, plan, "https://soc.test/approve/TKN", "https://soc.test/reject/TKN"
    )
    assert "Risk: HIGH" in body
    assert "Hacktool detectado" in body
    assert "disable_user → jdoe" in body
    assert "force_password_change → asmith" in body
    assert "https://soc.test/approve/TKN" in body
    assert "https://soc.test/reject/TKN" in body
    assert alert.alert_id in body


def test_html_body_escapes_user_data(alert) -> None:
    """Defensa básica: si la alerta contiene HTML, no debe romper el rendering."""
    plan = NarratorPlan(
        executive_summary="<script>alert('xss')</script> bad",
        risk_level="low",
        actions=[
            ProposedAction(
                type="notify_only",
                target="<b>weird</b>",
                justification="contiene & entities",
            )
        ],
        rationale="ok",
    )
    html = _build_html_body(
        alert, plan, "https://soc.test/approve/x", "https://soc.test/reject/x"
    )
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "&lt;b&gt;weird&lt;/b&gt;" in html


def test_text_body_empty_actions(alert) -> None:
    plan = NarratorPlan(
        executive_summary="todo bien", risk_level="low", actions=[], rationale="r"
    )
    body = _build_text_body(alert, plan, "u/a", "u/r")
    assert "(ninguna - monitor only)" in body


def test_build_message_has_multipart_and_correct_headers(settings, alert, plan) -> None:
    msg = _build_message(settings, alert, plan, "TKN123")
    assert msg["From"] == "soc-l1@test"
    # EmailMessage normaliza "a,b" → "a, b" en headers de address list
    assert "soc@test" in msg["To"]
    assert "oncall@test" in msg["To"]
    assert "HIGH" in msg["Subject"]
    assert "desktop-1234" in msg["Subject"]
    # multipart: text/plain + text/html
    parts = list(msg.iter_parts())
    types = {p.get_content_type() for p in parts}
    assert "text/plain" in types
    assert "text/html" in types


def test_subject_truncates_long_titles(settings, alert) -> None:
    long_title_alert = alert.model_copy(update={"title": "A" * 200})
    plan = NarratorPlan(
        executive_summary="s", risk_level="low", actions=[], rationale="r"
    )
    msg = _build_message(settings, long_title_alert, plan, "TKN")
    # Title sliced a 60 chars
    assert "A" * 60 in msg["Subject"]
    assert "A" * 61 not in msg["Subject"]


@pytest.mark.asyncio
async def test_send_skips_when_smtp_not_configured(alert, plan) -> None:
    """En entornos sin SMTP (default), send_approval_email no debe crashear ni intentar conexión."""
    s = Settings(openai_api_key="test", smtp_host="", smtp_to_approvers="")
    with patch("src.mailer._send_sync") as mocked:
        await send_approval_email(s, alert, plan, "TKN")
        mocked.assert_not_called()


@pytest.mark.asyncio
async def test_send_invokes_smtp_when_configured(settings, alert, plan) -> None:
    """Con SMTP configurado, _send_sync se llama con el msg construido."""
    with patch("src.mailer._send_sync") as mocked:
        await send_approval_email(settings, alert, plan, "TKN999")
        mocked.assert_called_once()
        args, _ = mocked.call_args
        sent_msg = args[1]
        assert "soc@test" in sent_msg["To"]
        assert "oncall@test" in sent_msg["To"]
        # Sanity: el token aparece en el body
        body_text = sent_msg.get_body("plain").get_content()
        assert "TKN999" in body_text


@pytest.mark.asyncio
async def test_send_propagates_smtp_exception(settings, alert, plan) -> None:
    """Errores de SMTP deben re-elevarse (el caller decide qué hacer)."""
    with patch("src.mailer._send_sync", side_effect=ConnectionRefusedError("nope")):
        with pytest.raises(ConnectionRefusedError):
            await send_approval_email(settings, alert, plan, "TKN")
