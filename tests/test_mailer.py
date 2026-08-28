"""Tests del mailer - construcción del mensaje + skip si no hay SMTP configurado."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from src import report_theme
from src.agents.narrator import NarratorPlan, ProposedAction
from src.config import Settings
from src.mailer import (
    _build_closure_html_body,
    _build_closure_message,
    _build_closure_text_body,
    _build_html_body,
    _build_message,
    _build_text_body,
    _closure_timeline,
    send_approval_email,
    send_closure_email,
)
from src.normalize import normalize

TIMELINE_EVENTS = [
    {"stage": "triage", "ts": "2026-06-06T14:00:00+00:00", "summary": "ruido sospechoso", "detail": "verdict=fast_track_critical"},
    {"stage": "enricher", "ts": "2026-06-06T14:00:05+00:00", "summary": "jdoe no en AD", "detail": "users=1"},
    {"stage": "threat_intel", "ts": "2026-06-06T14:00:08+00:00", "summary": "VT 66/68 malicious", "detail": None},
    {"stage": "narrator", "ts": "2026-06-06T14:00:12+00:00", "summary": "Emotet activo, aislar", "detail": "risk=critical actions=2"},
]

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


def test_subject_fits_inbox_budget(settings, alert) -> None:
    """El asunto se recorta al presupuesto de bandeja, no a un slice fijo.

    Outlook corta la lista cerca de los 72 caracteres. Antes el titulo se
    cortaba a 60 fijos y despues se le concatenaba host y ticket, asi que el
    asunto igual se pasaba y lo que se perdia era la cola -- justo el ticket.
    """
    long_title_alert = alert.model_copy(update={"title": "A" * 200})
    plan = NarratorPlan(
        executive_summary="s", risk_level="low", actions=[], rationale="r"
    )
    msg = _build_message(settings, long_title_alert, plan, "TKN")
    assert len(msg["Subject"]) <= report_theme.SUBJECT_BUDGET
    # El recorte cae sobre el titulo; prefijo y estado quedan intactos porque
    # son lo que filtran las reglas de bandeja.
    assert msg["Subject"].startswith("[SOC L1][INCIDENTE] LOW \u00b7 ")
    assert "\u2026" in msg["Subject"]
    assert "desktop-1234" in msg["Subject"]


def test_subject_no_gira_al_vacio_con_campos_minimos() -> None:
    """El recorte corta el loop cuando ya no puede achicar nada mas.

    Con campos que no bajan de `_MIN_CAMPO` no hay forma de entrar en el
    presupuesto: la funcion tiene que devolver igual, no colgarse.
    """
    s = report_theme.subject("INCIDENTE", "CRITICAL", "abcdefghijkl", "mnopqrstuvwx", budget=20)
    assert s.startswith("[SOC L1][INCIDENTE] CRITICAL")
    assert len(s) > 20  # no entra, pero devolvio


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


# ===== Email de cierre =====


def test_closure_timeline_adds_decision_and_execution() -> None:
    events = _closure_timeline(
        TIMELINE_EVENTS,
        decision="approved",
        decided_by_ip="1.2.3.4",
        decided_at="2026-06-06T14:05:00+00:00",
        execution_results=[{"action_type": "isolate_host", "target": "h", "ok": True, "message": "ok"}],
        executed_at="2026-06-06T14:05:02+00:00",
    )
    stages = [e["stage"] for e in events]
    assert "decision" in stages and "execution" in stages
    # ordenado por ts: pipeline antes que decisión/ejecución
    assert stages.index("triage") < stages.index("decision") < stages.index("execution")


def test_closure_timeline_rejection_has_no_execution() -> None:
    events = _closure_timeline(
        TIMELINE_EVENTS, decision="rejected", decided_by_ip="1.2.3.4",
        decided_at="2026-06-06T14:05:00+00:00", execution_results=None, executed_at=None,
    )
    assert "execution" not in [e["stage"] for e in events]
    assert "decision" in [e["stage"] for e in events]


def test_closure_html_contains_all_stages(alert, plan) -> None:
    events = _closure_timeline(
        TIMELINE_EVENTS, decision="approved", decided_by_ip="1.2.3.4",
        decided_at="2026-06-06T14:05:00+00:00",
        execution_results=[{"action_type": "isolate_host", "target": "desktop-1234", "ok": True, "message": "DRY_RUN"}],
        executed_at="2026-06-06T14:05:02+00:00",
    )
    html = _build_closure_html_body(alert, plan, events, [{"action_type": "isolate_host", "target": "desktop-1234", "ok": True, "message": "DRY_RUN"}], "approved")
    assert "TRIAGE" in html and "ENRICHER" in html and "THREAT INTEL" in html and "NARRATOR" in html
    assert "isolate_host" in html
    assert "VT 66/68 malicious" in html


def test_closure_text_rejection_omits_execution(alert, plan) -> None:
    events = _closure_timeline(
        TIMELINE_EVENTS, decision="rejected", decided_by_ip="9.9.9.9",
        decided_at="2026-06-06T14:05:00+00:00", execution_results=None, executed_at=None,
    )
    body = _build_closure_text_body(alert, plan, events, None, "rejected")
    assert "CASO CERRADO (RECHAZADO)" in body
    assert "EJECUCIÓN" not in body


def test_closure_subject_distinguishes_decision(settings, alert, plan) -> None:
    msg = _build_closure_message(
        settings, alert, plan, decision="approved", timeline_events=TIMELINE_EVENTS,
        execution_results=[], decided_by_ip="1.2.3.4",
        decided_at="2026-06-06T14:05:00+00:00", executed_at="2026-06-06T14:05:02+00:00",
    )
    # "CERRADO" es el ESTADO (posicion fija, filtrable) y la decision el
    # contexto. El host NO va: en el cierre el titulo ya lo identifica y
    # sacarlo es lo que deja entrar al ticket dentro del presupuesto.
    assert msg["Subject"].startswith("[SOC L1][INCIDENTE] CERRADO \u00b7 APROBADO \u00b7 ")
    assert len(msg["Subject"]) <= report_theme.SUBJECT_BUDGET

    rechazado = _build_closure_message(
        settings, alert, plan, decision="rejected", timeline_events=TIMELINE_EVENTS,
        execution_results=[], decided_by_ip="1.2.3.4",
        decided_at="2026-06-06T14:05:00+00:00", executed_at=None,
    )
    assert "RECHAZADO" in rechazado["Subject"]


def test_closure_html_escapes_user_data(alert) -> None:
    evil_plan = NarratorPlan(
        executive_summary="<script>alert('xss')</script>", risk_level="low",
        actions=[], rationale="r",
    )
    events = _closure_timeline(
        [{"stage": "triage", "ts": "2026-06-06T14:00:00+00:00", "summary": "<b>x</b>", "detail": None}],
        decision="rejected", decided_by_ip="1.2.3.4",
        decided_at="2026-06-06T14:05:00+00:00", execution_results=None, executed_at=None,
    )
    html = _build_closure_html_body(alert, evil_plan, events, None, "rejected")
    assert "<script>" not in html
    assert "&lt;b&gt;x&lt;/b&gt;" in html


@pytest.mark.asyncio
async def test_closure_skips_when_smtp_not_configured(alert, plan) -> None:
    s = Settings(openai_api_key="test", smtp_host="", smtp_to_approvers="")
    with patch("src.mailer._send_sync") as mocked:
        await send_closure_email(
            s, alert, plan, decision="approved", timeline_events=[],
            execution_results=[], decided_by_ip=None, decided_at=None, executed_at=None,
        )
        mocked.assert_not_called()


@pytest.mark.asyncio
async def test_closure_does_not_propagate_smtp_exception(settings, alert, plan) -> None:
    """A diferencia del approval, el cierre NO re-eleva: es fire-and-forget."""
    with patch("src.mailer._send_sync", side_effect=ConnectionRefusedError("nope")):
        # No debe levantar
        await send_closure_email(
            settings, alert, plan, decision="approved", timeline_events=TIMELINE_EVENTS,
            execution_results=[], decided_by_ip="1.2.3.4",
            decided_at="2026-06-06T14:05:00+00:00", executed_at="2026-06-06T14:05:02+00:00",
        )


@pytest.mark.asyncio
async def test_closure_invokes_smtp_when_configured(settings, alert, plan) -> None:
    with patch("src.mailer._send_sync") as mocked:
        await send_closure_email(
            settings, alert, plan, decision="approved", timeline_events=TIMELINE_EVENTS,
            execution_results=[{"action_type": "isolate_host", "target": "h", "ok": True, "message": "ok"}],
            decided_by_ip="1.2.3.4", decided_at="2026-06-06T14:05:00+00:00",
            executed_at="2026-06-06T14:05:02+00:00",
        )
        mocked.assert_called_once()


# ===== Alertas de correo (Defender for Office 365) =====


@pytest.fixture
def o365_alert():
    raw = json.loads((FIXTURES / "defender_o365_malicious_url.json").read_text())
    return normalize(raw)


@pytest.fixture
def o365_plan() -> NarratorPlan:
    return NarratorPlan(
        executive_summary="Dos buzones recibieron un correo con URL maliciosa.",
        risk_level="low",
        actions=[
            ProposedAction(
                type="notify_only",
                target="jperez, mgomez",
                justification="Defender ya removió los mensajes.",
            )
        ],
        rationale="Phishing removido post-entrega.",
    )


def test_o365_html_has_email_section(o365_alert, o365_plan) -> None:
    """El correo trae asunto, destinatarios, remitente y URL.

    Regresión: estas alertas llegaban con "Información principal" vacía porque
    todo el template colgaba de device.hostname / files, que en O365 no existen.
    """
    html = _build_html_body(
        o365_alert, o365_plan, "http://x/a", "http://x/r", ttl_hours=24
    )
    assert "Correos involucrados (2)" in html
    assert "jperez@contoso.com" in html
    assert "mgomez@contoso.com" in html
    assert "abre.ai/rw8y" in html
    assert "200.41.220.50" in html
    assert "Actualiz" in html  # el asunto, escapado


def test_o365_html_pivot_is_subject_not_none(o365_alert, o365_plan) -> None:
    """Sin host, el titular es el asunto + buzones (antes decía "-")."""
    html = _build_html_body(
        o365_alert, o365_plan, "http://x/a", "http://x/r", ttl_hours=24
    )
    assert "Buzones" in html
    assert "<strong>-</strong>" not in html


def test_o365_html_shows_vendor_mitre(o365_alert, o365_plan) -> None:
    html = _build_html_body(
        o365_alert, o365_plan, "http://x/a", "http://x/r", ttl_hours=24
    )
    assert "T1566.002" in html


def test_o365_text_body_has_emails(o365_alert, o365_plan) -> None:
    txt = _build_text_body(o365_alert, o365_plan, "http://x/a", "http://x/r")
    assert "CORREOS INVOLUCRADOS (2)" in txt
    assert "jperez@contoso.com" in txt
    assert "abre.ai/rw8y" in txt
    assert "(sin host)" not in txt


def test_endpoint_email_has_no_email_section(alert, plan) -> None:
    """Las alertas de endpoint siguen igual: sin sección de correos."""
    html = _build_html_body(alert, plan, "http://x/a", "http://x/r", ttl_hours=24)
    assert "Correos involucrados" not in html
