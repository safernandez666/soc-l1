"""E2E hermético de una enumeración de cuentas parecida al ticket #5464.

Sin LLM, InvGate, SMTP ni Teams reales: se simulan el Enricher, el Narrator y los
clientes. Lo que se verifica es el cableado: alerts.json → resumen → alerta → Narrator,
descripción del ticket, email, card de Teams y actualización final de la ráfaga.
"""
from __future__ import annotations

import asyncio
import functools
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import src.main as main
from src.agents.enricher import EnrichmentResult
from src.agents.narrator import NarratorPlan, ProposedAction
from src.config import Settings
from src.mailer import _build_html_body, _build_text_body
from src.models import InvgateTicketResult
from src.normalize import normalize
from src.teams import _evidence_blocks
from src.tools import auth_spray
from src.trace import PipelineTrace


def _alert():
    return normalize({
        "timestamp": "2026-10-26T07:09:31.290-0300",
        "rule": {"id": "200003", "level": 10, "groups": ["azure", "defender"],
                 "description": "Defender [medium]: Suspected account enumeration"},
        "data": {
            "id": "ri-e2e_aml", "title": "Suspected account enumeration (Kerberos, NTLM, AD FS)",
            "severity": "medium", "category": "Discovery", "mitreTechniques": ["T1087.002"],
            "productName": "Microsoft Defender for Identity",
            "firstActivityDateTime": "2026-10-26T09:46:11Z",
            "lastActivityDateTime": "2026-10-26T09:51:44Z",
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.deviceEvidence",
                 "roles": ["source"], "hostName": "178-16-53-33", "deviceDnsName": "178-16-53-33"},
                {"@odata.type": "#microsoft.graph.security.deviceEvidence",
                 "roles": ["destination"], "hostName": "srvdc2",
                 "deviceDnsName": "srvdc2.grupoalemana.dns", "lastIpAddress": "192.168.32.28"},
                {"@odata.type": "#microsoft.graph.security.userEvidence", "roles": ["scanned"],
                 "userAccount": {"accountName": "smtp", "domainName": "grupoalemana.dns"}},
            ],
        },
    })


def _ev(ts: str, agent: str, user: str, status: str, event_id: str = "4776", **ed) -> str:
    return json.dumps({"timestamp": ts, "agent": {"name": agent}, "data": {"win": {
        "system": {"eventID": event_id},
        "eventdata": {"targetUserName": user, **({"status": status} if status else {}), **ed}}}})


def _spray_file(tmp_path: Path, *, minutes: int) -> str:
    """Ruido previo + spray de 12 nombres/minuto contra SRVDC2 + un origen + ruido posterior."""
    lines = [_ev("2026-10-26T05:00:00.000-0300", "SRVDC2", "veeambackup", "0xc0000064")]
    for m in range(40, 40 + minutes):  # 06:40.. -03 = 09:40..Z
        for i in range(12):
            name = "smtp" if (m, i) == (41, 0) else f"user{m}x{i}"
            status = "0xc000006a" if name == "smtp" else "0xc0000064"
            lines.append(_ev(f"2026-10-26T06:{m:02d}:{i * 4:02d}.000-0300", "SRVDC2", name, status))
    lines.append(_ev("2026-10-26T06:45:30.000-0300", "SRVEXCHANGE2016", "info", "0xc0000064",
                     workstation="WIN-TEST01"))
    lines.append(_ev("2026-10-26T09:30:00.000-0300", "SRVDC2", "veeambackup", "0xc0000064"))
    p = tmp_path / "alerts.json"
    p.write_text("\n".join(lines) + "\n")
    return str(p)


@pytest.fixture
def spray(tmp_path, monkeypatch):
    path = _spray_file(tmp_path, minutes=19)  # 06:40–06:58 -03
    monkeypatch.setattr(
        auth_spray, "summarize_auth_failures",
        functools.partial(auth_spray.summarize_auth_failures, alerts_path=path),
    )
    return path


def _plan() -> NarratorPlan:
    return NarratorPlan(
        executive_summary="Spray de usuarios contra el dominio.", risk_level="medium",
        actions=[ProposedAction(type="notify_only", target="smtp", justification="registrar")],
        rationale="Enumeración T1087.002.",
    )


def test_pipeline_attaches_evidence_to_narrator_ticket_and_trace(spray, monkeypatch):
    seen: dict = {}

    async def fake_enrich(alert, **_kw):
        return EnrichmentResult(summary="ok", flags=[])

    async def fake_narrate(alert, **_kw):
        seen["narrator_alert"] = alert
        return _plan()

    class FakeInvgate:
        def __init__(self, *_a, **_k): ...
        async def __aenter__(self): return self
        async def __aexit__(self, *_a): ...
        async def create_incident(self, *, title, description, priority_id, **_k):
            seen["description"] = description
            return InvgateTicketResult(ok=True, request_id=9999)

    async def fake_pending(*_a, **kw):
        seen["alert_json"] = kw["alert_json"]
        return "tok"

    async def fake_email(settings, alert, plan, token, **_kw):
        seen["email_alert"] = alert

    monkeypatch.setattr("src.agents.enricher.enrich_alert", fake_enrich)
    monkeypatch.setattr("src.agents.narrator.narrate_incident", fake_narrate)
    monkeypatch.setattr("src.tools.invgate.InvgateClient", FakeInvgate)
    monkeypatch.setattr("src.tools.invgate.is_configured", lambda _s: True)
    monkeypatch.setattr("src.state.create_pending_approval", fake_pending)
    monkeypatch.setattr("src.mailer.send_approval_email", fake_email)
    monkeypatch.setattr(main, "_spray_followup_safely", lambda *a, **k: asyncio.sleep(0))
    monkeypatch.setattr(main, "_build_ldap_cfg_safely", lambda: None)

    settings = Settings(enable_enricher=True, enable_threat_intel=False, enable_narrator=True)
    alert, trace = _alert(), PipelineTrace(alert_id="ri-e2e_aml")
    asyncio.run(main._enrich_and_request_approval(
        alert, SimpleNamespace(verdict="analyze"), settings, trace
    ))

    evidence = alert.wazuh_evidence
    assert evidence and "229 fallos" in evidence  # 19 min × 12 nombres + 'info' de Exchange
    assert "WIN-TEST01" in evidence and "smtp" in evidence
    assert "veeambackup" not in evidence  # ruido fuera de la ráfaga
    assert alert.network.src_ip_external == "178.16.53.33"
    assert seen["narrator_alert"].wazuh_evidence == evidence
    assert "Evidencia en Wazuh:" in seen["description"] and "WIN-TEST01" in seen["description"]
    assert "wazuh_evidence" in seen["alert_json"]
    assert any(e.stage == "wazuh_evidence" for e in trace.events)


def test_email_and_teams_carry_the_evidence(spray):
    alert = _alert()
    alert.wazuh_evidence = auth_spray.summarize_auth_failures(alert).to_text()
    plan = _plan()
    text = _build_text_body(alert, plan, "http://a", "http://r")
    html = _build_html_body(alert, plan, "http://a", "http://r")
    assert "EVIDENCIA EN WAZUH" in text and "WIN-TEST01" in text
    assert "Evidencia en Wazuh" in html and "WIN-TEST01" in html
    blocks = _evidence_blocks(alert)
    assert blocks and "Evidencia en Wazuh" in blocks[0]["text"]
    assert len(blocks[1]["text"]) <= 700


def test_email_and_teams_unchanged_without_evidence():
    alert = _alert()
    assert "EVIDENCIA EN WAZUH" not in _build_text_body(alert, _plan(), "http://a", "http://r")
    assert _evidence_blocks(alert) == []


class _Client:
    comments: list[str] = []
    def __init__(self, *_a, **_k): ...
    async def __aenter__(self): return self
    async def __aexit__(self, *_a): ...
    async def add_comment(self, rid, body, internal=False, **_k):
        _Client.comments.append(body)


def _followup_env(monkeypatch, summaries):
    _Client.comments = []
    monkeypatch.setattr("src.tools.invgate.InvgateClient", _Client)
    queue = list(summaries)
    monkeypatch.setattr(auth_spray, "summarize_auth_failures", lambda _a: queue.pop(0) if len(queue) > 1 else queue[0])


def _summary(end_minutes_ago: float, failures: int, *, burst: bool = True):
    now = datetime.now(tz=timezone.utc)
    s = auth_spray.AuthSpraySummary(start=now - timedelta(hours=2),
                                    end=now - timedelta(minutes=end_minutes_ago))
    s.failures, s.burst_found = failures, burst
    s.first_seen = s.last_seen = "09:00"
    s.names["x"] = failures
    s.by_agent["SRVDC2"] = failures
    s.by_status["0xc0000064"] = failures
    return s


async def _noop_sleep(_s): ...


def test_followup_waits_for_quiet_then_comments_once(monkeypatch):
    alert = _alert()
    alert.wazuh_evidence = _summary(0, 300).to_text()
    _followup_env(monkeypatch, [_summary(1, 600), _summary(3, 900), _summary(30, 1679)])
    ok = asyncio.run(main._spray_followup_safely(Settings(), alert, 5464, sleep=_noop_sleep))
    assert ok is True and len(_Client.comments) == 1
    assert "1679 fallos" in _Client.comments[0] and "terminó" in _Client.comments[0]


def test_followup_skips_when_nothing_new_or_no_burst(monkeypatch):
    alert = _alert()
    same = _summary(30, 300)
    alert.wazuh_evidence = same.to_text()
    _followup_env(monkeypatch, [same])
    assert asyncio.run(main._spray_followup_safely(Settings(), alert, 1, sleep=_noop_sleep)) is False
    _followup_env(monkeypatch, [_summary(30, 5, burst=False)])
    assert asyncio.run(main._spray_followup_safely(Settings(), alert, 1, sleep=_noop_sleep)) is False
    assert _Client.comments == []


def test_followup_gives_up_after_max_wait(monkeypatch):
    alert = _alert()
    alert.wazuh_evidence = "x"
    _followup_env(monkeypatch, [_summary(0, 900)])  # nunca se calma
    ok = asyncio.run(main._spray_followup_safely(Settings(), alert, 1, sleep=_noop_sleep,
                                           poll_seconds=300, max_seconds=900))
    assert ok is False and _Client.comments == []
