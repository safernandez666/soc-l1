"""Tests for the CLI email wireup in `once`."""
from datetime import datetime, timezone
from unittest.mock import patch

from src.wazuh_health.contracts import ProbeResult
from src.wazuh_health.cli import _build_email_notifier, _maybe_send_digest_email
from src.wazuh_health.config.settings import load_config
from src.wazuh_health.store.audit_store import AuditStore
from src.wazuh_health.store.db import connect, migrate


def _set_email_env(monkeypatch, **extra):
    monkeypatch.setenv("OPENAI_MODEL_LIGHT", "gpt-4o-mini")
    monkeypatch.setenv("OPENAI_MODEL_HEAVY", "gpt-4o")
    monkeypatch.setenv("WAZUH_HEALTH_EMAIL_TO", "ops@example.com")
    for k, v in extra.items():
        monkeypatch.setenv(k, v)


def test_no_email_notifier_when_recipient_unset(monkeypatch):
    monkeypatch.delenv("WAZUH_HEALTH_EMAIL_TO", raising=False)
    monkeypatch.setenv("OPENAI_MODEL_LIGHT", "gpt-4o-mini")
    monkeypatch.setenv("OPENAI_MODEL_HEAVY", "gpt-4o")
    cfg = load_config()
    assert _build_email_notifier(cfg) is None


def test_email_notifier_built_when_recipient_set(monkeypatch):
    _set_email_env(monkeypatch,
                   WAZUH_HEALTH_SMTP_HOST="smtp.gmail.com",
                   WAZUH_HEALTH_SMTP_PORT="587",
                   WAZUH_HEALTH_SMTP_TLS="true",
                   WAZUH_HEALTH_SMTP_USER="bot@example.com",
                   WAZUH_HEALTH_SMTP_PASSWORD="abcd")
    cfg = load_config()
    n = _build_email_notifier(cfg)
    assert n is not None
    assert n._host == "smtp.gmail.com"
    assert n._port == 587
    assert n._use_tls is True
    assert n._user == "bot@example.com"
    assert n._to == "ops@example.com"


def test_maybe_send_digest_email_sends_when_configured(monkeypatch):
    _set_email_env(monkeypatch)
    cfg = load_config()
    conn = connect(":memory:"); migrate(conn)
    audit = AuditStore(conn)
    audit.record_probe_run(ProbeResult(
        probe="capacity", run_at=datetime.now(tz=timezone.utc),
        metrics={"disk.var_ossec.free_pct": 50.0}, artifacts={}, errors=[],
    ))
    with patch("smtplib.SMTP") as cls:
        smtp = cls.return_value.__enter__.return_value
        sent = _maybe_send_digest_email(cfg, audit)
        assert sent is True
        smtp.send_message.assert_called_once()


def test_maybe_send_digest_email_skips_when_unconfigured(monkeypatch):
    monkeypatch.delenv("WAZUH_HEALTH_EMAIL_TO", raising=False)
    monkeypatch.setenv("OPENAI_MODEL_LIGHT", "gpt-4o-mini")
    monkeypatch.setenv("OPENAI_MODEL_HEAVY", "gpt-4o")
    cfg = load_config()
    conn = connect(":memory:"); migrate(conn)
    audit = AuditStore(conn)
    with patch("smtplib.SMTP") as cls:
        sent = _maybe_send_digest_email(cfg, audit)
        assert sent is False
        cls.assert_not_called()
