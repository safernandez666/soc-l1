"""Tests for the extended EmailNotifier (auth + STARTTLS + implicit TLS)."""
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from src.wazuh_health.contracts import WazuhHealthReport
from src.wazuh_health.notify.email import EmailNotifier


def _report():
    return WazuhHealthReport(
        generated_at=datetime.now(tz=timezone.utc),
        window_hours=6, summary="ok",
        by_domain={"hygiene": [], "capacity": [], "coverage": []},
        top_priorities=[],
    )


def test_starttls_login_path():
    n = EmailNotifier(
        to="a@b.com", smtp_host="smtp.gmail.com", smtp_port=587,
        sender="from@b.com", smtp_user="u", smtp_password="p", use_tls=True,
    )
    with patch("smtplib.SMTP") as cls:
        smtp = MagicMock()
        cls.return_value.__enter__.return_value = smtp
        n.notify_report(_report(), markdown="# r")
        cls.assert_called_once_with("smtp.gmail.com", 587, timeout=30.0)
        smtp.starttls.assert_called_once()
        smtp.login.assert_called_once_with("u", "p")
        smtp.send_message.assert_called_once()


def test_implicit_tls_uses_smtp_ssl():
    n = EmailNotifier(
        to="a@b.com", smtp_host="smtp.gmail.com", smtp_port=465,
        sender="from@b.com", smtp_user="u", smtp_password="p", use_tls=False,
    )
    with patch("smtplib.SMTP_SSL") as cls:
        smtp = MagicMock()
        cls.return_value.__enter__.return_value = smtp
        n.notify_report(_report(), markdown="# r")
        cls.assert_called_once()
        smtp.login.assert_called_once_with("u", "p")


def test_plain_smtp_no_auth_no_tls():
    n = EmailNotifier(to="a@b.com", smtp_host="localhost", smtp_port=25)
    with patch("smtplib.SMTP") as cls:
        smtp = MagicMock()
        cls.return_value.__enter__.return_value = smtp
        n.notify_report(_report(), markdown="# r")
        smtp.starttls.assert_not_called()
        smtp.login.assert_not_called()
        smtp.send_message.assert_called_once()


def test_notify_digest_path():
    n = EmailNotifier(to="a@b.com")
    with patch("smtplib.SMTP") as cls:
        smtp = MagicMock()
        cls.return_value.__enter__.return_value = smtp
        n.notify_digest(subject="x", markdown="# y")
        smtp.send_message.assert_called_once()


def test_custom_subject_overrides_default():
    n = EmailNotifier(to="a@b.com")
    with patch("smtplib.SMTP") as cls:
        smtp = MagicMock()
        cls.return_value.__enter__.return_value = smtp
        n.notify_report(_report(), markdown="# r", subject="my-subject")
        sent_msg = smtp.send_message.call_args.args[0]
        assert sent_msg["Subject"] == "my-subject"
