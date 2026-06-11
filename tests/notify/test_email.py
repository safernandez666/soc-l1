from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from src.wazuh_health.contracts import WazuhHealthReport
from src.wazuh_health.notify.email import EmailNotifier


def test_email_notifier_only_sends_periodic_reports():
    n = EmailNotifier(to="ops@example.com", smtp_host="localhost")
    with patch("smtplib.SMTP") as smtp_cls:
        smtp = MagicMock()
        smtp_cls.return_value.__enter__.return_value = smtp
        report = WazuhHealthReport(
            generated_at=datetime.now(tz=timezone.utc),
            window_hours=6, summary="ok",
            by_domain={"hygiene": [], "capacity": [], "coverage": []},
            top_priorities=[],
        )
        n.notify_report(report, markdown="# report")
        smtp.send_message.assert_called_once()
