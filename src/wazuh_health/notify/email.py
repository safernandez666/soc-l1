"""Email notifier — periodic reports only, no per-finding spam."""
from __future__ import annotations

import smtplib
from email.message import EmailMessage
from pathlib import Path

from src.wazuh_health.contracts import DomainFinding, WazuhHealthReport


class EmailNotifier:
    enabled: bool = True

    def __init__(
        self,
        *,
        to: str,
        smtp_host: str = "localhost",
        smtp_port: int = 25,
        sender: str = "wazuh-health@localhost",
    ) -> None:
        self._to = to
        self._sender = sender
        self._host = smtp_host
        self._port = smtp_port

    def notify_finding(self, finding: DomainFinding) -> None:
        return None  # report-only by design

    def notify_report(self, report: WazuhHealthReport, *, markdown: str) -> Path | None:
        msg = EmailMessage()
        msg["From"] = self._sender
        msg["To"] = self._to
        msg["Subject"] = f"Wazuh Health Report ({report.window_hours}h)"
        msg.set_content(markdown)
        with smtplib.SMTP(self._host, self._port) as smtp:
            smtp.send_message(msg)
        return None
