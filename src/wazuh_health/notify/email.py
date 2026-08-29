"""Email notifier — periodic reports only, no per-finding spam.

Supports plain SMTP (localhost:25), STARTTLS (port 587, Gmail / Office365),
and implicit TLS (port 465). Authenticates if `smtp_user` is provided.
"""
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
        smtp_user: str | None = None,
        smtp_password: str | None = None,
        use_tls: bool = False,
        timeout_s: float = 30.0,
    ) -> None:
        self._to = to
        self._sender = sender
        self._host = smtp_host
        self._port = smtp_port
        self._user = smtp_user
        self._password = smtp_password
        self._use_tls = use_tls
        self._timeout = timeout_s

    def notify_finding(self, finding: DomainFinding) -> None:
        return None  # report-only by design

    def _send(self, msg: EmailMessage) -> None:
        # Implicit TLS on 465 → SMTP_SSL. Everything else → SMTP + optional STARTTLS.
        if self._port == 465:
            with smtplib.SMTP_SSL(self._host, self._port, timeout=self._timeout) as smtp:
                if self._user:
                    smtp.login(self._user, self._password or "")
                smtp.send_message(msg)
            return
        with smtplib.SMTP(self._host, self._port, timeout=self._timeout) as smtp:
            if self._use_tls:
                smtp.starttls()
            if self._user:
                smtp.login(self._user, self._password or "")
            smtp.send_message(msg)

    def notify_report(
        self, report: WazuhHealthReport, *, markdown: str, subject: str | None = None
    ) -> Path | None:
        msg = EmailMessage()
        msg["From"] = self._sender
        msg["To"] = self._to
        msg["Subject"] = subject or f"Wazuh Health Report ({report.window_hours}h)"
        msg.set_content(markdown)
        self._send(msg)
        return None

    def notify_digest(
        self, *, subject: str, markdown: str, html: str | None = None
    ) -> None:
        """Send the digest. Con `html` va multipart, si no queda solo texto.

        Lo usa `wazuh-health once` para mandar el resultado de los probes sin
        invocar al LLM. El Markdown viaja como parte text/plain: en un cliente
        de correo, solo, se veían los `#` y los `**` literales.
        """
        if html is None:
            msg = EmailMessage()
            msg["From"] = self._sender
            msg["To"] = self._to
            msg["Subject"] = subject
            msg.set_content(markdown)
            self._send(msg)
            return

        # El armado lo hace report_theme: Date, Message-ID, quoted-printable y
        # el logo por Content-ID. Ver la nota de build_message() sobre No Deseado.
        from src import report_theme as T

        self._send(
            T.build_message(
                from_addr=self._sender,
                recipients=[t.strip() for t in self._to.split(",") if t.strip()],
                subject=subject,
                html=html,
                plain=markdown,
                logo_bytes=T.load_logo(),
            )
        )
