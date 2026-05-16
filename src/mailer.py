"""SMTP mailer - envío de emails de aprobación.

Stdlib (smtplib + email.message) corriendo bajo asyncio.to_thread para no
agregar deps. Soporta STARTTLS (necesario para Exchange 2016 según el server
de Example Corp) y self-signed certs via ssl_verify=False.

Renderiza email multipart (text/plain + text/html) con links de approve/reject.
"""
from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
from email.message import EmailMessage
from html import escape

from src.agents.narrator import NarratorPlan
from src.config import Settings
from src.models import NormalizedAlert

logger = logging.getLogger("soc-l1")


def _build_text_body(
    alert: NormalizedAlert,
    plan: NarratorPlan,
    approve_url: str,
    reject_url: str,
) -> str:
    lines: list[str] = []
    lines.append(f"SOC L1 - APROBACION REQUERIDA")
    lines.append(f"Risk: {plan.risk_level.upper()}")
    lines.append("=" * 60)
    lines.append("")
    lines.append("RESUMEN EJECUTIVO")
    lines.append(plan.executive_summary)
    lines.append("")
    lines.append("CONTEXTO")
    lines.append(f"  Alert ID:  {alert.alert_id}")
    lines.append(f"  Host:      {alert.device.hostname or '(sin host)'}")
    lines.append(f"  Severity:  {alert.severity_source}")
    lines.append(f"  Wazuh:     rule {alert.wazuh_rule.id} (level {alert.wazuh_rule.level})")
    lines.append(f"  Title:     {alert.title}")
    lines.append("")
    lines.append(f"ACCIONES PROPUESTAS ({len(plan.actions)})")
    if not plan.actions:
        lines.append("  (ninguna - monitor only)")
    for i, a in enumerate(plan.actions, 1):
        lines.append(f"  {i}. {a.type} → {a.target}")
        lines.append(f"     {a.justification}")
    lines.append("")
    lines.append("ANALISIS")
    lines.append(plan.rationale)
    lines.append("")
    lines.append("=" * 60)
    lines.append("DECISION (single-use, TTL 24h):")
    lines.append(f"  APROBAR:  {approve_url}")
    lines.append(f"  RECHAZAR: {reject_url}")
    lines.append("")
    lines.append("Soc L1 - Example Corp")
    return "\n".join(lines)


def _build_html_body(
    alert: NormalizedAlert,
    plan: NarratorPlan,
    approve_url: str,
    reject_url: str,
) -> str:
    risk_color = {
        "low": "#28a745",
        "medium": "#ffc107",
        "high": "#fd7e14",
        "critical": "#dc3545",
    }.get(plan.risk_level, "#6c757d")

    actions_html = ""
    if not plan.actions:
        actions_html = "<li><em>(ninguna - monitor only)</em></li>"
    else:
        for a in plan.actions:
            actions_html += (
                f"<li><strong>{escape(a.type)}</strong> → "
                f"<code>{escape(a.target)}</code><br>"
                f"<small>{escape(a.justification)}</small></li>"
            )

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, system-ui, sans-serif; max-width: 720px; margin: 20px auto; color: #222;">
  <h2 style="margin-bottom: 4px;">SOC L1 — Aprobación requerida</h2>
  <p style="margin-top: 0;">
    <span style="background: {risk_color}; color: white; padding: 3px 10px; border-radius: 4px; font-weight: bold; font-size: 12px;">
      RISK: {escape(plan.risk_level.upper())}
    </span>
  </p>

  <h3>Resumen ejecutivo</h3>
  <p>{escape(plan.executive_summary)}</p>

  <h3>Contexto</h3>
  <ul>
    <li><strong>Alert ID:</strong> <code>{escape(alert.alert_id)}</code></li>
    <li><strong>Host:</strong> {escape(alert.device.hostname or "(sin host)")}</li>
    <li><strong>Severity:</strong> {escape(alert.severity_source)}</li>
    <li><strong>Wazuh rule:</strong> {escape(str(alert.wazuh_rule.id))} (level {alert.wazuh_rule.level})</li>
    <li><strong>Title:</strong> {escape(alert.title)}</li>
  </ul>

  <h3>Acciones propuestas ({len(plan.actions)})</h3>
  <ul>{actions_html}</ul>

  <h3>Análisis</h3>
  <p style="white-space: pre-wrap;">{escape(plan.rationale)}</p>

  <hr>
  <p style="margin: 24px 0;">
    <a href="{escape(approve_url)}"
       style="background: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; margin-right: 8px;">
      ✓ APROBAR
    </a>
    <a href="{escape(reject_url)}"
       style="background: #dc3545; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold;">
      ✗ RECHAZAR
    </a>
  </p>
  <p style="font-size: 11px; color: #888;">
    Single-use, TTL 24h. Primer click decide.<br>
    Soc L1 — Example Corp
  </p>
</body></html>
"""


def _build_message(
    settings: Settings,
    alert: NormalizedAlert,
    plan: NarratorPlan,
    token: str,
) -> EmailMessage:
    approve_url = f"{settings.approval_base_url.rstrip('/')}/approve/{token}"
    reject_url = f"{settings.approval_base_url.rstrip('/')}/reject/{token}"

    msg = EmailMessage()
    msg["Subject"] = (
        f"[SOC L1][{plan.risk_level.upper()}] {alert.device.hostname or 'unknown'} - "
        f"{alert.title[:60]}"
    )
    msg["From"] = settings.smtp_from
    msg["To"] = settings.smtp_to_approvers
    msg.set_content(_build_text_body(alert, plan, approve_url, reject_url))
    msg.add_alternative(
        _build_html_body(alert, plan, approve_url, reject_url), subtype="html"
    )
    return msg


def _send_sync(settings: Settings, msg: EmailMessage) -> None:
    """Conexión SMTP sincrónica con STARTTLS opcional. Corre bajo to_thread."""
    if settings.smtp_use_starttls:
        ctx = ssl.create_default_context()
        if not settings.smtp_ssl_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20) as srv:
            srv.ehlo()
            srv.starttls(context=ctx)
            srv.ehlo()
            if settings.smtp_user and settings.smtp_password:
                srv.login(settings.smtp_user, settings.smtp_password)
            srv.send_message(msg)
    else:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20) as srv:
            if settings.smtp_user and settings.smtp_password:
                srv.login(settings.smtp_user, settings.smtp_password)
            srv.send_message(msg)


async def send_approval_email(
    settings: Settings,
    alert: NormalizedAlert,
    plan: NarratorPlan,
    token: str,
) -> None:
    """Envía email de aprobación. Si SMTP no está configurado, loggea y skip."""
    if not settings.smtp_host or not settings.smtp_to_approvers:
        logger.warning(
            "mailer: SMTP no configurado (host=%r to=%r) - skip email para alert=%s",
            settings.smtp_host,
            settings.smtp_to_approvers,
            alert.alert_id,
        )
        return

    msg = _build_message(settings, alert, plan, token)
    try:
        await asyncio.to_thread(_send_sync, settings, msg)
        logger.info(
            "mailer: email enviado | alert=%s to=%s subject=%r",
            alert.alert_id,
            settings.smtp_to_approvers,
            msg["Subject"],
        )
    except Exception:
        logger.exception(
            "mailer: send failed | alert=%s to=%s",
            alert.alert_id,
            settings.smtp_to_approvers,
        )
        raise
