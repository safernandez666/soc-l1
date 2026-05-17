"""SMTP mailer - envío de emails de aprobación.

Diseño visual alineado con el integrator unified de Wazuh (mismo system: banner
de severidad con border-left, info-table, cards con border-left coloreado).

Stdlib (smtplib + email.message) corriendo bajo asyncio.to_thread para no
agregar deps. Soporta STARTTLS y self-signed certs via ssl_verify=False.

Outlook 2016 + Exchange:
  - Todo CSS crítico (colores, padding) está inline en cada elemento
  - Tablas para layout (no flexbox/grid - el motor Word de Outlook no las entiende)
  - Sin media queries (asume desktop)
  - Sin imágenes embedded (CID se marcan como blocked content en muchos webmails)
"""
from __future__ import annotations

import asyncio
import html
import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

from src.agents.narrator import NarratorPlan
from src.config import Settings
from src.models import NormalizedAlert

logger = logging.getLogger("soc-l1")


# ===== Design tokens (mismos hex que el integrator unified Wazuh v4.9) =====

SEV_STYLES = {
    "critical": {"bg": "#7f1d1d", "label": "SEVERIDAD CRÍTICA"},
    "high":     {"bg": "#991b1b", "label": "🚨 SEVERIDAD ALTA"},
    "medium":   {"bg": "#b45309", "label": "⚠️ SEVERIDAD MEDIA"},
    "low":      {"bg": "#a16207", "label": "SEVERIDAD BAJA"},
}
_DEFAULT_SEV = {"bg": "#475569", "label": "ALERTA"}

BADGE_STYLES = {
    "default":  ("#f1f5f9", "#334155"),
    "info":     ("#dbeafe", "#1e40af"),
    "success":  ("#dcfce7", "#166534"),
    "warning":  ("#fef3c7", "#92400e"),
    "danger":   ("#fee2e2", "#7f1d1d"),
    "critical": ("#7f1d1d", "#ffffff"),
}


def _esc(x: Any) -> str:
    """html.escape con fallback a '-' para None/empty."""
    if x is None or x == "" or x == []:
        return "-"
    return html.escape(str(x))


def _badge(text: str, style: str = "default") -> str:
    bg, fg = BADGE_STYLES.get(style, BADGE_STYLES["default"])
    return (
        f"<span style=\"display:inline-block;padding:4px 12px;border-radius:16px;"
        f"background:{bg};color:{fg};font:bold 11px/14px sans-serif;"
        f"text-transform:uppercase;\">{html.escape(text)}</span>"
    )


def _risk_badge_style(risk: str) -> str:
    """Mapea risk_level del Narrator a la key de BADGE_STYLES."""
    return {
        "critical": "critical",
        "high":     "danger",
        "medium":   "warning",
        "low":      "info",
    }.get(risk, "default")


# ===== Plain text body (fallback) =====


def _build_text_body(
    alert: NormalizedAlert,
    plan: NarratorPlan,
    approve_url: str,
    reject_url: str,
) -> str:
    lines: list[str] = []
    lines.append("SOC L1 - APROBACION REQUERIDA")
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


# ===== HTML body con design system =====


def _ctx_rows(alert: NormalizedAlert, plan: NarratorPlan) -> str:
    """Construye los <tr> de la tabla de contexto."""
    sev_badge_style = "critical" if alert.severity_source in ("critical", "high") else "warning"

    rows: list[tuple[str, str]] = [
        ("Alert ID",       f"<code>{_esc(alert.alert_id)}</code>"),
        ("Host",           (
            f"<strong>{_esc(alert.device.hostname)}</strong>"
            + (f" <code style='color:#64748b;'>{_esc(alert.device.internal_ip)}</code>"
               if alert.device.internal_ip else "")
        )),
        ("Severidad Wazuh", _badge(alert.severity_source.upper(), sev_badge_style)),
        ("Risk asignado",   _badge(plan.risk_level.upper(), _risk_badge_style(plan.risk_level))),
        ("Wazuh rule",     f"{_esc(alert.wazuh_rule.id)} (level {alert.wazuh_rule.level})"),
        ("Categoría",      _esc(alert.category)),
        ("Source",         _esc(alert.source)),
        ("Timestamp",      f"<code style='font-size:12px;'>{_esc(alert.timestamp)}</code>"),
    ]

    # Usuarios involucrados
    if alert.users_involved:
        users_html = ", ".join(
            f"<code>{_esc(u.sam)}</code> "
            f"<span style='color:#64748b;font-size:11px;'>({_esc(u.role)})</span>"
            for u in alert.users_involved
        )
        rows.append(("Usuarios", users_html))

    # Archivos
    if alert.files:
        files_html_parts = []
        for f in alert.files[:3]:  # cap a 3 para no inundar el email
            badge_style = "critical" if (f.verdict or "").lower() == "malicious" else "warning"
            badge_html = _badge(f.verdict or "unknown", badge_style)
            name = f.name or "(sin nombre)"
            sha = (f.sha256[:16] + "…") if f.sha256 else "-"
            files_html_parts.append(
                f"{badge_html} <strong>{_esc(name)}</strong> "
                f"<code style='font-size:11px;color:#64748b;'>{_esc(sha)}</code>"
            )
        files_html = "<br>".join(files_html_parts)
        if len(alert.files) > 3:
            files_html += f"<br><em style='color:#64748b;'>+{len(alert.files) - 3} más…</em>"
        rows.append(("Archivos", files_html))

    return "\n".join(
        f"<tr><td class='label'>{label}:</td><td class='value'>{value}</td></tr>"
        for label, value in rows
    )


def _actions_html(plan: NarratorPlan) -> str:
    """Lista <li> con cada acción propuesta."""
    if not plan.actions:
        return (
            "<li style='color:#64748b;font-style:italic;'>"
            "(ninguna - monitor only)</li>"
        )
    items = []
    for a in plan.actions:
        items.append(
            f"<li><strong>{_esc(a.type)}</strong> → "
            f"<code style='background:#e0f2fe;padding:2px 6px;border-radius:3px;'>"
            f"{_esc(a.target)}</code>"
            f"<div style='font-size:12px;color:#475569;margin-top:4px;line-height:1.5;'>"
            f"{_esc(a.justification)}</div></li>"
        )
    return "\n".join(items)


def _build_html_body(
    alert: NormalizedAlert,
    plan: NarratorPlan,
    approve_url: str,
    reject_url: str,
    ttl_hours: int = 24,
    review_url: str | None = None,
) -> str:
    """Renderiza el email HTML matcheando el design system del integrator Wazuh unified v4.9.

    Layout (idéntico al Wazuh original):
      - Header con border-left por severidad (NO banner top coloreado completo)
      - 2 badges inline en header: rule# + risk asignado
      - Pivot section destacando la info principal (host + archivo)
      - Info-table con todos los campos
      - Card amarilla "Recomendación" (= nuestro Análisis del Narrator)
      - Card azul "Acciones Sugeridas" (= nuestras ProposedActions)
      - Approval section subtle al final (botones APROBAR/RECHAZAR)
      - Footer

    Color del border-left = plan.risk_level (assessment del Narrator).
    """
    sev_cfg = SEV_STYLES.get(plan.risk_level, _DEFAULT_SEV)
    color = sev_cfg["bg"]
    risk_badge_key = _risk_badge_style(plan.risk_level)
    risk_badge_html = _badge(plan.risk_level.upper(), risk_badge_key)
    rule_badge_html = _badge(
        f"RULE {alert.wazuh_rule.id or '?'} • NIVEL {alert.wazuh_rule.level}",
        "info",
    )

    # Pivot value: lo más jugoso de la alerta. Host + archivo malicious (si hay).
    pivot_value = f"<strong>{_esc(alert.device.hostname)}</strong>"
    if alert.files:
        f0 = alert.files[0]
        verdict_txt = (f0.verdict or "unknown").lower()
        verdict_style = "critical" if verdict_txt == "malicious" else "warning"
        pivot_value += (
            f" → {_badge(verdict_txt, verdict_style)} "
            f"<code>{_esc(f0.name)}</code>"
        )
    elif alert.users_involved:
        sams = ", ".join(_esc(u.sam) for u in alert.users_involved[:3])
        pivot_value += f" → usuarios: {sams}"

    # Si tenemos review_url, mandamos UN solo botón "Revisar y decidir" que abre la
    # página con checkboxes per-action. Si no, fallback al patrón viejo (2 botones).
    if review_url:
        cta_buttons = (
            f"<a href='{html.escape(review_url)}' "
            f"style='display:inline-block;background:{color};color:white;"
            f"padding:14px 32px;text-decoration:none;border-radius:6px;"
            f"font-weight:bold;font-size:14px;margin:4px 8px;'>"
            f"📋 REVISAR Y DECIDIR</a>"
        )
    else:
        cta_buttons = (
            f"<a href='{html.escape(approve_url)}' "
            f"style='display:inline-block;background:#16a34a;color:white;"
            f"padding:12px 28px;text-decoration:none;border-radius:6px;"
            f"font-weight:bold;font-size:14px;margin:4px 8px;'>"
            f"✅ APROBAR Y EJECUTAR</a>"
            f"<a href='{html.escape(reject_url)}' "
            f"style='display:inline-block;background:#dc2626;color:white;"
            f"padding:12px 28px;text-decoration:none;border-radius:6px;"
            f"font-weight:bold;font-size:14px;margin:4px 8px;'>"
            f"❌ RECHAZAR</a>"
        )

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>SOC L1 — {_esc(alert.title)}</title>
  <style>
    body {{ font-family: sans-serif; background: #f8fafc; margin: 0; padding: 20px; }}
    .container {{ max-width: 800px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; }}
    .header {{ padding: 24px; border-left: 8px solid {color}; background: #f8fafc; }}
    .title {{ font-size: 24px; font-weight: bold; margin-bottom: 8px; color: #0f172a; }}
    .pivot-section {{ background: #fef2f2; padding: 16px; margin: 20px; border-radius: 8px; border-left: 4px solid {color}; }}
    .pivot-label {{ font-weight: bold; color: #374151; margin-bottom: 4px; font-size: 13px; }}
    .pivot-value {{ font-family: monospace; font-size: 15px; font-weight: bold; color: #1f2937; }}
    .info-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
    .info-table td {{ padding: 12px 16px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
    .info-table .label {{ font-weight: bold; width: 160px; background: #f9fafb; color: #475569; font-size: 13px; }}
    .info-table .value {{ font-size: 13px; color: #0f172a; }}
    .approval-section {{ background: #f8fafc; padding: 24px; margin: 20px; border-radius: 8px; border: 1px solid #e5e7eb; text-align: center; }}
    .footer {{ padding: 16px; background: #f8fafc; text-align: center; font-size: 12px; color: #64748b; }}
    code {{ font-family: 'SF Mono', Monaco, monospace; font-size: 12px; }}
  </style>
</head>
<body>
  <div class="container">

    <!-- Header con border-left por severidad (estilo Wazuh) -->
    <div class="header">
      <div class="title">{_esc(alert.title)}</div>
      <div style="font-size:14px;color:#64748b;margin-top:4px;">
        {_esc(alert.wazuh_rule.description)}
      </div>
      <div style="margin-top:10px;">
        {rule_badge_html}
        {risk_badge_html}
      </div>
    </div>

    <!-- Pivot section: info principal destacada -->
    <div class="pivot-section">
      <div class="pivot-label">Información Principal:</div>
      <div class="pivot-value">{pivot_value}</div>
    </div>

    <!-- Resumen ejecutivo del Narrator (estilo párrafo, fuera de tabla) -->
    <div style="padding:0 24px;">
      <div style="font-weight:bold;color:#0f172a;font-size:14px;margin-bottom:8px;">
        📝 Resumen ejecutivo
      </div>
      <div style="color:#334155;font-size:14px;line-height:1.6;white-space:pre-line;">
        {_esc(plan.executive_summary)}
      </div>
    </div>

    <!-- Info-table (estilo Wazuh exacto) -->
    <div style="padding:0 24px;">
      <table class="info-table">
        {_ctx_rows(alert, plan)}
      </table>
    </div>

    <!-- Card amarilla "Recomendación" (= Análisis del Narrator) -->
    <div style="background:#fef3c7;padding:16px;margin:20px;border-radius:8px;border-left:4px solid #f59e0b;">
      <div style="font-weight:bold;color:#92400e;margin-bottom:8px;font-size:14px;">
        💡 Análisis del incidente:
      </div>
      <div style="color:#78350f;font-size:13px;line-height:1.6;white-space:pre-line;">
        {_esc(plan.rationale)}
      </div>
    </div>

    <!-- Card azul "Acciones Sugeridas" (= ProposedActions del Narrator) -->
    <div style="background:#f0f9ff;padding:16px;margin:20px;border-radius:8px;border-left:4px solid #0284c7;">
      <div style="font-weight:bold;color:#0c4a6e;margin-bottom:12px;font-size:14px;">
        📋 Acciones propuestas ({len(plan.actions)}):
      </div>
      <ul style="margin:8px 0;padding-left:24px;color:#075985;font-size:13px;line-height:1.8;">
        {_actions_html(plan)}
      </ul>
    </div>

    <!-- Approval section: sutil, sin banner fuerte -->
    <div class="approval-section">
      <div style="font-weight:bold;color:#0f172a;font-size:14px;margin-bottom:6px;">
        ⚠️ Esta alerta requiere tu aprobación
      </div>
      <div style="color:#64748b;font-size:12px;margin-bottom:16px;">
        Link single-use, válido por {ttl_hours}h. Primer click decide.
      </div>
      {cta_buttons}
    </div>

    <div class="footer">
      <strong>SOC L1 · Wazuh + Defender</strong> • Pipeline multi-agente<br>
      Generado automáticamente — no responder a este email.
    </div>
  </div>
</body>
</html>
"""


# ===== Message build + send =====


def _build_message(
    settings: Settings,
    alert: NormalizedAlert,
    plan: NarratorPlan,
    token: str,
) -> EmailMessage:
    approve_url = f"{settings.approval_base_url.rstrip('/')}/approve/{token}"
    reject_url = f"{settings.approval_base_url.rstrip('/')}/reject/{token}"

    sev_label = SEV_STYLES.get(plan.risk_level, _DEFAULT_SEV)["label"]
    # Limpiar emoji para subject (Exchange/Outlook a veces los quema)
    sev_clean = sev_label.replace("🚨 ", "").replace("⚠️ ", "")

    msg = EmailMessage()
    msg["Subject"] = (
        f"[SOC L1][{plan.risk_level.upper()}] {alert.device.hostname or 'unknown'} - "
        f"{alert.title[:60]}"
    )
    msg["From"] = settings.smtp_from
    msg["To"] = settings.smtp_to_approvers
    msg.set_content(_build_text_body(alert, plan, approve_url, reject_url))
    review_url = f"{settings.approval_base_url.rstrip('/')}/review/{token}"
    msg.add_alternative(
        _build_html_body(
            alert, plan, approve_url, reject_url,
            ttl_hours=settings.approval_ttl_hours,
            review_url=review_url,
        ),
        subtype="html",
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
