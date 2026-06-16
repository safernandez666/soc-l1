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
from datetime import datetime
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
    "default":  ("#23272f", "#cbd5e1"),
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
    invgate_request_id: int | None = None,
) -> str:
    lines: list[str] = []
    lines.append("SOC L1 - APROBACION REQUERIDA")
    ticket_tag = f" | InvGate ticket #{invgate_request_id}" if invgate_request_id else ""
    lines.append(f"Risk: {plan.risk_level.upper()}{ticket_tag}")
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
    lines.append("SOC L1")
    return "\n".join(lines)


# ===== HTML body con design system =====


def _ctx_rows(alert: NormalizedAlert, plan: NarratorPlan) -> str:
    """Construye los <tr> de la tabla de contexto."""
    sev_badge_style = "critical" if alert.severity_source in ("critical", "high") else "warning"

    rows: list[tuple[str, str]] = [
        ("Alert ID",       f"<code>{_esc(alert.alert_id)}</code>"),
        ("Host",           (
            f"<strong>{_esc(alert.device.hostname)}</strong>"
            + (f" <code style='color:#94a3b8;'>{_esc(alert.device.internal_ip)}</code>"
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
            f"<span style='color:#94a3b8;font-size:11px;'>({_esc(u.role)})</span>"
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
                f"<code style='font-size:11px;color:#94a3b8;'>{_esc(sha)}</code>"
            )
        files_html = "<br>".join(files_html_parts)
        if len(alert.files) > 3:
            files_html += f"<br><em style='color:#94a3b8;'>+{len(alert.files) - 3} más…</em>"
        rows.append(("Archivos", files_html))

    return "\n".join(
        f"<tr><td class='label'>{label}:</td><td class='value'>{value}</td></tr>"
        for label, value in rows
    )


def _actions_html(plan: NarratorPlan) -> str:
    """Lista <li> con cada acción propuesta."""
    if not plan.actions:
        return (
            "<li style='color:#94a3b8;font-style:italic;'>"
            "(ninguna - monitor only)</li>"
        )
    items = []
    for a in plan.actions:
        items.append(
            f"<li><strong>{_esc(a.type)}</strong> → "
            f"<code style='background:#1b2b3a;padding:2px 6px;border-radius:3px;'>"
            f"{_esc(a.target)}</code>"
            f"<div style='font-size:12px;color:#94a3b8;margin-top:4px;line-height:1.5;'>"
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
    invgate_request_id: int | None = None,
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
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark light">
  <meta name="supported-color-schemes" content="dark light">
  <title>SOC L1 — {_esc(alert.title)}</title>
  <style>
    :root {{ color-scheme: dark light; supported-color-schemes: dark light; }}
    body {{ font-family: sans-serif; background-color:#0b0d10; margin:0; padding:20px; color:#e5e7eb; }}
    .container {{ max-width:800px; margin:0 auto; background-color:#14171c; border:1px solid #23272f; border-radius:12px; overflow:hidden; }}
    .header {{ padding:24px; border-left:8px solid {color}; background-color:#0b0d10; }}
    .title {{ font-size:24px; font-weight:bold; margin-bottom:8px; color:#f3f4f6; }}
    .pivot-section {{ background-color:#1b1f26; padding:16px; margin:20px; border-radius:8px; border-left:4px solid {color}; }}
    .pivot-label {{ font-weight:bold; color:#94a3b8; margin-bottom:4px; font-size:13px; }}
    .pivot-value {{ font-family:monospace; font-size:15px; font-weight:bold; color:#f3f4f6; }}
    .info-table {{ width:100%; border-collapse:collapse; margin:20px 0; }}
    .info-table td {{ padding:12px 16px; border-bottom:1px solid #23272f; vertical-align:top; }}
    .info-table .label {{ font-weight:bold; width:160px; background-color:#1b1f26; color:#94a3b8; font-size:13px; }}
    .info-table .value {{ font-size:13px; color:#e5e7eb; }}
    .approval-section {{ background-color:#1b1f26; padding:24px; margin:20px; border-radius:8px; border:1px solid #23272f; text-align:center; }}
    .footer {{ padding:16px; background-color:#0b0d10; text-align:center; font-size:12px; color:#94a3b8; }}
    code {{ font-family:'SF Mono',Monaco,monospace; font-size:12px; color:#cbd5e1; }}
  </style>
</head>
<body>
  <div class="container">

    <!-- Header con border-left por severidad (estilo Wazuh) -->
    <div class="header">
      <div class="title">{_esc(alert.title)}</div>
      <div style="font-size:14px;color:#94a3b8;margin-top:4px;">
        {_esc(alert.wazuh_rule.description)}
      </div>
      <div style="margin-top:10px;">
        {rule_badge_html}
        {risk_badge_html}
        {_badge(f"TICKET #{invgate_request_id}", "info") if invgate_request_id else ""}
      </div>
    </div>

    <!-- Pivot section: info principal destacada -->
    <div class="pivot-section">
      <div class="pivot-label">Información Principal:</div>
      <div class="pivot-value">{pivot_value}</div>
    </div>

    <!-- Resumen ejecutivo del Narrator (estilo párrafo, fuera de tabla) -->
    <div style="padding:0 24px;">
      <div style="font-weight:bold;color:#f3f4f6;font-size:14px;margin-bottom:8px;">
        📝 Resumen ejecutivo
      </div>
      <div style="color:#cbd5e1;font-size:14px;line-height:1.6;white-space:pre-line;">
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
    <div style="background-color:#241c10;padding:16px;margin:20px;border-radius:8px;border-left:4px solid #f59e0b;">
      <div style="font-weight:bold;color:#fbbf78;margin-bottom:8px;font-size:14px;">
        💡 Análisis del incidente:
      </div>
      <div style="color:#e8d5b0;font-size:13px;line-height:1.6;white-space:pre-line;">
        {_esc(plan.rationale)}
      </div>
    </div>

    <!-- Card azul "Acciones Sugeridas" (= ProposedActions del Narrator) -->
    <div style="background:#0f1d26;padding:16px;margin:20px;border-radius:8px;border-left:4px solid #38bdf8;">
      <div style="font-weight:bold;color:#7dd3fc;margin-bottom:12px;font-size:14px;">
        📋 Acciones propuestas ({len(plan.actions)}):
      </div>
      <ul style="margin:8px 0;padding-left:24px;color:#bae6fd;font-size:13px;line-height:1.8;">
        {_actions_html(plan)}
      </ul>
    </div>

    <!-- Approval section: sutil, sin banner fuerte -->
    <div class="approval-section">
      <div style="font-weight:bold;color:#f3f4f6;font-size:14px;margin-bottom:6px;">
        ⚠️ Esta alerta requiere tu aprobación
      </div>
      <div style="color:#94a3b8;font-size:12px;margin-bottom:16px;">
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
    invgate_request_id: int | None = None,
) -> EmailMessage:
    approve_url = f"{settings.approval_base_url.rstrip('/')}/approve/{token}"
    reject_url = f"{settings.approval_base_url.rstrip('/')}/reject/{token}"

    sev_label = SEV_STYLES.get(plan.risk_level, _DEFAULT_SEV)["label"]
    # Limpiar emoji para subject (Exchange/Outlook a veces los quema)
    sev_clean = sev_label.replace("🚨 ", "").replace("⚠️ ", "")

    ticket_tag = f" [ticket #{invgate_request_id}]" if invgate_request_id else ""
    msg = EmailMessage()
    msg["Subject"] = (
        f"[SOC L1][{plan.risk_level.upper()}] {alert.device.hostname or 'unknown'} - "
        f"{alert.title[:60]}{ticket_tag}"
    )
    msg["From"] = settings.smtp_from
    msg["To"] = settings.smtp_to_approvers
    msg.set_content(
        _build_text_body(
            alert, plan, approve_url, reject_url,
            invgate_request_id=invgate_request_id,
        )
    )
    review_url = f"{settings.approval_base_url.rstrip('/')}/review/{token}"
    msg.add_alternative(
        _build_html_body(
            alert, plan, approve_url, reject_url,
            ttl_hours=settings.approval_ttl_hours,
            review_url=review_url,
            invgate_request_id=invgate_request_id,
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
    invgate_request_id: int | None = None,
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

    msg = _build_message(settings, alert, plan, token, invgate_request_id=invgate_request_id)
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


# ===== Email de cierre de caso (post-decisión) con timeline por agente =====

# stage del PipelineTrace → (badge style, label legible)
_STAGE_META = {
    "triage":       ("info",    "🔍 TRIAGE"),
    "enricher":     ("default", "🧩 ENRICHER"),
    "threat_intel": ("warning", "🛰️ THREAT INTEL"),
    "narrator":     ("success", "🧠 NARRATOR"),
    "invgate":      ("info",    "🎫 TICKET"),
    "decision":     ("info",    "👤 DECISIÓN"),
    "execution":    ("default", "⚙️ EJECUCIÓN"),
}


def _fmt_clock(iso: str | None) -> str:
    """ISO8601 UTC → 'HH:MM:SS' en hora local del server. Fallback al string crudo."""
    if not iso:
        return "--:--:--"
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%H:%M:%S")
    except (TypeError, ValueError):
        return str(iso)


def _decision_label(decision: str) -> str:
    return {"approved": "APROBADO", "rejected": "RECHAZADO"}.get(decision, decision.upper())


def _closure_timeline(
    timeline_events: list[dict],
    *,
    decision: str,
    decided_by_ip: str | None,
    decided_at: str | None,
    execution_results: list[dict] | None,
    executed_at: str | None,
) -> list[dict]:
    """Combina los hitos del pipeline con la decisión humana y la ejecución.

    Devuelve una lista uniforme de {stage, ts, summary, detail} ordenada por ts.
    execution_results None → rechazo (sin fila de ejecución). [] → 0 acciones.
    """
    events: list[dict] = list(timeline_events)

    events.append({
        "stage": "decision",
        "ts": decided_at or "",
        "summary": f"Plan {_decision_label(decision)} por {decided_by_ip or 'IP desconocida'}",
        "detail": None,
    })

    if execution_results is not None:
        ok = sum(1 for r in execution_results if r.get("ok"))
        fail = len(execution_results) - ok
        if execution_results:
            summary = f"Ejecución completada: {ok} OK / {fail} FAIL"
        else:
            summary = "Aprobado sin acciones seleccionadas (0 ejecutadas)"
        events.append({
            "stage": "execution",
            "ts": executed_at or "",
            "summary": summary,
            "detail": None,
        })

    # Orden estable por ts (ISO ordena lexicográficamente). Los ts vacíos al final.
    events.sort(key=lambda e: e.get("ts") or "~")
    return events


def _timeline_rows_html(events: list[dict]) -> str:
    """Filas <tr> de la tabla de timeline (una por hito)."""
    rows = []
    for e in events:
        style, label = _STAGE_META.get(e.get("stage", ""), ("default", (e.get("stage") or "?").upper()))
        detail_html = (
            f"<div style='font-size:11px;color:#94a3b8;margin-top:3px;'>{_esc(e.get('detail'))}</div>"
            if e.get("detail") else ""
        )
        rows.append(
            "<tr>"
            f"<td style='padding:10px 12px;border-bottom:1px solid #23272f;white-space:nowrap;"
            f"vertical-align:top;font:bold 12px monospace;color:#94a3b8;'>{_fmt_clock(e.get('ts'))}</td>"
            f"<td style='padding:10px 12px;border-bottom:1px solid #23272f;white-space:nowrap;"
            f"vertical-align:top;'>{_badge(label, style)}</td>"
            f"<td style='padding:10px 12px;border-bottom:1px solid #23272f;vertical-align:top;"
            f"font-size:13px;color:#f3f4f6;line-height:1.5;'>{_esc(e.get('summary'))}{detail_html}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def _execution_rows_html(execution_results: list[dict] | None) -> str:
    """Sub-listado por acción ejecutada. Vacío si None (rechazo) o lista vacía."""
    if not execution_results:
        return ""
    items = []
    for r in execution_results:
        ok = r.get("ok")
        tag_style = "success" if ok else "danger"
        tag = "OK" if ok else "FAIL"
        msg = f" <span style='color:#94a3b8;'>— {_esc(r.get('message'))}</span>" if r.get("message") else ""
        items.append(
            f"<li style='margin:6px 0;'>{_badge(tag, tag_style)} "
            f"<strong style='font-family:monospace;'>{_esc(r.get('action_type'))}</strong> → "
            f"<code style='background:#1b2b3a;padding:2px 6px;border-radius:3px;'>{_esc(r.get('target'))}</code>"
            f"{msg}</li>"
        )
    return (
        "<div style='background-color:#1b1f26;padding:16px;margin:20px;border-radius:8px;"
        "border-left:4px solid #64748b;'>"
        "<div style='font-weight:bold;color:#f3f4f6;margin-bottom:8px;font-size:14px;'>"
        "⚙️ Resultado de la ejecución</div>"
        f"<ul style='margin:8px 0;padding-left:22px;font-size:13px;line-height:1.7;'>{''.join(items)}</ul>"
        "</div>"
    )


def _build_closure_text_body(
    alert: NormalizedAlert,
    plan: NarratorPlan,
    events: list[dict],
    execution_results: list[dict] | None,
    decision: str,
) -> str:
    lines: list[str] = []
    lines.append(f"SOC L1 - CASO CERRADO ({_decision_label(decision)})")
    lines.append(f"Risk: {plan.risk_level.upper()}")
    lines.append("=" * 60)
    lines.append("")
    lines.append("CONTEXTO")
    lines.append(f"  Alert ID:  {alert.alert_id}")
    lines.append(f"  Host:      {alert.device.hostname or '(sin host)'}")
    lines.append(f"  Title:     {alert.title}")
    lines.append("")
    lines.append("TIMELINE")
    for e in events:
        _, label = _STAGE_META.get(e.get("stage", ""), ("", (e.get("stage") or "?").upper()))
        clean = label.split(" ", 1)[-1] if " " in label else label
        lines.append(f"  {_fmt_clock(e.get('ts'))}  [{clean}]  {e.get('summary', '')}")
        if e.get("detail"):
            lines.append(f"            {e['detail']}")
    lines.append("")
    if execution_results:
        lines.append("EJECUCIÓN")
        for r in execution_results:
            tag = "OK" if r.get("ok") else "FAIL"
            lines.append(
                f"  [{tag}] {r.get('action_type', '?')} → {r.get('target', '?')}: "
                f"{r.get('message', '')}"
            )
        lines.append("")
    lines.append("=" * 60)
    lines.append("SOC L1 - notificación de cierre (no responder)")
    return "\n".join(lines)


def _build_closure_html_body(
    alert: NormalizedAlert,
    plan: NarratorPlan,
    events: list[dict],
    execution_results: list[dict] | None,
    decision: str,
    invgate_request_id: int | None = None,
) -> str:
    sev_cfg = SEV_STYLES.get(plan.risk_level, _DEFAULT_SEV)
    color = sev_cfg["bg"]
    decision_style = "success" if decision == "approved" else "danger"
    decision_badge = _badge(f"CASO CERRADO · {_decision_label(decision)}", decision_style)
    risk_badge_html = _badge(plan.risk_level.upper(), _risk_badge_style(plan.risk_level))

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark light">
  <meta name="supported-color-schemes" content="dark light">
  <title>SOC L1 — Caso cerrado {_esc(alert.alert_id)}</title>
  <style>
    :root {{ color-scheme: dark light; supported-color-schemes: dark light; }}
    body {{ font-family: sans-serif; background-color:#0b0d10; margin:0; padding:20px; color:#e5e7eb; }}
    .container {{ max-width:800px; margin:0 auto; background-color:#14171c; border:1px solid #23272f; border-radius:12px; overflow:hidden; }}
    .header {{ padding:24px; border-left:8px solid {color}; background-color:#0b0d10; }}
    .title {{ font-size:22px; font-weight:bold; margin-bottom:8px; color:#f3f4f6; }}
    .tl-table {{ width:100%; border-collapse:collapse; }}
    .footer {{ padding:16px; background-color:#0b0d10; text-align:center; font-size:12px; color:#94a3b8; }}
    code {{ font-family:'SF Mono',Monaco,monospace; font-size:12px; color:#cbd5e1; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="title">{_esc(alert.title)}</div>
      <div style="font-size:13px;color:#94a3b8;margin-top:4px;">
        Alerta <code>{_esc(alert.alert_id)}</code> · host <strong>{_esc(alert.device.hostname)}</strong>
      </div>
      <div style="margin-top:10px;">
        {decision_badge}
        {risk_badge_html}
        {_badge(f"TICKET #{invgate_request_id}", "info") if invgate_request_id else ""}
      </div>
    </div>

    <div style="padding:0 24px;">
      <div style="font-weight:bold;color:#f3f4f6;font-size:14px;margin:20px 0 8px;">
        📝 Resumen ejecutivo
      </div>
      <div style="color:#cbd5e1;font-size:14px;line-height:1.6;white-space:pre-line;">
        {_esc(plan.executive_summary)}
      </div>
    </div>

    <div style="background:#0f1d26;padding:16px;margin:20px;border-radius:8px;border-left:4px solid #38bdf8;">
      <div style="font-weight:bold;color:#7dd3fc;margin-bottom:12px;font-size:14px;">
        🕐 Timeline del caso
      </div>
      <table class="tl-table">
        {_timeline_rows_html(events)}
      </table>
    </div>

    {_execution_rows_html(execution_results)}

    <div class="footer">
      <strong>SOC L1 · Wazuh + Defender</strong> • Pipeline multi-agente<br>
      Notificación de cierre — generada automáticamente, no responder.
    </div>
  </div>
</body>
</html>
"""


def _build_closure_message(
    settings: Settings,
    alert: NormalizedAlert,
    plan: NarratorPlan,
    *,
    decision: str,
    timeline_events: list[dict],
    execution_results: list[dict] | None,
    decided_by_ip: str | None,
    decided_at: str | None,
    executed_at: str | None,
    invgate_request_id: int | None = None,
) -> EmailMessage:
    events = _closure_timeline(
        timeline_events,
        decision=decision,
        decided_by_ip=decided_by_ip,
        decided_at=decided_at,
        execution_results=execution_results,
        executed_at=executed_at,
    )
    ticket_tag = f" [ticket #{invgate_request_id}]" if invgate_request_id else ""
    msg = EmailMessage()
    msg["Subject"] = (
        f"[SOC L1][CERRADO: {_decision_label(decision)}][{plan.risk_level.upper()}] "
        f"{alert.device.hostname or 'unknown'} - {alert.title[:60]}{ticket_tag}"
    )
    msg["From"] = settings.smtp_from
    msg["To"] = settings.smtp_to_approvers
    msg.set_content(_build_closure_text_body(alert, plan, events, execution_results, decision))
    msg.add_alternative(
        _build_closure_html_body(
            alert, plan, events, execution_results, decision,
            invgate_request_id=invgate_request_id,
        ),
        subtype="html",
    )
    return msg


async def send_closure_email(
    settings: Settings,
    alert: NormalizedAlert,
    plan: NarratorPlan,
    *,
    decision: str,
    timeline_events: list[dict],
    execution_results: list[dict] | None,
    decided_by_ip: str | None,
    decided_at: str | None,
    executed_at: str | None,
    invgate_request_id: int | None = None,
) -> None:
    """Email de cierre con timeline por agente. Fire-and-forget.

    A diferencia de send_approval_email, NO re-raisea ante fallo de SMTP: el cierre es
    una notificación, no debe romper el flujo de decisión/ejecución que ya ocurrió.
    Skip silencioso si SMTP no está configurado.
    """
    if not settings.smtp_host or not settings.smtp_to_approvers:
        logger.warning(
            "mailer: SMTP no configurado - skip closure email para alert=%s",
            alert.alert_id,
        )
        return

    try:
        msg = _build_closure_message(
            settings, alert, plan,
            decision=decision,
            timeline_events=timeline_events,
            execution_results=execution_results,
            decided_by_ip=decided_by_ip,
            decided_at=decided_at,
            executed_at=executed_at,
            invgate_request_id=invgate_request_id,
        )
        await asyncio.to_thread(_send_sync, settings, msg)
        logger.info(
            "mailer: closure email enviado | alert=%s decision=%s to=%s subject=%r",
            alert.alert_id, decision, settings.smtp_to_approvers, msg["Subject"],
        )
    except Exception:
        logger.exception(
            "mailer: closure send failed | alert=%s decision=%s",
            alert.alert_id, decision,
        )
