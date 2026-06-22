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
from typing import TYPE_CHECKING, Any

from src.agents.narrator import NarratorPlan
from src.config import Settings
from src.models import NormalizedAlert

if TYPE_CHECKING:  # solo para type hints — evita imports en runtime / circular imports
    from src.agents.enricher import EnrichmentResult
    from src.agents.threatintel import ThreatIntelResult

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
    "default":  ("#e1e4e8", "#475569"),
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


# ===== Helpers de evidencia para la toma de decisión =====

# remediationStatus de Defender → (badge style, label legible). Es el campo MÁS
# decisivo: distingue "Defender ya neutralizó" de "la amenaza puede seguir viva".
_REMEDIATION_META = {
    "prevented":   ("success", "✓ Prevenido"),
    "blocked":     ("success", "✓ Bloqueado"),
    "remediated":  ("success", "✓ Remediado"),
    "quarantined": ("success", "✓ En cuarentena"),
    "active":      ("danger",  "⚠ ACTIVO — no remediado"),
    "failed":      ("danger",  "⚠ Remediación falló"),
    "notfound":    ("warning", "? No encontrado"),
    "unknown":     ("warning", "? Desconocido"),
}


def _remediation_meta(status: str | None) -> tuple[str, str]:
    """Normaliza el remediationStatus crudo a (badge style, label)."""
    key = (status or "unknown").strip().lower()
    return _REMEDIATION_META.get(key, ("warning", f"? {status}"))


def _worst_remediation(alert: NormalizedAlert) -> tuple[str, str] | None:
    """Estado de remediación 'más peligroso' entre todos los archivos.

    Devuelve (style, label) o None si no hay archivos. Prioriza danger > warning
    > success para que el reviewer vea el peor caso de un vistazo.
    """
    if not alert.files:
        return None
    _rank = {"danger": 0, "warning": 1, "success": 2, "default": 3, "info": 3}
    worst = min(
        (_remediation_meta(f.remediation) for f in alert.files),
        key=lambda m: _rank.get(m[0], 3),
    )
    return worst


def _risk_score_badge(risk_score: str | None) -> str:
    """device.riskScore de Defender → badge coloreado."""
    rs = (risk_score or "").strip().lower()
    style = {
        "high": "danger",
        "medium": "warning",
        "low": "info",
        "none": "success",
        "informational": "default",
    }.get(rs, "default")
    return _badge(risk_score.upper() if risk_score else "N/D", style)


def _is_defender(alert: NormalizedAlert) -> bool:
    """True si la alerta trae evidencia de endpoint (Defender/MDE)."""
    return bool(alert.threat and alert.threat.provider and "wazuh native" not in alert.threat.provider.lower())


# ===== Plain text body (fallback) =====


def _build_text_body(
    alert: NormalizedAlert,
    plan: NarratorPlan,
    approve_url: str,
    reject_url: str,
    invgate_request_id: int | None = None,
    enrichment: "EnrichmentResult | None" = None,
    threat_intel: "ThreatIntelResult | None" = None,
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
    lines.append(f"  Host:      {alert.device.hostname or '(sin host)'}"
                 + (f" ({alert.device.fqdn})" if alert.device.fqdn else ""))
    if alert.threat and (alert.threat.display_name or alert.threat.family):
        lines.append(f"  Amenaza:   {alert.threat.display_name or ''}"
                     + (f" [{alert.threat.family}]" if alert.threat.family else ""))
    worst = _worst_remediation(alert)
    if worst:
        lines.append(f"  Remediación: {worst[1]}")
    if _is_defender(alert) and alert.device.risk_score:
        lines.append(f"  Device risk: {alert.device.risk_score} | health: {alert.device.health or '-'}")
    lines.append(f"  Severity:  {alert.severity_source}")
    lines.append(f"  Wazuh:     rule {alert.wazuh_rule.id} (level {alert.wazuh_rule.level})")
    lines.append(f"  Title:     {alert.title}")
    if alert.threat and alert.threat.provider_actions:
        lines.append(f"  Defender:  {alert.threat.provider_actions}")
    if alert.threat and alert.threat.incident_url:
        lines.append(f"  Incidente: {alert.threat.incident_url}")
    if alert.threat and alert.threat.alert_url:
        lines.append(f"  Alerta MDE: {alert.threat.alert_url}")
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

    # Contexto local (MITRE + cuentas AD + flags)
    if enrichment is not None:
        rule = getattr(enrichment, "rule", None)
        tactics = list(getattr(rule, "mitre_tactics", []) or []) if rule else []
        techniques = list(getattr(rule, "mitre_techniques", []) or []) if rule else []
        flags = list(getattr(enrichment, "flags", []) or [])
        if tactics or techniques or flags:
            lines.append("CONTEXTO LOCAL")
            if tactics:
                lines.append(f"  MITRE tactics:    {', '.join(tactics)}")
            if techniques:
                lines.append(f"  MITRE techniques: {', '.join(techniques)}")
            for u in getattr(enrichment, "users", []) or []:
                if getattr(u, "found_in_ad", False):
                    st = "enabled" if getattr(u, "enabled", None) else "DISABLED"
                    lk = " locked" if getattr(u, "locked_out", None) else ""
                    lines.append(f"  AD {getattr(u, 'sam', '?')}: {st}{lk} (bad_pwd={getattr(u, 'bad_pwd_count', 0)})")
                else:
                    lines.append(f"  AD {getattr(u, 'sam', '?')}: no en AD")
            if flags:
                lines.append(f"  Flags: {', '.join(flags[:8])}")
            lines.append("")

    # Inteligencia externa (VT / AbuseIPDB / FortiGate)
    if threat_intel is not None:
        ti_lines: list[str] = []
        for r in getattr(threat_intel, "file_reports", []) or []:
            ti_lines.append(f"  VT {(getattr(r, 'sha256', '') or '')[:16]}…: "
                            f"{getattr(r, 'malicious_count', 0)}/{getattr(r, 'total_engines', 0)} malicious"
                            + (f" [{r.family}]" if getattr(r, 'family', None) else ""))
        for r in getattr(threat_intel, "ip_reports", []) or []:
            ti_lines.append(f"  AbuseIPDB {getattr(r, 'ip', '?')}: score={getattr(r, 'abuse_confidence_score', 0)}"
                            + (f" {r.country_code}" if getattr(r, 'country_code', None) else "")
                            + (" TOR" if getattr(r, 'is_tor', False) else ""))
        for r in getattr(threat_intel, "fortigate_contexts", []) or []:
            ti_lines.append(f"  FortiGate {getattr(r, 'ip', '?')}: {getattr(r, 'active_sessions', 0)} sesiones activas"
                            + (" (ya quarantined)" if getattr(r, 'already_quarantined', False) else ""))
        if ti_lines:
            lines.append("INTELIGENCIA EXTERNA")
            lines.extend(ti_lines)
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

    # Host: hostname + fqdn + IP interna + IP externa
    host_html = f"<strong>{_esc(alert.device.hostname)}</strong>"
    if alert.device.fqdn and alert.device.fqdn != alert.device.hostname:
        host_html += f" <span style='color:#6b7280;font-size:11px;'>{_esc(alert.device.fqdn)}</span>"
    ip_bits = []
    if alert.device.internal_ip:
        ip_bits.append(f"<code style='color:#6b7280;'>int {_esc(alert.device.internal_ip)}</code>")
    if alert.device.external_ip:
        ip_bits.append(f"<code style='color:#6b7280;'>ext {_esc(alert.device.external_ip)}</code>")
    if ip_bits:
        host_html += "<br>" + " ".join(ip_bits)

    rows: list[tuple[str, str]] = [
        ("Alert ID",       f"<code>{_esc(alert.alert_id)}</code>"),
        ("Host",           host_html),
    ]

    # Amenaza (clasificación real de Defender): display_name + family
    if alert.threat and (alert.threat.display_name or alert.threat.family):
        threat_html = ""
        if alert.threat.display_name:
            threat_html += f"<strong>{_esc(alert.threat.display_name)}</strong>"
        if alert.threat.family:
            threat_html += f" {_badge(alert.threat.family, 'danger')}"
        rows.append(("Amenaza", threat_html))

    # Remediación (peor caso entre archivos) — el campo más decisivo
    worst = _worst_remediation(alert)
    if worst:
        rows.append(("Remediación", _badge(worst[1], worst[0])))

    rows += [
        ("Severidad Wazuh", _badge(alert.severity_source.upper(), sev_badge_style)),
        ("Risk asignado",   _badge(plan.risk_level.upper(), _risk_badge_style(plan.risk_level))),
    ]

    # Postura del equipo (Defender): risk score + health + OS
    if _is_defender(alert) and (alert.device.risk_score or alert.device.health or alert.device.os):
        posture_bits = [f"risk {_risk_score_badge(alert.device.risk_score)}"]
        if alert.device.health:
            posture_bits.append(f"<span style='color:#57606a;'>health: {_esc(alert.device.health)}</span>")
        if alert.device.os:
            posture_bits.append(f"<span style='color:#6b7280;'>{_esc(alert.device.os)}</span>")
        rows.append(("Postura equipo", " · ".join(posture_bits)))

    rows += [
        ("Wazuh rule",     f"{_esc(alert.wazuh_rule.id)} (level {alert.wazuh_rule.level})"),
        ("Categoría",      _esc(alert.category)),
        ("Source",         _esc(alert.source)),
        ("Timestamp",      f"<code style='font-size:12px;'>{_esc(alert.timestamp)}</code>"),
    ]

    # Usuarios involucrados
    if alert.users_involved:
        users_html = ", ".join(
            f"<code>{_esc(u.sam)}</code> "
            f"<span style='color:#6b7280;font-size:11px;'>({_esc(u.role)})</span>"
            for u in alert.users_involved
        )
        rows.append(("Usuarios", users_html))

    # Archivos
    if alert.files:
        files_html_parts = []
        for f in alert.files[:3]:  # cap a 3 para no inundar el email
            badge_style = "critical" if (f.verdict or "").lower() == "malicious" else "warning"
            badge_html = _badge(f.verdict or "unknown", badge_style)
            rem_style, rem_label = _remediation_meta(f.remediation)
            name = f.name or "(sin nombre)"
            sha = (f.sha256[:16] + "…") if f.sha256 else "-"
            line = (
                f"{badge_html} {_badge(rem_label, rem_style)} <strong>{_esc(name)}</strong> "
                f"<code style='font-size:11px;color:#6b7280;'>{_esc(sha)}</code>"
            )
            if f.path:
                line += f"<div style='font-size:11px;color:#8b949e;margin-top:2px;'>{_esc(f.path)}</div>"
            files_html_parts.append(line)
        files_html = "<br>".join(files_html_parts)
        if len(alert.files) > 3:
            files_html += f"<br><em style='color:#6b7280;'>+{len(alert.files) - 3} más…</em>"
        rows.append(("Archivos", files_html))

    return "\n".join(
        f"<tr><td class='label'>{label}:</td><td class='value'>{value}</td></tr>"
        for label, value in rows
    )


def _actions_html(plan: NarratorPlan) -> str:
    """Lista <li> con cada acción propuesta."""
    if not plan.actions:
        return (
            "<li style='color:#6b7280;font-style:italic;'>"
            "(ninguna - monitor only)</li>"
        )
    items = []
    for a in plan.actions:
        items.append(
            f"<li><strong>{_esc(a.type)}</strong> → "
            f"<code style='background:#ddf4ff;padding:2px 6px;border-radius:3px;'>"
            f"{_esc(a.target)}</code>"
            f"<div style='font-size:12px;color:#6b7280;margin-top:4px;line-height:1.5;'>"
            f"{_esc(a.justification)}</div></li>"
        )
    return "\n".join(items)


def _defender_section(alert: NormalizedAlert) -> str:
    """Card con la guía del vendor (recommendedActions) + pivots a la consola de Defender.

    Vacío si la alerta no es de Defender o no hay nada que mostrar.
    """
    if not _is_defender(alert):
        return ""
    t = alert.threat
    has_actions = bool(t and t.provider_actions)
    links = []
    if t and t.incident_url:
        links.append(
            f"<a href='{html.escape(t.incident_url)}' "
            f"style='display:inline-block;background:#ddf4ff;color:#0969da;padding:8px 16px;"
            f"text-decoration:none;border-radius:5px;font-size:12px;font-weight:bold;margin:4px 6px 0 0;'>"
            f"🛡️ Ver incidente en Defender</a>"
        )
    if t and t.alert_url:
        links.append(
            f"<a href='{html.escape(t.alert_url)}' "
            f"style='display:inline-block;background:#ddf4ff;color:#0969da;padding:8px 16px;"
            f"text-decoration:none;border-radius:5px;font-size:12px;font-weight:bold;margin:4px 6px 0 0;'>"
            f"🔎 Ver alerta en Defender</a>"
        )
    if not has_actions and not links:
        return ""
    guidance = (
        f"<div style='color:#57606a;font-size:13px;line-height:1.6;'>"
        f"<span style='color:#6b7280;'>Guía del vendor:</span> {_esc(t.provider_actions)}</div>"
        if has_actions else ""
    )
    links_html = f"<div style='margin-top:10px;'>{''.join(links)}</div>" if links else ""
    return (
        "<div style='background-color:#f6f8fa;padding:16px;margin:20px;border-radius:8px;"
        "border-left:4px solid #64748b;'>"
        "<div style='font-weight:bold;color:#57606a;margin-bottom:8px;font-size:14px;'>"
        "🛡️ Defender — guía y pivots</div>"
        f"{guidance}{links_html}</div>"
    )


def _enrichment_section(enrichment: "EnrichmentResult | None") -> str:
    """Card de contexto local: MITRE ATT&CK, estado de cuenta AD y flags.

    Vacío si no hay enrichment o no aporta nada accionable.
    """
    if enrichment is None:
        return ""
    blocks: list[str] = []

    # MITRE ATT&CK (de la rule de Wazuh)
    rule = getattr(enrichment, "rule", None)
    tactics = list(getattr(rule, "mitre_tactics", []) or []) if rule else []
    techniques = list(getattr(rule, "mitre_techniques", []) or []) if rule else []
    mitre_ids = list(getattr(rule, "mitre_ids", []) or []) if rule else []
    if tactics or techniques or mitre_ids:
        chips = "".join(_badge(t, "warning") for t in tactics)
        tech_txt = ", ".join(_esc(t) for t in (techniques or mitre_ids))
        blocks.append(
            "<div style='margin-bottom:10px;'>"
            "<span style='color:#6b7280;font-size:12px;font-weight:bold;'>MITRE ATT&amp;CK:</span> "
            f"{chips}"
            + (f"<div style='font-size:12px;color:#57606a;margin-top:4px;'>{tech_txt}</div>" if tech_txt else "")
            + "</div>"
        )

    # Estado de cuenta AD por usuario (decisivo para disable_user / force_password_change)
    users = list(getattr(enrichment, "users", []) or [])
    user_rows = []
    for u in users:
        if not getattr(u, "found_in_ad", False):
            user_rows.append(
                f"<li><code>{_esc(getattr(u, 'sam', '?'))}</code> {_badge('no en AD', 'default')}</li>"
            )
            continue
        bits = [f"<code>{_esc(getattr(u, 'sam', '?'))}</code>"]
        enabled = getattr(u, "enabled", None)
        if enabled is True:
            bits.append(_badge("habilitada", "success"))
        elif enabled is False:
            bits.append(_badge("deshabilitada", "danger"))
        if getattr(u, "locked_out", None):
            bits.append(_badge("bloqueada", "warning"))
        meta = []
        for attr, lbl in (("department", ""), ("title", ""), ("manager", "mgr: ")):
            val = getattr(u, attr, None)
            if val:
                meta.append(f"{lbl}{_esc(val)}")
        bpc = getattr(u, "bad_pwd_count", None)
        if bpc:
            meta.append(f"bad_pwd={bpc}")
        meta_html = f" <span style='color:#6b7280;font-size:11px;'>{' · '.join(meta)}</span>" if meta else ""
        user_rows.append(f"<li>{' '.join(bits)}{meta_html}</li>")
    if user_rows:
        blocks.append(
            "<div style='margin-bottom:6px;'>"
            "<span style='color:#6b7280;font-size:12px;font-weight:bold;'>Cuentas (AD):</span>"
            f"<ul style='margin:6px 0;padding-left:20px;font-size:13px;line-height:1.7;color:#24292e;'>{''.join(user_rows)}</ul>"
            "</div>"
        )

    # Flags relevantes
    flags = list(getattr(enrichment, "flags", []) or [])
    if flags:
        chips = " ".join(_badge(f, "default") for f in flags[:8])
        blocks.append(
            "<div><span style='color:#6b7280;font-size:12px;font-weight:bold;'>Señales:</span> "
            f"{chips}</div>"
        )

    if not blocks:
        return ""
    return (
        "<div style='background-color:#f6f8fa;padding:16px;margin:20px;border-radius:8px;"
        "border-left:4px solid #8b949e;'>"
        "<div style='font-weight:bold;color:#1f2328;margin-bottom:10px;font-size:14px;'>"
        "🧩 Contexto local (AD + Wazuh)</div>"
        f"{''.join(blocks)}</div>"
    )


def _threat_intel_section(ti: "ThreatIntelResult | None") -> str:
    """Card de inteligencia externa: VirusTotal, AbuseIPDB y FortiGate.

    Vacío si no hay TI o ninguna fuente devolvió algo.
    """
    if ti is None:
        return ""
    blocks: list[str] = []

    # VirusTotal (file hashes)
    vt_items = []
    for r in getattr(ti, "file_reports", []) or []:
        mal = getattr(r, "malicious_count", 0)
        total = getattr(r, "total_engines", 0)
        style = "danger" if mal >= 10 else ("warning" if mal > 0 else "success")
        fam = getattr(r, "family", None)
        sha = (getattr(r, "sha256", "") or "")[:16]
        fam_html = f" {_badge(fam, 'danger')}" if fam else ""
        vt_items.append(
            f"<li>{_badge(f'{mal}/{total} malicious', style)} "
            f"<code style='font-size:11px;color:#6b7280;'>{_esc(sha)}…</code>{fam_html}</li>"
        )
    if vt_items:
        blocks.append(
            "<div style='margin-bottom:8px;'><span style='color:#6b7280;font-size:12px;font-weight:bold;'>"
            "VirusTotal:</span><ul style='margin:6px 0;padding-left:20px;font-size:13px;line-height:1.7;'>"
            f"{''.join(vt_items)}</ul></div>"
        )

    # AbuseIPDB (IP reputation)
    ip_items = []
    for r in getattr(ti, "ip_reports", []) or []:
        score = getattr(r, "abuse_confidence_score", 0)
        style = "danger" if score >= 75 else ("warning" if score >= 25 else "success")
        extra = []
        if getattr(r, "country_code", None):
            extra.append(_esc(r.country_code))
        if getattr(r, "is_tor", False):
            extra.append("TOR")
        if getattr(r, "is_whitelisted", False):
            extra.append("whitelisted")
        reports = getattr(r, "total_reports", 0)
        if reports:
            extra.append(f"{reports} reports")
        extra_html = f" <span style='color:#6b7280;font-size:11px;'>{' · '.join(extra)}</span>" if extra else ""
        ip_items.append(
            f"<li><code>{_esc(getattr(r, 'ip', '?'))}</code> {_badge(f'score {score}', style)}{extra_html}</li>"
        )
    if ip_items:
        blocks.append(
            "<div style='margin-bottom:8px;'><span style='color:#6b7280;font-size:12px;font-weight:bold;'>"
            "AbuseIPDB:</span><ul style='margin:6px 0;padding-left:20px;font-size:13px;line-height:1.7;'>"
            f"{''.join(ip_items)}</ul></div>"
        )

    # FortiGate (tráfico vivo / quarantine)
    fg_items = []
    for r in getattr(ti, "fortigate_contexts", []) or []:
        sess = getattr(r, "active_sessions", 0)
        quar = getattr(r, "already_quarantined", False)
        style = "danger" if sess > 0 else "default"
        quar_html = f" {_badge('ya en quarantine', 'success')}" if quar else ""
        fg_items.append(
            f"<li><code>{_esc(getattr(r, 'ip', '?'))}</code> "
            f"{_badge(f'{sess} sesiones activas', style)}{quar_html}</li>"
        )
    if fg_items:
        blocks.append(
            "<div><span style='color:#6b7280;font-size:12px;font-weight:bold;'>"
            "FortiGate:</span><ul style='margin:6px 0;padding-left:20px;font-size:13px;line-height:1.7;'>"
            f"{''.join(fg_items)}</ul></div>"
        )

    if not blocks:
        return ""
    return (
        "<div style='background-color:#f6f8fa;padding:16px;margin:20px;border-radius:8px;"
        "border-left:4px solid #8b5cf6;'>"
        "<div style='font-weight:bold;color:#1f2328;margin-bottom:10px;font-size:14px;'>"
        "🛰️ Inteligencia externa</div>"
        f"{''.join(blocks)}</div>"
    )


def _build_html_body(
    alert: NormalizedAlert,
    plan: NarratorPlan,
    approve_url: str,
    reject_url: str,
    ttl_hours: int = 24,
    review_url: str | None = None,
    invgate_request_id: int | None = None,
    enrichment: "EnrichmentResult | None" = None,
    threat_intel: "ThreatIntelResult | None" = None,
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
    .title {{ font-size: 24px; font-weight: bold; margin-bottom: 8px; }}
    .pivot-section {{ background: #fef2f2; padding: 16px; margin: 20px; border-radius: 8px; border-left: 4px solid {color}; }}
    .pivot-label {{ font-weight: bold; color: #374151; margin-bottom: 4px; }}
    .pivot-value {{ font-family: monospace; font-size: 16px; font-weight: bold; color: #1f2937; }}
    .info-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
    .info-table td {{ padding: 12px 16px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
    .info-table .label {{ font-weight: bold; width: 160px; background: #f9fafb; }}
    .approval-section {{ background: #f8fafc; padding: 24px; margin: 20px; border-radius: 8px; border: 1px solid #e5e7eb; text-align: center; }}
    .footer {{ padding: 16px; background: #f8fafc; text-align: center; font-size: 12px; color: #64748b; }}
    code {{ font-family:'SF Mono',Monaco,monospace; font-size: 12px; color: #475569; }}
  </style>
</head>
<body>
  <div class="container">

    <!-- Header con border-left por severidad (idéntico a Unified Email Notifier v4.9) -->
    <div class="header">
      <div class="title">{_esc(alert.title)}</div>
      <div style="font-size:14px;color:#64748b;margin-top:4px;">
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
      <div style="font-weight:bold;color:#1f2328;font-size:14px;margin-bottom:8px;">
        📝 Resumen ejecutivo
      </div>
      <div style="color:#57606a;font-size:14px;line-height:1.6;white-space:pre-line;">
        {_esc(plan.executive_summary)}
      </div>
    </div>

    <!-- Info-table (estilo Wazuh exacto) -->
    <div style="padding:0 24px;">
      <table class="info-table">
        {_ctx_rows(alert, plan)}
      </table>
    </div>

    {_defender_section(alert)}

    {_enrichment_section(enrichment)}

    {_threat_intel_section(threat_intel)}

    <!-- Card "Recomendación" (= Análisis del Narrator) — paleta v4.9 -->
    <div style="background:#fef3c7;padding:16px;margin:20px;border-radius:8px;border-left:4px solid #f59e0b;">
      <div style="font-weight:bold;color:#92400e;margin-bottom:8px;font-size:14px;">
        💡 Análisis del incidente:
      </div>
      <div style="color:#78350f;font-size:13px;line-height:1.6;white-space:pre-line;">
        {_esc(plan.rationale)}
      </div>
    </div>

    <!-- Card "Acciones Sugeridas" (= ProposedActions del Narrator) — paleta v4.9 -->
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
      <div style="font-weight:bold;color:#1f2328;font-size:14px;margin-bottom:6px;">
        ⚠️ Esta alerta requiere tu aprobación
      </div>
      <div style="color:#6b7280;font-size:12px;margin-bottom:16px;">
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
    enrichment: "EnrichmentResult | None" = None,
    threat_intel: "ThreatIntelResult | None" = None,
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
            enrichment=enrichment,
            threat_intel=threat_intel,
        )
    )
    review_url = f"{settings.approval_base_url.rstrip('/')}/review/{token}"
    msg.add_alternative(
        _build_html_body(
            alert, plan, approve_url, reject_url,
            ttl_hours=settings.approval_ttl_hours,
            review_url=review_url,
            invgate_request_id=invgate_request_id,
            enrichment=enrichment,
            threat_intel=threat_intel,
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
    enrichment: "EnrichmentResult | None" = None,
    threat_intel: "ThreatIntelResult | None" = None,
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

    msg = _build_message(
        settings, alert, plan, token,
        invgate_request_id=invgate_request_id,
        enrichment=enrichment,
        threat_intel=threat_intel,
    )
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


async def send_fgt_observation_email(
    settings: Settings,
    *,
    alert_id: str,
    ip: str,
    rule_id: str | None,
    host: str | None,
    ttl_hours: int,
) -> None:
    """Fase 0: avisa por mail qué bloquearía SOC-L1, SIN ejecutar nada.

    Temporal hasta el cutover a Fase 1. Light, alineado al look de los correos.
    El caller ya hizo el dedup por IP; esto solo arma y manda.
    """
    if not settings.smtp_host or not settings.smtp_to_approvers:
        logger.warning(
            "mailer: SMTP no configurado - skip email FGT-OBSERVE para ip=%s", ip
        )
        return

    h = html.escape
    subject = f"[SOC L1][FortiGate · OBSERVACIÓN] Bloquearía {ip}"
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from
    msg["To"] = settings.smtp_to_approvers

    text = (
        f"SOC-L1 · FortiGate auto-block (Fase 0 — OBSERVACIÓN, no se ejecutó nada)\n\n"
        f"Bloquearía la IP: {ip}\n"
        f"Regla IPS:        {rule_id or '—'}\n"
        f"Host/origen:      {host or '—'}\n"
        f"Alerta:           {alert_id}\n"
        f"TTL del ban:      {ttl_hours}h (quarantine con TTL en Fase 1)\n\n"
        f"Esto es solo observación: SOC-L1 NO tocó el firewall. Hoy el bloqueo real lo "
        f"sigue haciendo el integration custom-email-unified de Wazuh. Cuando pasemos a "
        f"Fase 1, SOC-L1 ejecutará el quarantine y este aviso se reemplaza por el flujo "
        f"completo (ticket + aprobación).\n"
    )
    msg.set_content(text)

    rows = "".join(
        f'<tr><td style="padding:6px 12px;color:#6b7280;font-size:13px;white-space:nowrap;">{h(k)}</td>'
        f'<td style="padding:6px 12px;color:#1f2328;font-size:13px;font-family:monospace;">{h(v)}</td></tr>'
        for k, v in (
            ("Bloquearía IP", ip),
            ("Regla IPS", rule_id or "—"),
            ("Host / origen", host or "—"),
            ("Alerta", alert_id),
            ("TTL del ban", f"{ttl_hours}h"),
        )
    )
    body_html = f"""<!doctype html><html><body style="margin:0;background:#f6f8fa;padding:24px;font-family:-apple-system,Segoe UI,Roboto,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;margin:0 auto;background:#ffffff;border:1px solid #d0d7de;border-radius:12px;overflow:hidden;">
    <tr><td style="background:#9a6700;color:#ffffff;padding:18px 24px;font-weight:bold;font-size:15px;">
      🔭 FortiGate · OBSERVACIÓN (Fase 0)
    </td></tr>
    <tr><td style="padding:20px 24px 8px;color:#1f2328;font-size:14px;line-height:1.6;">
      SOC-L1 detectó una alerta IPS que <strong>bloquearía</strong> esta IP — pero
      <strong>no ejecutó nada</strong> (todavía estamos en Fase 0, solo observación).
    </td></tr>
    <tr><td style="padding:4px 12px 12px;">
      <table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border:1px solid #d0d7de;border-radius:8px;border-collapse:separate;">{rows}</table>
    </td></tr>
    <tr><td style="padding:0 24px 20px;color:#57606a;font-size:12px;line-height:1.5;">
      Hoy el bloqueo real lo hace el integration <code style="background:#eff2f5;padding:1px 5px;border-radius:3px;">custom-email-unified</code>
      de Wazuh. Cuando pasemos a Fase 1, SOC-L1 ejecuta el quarantine y este aviso se
      reemplaza por el flujo completo (ticket + aprobación).
    </td></tr>
    <tr><td style="background:#f6f8fa;padding:14px 24px;text-align:center;color:#6b7280;font-size:12px;">
      SOC L1 · ZebraSecurity — aviso temporal de Fase 0
    </td></tr>
  </table>
</body></html>"""
    msg.add_alternative(body_html, subtype="html")

    try:
        await asyncio.to_thread(_send_sync, settings, msg)
        logger.info(
            "mailer: email FGT-OBSERVE enviado | ip=%s rule=%s alert=%s to=%s",
            ip, rule_id, alert_id, settings.smtp_to_approvers,
        )
    except Exception:
        logger.exception("mailer: send FGT-OBSERVE failed | ip=%s alert=%s", ip, alert_id)


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
            f"<div style='font-size:11px;color:#6b7280;margin-top:3px;'>{_esc(e.get('detail'))}</div>"
            if e.get("detail") else ""
        )
        rows.append(
            "<tr>"
            f"<td style='padding:10px 12px;border-bottom:1px solid #e1e4e8;white-space:nowrap;"
            f"vertical-align:top;font:bold 12px monospace;color:#6b7280;'>{_fmt_clock(e.get('ts'))}</td>"
            f"<td style='padding:10px 12px;border-bottom:1px solid #e1e4e8;white-space:nowrap;"
            f"vertical-align:top;'>{_badge(label, style)}</td>"
            f"<td style='padding:10px 12px;border-bottom:1px solid #e1e4e8;vertical-align:top;"
            f"font-size:13px;color:#1f2328;line-height:1.5;'>{_esc(e.get('summary'))}{detail_html}</td>"
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
        msg = f" <span style='color:#6b7280;'>— {_esc(r.get('message'))}</span>" if r.get("message") else ""
        items.append(
            f"<li style='margin:6px 0;'>{_badge(tag, tag_style)} "
            f"<strong style='font-family:monospace;'>{_esc(r.get('action_type'))}</strong> → "
            f"<code style='background:#ddf4ff;padding:2px 6px;border-radius:3px;'>{_esc(r.get('target'))}</code>"
            f"{msg}</li>"
        )
    return (
        "<div style='background-color:#f6f8fa;padding:16px;margin:20px;border-radius:8px;"
        "border-left:4px solid #64748b;'>"
        "<div style='font-weight:bold;color:#1f2328;margin-bottom:8px;font-size:14px;'>"
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
    if alert.threat and (alert.threat.display_name or alert.threat.family):
        lines.append(f"  Amenaza:   {alert.threat.display_name or ''}"
                     + (f" [{alert.threat.family}]" if alert.threat.family else ""))
    worst = _worst_remediation(alert)
    if worst:
        lines.append(f"  Remediación: {worst[1]}")
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
  <title>SOC L1 — Caso cerrado {_esc(alert.alert_id)}</title>
  <style>
    body {{ font-family: sans-serif; background: #f8fafc; margin: 0; padding: 20px; }}
    .container {{ max-width: 800px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; }}
    .header {{ padding: 24px; border-left: 8px solid {color}; background: #f8fafc; }}
    .title {{ font-size: 22px; font-weight: bold; margin-bottom: 8px; }}
    .tl-table {{ width: 100%; border-collapse: collapse; }}
    .info-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
    .info-table td {{ padding: 12px 16px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
    .info-table .label {{ font-weight: bold; width: 160px; background: #f9fafb; }}
    .footer {{ padding: 16px; background: #f8fafc; text-align: center; font-size: 12px; color: #64748b; }}
    code {{ font-family:'SF Mono',Monaco,monospace; font-size: 12px; color: #475569; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="title">{_esc(alert.title)}</div>
      <div style="font-size:13px;color:#64748b;margin-top:4px;">
        Alerta <code>{_esc(alert.alert_id)}</code> · host <strong>{_esc(alert.device.hostname)}</strong>
      </div>
      <div style="margin-top:10px;">
        {decision_badge}
        {risk_badge_html}
        {_badge(f"TICKET #{invgate_request_id}", "info") if invgate_request_id else ""}
      </div>
    </div>

    <div style="padding:0 24px;">
      <div style="font-weight:bold;color:#1f2328;font-size:14px;margin:20px 0 8px;">
        📝 Resumen ejecutivo
      </div>
      <div style="color:#57606a;font-size:14px;line-height:1.6;white-space:pre-line;">
        {_esc(plan.executive_summary)}
      </div>
    </div>

    <!-- Contexto / evidencia (mismos campos de decisión que el email de aprobación) -->
    <div style="padding:0 24px;">
      <table class="info-table">
        {_ctx_rows(alert, plan)}
      </table>
    </div>

    {_defender_section(alert)}

    <div style="background:#f0f9ff;padding:16px;margin:20px;border-radius:8px;border-left:4px solid #0284c7;">
      <div style="font-weight:bold;color:#0c4a6e;margin-bottom:12px;font-size:14px;">
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
