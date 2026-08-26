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
from email.utils import formatdate, make_msgid, parseaddr
from typing import TYPE_CHECKING, Any

from src.agents.narrator import NarratorPlan
from src import report_theme as _theme
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
                    ad_name = getattr(u, "display_name", None)
                    name_part = f" ({ad_name})" if ad_name else ""
                    lines.append(f"  AD {getattr(u, 'sam', '?')}{name_part}: {st}{lk} (bad_pwd={getattr(u, 'bad_pwd_count', 0)})")
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

    # Devuelve la tabla entera, no <tr> sueltos: las clases .info-table/.label
    # vivían en el <style> del shell viejo, y al unificar el diseño las filas
    # quedaron sin columnas ni padding — se veían como texto corrido.
    return _theme.kv_rows(rows)


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
    return _theme.section(
        "Defender &mdash; gu&iacute;a y pivots",
        "Lo que recomienda el vendor y d&oacute;nde seguir la investigaci&oacute;n",
        guidance + links_html,
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
        # Nombre real de AD (displayName). Es deterministico (backfilled), no inventado.
        ad_name = getattr(u, "display_name", None)
        if ad_name:
            bits.append(f"<strong>{_esc(ad_name)}</strong>")
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
    return _theme.section(
        "Contexto local (AD + Wazuh)",
        "Qu&eacute; sabe la propia infraestructura sobre los involucrados",
        "".join(blocks),
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
    return _theme.section(
        "Inteligencia externa",
        "Reputaci&oacute;n de los indicadores en fuentes de terceros",
        "".join(blocks),
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

    # El badge del header sale del riesgo que evaluó el Narrator, no del nivel
    # crudo de la regla: es la lectura del SOC, que es la que hay que decidir.
    _BADGE_POR_RIESGO = {
        "critical": "critico", "high": "alto", "medium": "medio",
        "low": "bajo", "info": "info", "informational": "info",
    }
    badge_kind = _BADGE_POR_RIESGO.get((plan.risk_level or "").lower(), "medio")

    cuerpo = _theme.section(
        "Informaci&oacute;n principal",
        _esc(alert.wazuh_rule.description),
        _theme.callout(pivot_value, accent=color)
        + '<div style="padding-top:4px;">'
        + rule_badge_html + " " + risk_badge_html
        + (" " + _badge(f"TICKET #{invgate_request_id}", "info") if invgate_request_id else "")
        + "</div>",
    )

    cuerpo += _theme.section(
        "Resumen ejecutivo",
        "",
        f'<div style="font-family:{_theme.FONT};font-size:13px;line-height:21px;'
        f'color:{_theme.C_TEXT};white-space:pre-line;">{_esc(plan.executive_summary)}</div>'
        + _theme.spacer(18)
        + _ctx_rows(alert, plan),
    )

    cuerpo += _defender_section(alert)
    cuerpo += _enrichment_section(enrichment)
    cuerpo += _threat_intel_section(threat_intel)

    cuerpo += _theme.section(
        "An&aacute;lisis del incidente",
        "Por qu&eacute; el SOC lo lee as&iacute;",
        _theme.notice(
            f'<span style="white-space:pre-line;">{_esc(plan.rationale)}</span>',
            accent=_theme.C_HIGH, bg=_theme.C_WARN_BG,
        ),
    )

    cuerpo += _theme.section(
        f"Acciones propuestas ({len(plan.actions)})",
        "",
        f'<ul style="margin:0;padding-left:20px;font-family:{_theme.FONT};'
        f'font-size:13px;line-height:23px;color:{_theme.C_TEXT};">{_actions_html(plan)}</ul>',
    )

    cuerpo += _theme.section(
        "Esta alerta requiere tu aprobaci&oacute;n",
        f"Link de un solo uso, v&aacute;lido por {ttl_hours} h. El primer click decide.",
        f'<div style="text-align:center;padding-top:6px;">{cta_buttons}</div>',
    )

    return _theme.document(
        title=_esc(alert.title),
        subtitle=f"Notificaci&oacute;n de incidente &nbsp;&middot;&nbsp; {_esc(alert.wazuh_rule.description)}",
        body=cuerpo,
        footer="SOC L1 &middot; Wazuh + Defender &mdash; pipeline multi-agente<br>Generado autom&aacute;ticamente, no responder a este correo.",
        doc_title=f"SOC L1 - {_esc(alert.title)}",
        badge_kind=badge_kind,
        preheader=f"{plan.risk_level} &middot; {_esc(alert.title)} &middot; requiere decisi&oacute;n",
    )


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
    msg["Subject"] = _theme.subject(
        "INCIDENTE",
        plan.risk_level.upper(),
        alert.title,
        alert.device.hostname or "unknown",
        f"ticket #{invgate_request_id}" if invgate_request_id else "",
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


def _stamp_headers(settings: Settings, msg: EmailMessage) -> None:
    """Agrega Date y Message-ID si faltan.

    El stdlib no los pone y smtplib tampoco: sin ellos varios filtros antispam
    penalizan el mensaje (verificado contra el Exchange de Grupo Alemana, donde
    los reportes en HTML caían en No Deseado). Ver src/report_theme.py.
    """
    if "Date" not in msg:
        msg["Date"] = formatdate(localtime=True)
    if "Message-ID" not in msg:
        addr = parseaddr(settings.smtp_from or "")[1] or ""
        domain = addr.split("@")[-1] if "@" in addr else None
        msg["Message-ID"] = make_msgid(domain=domain) if domain else make_msgid()


def _embed_logo(msg: EmailMessage) -> None:
    """Adjunta el logo por Content-ID si el HTML lo referencia.

    El shell de report_theme apunta a `cid:logoalemana`. Sin esta parte el
    correo llega con el ícono de imagen rota; con ella Outlook lo pinta sin
    pedir "descargar imágenes", que es justamente por qué se usa CID y no URL.
    """
    raw = _theme.load_logo()
    if not raw:
        return
    for part in msg.walk():
        if part.get_content_type() != "text/html":
            continue
        if f"cid:{_theme.LOGO_CID}" not in part.get_content():
            continue
        part.add_related(
            raw, maintype="image", subtype="png", cid=f"<{_theme.LOGO_CID}>"
        )
        return


def _send_sync(settings: Settings, msg: EmailMessage) -> None:
    """Conexión SMTP sincrónica con STARTTLS opcional. Corre bajo to_thread."""
    _stamp_headers(settings, msg)
    _embed_logo(msg)
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
    # El asunto es texto plano: nada de entidades HTML acá.
    subject = _theme.subject(
        "BLOQUEOS", "OBSERVACION", ip,
        f"regla {rule_id}" if rule_id else "",
    )
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

    detalle = "".join(
        _theme.table_row(
            [
                (h(k), "left", f"color:{_theme.C_MUTED};white-space:nowrap;"),
                (_theme.code(h(v)), "left", ""),
            ],
            idx,
        )
        for idx, (k, v) in enumerate(
            (
                ("Bloquear&iacute;a la IP", ip),
                ("Regla IPS", rule_id or "&mdash;"),
                ("Host / origen", host or "&mdash;"),
                ("Alerta", alert_id),
                ("TTL del ban", f"{ttl_hours}h"),
            ),
            1,
        )
    )

    cuerpo = _theme.section(
        "Nada se ejecut&oacute;",
        "Fase 0 &mdash; solo observaci&oacute;n",
        _theme.notice(
            "SOC-L1 detect&oacute; una alerta IPS que <strong>bloquear&iacute;a</strong> esta IP, "
            "pero <strong>no toc&oacute; el firewall</strong>.",
            accent=_theme.C_HIGH,
        )
        + _theme.table_open([("Dato", "170", "left"), ("Valor", None, "left")])
        + detalle
        + _theme.TABLE_CLOSE,
    )
    cuerpo += _theme.section(
        "Por qu&eacute; recib&iacute;s este aviso",
        "",
        "Hoy el bloqueo real lo sigue haciendo el integration "
        + _theme.code("custom-email-unified")
        + " de Wazuh. Cuando pasemos a Fase 1, SOC-L1 ejecuta el quarantine y este "
        "aviso se reemplaza por el flujo completo, con ticket y aprobaci&oacute;n.",
    )

    body_html = _theme.document(
        title="FortiGate &middot; observaci&oacute;n",
        subtitle=f"Bloquear&iacute;a {h(ip)} &nbsp;&middot;&nbsp; no se ejecut&oacute; nada",
        body=cuerpo,
        footer="SOC L1 &mdash; aviso temporal de Fase 0",
        doc_title=f"FortiGate - observaci&oacute;n {ip}",
        badge_kind="atencion",
        preheader=f"Bloquear&iacute;a {ip} &middot; Fase 0, sin ejecutar",
    )
    msg.add_alternative(body_html, subtype="html", cte="quoted-printable")

    try:
        await asyncio.to_thread(_send_sync, settings, msg)
        logger.info(
            "mailer: email FGT-OBSERVE enviado | ip=%s rule=%s alert=%s to=%s",
            ip, rule_id, alert_id, settings.smtp_to_approvers,
        )
    except Exception:
        logger.exception("mailer: send FGT-OBSERVE failed | ip=%s alert=%s", ip, alert_id)


async def send_fgt_block_email(
    settings: Settings,
    *,
    alert_id: str,
    ip: str,
    rule_id: str | None,
    host: str | None,
    ttl_hours: int,
    expires_at: str | None = None,
    invgate_request_id: int | None = None,
    invgate_closed: bool = False,
    invgate_description: str | None = None,
) -> None:
    """Fase 1: confirma que SOC-L1 BLOQUEÓ la IP en FortiGate (quarantine con TTL).

    Reemplaza al aviso de Fase 0. El caller ya hizo el dedup por IP; esto solo arma y manda.
    Si se creó un ticket InvGate, incluye el número, su estado (cerrado/abierto) y el texto
    exacto que quedó registrado en el ticket (`invgate_description`).
    """
    if not settings.smtp_host or not settings.smtp_to_approvers:
        logger.warning(
            "mailer: SMTP no configurado - skip email FGT-BLOCK para ip=%s", ip
        )
        return

    h = html.escape
    # Estado del ticket para subject/cuerpo: cerrado vs abierto (close pudo dar 403).
    if invgate_request_id:
        ticket_state = "cerrado" if invgate_closed else "abierto"
        ticket_value = f"#{invgate_request_id} ({ticket_state})"
    else:
        ticket_value = "—"
    ticket_tag = f" · ticket #{invgate_request_id}" if invgate_request_id else ""

    subject = _theme.subject(
        "BLOQUEOS", "BLOQUEADA", ip,
        f"ticket #{invgate_request_id}" if invgate_request_id else "",
    )
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from
    msg["To"] = settings.smtp_to_approvers

    ticket_text = (
        f"Ticket InvGate:   {ticket_value}\n" if invgate_request_id else ""
    )
    ticket_block_text = (
        f"\n--- Contenido del ticket InvGate #{invgate_request_id} ---\n"
        f"{invgate_description}\n"
        if invgate_request_id and invgate_description
        else ""
    )
    text = (
        f"SOC-L1 · FortiGate auto-block (Fase 1 — EJECUTADO)\n\n"
        f"IP bloqueada:     {ip}\n"
        f"Regla IPS:        {rule_id or '—'}\n"
        f"Host/origen:      {host or '—'}\n"
        f"Alerta:           {alert_id}\n"
        f"TTL del ban:      {ttl_hours}h (quarantine con TTL)\n"
        f"Expira:           {expires_at or '—'}\n"
        f"{ticket_text}\n"
        f"SOC-L1 aplicó un quarantine (banned users con TTL) sobre la IP origen en "
        f"FortiGate. El ban se libera solo al vencer el TTL.\n"
        f"{ticket_block_text}"
    )
    msg.set_content(text)

    # Detalle en el sistema de diseño compartido (ver src/report_theme.py):
    # tablas para el layout, inline CSS, y el rojo de alerta solo en el encabezado.
    detalle_rows = "".join(
        _theme.table_row(
            [
                (h(k), "left", f"color:{_theme.C_MUTED};white-space:nowrap;"),
                (f'<code style="font-size:12px;">{h(v)}</code>', "left", "font-weight:bold;"),
            ],
            idx,
        )
        for idx, (k, v) in enumerate(
            (
                ("IP bloqueada", ip),
                ("Regla IPS", rule_id or "—"),
                ("Host / origen", host or "—"),
                ("Alerta", alert_id),
                ("TTL del ban", f"{ttl_hours}h"),
                ("Expira", expires_at or "—"),
                ("Ticket InvGate", ticket_value),
            ),
            1,
        )
    )

    cuerpo = _theme.section(
        "Acci&oacute;n ejecutada",
        "Bloqueo autom&aacute;tico aplicado en FortiGate",
        _theme.notice(
            "SOC-L1 detect&oacute; una alerta IPS de alta confianza y <strong>bloque&oacute; la IP origen</strong> "
            "en FortiGate mediante quarantine con TTL. El ban se libera solo al vencer el TTL.",
            accent=_theme.C_CRIT,
            bg="#fdf1f2",
        )
        + _theme.table_open(
            [("Dato", "150", "left"), ("Valor", None, "left")]
        )
        + detalle_rows
        + _theme.TABLE_CLOSE,
    )

    if invgate_request_id and invgate_description:
        cuerpo += _theme.section(
            f"Contenido registrado en el ticket InvGate #{h(str(invgate_request_id))}",
            "",
            f'''<pre style="margin:0;padding:14px 16px;background:#f6f8fa;border:1px solid {_theme.C_BORDER};'''
            f'''border-radius:8px;color:{_theme.C_TEXT};font-size:12px;line-height:1.5;white-space:pre-wrap;'''
            f'''font-family:{_theme.MONO};">{h(invgate_description)}</pre>''',
        )

    body_html = _theme.document(
        title="FortiGate &middot; IP bloqueada",
        subtitle=f"Auto-block ejecutado &nbsp;&middot;&nbsp; {h(ip)}",
        body=cuerpo,
        footer="SOC L1 &mdash; auto-block de FortiGate",
        doc_title=f"FortiGate - IP bloqueada {ip}",
        # Sin badge explícito caía en el default "INFORMATIVO", con la franja
        # verde, en un correo que anuncia un bloqueo por una alerta IPS.
        badge_kind="alto",
        preheader=f"IP {ip} bloqueada por {ttl_hours}h &middot; sin intervenci&oacute;n necesaria",
    )
    msg.add_alternative(body_html, subtype="html", cte="quoted-printable")

    try:
        await asyncio.to_thread(_send_sync, settings, msg)
        logger.info(
            "mailer: email FGT-BLOCK enviado | ip=%s rule=%s alert=%s ticket=%s to=%s",
            ip, rule_id, alert_id, invgate_request_id or "n/a", settings.smtp_to_approvers,
        )
    except Exception:
        logger.exception("mailer: send FGT-BLOCK failed | ip=%s alert=%s", ip, alert_id)


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
    return _theme.section(
        "Resultado de la ejecuci&oacute;n",
        "Qu&eacute; devolvi&oacute; cada acci&oacute;n al aplicarse",
        f'<ul style="margin:0;padding-left:20px;font-family:{_theme.FONT};'
        f'font-size:13px;line-height:23px;color:{_theme.C_TEXT};">{"".join(items)}</ul>',
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

    _BADGE_POR_RIESGO = {
        "critical": "critico", "high": "alto", "medium": "medio",
        "low": "bajo", "info": "info", "informational": "info",
    }
    badge_kind = _BADGE_POR_RIESGO.get((plan.risk_level or "").lower(), "medio")

    cuerpo = _theme.section(
        "Caso cerrado",
        f"Alerta {_esc(alert.alert_id)} &middot; host {_esc(alert.device.hostname)}",
        f'<div style="padding-bottom:12px;">{decision_badge} {risk_badge_html}'
        + (f' {_badge(f"TICKET #{invgate_request_id}", "info")}' if invgate_request_id else "")
        + "</div>"
        + f'<div style="font-family:{_theme.FONT};font-size:13px;line-height:21px;'
        f'color:{_theme.C_TEXT};white-space:pre-line;">{_esc(plan.executive_summary)}</div>'
        + _theme.spacer(18)
        + _ctx_rows(alert, plan),
    )

    cuerpo += _defender_section(alert)

    cuerpo += _theme.section(
        "Timeline del caso",
        "Qu&eacute; hizo cada agente y cu&aacute;ndo",
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">{_timeline_rows_html(events)}</table>',
    )

    cuerpo += _execution_rows_html(execution_results)

    return _theme.document(
        title=_esc(alert.title),
        subtitle=f"Notificaci&oacute;n de cierre &nbsp;&middot;&nbsp; {_decision_label(decision)}",
        body=cuerpo,
        footer="SOC L1 &middot; Wazuh + Defender &mdash; pipeline multi-agente<br>Notificaci&oacute;n de cierre, generada autom&aacute;ticamente. No responder.",
        doc_title=f"SOC L1 - caso cerrado {_esc(alert.alert_id)}",
        badge_kind=badge_kind,
        preheader=f"Caso cerrado: {_decision_label(decision)} &middot; {_esc(alert.title)}",
    )


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
    msg["Subject"] = _theme.subject(
        "INCIDENTE",
        "CERRADO",
        _decision_label(decision),
        alert.title,
        f"ticket #{invgate_request_id}" if invgate_request_id else "",
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
