"""Render del reporte (HTML y texto plano) y envío por correo.

El diseño NO depende de un <style>: todo el layout va en <table> con CSS inline
(Outlook 2016 / Exchange renderiza con el motor de Word e ignora buena parte de
un <style>). Ver src/report_theme.py para las restricciones y las señales
antispam que hay que evitar.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from html import escape

from src import report_theme as _theme
from src.vuln.scoring import (
    EPSS_HIGH_THRESHOLD,
    PRIORITY_THRESHOLD,
    W_CVSS,
    W_EPSS,
    W_KEV,
)

EMAIL_CONFIG_FILE = os.getenv("VULN_EMAIL_CONFIG", "/var/ossec/etc/email-config.json")

TOP_LIMIT = int(os.getenv("VULN_TOP_LIMIT", "15"))
ORG_NAME = os.getenv("VULN_ORG_NAME", "Grupo Alemana")

logger = logging.getLogger("vuln_priority")

# Sistema de diseño compartido.
CSS = _theme.CSS
FONT = _theme.FONT
C_GREEN, C_GREEN_DK = _theme.C_GREEN, _theme.C_GREEN_DK
C_CRIT, C_HIGH, C_MED = _theme.C_CRIT, _theme.C_HIGH, _theme.C_MED
C_MUTED, C_TEXT, C_BORDER, C_BG = _theme.C_MUTED, _theme.C_TEXT, _theme.C_BORDER, _theme.C_BG

_sev_color = _theme.sev_color
_num = _theme.num
_badge = _theme.badge
_metric_card = _theme.metric_card
_delta_badge = _theme.delta_badge


def render_coverage_notice(cov: dict) -> str:
    """Aviso de calidad del dato, arriba de todo: condiciona la lectura del resto."""
    if not cov.get("disponible"):
        return ""
    desf, sin = cov["desfasados"], cov["sin_datos"]
    if not desf and not sin:
        return ""

    partes = []
    if desf:
        detalle = "; ".join(
            f"{escape(d['host'])} (indexado {escape(d['indexado'])} &rarr; real "
            f"{escape(d['actual'])}, {_num(d['hallazgos'])} hallazgos)"
            for d in desf[:6]
        )
        partes.append(
            f"<strong>{len(desf)} host(s) con inventario desfasado.</strong> El detector de "
            f"vulnerabilidades conserva un build de sistema operativo anterior al que el "
            f"agente reporta hoy, as&iacute; que sus <strong>{_num(cov['hallazgos_dudosos'])} "
            f"hallazgos</strong> pueden estar ya parcheados: {detalle}."
        )
    if sin:
        partes.append(
            f"<strong>{len(sin)} host(s) sin ning&uacute;n hallazgo.</strong> Los agentes est&aacute;n "
            f"activos y reportan paquetes y hotfixes, pero el detector no genera datos para ellos, "
            f"as&iacute; que no aparecen en este reporte: {escape(', '.join(sin[:10]))}."
        )
    partes.append(
        "En ambos casos el problema est&aacute; en el detector de Wazuh, no en los datos que env&iacute;an "
        "los agentes. Los totales de abajo deben leerse con esa salvedad."
    )

    return _theme.section(
        "Aviso sobre la calidad de los datos",
        "Leer antes que los n&uacute;meros",
        _theme.notice(
            "<br><br>".join(partes), accent=_theme.C_HIGH, bg="#fff8e6"
        ),
    )


def render_compliance_fragment(comp: dict, prev_file: str, host_limit: int = 12) -> str:
    """Sección de cumplimiento de parches por host (datos del reporte semanal original)."""
    if not comp["has_previous"]:
        prev_label = "sin semana anterior para comparar"
    else:
        base = os.path.basename(prev_file).replace("snapshot_", "")[:8]
        try:
            prev_label = "vs. " + datetime.strptime(base, "%Y%m%d").strftime("%d/%m/%Y")
        except ValueError:
            prev_label = "vs. semana anterior"

    sla = comp["sla"]
    sla_color = C_GREEN if sla >= 80 else C_HIGH if sla >= 60 else C_CRIT
    sla_text = "Cumpliendo" if sla >= 80 else "Cerca del objetivo" if sla >= 60 else "Acci&oacute;n requerida"

    cards = [
        _metric_card("HOSTS MONITOREADOS", _num(comp["total_hosts"]), C_TEXT,
                     f"+{comp['new_hosts']} nuevos" if comp["new_hosts"] else "sin altas nuevas"),
        _metric_card("CR&Iacute;TICAS", _num(comp["critical_now"]), C_CRIT,
                     f"{_delta_badge(comp['critical_delta'])} vs. anterior"),
        _metric_card("ALTAS", _num(comp["high_now"]), C_HIGH,
                     f"{_delta_badge(comp['high_delta'])} vs. anterior"),
        _metric_card("MEDIAS / BAJAS", _num(comp["medium_now"] + comp["low_now"]), C_MUTED,
                     f"M: {_num(comp['medium_now'])} &middot; B: {_num(comp['low_now'])}"),
        _metric_card("SLA DE PARCHEO", f"{sla:.0f}%", sla_color,
                     f"{sla_text} &middot; {comp['improved']} mejoraron, {comp['worsened']} empeoraron"),
    ]

    gone = comp.get("removed_hosts") or []
    gone_note = ""
    if gone:
        lista = escape(", ".join(gone))
        gone_note = f"""
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#fff8e6" style="background-color:#fff8e6;border-left:4px solid {C_HIGH};border-collapse:separate;border-radius:8px;">
        <tr>
          <td style="padding:10px 12px;font-family:{FONT};font-size:12px;line-height:17px;color:{C_TEXT};">
            <strong>Dej&oacute; de reportar:</strong> {lista}.
            No se cuenta como mejora ni entra en el SLA &mdash; un agente que no reporta no es un host parcheado.
            Conviene verificar el estado del agente Wazuh en ese equipo.
          </td>
        </tr>
      </table>"""

    parts = [f"""
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#ffffff" style="background-color:#ffffff;border:1px solid {C_BORDER};border-collapse:separate;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,0.06);">
  <tr>
    <td style="padding:20px 22px;font-family:{FONT};">
      <div style="font-family:{FONT};font-size:15px;line-height:20px;font-weight:bold;color:{_theme.C_INK};padding-bottom:3px;">Cumplimiento de parches por host</div>
      <div style="font-family:{FONT};font-size:12px;line-height:17px;color:{C_MUTED};padding-bottom:16px;">Evoluci&oacute;n semana contra semana &middot; {prev_label}</div>
{gone_note}
{_theme.metric_row(cards)}
    </td>
  </tr>
</table>
"""]

    # Hosts con mayor movimiento: primero los que empeoraron (accionables), luego los que mejoraron.
    movers = [r for r in comp["rows"] if r["trend"] != "stable" and not r["was_removed"]]
    movers.sort(key=lambda r: (r["trend"] != "worsened", -abs(r["total_delta"])))
    movers = movers[:host_limit]

    if movers:
        th = f"font-family:{FONT};font-size:11px;font-weight:bold;color:#ffffff;padding:10px 9px;letter-spacing:0.3px;text-align:left;"
        td_base = (
            f"font-family:{FONT};font-size:12px;line-height:18px;color:{C_TEXT};"
            f"padding:9px 9px;border-bottom:1px solid {_theme.C_SOFT};vertical-align:top;"
        )
        parts.append(f"""
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#ffffff" style="background-color:#ffffff;border:1px solid {C_BORDER};border-collapse:separate;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,0.06);">
  <tr>
    <td style="padding:20px 22px;font-family:{FONT};">
      <div style="font-family:{FONT};font-size:15px;line-height:20px;font-weight:bold;color:{_theme.C_INK};padding-bottom:3px;">Hosts con mayor movimiento</div>
      <div style="font-family:{FONT};font-size:12px;color:{C_MUTED};padding-bottom:12px;">Cr&iacute;ticas + altas, respecto de la semana anterior</div>
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
        <tr bgcolor="{C_GREEN}" style="background-color:{C_GREEN};">
          <th align="left" style="{th}">Host</th>
          <th width="96" align="center" style="{th}text-align:center;">Cr&iacute;ticas</th>
          <th width="96" align="center" style="{th}text-align:center;">Altas</th>
          <th width="76" align="center" style="{th}text-align:center;">Variaci&oacute;n</th>
          <th width="86" align="center" style="{th}text-align:center;">Estado</th>
        </tr>
""")
        for i, r in enumerate(movers, 1):
            row_bg = "#ffffff" if i % 2 else "#fafbfc"
            if r["trend"] == "improved":
                estado = _badge("MEJOR&Oacute;", "#d4edda", "#155724", "#b7dfc2")
            else:
                estado = _badge("EMPEOR&Oacute;", "#f8d7da", "#721c24", "#f1b7bd")
            nuevo = "<br>" + _badge("NUEVO", "#fff3cd", "#856404", "#ffe6a1") if r["is_new"] else ""
            parts.append(f"""
        <tr bgcolor="{row_bg}" style="background-color:{row_bg};">
          <td style="{td_base}font-weight:bold;">{escape(r['host'])}{nuevo}</td>
          <td align="center" style="{td_base}text-align:center;">{r['critical_before']} &rarr; <strong style="color:{C_CRIT};">{r['critical_now']}</strong></td>
          <td align="center" style="{td_base}text-align:center;">{r['high_before']} &rarr; <strong style="color:{C_HIGH};">{r['high_now']}</strong></td>
          <td align="center" style="{td_base}text-align:center;">{_delta_badge(r['total_delta'])}</td>
          <td align="center" style="{td_base}text-align:center;">{estado}</td>
        </tr>
""")
        parts.append("""
      </table>
    </td>
  </tr>
</table>
""")
    return _theme.spacer(16).join(parts)


def render_fragment(summary: dict, groups: list[dict], top_limit: int = TOP_LIMIT) -> str:
    """Sección HTML de priorización (embebible en el reporte semanal).

    Layout 100% con tablas anidadas y CSS inline: el destinatario lee en
    Outlook 2016 / Exchange (motor de Word), que no soporta grid ni flex e
    ignora buena parte del <style> del head.
    """
    top = groups[:top_limit]
    parts: list[str] = []

    baseline_note = ""
    if summary.get("baseline"):
        baseline_note = f"""
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#f4f6f8" style="background-color:{C_BG};border-left:4px solid {C_MUTED};border-collapse:separate;border-radius:8px;">
        <tr>
          <td style="padding:10px 12px;font-family:{FONT};font-size:12px;line-height:17px;color:{C_MUTED};">
            <strong style="color:{C_TEXT};">Primera corrida:</strong> se estableci&oacute; la l&iacute;nea base.
            El comparativo de ciclo de vida (nuevas / resueltas / reabiertas) arranca la pr&oacute;xima semana.
          </td>
        </tr>
      </table>
"""

    # ---- Sección 1: métricas ejecutivas -----------------------------------
    # 5 métricas sin grid: tabla de 3 columnas, 2 filas; la última tarjeta
    # ocupa 2 columnas (colspan) para no dejar hueco y para que entren los
    # tres números del ciclo de vida en una línea.
    cards = [
        _metric_card(
            "EXPLOTADAS IN-THE-WILD",
            _num(summary["kev_count"]),
            C_CRIT,
            "hallazgos en cat&aacute;logo CISA KEV",
        ),
        _metric_card(
            "USADAS POR RANSOMWARE",
            _num(summary["kev_ransomware_count"]),
            C_CRIT,
            "campa&ntilde;as confirmadas",
        ),
        _metric_card(
            f"EPSS &ge; {EPSS_HIGH_THRESHOLD:.0%}",
            _num(summary["epss_high_count"]),
            C_HIGH,
            "alta prob. de explotaci&oacute;n a 30 d&iacute;as",
        ),
        _metric_card(
            f"PRIORIDAD &ge; {PRIORITY_THRESHOLD:.0f}",
            _num(summary["priority_high_count"]),
            C_HIGH,
            f"de {_num(summary['total_active'])} hallazgos activos",
        ),
        _metric_card(
            "CICLO DE VIDA",
            _num(summary["resolved_count"]),
            C_GREEN,
            f"resueltas &middot; {_num(summary['new_count'])} nuevas "
            f"&middot; {_num(summary['reopened_count'])} reabiertas",
        ),
    ]

    parts.append(f"""
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#ffffff" style="background-color:#ffffff;border:1px solid {C_BORDER};border-collapse:separate;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,0.06);">
  <tr>
    <td style="padding:20px 22px;font-family:{FONT};">
      <div style="font-family:{FONT};font-size:15px;line-height:20px;font-weight:bold;color:{_theme.C_INK};padding-bottom:3px;">Priorizaci&oacute;n por explotabilidad real</div>
      <div style="font-family:{FONT};font-size:12px;line-height:17px;color:{C_MUTED};padding-bottom:16px;">EPSS (FIRST.org) + cat&aacute;logo CISA KEV</div>
{baseline_note}
{_theme.metric_row(cards)}
    </td>
  </tr>
</table>
""")

    # ---- Sección 2: tabla Top N -------------------------------------------
    th = (
        f"font-family:{FONT};font-size:11px;font-weight:bold;color:#ffffff;"
        f"padding:8px 5px;text-align:left;"
    )
    parts.append(f"""
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#ffffff" style="background-color:#ffffff;border:1px solid {C_BORDER};border-collapse:separate;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,0.06);">
  <tr>
    <td style="padding:20px 22px;font-family:{FONT};">
      <div style="font-family:{FONT};font-size:15px;line-height:20px;font-weight:bold;color:{_theme.C_INK};padding-bottom:3px;">Top {len(top)} CVEs a parchear primero</div>
      <div style="font-family:{FONT};font-size:12px;color:{C_MUTED};padding-bottom:12px;">Ordenados por score de prioridad, de mayor a menor</div>
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
        <tr bgcolor="{C_GREEN}" style="background-color:{C_GREEN};">
          <th width="18" align="left" style="{th}">#</th>
          <th width="104" align="left" style="{th}">CVE</th>
          <th width="52" align="left" style="{th}">Sev.</th>
          <th width="34" align="right" style="{th}text-align:right;">CVSS</th>
          <th width="46" align="right" style="{th}text-align:right;">EPSS</th>
          <th width="76" align="center" style="{th}text-align:center;">KEV</th>
          <th width="36" align="right" style="{th}text-align:right;">Hosts</th>
          <th width="52" align="right" style="{th}text-align:right;">Prior.</th>
          <th align="left" style="{th}">Producto afectado</th>
        </tr>
""")

    td_base = (
        f"font-family:{FONT};font-size:12px;line-height:16px;color:{C_TEXT};"
        f"padding:7px 5px;border-bottom:1px solid #eef2f5;vertical-align:top;"
    )

    for i, g in enumerate(top, 1):
        kev_badge = f'<span style="color:{C_MUTED};">&mdash;</span>'
        if g.get("kev_ransomware"):
            kev_badge = _badge("RANSOMWARE", C_CRIT, "#ffffff")
        elif g.get("cisa_kev"):
            kev_badge = _badge("KEV", "#f8d7da", "#721c24", "#f1b7bd")

        new_badge = (
            "<br>" + _badge("NUEVA", "#fff3cd", "#856404", "#ffe6a1")
            if g.get("is_new_group")
            else ""
        )
        pkgs = escape(", ".join(g.get("packages") or [])[:70]) or "&mdash;"
        hosts_tip = escape(", ".join(g.get("hosts_list", [])[:8]))
        ref = g.get("reference") or f"https://nvd.nist.gov/vuln/detail/{g['cve']}"
        prio = float(g["priority_score"])
        prio_color = C_CRIT if prio >= PRIORITY_THRESHOLD else C_TEXT
        row_bg = "#ffffff" if i % 2 else "#fafbfc"

        parts.append(f"""
        <tr bgcolor="{row_bg}" style="background-color:{row_bg};">
          <td align="left" style="{td_base}color:{C_MUTED};">{i}</td>
          <td align="left" style="{td_base}">
            <a href="{escape(ref)}" style="color:{C_GREEN_DK};font-weight:bold;text-decoration:none;">{escape(g['cve'])}</a>{new_badge}
          </td>
          <td align="left" style="{td_base}color:{_sev_color(g.get('severity'))};font-weight:bold;">{escape(str(g.get('severity','')))}</td>
          <td align="right" style="{td_base}text-align:right;">{g['cvss_score']:.1f}</td>
          <td align="right" style="{td_base}text-align:right;">{g['epss_score']*100:.2f}%</td>
          <td align="center" style="{td_base}text-align:center;">{kev_badge}</td>
          <td align="right" title="{hosts_tip}" style="{td_base}text-align:right;">{g['hosts_count']}</td>
          <td align="right" style="{td_base}text-align:right;font-weight:bold;color:{prio_color};">{prio:.1f}</td>
          <td align="left" style="{td_base}color:{C_MUTED};font-size:11px;">{pkgs}</td>
        </tr>
""")

    parts.append("""
      </table>
    </td>
  </tr>
</table>
""")

    # ---- Sección 3: metodología + privacidad -------------------------------
    p = f"font-family:{FONT};font-size:12px;line-height:18px;color:{C_MUTED};margin:0;"
    parts.append(f"""
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#ffffff" style="background-color:#ffffff;border:1px solid {C_BORDER};border-collapse:separate;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,0.06);">
  <tr>
    <td style="padding:20px 22px;font-family:{FONT};">
      <div style="font-family:{FONT};font-size:14px;font-weight:bold;color:{C_TEXT};padding-bottom:10px;">C&oacute;mo leer este reporte</div>
      <p style="{p}padding-bottom:8px;">
        <strong style="color:{C_TEXT};">C&aacute;lculo de la prioridad:</strong>
        CVSS &times; {W_CVSS:g} &nbsp;+&nbsp; EPSS &times; {W_EPSS:g} &nbsp;+&nbsp; CISA&nbsp;KEV &times; {W_KEV:g}, con tope 100.
      </p>
      <p style="{p}padding-bottom:8px;">
        <strong style="color:{C_TEXT};">EPSS</strong> (FIRST.org) estima la probabilidad de que la vulnerabilidad sea
        explotada en los pr&oacute;ximos 30 d&iacute;as. Se considera alta a partir de {EPSS_HIGH_THRESHOLD:.0%}.
      </p>
      <p style="{p}padding-bottom:8px;">
        <strong style="color:{C_TEXT};">CISA KEV</strong> es el cat&aacute;logo oficial de vulnerabilidades con
        explotaci&oacute;n confirmada en ataques reales. Un CVSS 9.8 sin explotaci&oacute;n conocida corre por detr&aacute;s
        de un CVSS 7.5 que ya se est&aacute; explotando activamente.
      </p>
      <p style="{p}">
        <strong style="color:{C_TEXT};">Privacidad:</strong> hacia FIRST y CISA solo viajan identificadores CVE;
        ning&uacute;n dato de activos, paquetes ni credenciales sale del entorno.
      </p>
    </td>
  </tr>
</table>
""")
    return _theme.spacer(16).join(parts)


def render_plain_coverage(cov: dict) -> list[str]:
    """Aviso de calidad del dato para la versión texto plano."""
    if not cov.get("disponible") or (not cov["desfasados"] and not cov["sin_datos"]):
        return []
    out = ["AVISO SOBRE LA CALIDAD DE LOS DATOS", ""]
    if cov["desfasados"]:
        out.append(
            f"{len(cov['desfasados'])} host(s) con inventario desfasado: el detector conserva "
            f"un build de SO anterior al que reporta el agente, asi que sus "
            f"{cov['hallazgos_dudosos']} hallazgos pueden estar ya parcheados."
        )
        for d in cov["desfasados"][:6]:
            out.append(f"  {d['host']:<20} indexado {d['indexado']} -> real {d['actual']} ({d['hallazgos']} hallazgos)")
    if cov["sin_datos"]:
        out.append(
            f"{len(cov['sin_datos'])} host(s) sin ningun hallazgo pese a estar activos: "
            + ", ".join(cov["sin_datos"][:10])
        )
    out += ["", "El problema esta en el detector de Wazuh, no en los datos de los agentes.", ""]
    return out


def render_plain_compliance(comp: dict) -> list[str]:
    """Bloque de cumplimiento para la versión texto plano."""
    if not comp:
        return []
    out = [
        "CUMPLIMIENTO DE PARCHES POR HOST",
        "",
        f"Hosts monitoreados: {comp['total_hosts']} ({comp['new_hosts']} nuevos)",
        f"Criticas: {comp['critical_now']} ({comp['critical_delta']:+d} vs. semana anterior)",
        f"Altas: {comp['high_now']} ({comp['high_delta']:+d} vs. semana anterior)",
        f"Medias/Bajas: {comp['medium_now']} / {comp['low_now']}",
        (f"Dejo de reportar: {', '.join(comp['removed_hosts'])} "
         "(no cuenta como mejora ni entra en el SLA)" if comp.get('removed_hosts') else ""),
        f"SLA de parcheo: {comp['sla']:.0f}% "
        f"({comp['improved']} mejoraron, {comp['worsened']} empeoraron, {comp['stable']} sin cambios)",
        "",
    ]
    movers = [r for r in comp["rows"] if r["trend"] != "stable" and not r["was_removed"]]
    movers.sort(key=lambda r: (r["trend"] != "worsened", -abs(r["total_delta"])))
    if movers:
        out.append("Hosts con mayor movimiento (criticas + altas):")
        for r in movers[:12]:
            marca = "EMPEORO" if r["trend"] == "worsened" else "MEJORO"
            out.append(
                f"  {r['host']:<22} criticas {r['critical_before']}->{r['critical_now']}  "
                f"altas {r['high_before']}->{r['high_now']}  ({r['total_delta']:+d}) {marca}"
            )
        out.append("")
    return out


def render_plain(
    summary: dict,
    groups: list[dict],
    top_limit: int = TOP_LIMIT,
    comp: dict | None = None,
    cov: dict | None = None,
) -> str:
    """Versión texto plano equivalente al HTML.

    No es decorativa: si la parte text/plain no se parece a la HTML, los filtros
    antispam lo penalizan (regla clásica de "multipart alternative diferente").
    """
    fecha = datetime.now().strftime("%d/%m/%Y")
    out = [
        f"{ORG_NAME} - Gerencia Tecnologia",
        f"Reporte de vulnerabilidades y cumplimiento de parches - {fecha}",
        "",
        *render_plain_coverage(cov or {}),
        *render_plain_compliance(comp or {}),
        "PRIORIZACION POR EXPLOTABILIDAD REAL",
        "",
        f"Hallazgos activos: {summary['total_active']} en {summary['hosts_affected']} hosts",
        f"En catalogo CISA KEV: {summary['kev_count']} (ligados a ransomware: {summary['kev_ransomware_count']})",
        f"Con EPSS >= {EPSS_HIGH_THRESHOLD:.0%}: {summary['epss_high_count']}",
        f"Con prioridad >= {PRIORITY_THRESHOLD:.0f}: {summary['priority_high_count']}",
        f"Ciclo de vida: {summary['new_count']} nuevas, {summary['resolved_count']} resueltas, "
        f"{summary['reopened_count']} reabiertas",
        "",
        f"TOP {min(top_limit, len(groups))} A PARCHEAR PRIMERO",
        "",
    ]
    for i, g in enumerate(groups[:top_limit], 1):
        marca = " [KEV]" if g.get("cisa_kev") else ""
        out.append(
            f"{i:2d}. {g['cve']}{marca} | prioridad {g['priority_score']:.1f} | "
            f"CVSS {g['cvss_score']:.1f} | EPSS {g['epss_score']*100:.2f}% | "
            f"{g['hosts_count']} host(s)"
        )
        if g.get("packages"):
            out.append(f"    Producto: {', '.join(g['packages'])[:80]}")
    out += [
        "",
        f"Prioridad = CVSS x {W_CVSS:g} + EPSS x {W_EPSS:g} + CISA KEV x {W_KEV:g}, tope 100.",
        "EPSS (FIRST.org) estima la probabilidad de explotacion en los proximos 30 dias.",
        "CISA KEV es el catalogo oficial de vulnerabilidades con explotacion confirmada.",
        "",
        f"Generado por Wazuh SIEM. Run ID: {summary['run_id']}",
    ]
    return "\n".join(out)


def render_email(
    summary: dict,
    groups: list[dict],
    top_limit: int = TOP_LIMIT,
    comp: dict | None = None,
    prev_file: str = "",
    cov: dict | None = None,
) -> str:
    """Documento HTML completo, ancho fijo 700px centrado con tabla exterior.

    Si viene `comp`, el reporte arranca con el cumplimiento de parches por host
    (los datos del semanal original) y sigue con la priorización.
    """
    fecha = datetime.now().strftime("%d/%m/%Y")
    compliance = render_compliance_fragment(comp, prev_file) if comp else ""
    # El aviso de calidad va primero: condiciona cómo se leen todos los números.
    aviso = render_coverage_notice(cov or {})
    titulo = (
        "Reporte de Vulnerabilidades y Cumplimiento de Parches"
        if comp
        else "Priorizaci&oacute;n de Vulnerabilidades por Explotabilidad Real"
    )
    # Badge del header: lo manda el peor indicador del parque, no el total de
    # hallazgos. Un parque con 3 CVEs en el catálogo KEV es CRITICO aunque el
    # número global haya bajado.
    if not summary.get("total_active"):
        badge_kind = "sin_datos"
    elif summary.get("kev_count"):
        badge_kind = "critico"
    elif summary.get("epss_high_count") or summary.get("priority_high_count"):
        badge_kind = "atencion"
    else:
        badge_kind = "ok"

    return _theme.document(
        org=ORG_NAME,
        title=titulo,
        subtitle=(
            f"{fecha} &nbsp;&middot;&nbsp; {_num(summary['total_active'])} hallazgos "
            f"activos en {_num(summary['hosts_affected'])} hosts"
        ),
        body=f"{aviso}{compliance}{render_fragment(summary, groups, top_limit)}",
        footer=(
            "Generado autom&aacute;ticamente por Wazuh SIEM<br>"
            "Fuentes: Wazuh Vulnerability Detector &middot; FIRST EPSS &middot; CISA KEV<br>"
            f"Run ID: {escape(summary['run_id'])}"
        ),
        doc_title=f"Priorizaci&oacute;n de Vulnerabilidades - {ORG_NAME}",
        badge_kind=badge_kind,
        preheader=(
            f"{_num(summary['total_active'])} hallazgos activos &middot; "
            f"{_num(summary.get('kev_count', 0))} explotadas in-the-wild"
        ),
    )


# --------------------------------------------------------------------------
# 7. Envío
# --------------------------------------------------------------------------
def load_email_config(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def send_email(
    cfg: dict,
    html: str,
    subject: str,
    recipients: list[str],
    plain: str = "",
    debug: bool = False,
) -> bool:
    """Delega en el tema compartido, que centraliza los arreglos antispam."""
    ok, info = _theme.send_report(
        cfg, html=html, plain=plain or "Reporte de vulnerabilidades priorizadas.",
        subject=subject, recipients=recipients, debug=debug,
    )
    if not ok:
        logger.error("Error enviando el mail: %s", info)
        return False
    logger.info("Mail aceptado por el servidor para: %s", ", ".join(recipients))
    logger.info("Message-ID: %s", info)
    return True
