"""Sistema de diseño compartido para los reportes por correo.

Lo usan el reporte de vulnerabilidades, el semanal de bloqueos FortiGate y la
notificación instantánea de bloqueo, para que los tres se vean como una familia.

Dos restricciones mandan sobre todo lo demás:

1. **Outlook 2016** renderiza con el motor de Word. No soporta `display:grid`,
   flexbox, CSS variables ni `position`. Todo el layout va con tablas anidadas
   e inline CSS. `border-radius` y `box-shadow` sí se usan, pero solo como
   progressive enhancement: Outlook los ignora y degrada a cuadrado sin romperse.

2. **Los filtros antispam** del camino Exchange -> internet mandaban a No Deseado
   los mails armados con el default de `MIMEText`. Ver `build_message()`: hacen
   falta Date, Message-ID, quoted-printable y una parte de texto plano que sea
   equivalente real al HTML, no un placeholder de una línea.
"""
from __future__ import annotations

import smtplib
from email.charset import QP, Charset
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid, parseaddr
from html import escape

# --------------------------------------------------------------------------
# Paleta y tipografía
# --------------------------------------------------------------------------
# Fuentes web-safe: el motor de Word no resuelve fuentes web ni @import.
FONT = "Arial,Helvetica,sans-serif"

C_GREEN = "#5da339"      # verde corporativo Grupo Alemana
C_GREEN_DK = "#4a8f2f"
C_CRIT = "#dc3545"
C_HIGH = "#ff9800"
C_MED = "#ffc107"
C_OK = "#28a745"
C_MUTED = "#6c757d"
C_TEXT = "#333333"
C_BORDER = "#e2e8ec"
C_BG = "#f4f6f8"
C_ROW_ALT = "#fafbfc"

# Fondos suaves para badges
C_OK_BG, C_OK_FG, C_OK_BR = "#d4edda", "#155724", "#b7dfc2"
C_BAD_BG, C_BAD_FG, C_BAD_BR = "#f8d7da", "#721c24", "#f1b7bd"
C_WARN_BG, C_WARN_FG, C_WARN_BR = "#fff3cd", "#856404", "#ffe6a1"

CSS = """
<style type="text/css">
  body{margin:0;padding:0;background-color:#f4f6f8;}
  table{border-collapse:collapse;mso-table-lspace:0pt;mso-table-rspace:0pt;}
  body,table,td,div,p,a{-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;}
  a{color:#4a8f2f;}
  @media only screen and (max-width:640px){
    .rt-shell{width:100% !important;}
    .rt-metric{display:block !important;width:100% !important;padding:0 0 10px 0 !important;}
  }
</style>
"""

CARD_STYLE = (
    f"background-color:#ffffff;border:1px solid {C_BORDER};"
    "border-collapse:separate;border-radius:10px;"
    "box-shadow:0 1px 3px rgba(0,0,0,0.06);"
)
SECTION_STYLE = (
    f"background-color:#ffffff;border:1px solid {C_BORDER};margin-bottom:16px;"
    "border-collapse:separate;border-radius:12px;"
    "box-shadow:0 1px 3px rgba(0,0,0,0.06);"
)


# --------------------------------------------------------------------------
# Primitivos
# --------------------------------------------------------------------------
def num(value) -> str:
    """12608 -> '12.608' (separador de miles local)."""
    try:
        return f"{int(value):,}".replace(",", ".")
    except (TypeError, ValueError):
        return escape(str(value))


def sev_color(sev: str) -> str:
    return {
        "critical": C_CRIT, "critica": C_CRIT, "crítica": C_CRIT,
        "high": C_HIGH, "alta": C_HIGH,
        "medium": C_MED, "media": C_MED,
        "low": C_MUTED, "baja": C_MUTED,
    }.get(str(sev).lower(), C_MUTED)


def badge(text: str, bg: str, fg: str, border: str = "") -> str:
    """Badge de fondo sólido. Sin depender de border-radius para ser legible."""
    brd = f"border:1px solid {border};" if border else ""
    return (
        f'<span style="background-color:{bg};color:{fg};{brd}'
        f"padding:2px 6px;border-radius:10px;font-family:{FONT};font-size:10px;"
        f'font-weight:bold;white-space:nowrap;">{text}</span>'
    )


def badge_ok(text: str) -> str:
    return badge(text, C_OK_BG, C_OK_FG, C_OK_BR)


def badge_bad(text: str) -> str:
    return badge(text, C_BAD_BG, C_BAD_FG, C_BAD_BR)


def badge_warn(text: str) -> str:
    return badge(text, C_WARN_BG, C_WARN_FG, C_WARN_BR)


def delta_badge(delta: int, lower_is_better: bool = True) -> str:
    """Flecha + magnitud, coloreada según convenga que el número baje o suba."""
    if delta == 0:
        return badge("&rarr; 0", "#eef2f5", C_MUTED, C_BORDER)
    good = (delta < 0) if lower_is_better else (delta > 0)
    arrow = "&darr;" if delta < 0 else "&uarr;"
    text = f"{arrow} {abs(delta)}"
    return badge_ok(text) if good else badge_bad(text)


def metric_card(label: str, value: str, color: str, sub: str = "") -> str:
    """Tarjeta de métrica: tabla de una celda, sin grid ni flex."""
    sub_html = (
        f'<div style="font-family:{FONT};font-size:11px;line-height:15px;'
        f'color:{C_MUTED};padding-top:4px;">{sub}</div>'
        if sub
        else ""
    )
    return f"""<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#ffffff" style="{CARD_STYLE}">
  <tr>
    <td style="padding:12px 14px;font-family:{FONT};">
      <div style="font-family:{FONT};font-size:10px;color:{C_MUTED};font-weight:bold;">{label}</div>
      <div style="font-family:{FONT};font-size:26px;line-height:30px;font-weight:bold;color:{color};padding-top:4px;">{value}</div>
      {sub_html}
    </td>
  </tr>
</table>"""


def metric_row(cards: list[str]) -> str:
    """Distribuye N tarjetas en filas de hasta 3, sin grid.

    Con 5 tarjetas quedan 3 arriba y 2 abajo (la última ocupa dos columnas),
    que es la disposición que mejor se lee a 700px.
    """
    if not cards:
        return ""
    rows: list[str] = []
    chunks = [cards[i : i + 3] for i in range(0, len(cards), 3)]
    for ci, chunk in enumerate(chunks):
        last_row = ci == len(chunks) - 1
        pad_bottom = "0" if last_row else "10px"
        cells = []
        for i, card in enumerate(chunk):
            left = "0" if i == 0 else "5px"
            right = "0" if i == len(chunk) - 1 else "5px"
            # Si la última fila viene incompleta, la última tarjeta ocupa el resto.
            colspan = ""
            if last_row and len(chunk) < 3 and i == len(chunk) - 1:
                colspan = f' colspan="{3 - len(chunk) + 1}"'
            width = f' width="{100 // max(len(chunk), 1)}%"' if not colspan else ""
            cells.append(
                f'<td class="rt-metric"{colspan}{width} valign="top" '
                f'style="padding:0 {right} {pad_bottom} {left};">{card}</td>'
            )
        rows.append(f"<tr>{''.join(cells)}</tr>")
    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">'
        + "".join(rows)
        + "</table>"
    )


def section(title: str, subtitle: str = "", body: str = "") -> str:
    """Tarjeta blanca redondeada con título, bajada opcional y contenido."""
    sub = (
        f'<div style="font-family:{FONT};font-size:12px;color:{C_MUTED};'
        f'padding-bottom:14px;">{subtitle}</div>'
        if subtitle
        else '<div style="height:10px;line-height:10px;">&nbsp;</div>'
    )
    return f"""
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#ffffff" style="{SECTION_STYLE}">
  <tr>
    <td style="padding:18px;font-family:{FONT};">
      <div style="font-family:{FONT};font-size:15px;font-weight:bold;color:{C_TEXT};padding-bottom:4px;">{title}</div>
      {sub}
      {body}
    </td>
  </tr>
</table>
"""


def notice(text: str, accent: str = C_HIGH, bg: str = "#fff8e6") -> str:
    """Callout con borde de color a la izquierda, para avisos dentro de una sección."""
    return f"""
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="{bg}" style="background-color:{bg};border-left:4px solid {accent};margin-bottom:14px;border-collapse:separate;border-radius:8px;">
        <tr>
          <td style="padding:10px 12px;font-family:{FONT};font-size:12px;line-height:17px;color:{C_TEXT};">{text}</td>
        </tr>
      </table>"""


def table_open(columns: list[tuple]) -> str:
    """Abre una tabla de datos. columns = [(label, width|None, align)]."""
    th = f"font-family:{FONT};font-size:11px;font-weight:bold;color:#ffffff;padding:8px 5px;"
    cells = []
    for label, width, align in columns:
        w = f' width="{width}"' if width else ""
        cells.append(
            f'<th{w} align="{align}" style="{th}text-align:{align};">{label}</th>'
        )
    return f"""<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
        <tr bgcolor="{C_GREEN}" style="background-color:{C_GREEN};">{''.join(cells)}</tr>
"""


TD_BASE = (
    f"font-family:{FONT};font-size:12px;line-height:16px;color:{C_TEXT};"
    f"padding:7px 5px;border-bottom:1px solid #eef2f5;vertical-align:top;"
)


def table_row(cells: list[tuple], index: int) -> str:
    """Fila de datos con cebra. cells = [(html, align, extra_style)]."""
    bg = "#ffffff" if index % 2 else C_ROW_ALT
    out = []
    for html, align, extra in cells:
        out.append(
            f'<td align="{align}" style="{TD_BASE}text-align:{align};{extra}">{html}</td>'
        )
    return f'<tr bgcolor="{bg}" style="background-color:{bg};">{"".join(out)}</tr>'


TABLE_CLOSE = "      </table>"


def document(
    *,
    org: str,
    title: str,
    subtitle: str,
    body: str,
    footer: str = "",
    doc_title: str = "",
) -> str:
    """Documento HTML completo: ancho fijo 700px centrado con tabla exterior."""
    foot = (
        f"""
        <tr>
          <td align="center" style="padding:4px 12px 8px 12px;">
            <div style="font-family:{FONT};font-size:11px;line-height:16px;color:{C_MUTED};">{footer}</div>
          </td>
        </tr>"""
        if footer
        else ""
    )
    return f"""<!DOCTYPE html>
<html lang="es" xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="x-apple-disable-message-reformatting">
<title>{escape(doc_title or title)}</title>{CSS}</head>
<body bgcolor="{C_BG}" style="margin:0;padding:0;background-color:{C_BG};">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="{C_BG}" style="background-color:{C_BG};">
  <tr>
    <td align="center" style="padding:20px 10px;">

      <table role="presentation" class="rt-shell" width="700" cellpadding="0" cellspacing="0" border="0" align="center" style="width:700px;max-width:700px;">

        <tr>
          <td bgcolor="{C_GREEN}" align="center" style="background-color:{C_GREEN};padding:22px 24px;border-radius:12px 12px 0 0;">
            <div style="font-family:{FONT};font-size:12px;font-weight:bold;color:#ffffff;padding-bottom:8px;">{escape(org.upper())} &nbsp;&middot;&nbsp; GERENCIA TECNOLOG&Iacute;A</div>
            <div style="font-family:{FONT};font-size:19px;line-height:24px;font-weight:bold;color:#ffffff;">{title}</div>
          </td>
        </tr>
        <tr>
          <td bgcolor="{C_GREEN_DK}" align="center" style="background-color:{C_GREEN_DK};padding:9px 24px;border-radius:0 0 12px 12px;">
            <div style="font-family:{FONT};font-size:12px;color:#ffffff;">{subtitle}</div>
          </td>
        </tr>

        <tr>
          <td style="padding:16px 0 0 0;">
            {body}
          </td>
        </tr>
{foot}
      </table>

    </td>
  </tr>
</table>
</body></html>"""


# --------------------------------------------------------------------------
# Envío
# --------------------------------------------------------------------------
def build_message(
    *,
    from_addr: str,
    recipients: list[str],
    subject: str,
    html: str,
    plain: str,
) -> MIMEMultipart:
    """Arma el mensaje evitando las tres señales que lo mandaban a No Deseado.

    Verificado el 2026-08-17 contra el Exchange de Grupo Alemana: los mismos
    contenidos con el default de MIMEText caían en No Deseado, y con estos tres
    cambios entran a bandeja.
    """
    envelope_from = parseaddr(from_addr)[1] or from_addr
    domain = envelope_from.split("@")[-1] if "@" in envelope_from else "localhost"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(recipients)
    # 1) El stdlib no agrega Date ni Message-ID, y sin ellos varios filtros penalizan.
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=domain)

    # 2) quoted-printable en vez del base64 por defecto: un cuerpo de texto en
    #    base64 es señal de ofuscación.
    cs = Charset("utf-8")
    cs.header_encoding = QP
    cs.body_encoding = QP
    # 3) La parte de texto tiene que ser el reporte de verdad, no un placeholder:
    #    un multipart/alternative asimétrico también suma score.
    msg.attach(MIMEText(plain, "plain", _charset=cs))
    msg.attach(MIMEText(html, "html", _charset=cs))
    return msg


def send_report(
    cfg: dict,
    *,
    html: str,
    plain: str,
    subject: str,
    recipients: list[str],
    debug: bool = False,
) -> tuple[bool, str]:
    """Envía por SMTP. Devuelve (ok, message_id_o_error)."""
    from_addr = cfg.get("from", "Wazuh SIEM <wazuh@grupoalemana.com>")
    envelope_from = parseaddr(from_addr)[1] or from_addr
    msg = build_message(
        from_addr=from_addr, recipients=recipients,
        subject=subject, html=html, plain=plain,
    )

    server = smtplib.SMTP(
        cfg.get("smtp_host", "localhost"), int(cfg.get("smtp_port", 25)), timeout=30
    )
    if debug:
        server.set_debuglevel(1)
    try:
        server.ehlo()
        if cfg.get("use_tls"):
            server.starttls()
            server.ehlo()
        if cfg.get("username") and cfg.get("password"):
            server.login(cfg["username"], cfg["password"])
        refused = server.sendmail(envelope_from, recipients, msg.as_string())
        if refused:
            return False, f"destinatarios rechazados: {refused}"
    finally:
        try:
            server.quit()
        except smtplib.SMTPException:
            pass
    return True, msg["Message-ID"]
