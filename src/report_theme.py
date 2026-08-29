"""Sistema de diseño compartido para TODO correo que sale del SOC.

Lo usan los reportes de cron (vulnerabilidades, semanal de bloqueos FortiGate,
cobertura de agentes, diario de seguridad IA), las notificaciones instantáneas
del SOAR (incidente, cierre, bloqueo) y los avisos de ABM de Active Directory.
Un solo lugar define paleta, tipografía, shell y componentes: si un correo se
ve distinto de los demás, es un bug acá o el correo no está usando el módulo.

Tres restricciones mandan sobre todo lo demás:

1. **Outlook 2016** renderiza con el motor de Word. No soporta `display:grid`,
   flexbox, CSS variables ni `position`, y descarta el CSS de `<head>` salvo las
   media queries. Todo el layout va con tablas anidadas e inline CSS.
   `border-radius` y `box-shadow` sí se usan, pero solo como progressive
   enhancement: Outlook los ignora y degrada a cuadrado sin romperse.

2. **Los filtros antispam** del camino Exchange -> internet mandaban a No Deseado
   los mails armados con el default de `MIMEText`. Ver `build_message()`: hacen
   falta Date, Message-ID, quoted-printable y una parte de texto plano que sea
   equivalente real al HTML, no un placeholder de una línea.

3. **Contraste WCAG AA.** Cada color de la paleta se verificó con la fórmula de
   luminancia relativa, no a ojo. El verde de marca (#52a527) tiene 3,1:1 contra
   blanco: alcanza para un número de 26px en negrita (umbral 3:1) pero NO para
   texto chico (umbral 4,5:1). Por eso hay dos verdes — ver abajo.

Estructura de un correo, de afuera hacia adentro (`document()`):

    banda blanca con el logo  ->  header oscuro + badge de severidad
    ->  franja de acento de 4px  ->  bajada  ->  cuerpo  ->  pie
"""
from __future__ import annotations

import os
import smtplib
from email.charset import QP, Charset
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid, parseaddr
from html import escape

# --------------------------------------------------------------------------
# Paleta y tipografía
# --------------------------------------------------------------------------
# Fuentes web-safe: el motor de Word no resuelve fuentes web ni @import.
FONT = "Arial,Helvetica,sans-serif"
MONO = "Consolas,'Courier New',monospace"

# Verde de marca, muestreado del PNG del logo (no aproximado a ojo).
# Regla: el saturado va SOLO en elementos decorativos (franjas, bordes,
# border-top de las tarjetas, viñetas). Para texto, links y fondos con texto
# blanco encima se usa la variante oscura.
C_GREEN = "#52a527"       # 3,10:1 vs blanco — decorativo y números grandes
C_GREEN_DK = "#3f7d1f"    # 5,04:1 vs blanco — texto, links, fondo de th

# Semánticos. NO se retonan por marca: un badge rojo se entiende de un vistazo
# en cualquier convención y cambiarlo por el color de la empresa rompe eso.
C_CRIT = "#d81f26"        # 5,07:1 — crítico / alto
C_HIGH = "#c2740a"        # 3,62:1 — atención (el #ff9800 anterior daba 2,16:1)
C_MED = "#a37500"         # 4,12:1 — medio (el #ffc107 anterior daba 1,63:1)
C_OK = "#3f7d1f"          # 5,04:1 — todo bien (coincide con la marca)

C_INK = "#263129"         # 13,52:1 — header oscuro y títulos
C_TEXT = "#333333"        # 12,63:1 — texto de cuerpo
C_MUTED = "#6b737a"       # 4,82:1 — texto secundario, labels
C_BORDER = "#e2e6e3"
C_BG = "#eef1ef"          # fondo exterior, tinte verdoso sutil
C_SOFT = "#f4f7f4"        # fondo de cajas y encabezados suaves
C_ROW_ALT = "#fafbfa"

# Compatibilidad con el código que importaba el nombre viejo.
C_GREEN_LIGHT = C_GREEN

# Fondos suaves para badges (fondo, tinta, borde).
C_OK_BG, C_OK_FG, C_OK_BR = "#eaf5e4", "#2f6b17", "#cfe6c2"
C_BAD_BG, C_BAD_FG, C_BAD_BR = "#fde7e9", "#a3121c", "#f1b7bd"
C_WARN_BG, C_WARN_FG, C_WARN_BR = "#fff6e0", "#8a6300", "#ffe6a1"

# Badge del header: (acento de la franja, fondo, tinta, etiqueta).
BADGES = {
    "critico": (C_CRIT, C_BAD_BG, C_BAD_FG, "CRITICO"),
    "alto": (C_CRIT, C_BAD_BG, C_BAD_FG, "ALTO"),
    "atencion": (C_HIGH, C_WARN_BG, C_WARN_FG, "ATENCION"),
    "medio": (C_HIGH, C_WARN_BG, C_WARN_FG, "MEDIO"),
    "bajo": (C_GREEN, C_OK_BG, C_OK_FG, "BAJO"),
    "ok": (C_GREEN, C_OK_BG, C_OK_FG, "OK"),
    "info": (C_GREEN, C_SOFT, C_MUTED, "INFORMATIVO"),
    "sin_datos": (C_MUTED, C_SOFT, C_MUTED, "SIN DATOS"),
}

CSS = """
<style type="text/css">
  body{margin:0;padding:0;background-color:#eef1ef;}
  table{border-collapse:collapse;mso-table-lspace:0pt;mso-table-rspace:0pt;}
  body,table,td,div,p,a{-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;}
  a{color:#3f7d1f;}
  @media only screen and (max-width:640px){
    .rt-shell{width:100% !important;}
    .rt-metric{display:block !important;width:100% !important;padding:0 0 10px 0 !important;}
    .rt-col{display:block !important;width:100% !important;padding:0 0 10px 0 !important;}
  }
</style>
"""

CARD_STYLE = (
    f"background-color:#ffffff;border:1px solid {C_BORDER};"
    "border-collapse:separate;border-radius:10px;"
    "box-shadow:0 1px 3px rgba(0,0,0,0.06);"
)
SECTION_STYLE = (
    f"background-color:#ffffff;border:1px solid {C_BORDER};"
    "border-collapse:separate;border-radius:12px;"
    "box-shadow:0 1px 3px rgba(0,0,0,0.06);"
)
# La separación entre secciones NO va por margin: el motor de Word lo ignora en
# tablas y las tarjetas quedan pegadas. Va por una fila espaciadora (spacer()).
SECTION_GAP = 16

# --------------------------------------------------------------------------
# Logo
# --------------------------------------------------------------------------
LOGO_CID = "logoalemana"
LOGO_FILE = os.getenv(
    "REPORT_LOGO_FILE",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "assets", "logo-grupo-alemana.png"),
)


def load_logo() -> bytes | None:
    """Bytes del logo para incrustarlo por CID. None si no está el archivo.

    Va por Content-ID y no por URL porque Outlook, con una imagen remota,
    muestra la barra de "descargar imágenes" y el correo arranca sin marca.
    """
    try:
        with open(LOGO_FILE, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def logo_data_uri() -> str | None:
    """El logo como `data:` — para previsualizar un .html suelto en el browser.

    En un correo de verdad NO se usa: Gmail descarta las imágenes en data URI.
    """
    import base64

    raw = load_logo()
    if raw is None:
        return None
    return "data:image/png;base64," + base64.b64encode(raw).decode()


# --------------------------------------------------------------------------
# Primitivos
# --------------------------------------------------------------------------
def num(value) -> str:
    """12608 -> '12.608' (separador de miles local)."""
    try:
        return f"{int(value):,}".replace(",", ".")
    except (TypeError, ValueError):
        return str(value)


def sev_color(sev: str) -> str:
    """Color semántico para una severidad textual."""
    s = (sev or "").strip().lower()
    if s in ("critical", "critica", "crítica", "critico", "crítico"):
        return C_CRIT
    if s in ("high", "alta", "alto"):
        return C_HIGH
    if s in ("medium", "media", "medio"):
        return C_MED
    return C_MUTED


def badge(text: str, bg: str, fg: str, border: str = "") -> str:
    """Píldora de color con texto en negrita."""
    br = f"border:1px solid {border};" if border else ""
    return (
        f'<span style="display:inline-block;background-color:{bg};color:{fg};{br}'
        f'font-family:{FONT};font-size:11px;font-weight:bold;line-height:14px;'
        f'padding:3px 9px;border-radius:10px;white-space:nowrap;">{text}</span>'
    )


def badge_ok(text: str) -> str:
    return badge(text, C_OK_BG, C_OK_FG, C_OK_BR)


def badge_bad(text: str) -> str:
    return badge(text, C_BAD_BG, C_BAD_FG, C_BAD_BR)


def badge_warn(text: str) -> str:
    return badge(text, C_WARN_BG, C_WARN_FG, C_WARN_BR)


def delta_badge(delta: int, lower_is_better: bool = True) -> str:
    """Variación contra la edición anterior, con la flecha y el color correctos."""
    if not delta:
        return badge("=", C_SOFT, C_MUTED, C_BORDER)
    subio = delta > 0
    malo = subio if lower_is_better else not subio
    flecha = "&#9650;" if subio else "&#9660;"
    texto = f"{flecha} {abs(delta)}"
    return badge_bad(texto) if malo else badge_ok(texto)


def spacer(px: int = 16) -> str:
    """Separación vertical que Outlook respeta.

    El motor de Word ignora `margin` en tablas y divs, así que los bloques que
    se separaban con margin-bottom quedaban pegados uno contra otro. Una fila
    con altura explícita sí la respeta.
    """
    return (
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'border="0"><tr><td height="{px}" style="height:{px}px;line-height:{px}px;'
        f'font-size:0;">&nbsp;</td></tr></table>'
    )


def code(text: str) -> str:
    """Valor técnico (usuario, IP, hash) en monoespaciada sobre fondo suave."""
    return (
        f'<code style="font-family:{MONO};font-size:12px;background-color:{C_SOFT};'
        f'border:1px solid {C_BORDER};border-radius:4px;padding:1px 5px;'
        f'color:{C_INK};">{text}</code>'
    )


# --------------------------------------------------------------------------
# Componentes de contenido
# --------------------------------------------------------------------------
def metric_card(label: str, value: str, color: str, sub: str = "") -> str:
    """Tarjeta de métrica: valor grande arriba, label en versalitas abajo.

    Es la ÚNICA card del sistema. Antes había cuatro variantes distintas (una
    por familia de correo) y no se parecían entre sí; si necesitás otra forma,
    cambiá esta y se propaga a todos los correos.

    El `border-top` de color es lo que hace legible una fila de tarjetas de un
    vistazo: el ojo agarra la banda antes que el número.
    """
    sub_html = (
        f'<div style="font-family:{FONT};font-size:11px;line-height:15px;'
        f'color:{C_MUTED};padding-top:5px;">{sub}</div>'
        if sub
        else ""
    )
    return f"""<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#ffffff" style="{CARD_STYLE}border-top:3px solid {color};">
  <tr>
    <td align="center" style="padding:18px 12px 16px 12px;font-family:{FONT};">
      <div style="font-family:{FONT};font-size:28px;line-height:32px;font-weight:bold;color:{color};">{value}</div>
      <div style="font-family:{FONT};font-size:10px;line-height:14px;font-weight:bold;color:{C_MUTED};text-transform:uppercase;letter-spacing:0.7px;padding-top:10px;">{label}</div>
      {sub_html}
    </td>
  </tr>
</table>"""


def metric_row(cards: list[str]) -> str:
    """Grilla de 3 columnas fijas. Sin grid ni flex: solo tablas.

    Las columnas miden siempre lo mismo (33/34/33) y las posiciones que sobran
    se rellenan con celdas vacías. Antes la última fila se repartía entre las
    tarjetas que quedaban —dos tarjetas ocupaban 50% cada una— así que con 5
    métricas la segunda fila no alineaba con la primera: los bordes izquierdos
    de la tarjeta 2 y la 5 caían en columnas distintas.
    """
    if not cards:
        return ""
    COLS = 3
    ANCHOS = ("33%", "34%", "33%")
    filas: list[str] = []
    bloques = [cards[i : i + COLS] for i in range(0, len(cards), COLS)]
    for bi, bloque in enumerate(bloques):
        ultima = bi == len(bloques) - 1
        abajo = "0" if ultima else "12px"
        celdas = []
        for i in range(COLS):
            izq = "0" if i == 0 else "6px"
            der = "0" if i == COLS - 1 else "6px"
            contenido = bloque[i] if i < len(bloque) else "&nbsp;"
            celdas.append(
                f'<td class="rt-metric" width="{ANCHOS[i]}" valign="top" '
                f'style="width:{ANCHOS[i]};padding:0 {der} {abajo} {izq};">{contenido}</td>'
            )
        filas.append(f"<tr>{''.join(celdas)}</tr>")
    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'border="0" style="table-layout:fixed;">'
        + "".join(filas)
        + "</table>"
    )


def section(title: str, subtitle: str = "", body: str = "") -> str:
    """Tarjeta blanca redondeada con título, bajada opcional y contenido."""
    sub = (
        f'<div style="font-family:{FONT};font-size:12px;line-height:17px;'
        f'color:{C_MUTED};padding:3px 0 16px 0;">{subtitle}</div>'
        if subtitle
        else '<div style="height:12px;line-height:12px;font-size:0;">&nbsp;</div>'
    )
    return f"""
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#ffffff" style="{SECTION_STYLE}">
  <tr>
    <td style="padding:20px 22px;font-family:{FONT};">
      <div style="font-family:{FONT};font-size:15px;line-height:20px;font-weight:bold;color:{C_INK};">{title}</div>
      {sub}
      {body}
    </td>
  </tr>
</table>
{spacer(SECTION_GAP)}
"""


def notice(text: str, accent: str = C_HIGH, bg: str = C_WARN_BG) -> str:
    """Callout con borde de color a la izquierda, para avisos dentro de una sección."""
    return f"""
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="{bg}" style="background-color:{bg};border-left:4px solid {accent};border-collapse:separate;border-radius:8px;">
        <tr>
          <td style="padding:13px 15px;font-family:{FONT};font-size:12px;line-height:19px;color:{C_TEXT};">{text}</td>
        </tr>
      </table>
      {spacer(14)}"""


def callout(text: str, title: str = "", accent: str = C_GREEN, bg: str = C_SOFT) -> str:
    """Caja de resumen: el bloque de "Resumen ejecutivo" / "Qué pasó".

    Es `notice()` con más aire y un título opcional en negrita; se usa para el
    párrafo que abre el correo, no para avisos sueltos dentro de una sección.
    """
    head = (
        f'<div style="font-family:{FONT};font-size:13px;font-weight:bold;'
        f'color:{C_INK};padding-bottom:6px;">{title}</div>'
        if title
        else ""
    )
    return f"""
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="{bg}" style="background-color:{bg};border:1px solid {C_BORDER};border-left:4px solid {accent};border-collapse:separate;border-radius:8px;">
        <tr>
          <td style="padding:16px 18px;font-family:{FONT};font-size:13px;line-height:21px;color:{C_TEXT};">{head}{text}</td>
        </tr>
      </table>
      {spacer(14)}"""


def kv_rows(pairs: list[tuple]) -> str:
    """Filas etiqueta/valor. `pairs` = [(etiqueta, valor_html)].

    Es la forma canónica de listar el detalle de un evento (usuario, IP, regla,
    equipo). Reemplaza a las `<table class="info-table">` sueltas que cada
    correo se armaba por su cuenta.
    """
    filas = []
    for k, v in pairs:
        filas.append(
            f'<tr>'
            f'<td valign="top" width="170" style="font-family:{FONT};font-size:12px;'
            f'line-height:18px;color:{C_MUTED};padding:6px 10px 6px 0;'
            f'border-bottom:1px solid {C_SOFT};">{k}</td>'
            f'<td valign="top" style="font-family:{FONT};font-size:13px;line-height:18px;'
            f'font-weight:bold;color:{C_INK};padding:6px 0;'
            f'border-bottom:1px solid {C_SOFT};">{v}</td>'
            f'</tr>'
        )
    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'border="0" style="table-layout:fixed;">'
        + "".join(filas)
        + "</table>"
    )


def bullet_list(items: list, dot: str = C_GREEN) -> str:
    """Lista con viñeta redonda de color. Acepta str o (texto, color_de_viñeta).

    La viñeta por color permite mezclar gravedades en una misma lista (roja lo
    que hay que mirar ya, verde lo informativo) sin agregar iconos ni imágenes.
    """
    if not items:
        return ""
    filas = []
    for it in items:
        texto, color = (it, dot) if isinstance(it, str) else (it[0], it[1])
        filas.append(
            f'<tr>'
            # La viñeta se baja con el padding del <td>, no con margin-top del
            # div: el motor de Word ignora margin y el punto quedaba pegado
            # arriba en vez de alineado con la primera línea del texto.
            f'<td width="20" valign="top" style="width:20px;padding:14px 0 7px 0;">'
            f'<div style="width:7px;height:7px;background-color:{color};'
            f'border-radius:50%;font-size:0;line-height:0;">&nbsp;</div></td>'
            f'<td style="font-family:{FONT};font-size:13px;line-height:21px;'
            f'color:{C_TEXT};padding:7px 0;">{texto}</td>'
            f'</tr>'
        )
    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">'
        + "".join(filas)
        + "</table>"
    )


def two_col(left: str, right: str) -> str:
    """Dos columnas al 50% que colapsan a una en celular (clase .rt-col)."""
    if not (left and right):
        return left or right
    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>'
        f'<td class="rt-col" width="50%" valign="top" style="padding-right:8px;">{left}</td>'
        f'<td class="rt-col" width="50%" valign="top" style="padding-left:8px;">{right}</td>'
        '</tr></table>'
    )


def table_open(columns: list[tuple]) -> str:
    """Abre una tabla de datos. columns = [(label, width|None, align)].

    El encabezado va en el verde oscuro, no en el de marca: blanco sobre
    #52a527 da 3,1:1 y el texto de 11px necesita 4,5:1.
    """
    th = f"font-family:{FONT};font-size:11px;font-weight:bold;color:#ffffff;padding:10px 9px;letter-spacing:0.3px;"
    cells = []
    for label, width, align in columns:
        w = f' width="{width}"' if width else ""
        cells.append(
            f'<th{w} align="{align}" style="{th}text-align:{align};">{label}</th>'
        )
    return f"""<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
        <tr bgcolor="{C_GREEN_DK}" style="background-color:{C_GREEN_DK};">{''.join(cells)}</tr>
"""


TD_BASE = (
    f"font-family:{FONT};font-size:12px;line-height:18px;color:{C_TEXT};"
    f"padding:9px 9px;border-bottom:1px solid {C_SOFT};vertical-align:top;"
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


# --------------------------------------------------------------------------
# Shell del documento
# --------------------------------------------------------------------------
ORG_DEFAULT = os.getenv("REPORT_ORG_NAME", "Grupo Alemana")
BRAND_DEFAULT = os.getenv("REPORT_BRAND", "SOC Grupo Alemana")
LEGAL_DEFAULT = os.getenv(
    "REPORT_LEGAL", "Grupo Alemana &middot; Seguridad de la Informaci&oacute;n"
)


def document(
    *,
    org: str = "",
    title: str,
    subtitle: str = "",
    body: str,
    footer: str = "",
    doc_title: str = "",
    badge_kind: str = "info",
    preheader: str = "",
    logo_src: str = "",
    brand: str = "",
) -> str:
    """Documento HTML completo: 700px centrado, con el shell de marca.

    `badge_kind` es una clave de BADGES y define tanto la píldora del header
    como el color de la franja de acento — es la señal de gravedad que se lee
    antes que cualquier texto.

    `logo_src` por defecto apunta al CID que incrusta `build_message()`. Para
    generar un .html suelto que se abra en el browser hay que pasarle
    `logo_data_uri()`.

    `preheader` es el texto que Gmail/Outlook muestran en la lista de correos
    antes de abrirlos. Va oculto en el HTML. Sin él, el cliente muestra el
    primer texto que encuentra, que suele ser el nombre de la empresa repetido.
    """
    org = org or ORG_DEFAULT
    brand = brand or BRAND_DEFAULT
    logo_src = logo_src or f"cid:{LOGO_CID}"
    accent, b_bg, b_fg, b_label = BADGES.get(
        (badge_kind or "info").lower(), BADGES["info"]
    )

    pre = (
        f'<div style="display:none;max-height:0;overflow:hidden;mso-hide:all;'
        f'font-size:1px;line-height:1px;color:{C_BG};">{preheader}</div>'
        if preheader
        else ""
    )

    bajada = (
        f"""
        <tr>
          <td bgcolor="{C_SOFT}" style="background-color:{C_SOFT};padding:10px 22px;border-left:1px solid {C_BORDER};border-right:1px solid {C_BORDER};">
            <div style="font-family:{FONT};font-size:12px;line-height:17px;color:{C_MUTED};">{subtitle}</div>
          </td>
        </tr>"""
        if subtitle
        else ""
    )

    foot = (
        f'<div style="font-family:{FONT};font-size:11px;line-height:16px;'
        f'color:{C_MUTED};padding-bottom:6px;">{footer}</div>'
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
<meta name="color-scheme" content="light only">
<meta name="supported-color-schemes" content="light">
<title>{escape(doc_title or title)}</title>{CSS}</head>
<body bgcolor="{C_BG}" style="margin:0;padding:0;background-color:{C_BG};">
{pre}
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="{C_BG}" style="background-color:{C_BG};">
  <tr>
    <td align="center" style="padding:20px 10px;">

      <table role="presentation" class="rt-shell" width="700" cellpadding="0" cellspacing="0" border="0" align="center" style="width:700px;max-width:700px;">

        <!-- Banda de marca: logo a la izquierda, nombre del SOC a la derecha -->
        <tr>
          <td bgcolor="#ffffff" style="background-color:#ffffff;padding:14px 22px;border:1px solid {C_BORDER};border-bottom:none;border-radius:12px 12px 0 0;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
              <tr>
                <td align="left" valign="middle">
                  <img src="{logo_src}" alt="{escape(org)}" height="38" style="height:38px;width:auto;display:block;border:0;outline:none;text-decoration:none;">
                </td>
                <td align="right" valign="middle" style="font-family:{FONT};font-size:13px;font-weight:bold;color:{C_INK};">{escape(brand)}</td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Header oscuro: título a la izquierda, badge de severidad a la derecha -->
        <tr>
          <td bgcolor="{C_INK}" style="background-color:{C_INK};padding:18px 22px;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
              <tr>
                <td align="left" valign="middle" style="font-family:{FONT};font-size:17px;line-height:22px;font-weight:bold;color:#ffffff;">{title}</td>
                <td align="right" valign="middle" style="padding-left:12px;">{badge(b_label, b_bg, b_fg)}</td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Franja de acento: el color del badge, 4px -->
        <tr>
          <td bgcolor="{accent}" style="background-color:{accent};height:4px;line-height:4px;font-size:0;">&nbsp;</td>
        </tr>
{bajada}

        <!-- Cuerpo -->
        <tr>
          <td style="padding:16px 0 0 0;">
            {body}
          </td>
        </tr>

        <!-- Pie -->
        <tr>
          <td align="center" style="padding:4px 12px 10px 12px;">
            {foot}
            <div style="font-family:{FONT};font-size:11px;line-height:16px;font-weight:bold;color:{C_INK};">{LEGAL_DEFAULT}</div>
          </td>
        </tr>

      </table>

    </td>
  </tr>
</table>
</body></html>"""


# Alias: el kit del que viene el diseño la llama shell().
shell = document


# --------------------------------------------------------------------------
# Asunto canónico
# --------------------------------------------------------------------------
# "[SOC <Cliente>][<FAMILIA>] <campos fijos> · <campos variables>"
#
# Un solo prefijo para TODO correo del SOC. Las reglas de bandeja del cliente
# evalúan "contiene" desde el arranque del asunto: si un script usa
# "[SOC Alemana]" y otro "[Wazuh SIEM]", el filtro agarra la mitad de los
# correos y la otra mitad queda suelta en la bandeja.
CLIENTE = os.getenv("REPORT_CLIENTE", "L1")

FAMILIAS = (
    "RESUMEN",     # diario de seguridad (IA)
    "VULNS",       # semanal de parches + cobertura de agentes
    "BLOQUEOS",    # auto-block FortiGate: evento y semanal
    "INCIDENTE",   # SOAR: alerta que requiere decision, y su cierre
    "ABM",         # alta/baja/modificacion en Active Directory
    "SIEM",        # salud del SIEM (interno)
)

# Presupuesto de largo. Outlook corta la lista de la bandeja cerca de los 72
# caracteres: lo que pase de ahi no se lee sin abrir el correo. Medido sobre
# los 11 asuntos reales del SOC, 5 se cortaban y lo que perdian era justo la
# cola -- el ticket y el host.
SUBJECT_BUDGET = 72
_MIN_CAMPO = 12  # por debajo de esto un campo recortado ya no dice nada


def subject(familia: str, *partes: str, budget: int = SUBJECT_BUDGET) -> str:
    """Asunto con gramatica de posicion fija, recortado para entrar en la bandeja.

        [SOC L1][FAMILIA] ESTADO . sujeto . contexto

    `ESTADO` es SIEMPRE severidad o ciclo de vida (HIGH, BLOQUEADA, CERRADO,
    ALTA, DEGRADADO); `sujeto` es la unica entidad de la que habla el correo
    (una IP, un usuario, un host); el resto es contexto (`ticket #N`). La fecha
    no va salvo en los reportes periodicos, donde identifica la edicion y va
    ultima: ya esta en el header `Date` y en la columna de la bandeja, y
    ponerla primera empuja lo que importa mas alla del corte.

    Si no entra en `budget` recorta el campo mas largo, nunca el prefijo ni el
    estado, que son lo que se filtra.

        >>> subject("BLOQUEOS", "BLOQUEADA", "203.0.113.77", "ticket #3055")
        '[SOC L1][BLOQUEOS] BLOQUEADA \u00b7 203.0.113.77 \u00b7 ticket #3055'
    """
    fam = (familia or "").upper()
    campos = [str(p).replace("&middot;", "\u00b7").strip() for p in partes if p]
    campos = [c for c in campos if c]
    base = f"[SOC {CLIENTE}][{fam}]"
    if not campos:
        return base

    def _render() -> str:
        return f"{base} " + " \u00b7 ".join(campos)

    while len(_render()) > budget:
        i = max(range(len(campos)), key=lambda k: len(campos[k]))
        largo = len(campos[i])
        if largo <= _MIN_CAMPO:
            break  # ya no hay de donde recortar sin volverlo ilegible
        exceso = len(_render()) - budget
        # -1 por la elipsis; el min() garantiza que cada vuelta acorte de verdad
        objetivo = max(_MIN_CAMPO, min(largo - exceso - 1, largo - 2))
        recortado = campos[i][:objetivo].rstrip(" \u00b7,-") + "\u2026"
        if len(recortado) >= largo:
            break  # no shrink -> cortar el loop antes de que gire al vacio
        campos[i] = recortado
    return _render()


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
    logo_bytes: bytes | None = None,
) -> MIMEMultipart:
    """Arma el mensaje evitando las tres señales que lo mandaban a No Deseado.

    Verificado el 2026-08-17 contra el Exchange de Grupo Alemana: los mismos
    contenidos con el default de MIMEText caían en No Deseado, y con estos tres
    cambios entran a bandeja.

    Si viene `logo_bytes`, el alternative se envuelve en un multipart/related y
    el logo se adjunta inline por Content-ID: así Outlook lo pinta sin pedir
    "descargar imágenes".
    """
    envelope_from = parseaddr(from_addr)[1] or from_addr
    domain = envelope_from.split("@")[-1] if "@" in envelope_from else "localhost"

    alt = MIMEMultipart("alternative")
    # 2) quoted-printable en vez del base64 por defecto: un cuerpo de texto en
    #    base64 es señal de ofuscación.
    cs = Charset("utf-8")
    cs.header_encoding = QP
    cs.body_encoding = QP
    # 3) La parte de texto tiene que ser el reporte de verdad, no un placeholder:
    #    un multipart/alternative asimétrico también suma score.
    alt.attach(MIMEText(plain, "plain", _charset=cs))
    alt.attach(MIMEText(html, "html", _charset=cs))

    if logo_bytes:
        msg: MIMEMultipart = MIMEMultipart("related")
        msg.attach(alt)
        img = MIMEImage(logo_bytes, _subtype="png")
        img.add_header("Content-ID", f"<{LOGO_CID}>")
        img.add_header("Content-Disposition", "inline", filename="logo.png")
        msg.attach(img)
    else:
        msg = alt

    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(recipients)
    # 1) El stdlib no agrega Date ni Message-ID, y sin ellos varios filtros penalizan.
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=domain)
    return msg


def send_report(
    cfg: dict,
    *,
    html: str,
    plain: str,
    subject: str,
    recipients: list[str],
    debug: bool = False,
    embed_logo: bool = True,
) -> tuple[bool, str]:
    """Envía por SMTP. Devuelve (ok, message_id_o_error)."""
    from_addr = cfg.get("from", "Wazuh SIEM <wazuh@grupoalemana.com>")
    envelope_from = parseaddr(from_addr)[1] or from_addr
    msg = build_message(
        from_addr=from_addr, recipients=recipients,
        subject=subject, html=html, plain=plain,
        logo_bytes=load_logo() if embed_logo else None,
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
