"""Correos de ABM: altas, bajas y modificaciones en Active Directory.

Estas alertas NO pasan por el pipeline de SOC-L1 — las notifica directo el
integration `custom-email-unified` del manager de Wazuh (reglas 100080-100086,
100107-100108 y las nativas 60107-60113). Este módulo existe para que ese
correo use el mismo sistema de diseño que todos los demás, y para que el HTML
quede versionado en el repo en vez de vivir dentro de un archivo de 1300
líneas propiedad de root en /var/ossec/integrations/.

Uso desde el integration:

    import sys; sys.path.insert(0, "/opt/soc-l1")
    from src.abm_mail import build_abm_email
    html, texto, asunto, badge = build_abm_email(alerta_json)

`build_abm_email` no envía: devuelve las piezas, y el que envía sigue siendo
el integration (que ya tiene la config SMTP). Para el envío conviene usar
`report_theme.build_message()`, que resuelve Date/Message-ID/quoted-printable
y adjunta el logo por Content-ID.
"""
from __future__ import annotations

from datetime import datetime
from html import escape
from typing import Any

from src import report_theme as T

# --------------------------------------------------------------------------
# Catálogo de eventos
# --------------------------------------------------------------------------
# (título, badge, qué revisar). El badge es la señal de gravedad del header:
# un alta rutinaria y una alta en Domain Admins no pueden verse igual.
EVENTOS: dict[str, tuple[str, str, str]] = {
    "100080": ("Alta de usuario en Active Directory", "atencion", "alta"),
    "100081": ("Usuario creado por ANONYMOUS LOGON", "critico", "anonimo"),
    "100082": ("Baja de usuario en Active Directory", "alto", "baja"),
    "100083": ("Alta en grupo de seguridad LOCAL", "atencion", "grupo_alta"),
    "100084": ("Alta en grupo de seguridad GLOBAL", "alto", "grupo_alta"),
    "100085": ("Baja de grupo de seguridad LOCAL", "medio", "grupo_baja"),
    "100086": ("Baja de grupo de seguridad GLOBAL", "medio", "grupo_baja"),
    "100107": ("Alta en GRUPO PRIVILEGIADO", "critico", "privilegiado_alta"),
    "100108": ("Baja de GRUPO PRIVILEGIADO", "alto", "privilegiado_baja"),
    "60107": ("Intento fallido de operación privilegiada", "atencion", "fallido"),
    "60108": ("Sesión reconectada o desconectada", "info", "sesion"),
    "60109": ("Cuenta de usuario creada o habilitada", "atencion", "alta"),
    "60113": ("Cuenta de grupo modificada", "medio", "grupo_alta"),
}

# Qué mirar según el tipo de evento. Cada viñeta lleva su color: rojo lo que
# hay que atender ya, verde lo que es verificación de rutina.
REVISAR: dict[str, list[tuple[str, str]]] = {
    "alta": [
        ("Confirmar con RR.HH. que el alta corresponde a un ingreso real.", T.C_GREEN),
        ("Verificar que los grupos asignados sean los m&iacute;nimos para el puesto.", T.C_GREEN),
        ("Si no corresponde a un ingreso, deshabilitar la cuenta y escalar como "
         "posible persistencia.", T.C_CRIT),
    ],
    "baja": [
        ("Confirmar que la baja corresponde a una desvinculaci&oacute;n informada.", T.C_GREEN),
        ("Revisar que no queden sesiones activas ni tokens vigentes de la cuenta.", T.C_HIGH),
        ("Si la baja no estaba prevista, es un borrado de cuenta no autorizado: "
         "escalar de inmediato.", T.C_CRIT),
    ],
    "grupo_alta": [
        ("Validar que el grupo otorgue solo los permisos que el puesto necesita.", T.C_GREEN),
        ("Confirmar que el cambio tenga un pedido formal asociado.", T.C_GREEN),
    ],
    "grupo_baja": [
        ("Verificar que la remoci&oacute;n sea intencional y no deje al usuario "
         "sin acceso a lo que necesita.", T.C_GREEN),
    ],
    "privilegiado_alta": [
        ("Un alta en un grupo privilegiado da control amplio del dominio. "
         "Validarla <strong>ahora</strong>, no en el pr&oacute;ximo repaso.", T.C_CRIT),
        ("Confirmar el pedido formal y quién lo autoriz&oacute;.", T.C_CRIT),
        ("Si no hay pedido, revertir el cambio y revisar qué m&aacute;s hizo la "
         "cuenta que lo ejecut&oacute;.", T.C_CRIT),
    ],
    "privilegiado_baja": [
        ("Confirmar que la remoci&oacute;n del privilegio sea intencional.", T.C_HIGH),
        ("Si no lo es, puede ser un atacante sacando competencia del dominio.", T.C_CRIT),
    ],
    "anonimo": [
        ("Una cuenta creada por ANONYMOUS LOGON no tiene explicaci&oacute;n "
         "leg&iacute;tima. Tratar como compromiso hasta probar lo contrario.", T.C_CRIT),
        ("Deshabilitar la cuenta creada y aislar el controlador de dominio.", T.C_CRIT),
    ],
    "fallido": [
        ("Un intento fallido aislado es ruido; varios sobre la misma cuenta son "
         "escalamiento de privilegios en curso.", T.C_HIGH),
    ],
    "sesion": [
        ("Evento informativo. Solo interesa si acompa&ntilde;a a otro hallazgo.", T.C_GREEN),
    ],
}

_DEFAULT = ("Evento de Active Directory", "medio", "grupo_alta")


def _campo(alerta: dict[str, Any], *rutas: str, default: str = "") -> str:
    """Primer valor no vacío entre varias rutas con punto."""
    for ruta in rutas:
        nodo: Any = alerta
        for parte in ruta.split("."):
            if not isinstance(nodo, dict):
                nodo = None
                break
            nodo = nodo.get(parte)
        if nodo not in (None, "", "-"):
            return str(nodo)
    return default


def _fecha(ts: str) -> str:
    """El timestamp de Wazuh a hora local legible."""
    if not ts:
        return datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime(
            "%d/%m/%Y %H:%M:%S"
        )
    except ValueError:
        return ts


def build_abm_email(alerta: dict[str, Any]) -> tuple[str, str, str, str]:
    """Devuelve (html, texto_plano, asunto, badge_kind) para una alerta de ABM."""
    rule_id = _campo(alerta, "rule.id", default="?")
    titulo, badge_kind, clase = EVENTOS.get(rule_id, _DEFAULT)

    usuario = _campo(alerta, "data.win.eventdata.targetUserName", default="-")
    miembro = _campo(alerta, "data.win.eventdata.memberName", default="")
    ejecutor = _campo(alerta, "data.win.eventdata.subjectUserName", default="-")
    equipo = _campo(alerta, "data.win.system.computer", "agent.name", default="-")
    event_id = _campo(alerta, "data.win.system.eventID", default="-")
    agente = _campo(alerta, "agent.name", default="-")
    agente_id = _campo(alerta, "agent.id", default="-")
    nivel = _campo(alerta, "rule.level", default="-")
    descripcion = _campo(alerta, "rule.description", default=titulo)
    mitre = ", ".join(_campo(alerta, "rule.mitre.id", default="").split()) or "-"
    veces = _campo(alerta, "rule.firedtimes", default="1")
    fecha = _fecha(_campo(alerta, "timestamp"))

    # En las altas/bajas de grupo, el "usuario" de la regla es el GRUPO y el
    # que entra o sale es memberName. Nombrarlos al revés hace ilegible el correo.
    es_grupo = clase.startswith("grupo") or clase.startswith("privilegiado")
    sujeto = miembro if (es_grupo and miembro) else usuario
    # memberName llega como DN completo ("CN=svc_backup,OU=Servicios,DC=..."):
    # en el asunto entra solo el CN, o la línea se vuelve ilegible en la bandeja.
    sujeto_corto = sujeto
    if sujeto.upper().startswith("CN="):
        sujeto_corto = sujeto.split(",")[0][3:]

    if es_grupo and miembro:
        que_paso = (
            f"Se modific&oacute; la membres&iacute;a del grupo <strong>{escape(usuario)}</strong>: "
            f"la cuenta <strong>{escape(miembro)}</strong> fue "
            f"{'agregada' if 'alta' in clase else 'removida'}. "
            f"Lo ejecut&oacute; <strong>{escape(ejecutor)}</strong> desde "
            f"<strong>{escape(equipo)}</strong>."
        )
    else:
        que_paso = (
            f"Evento sobre la cuenta <strong>{escape(sujeto)}</strong> en "
            f"<strong>{escape(equipo)}</strong>, ejecutado por "
            f"<strong>{escape(ejecutor)}</strong>."
        )

    pares: list[tuple[str, str]] = [("Acci&oacute;n", escape(titulo))]
    if es_grupo and miembro:
        pares += [("Grupo", T.code(escape(usuario))), ("Miembro", T.code(escape(miembro)))]
    else:
        pares.append(("Usuario", T.code(escape(sujeto))))
    pares += [
        ("Ejecutado por", T.code(escape(ejecutor))),
        ("Equipo / DC", escape(equipo)),
        ("Event ID de Windows", escape(event_id)),
        ("Regla Wazuh", f"{escape(rule_id)} (nivel {escape(nivel)})"),
        ("Descripci&oacute;n", escape(descripcion)),
        ("MITRE ATT&amp;CK", escape(mitre)),
        ("Agente", f"{escape(agente)} (ID {escape(agente_id)})"),
        ("Veces disparada", escape(veces)),
        ("Fecha y hora", escape(fecha)),
    ]

    cuerpo = T.section("Qu&eacute; pas&oacute;", "", T.callout(que_paso))
    cuerpo += T.section("Detalle del evento", "", T.kv_rows(pares))
    cuerpo += T.section(
        "Qu&eacute; revisar", "", T.bullet_list(REVISAR.get(clase, []))
    )
    cuerpo += T.section(
        "Alcance",
        "",
        T.notice(
            "Este correo es <strong>informativo</strong>: el cambio ya ocurri&oacute; "
            "y el SOC no ejecuta ninguna acci&oacute;n autom&aacute;tica sobre cuentas "
            "de Active Directory. La validaci&oacute;n con RR.HH. o con el pedido "
            "formal queda del lado de IT.",
            accent=T.C_MUTED,
            bg=T.C_SOFT,
        ),
    )

    html = T.document(
        title=escape(titulo),
        subtitle=f"Alta / Baja / Modificaci&oacute;n &nbsp;&middot;&nbsp; {escape(fecha)}",
        body=cuerpo,
        footer="Centro de Operaciones de Seguridad &middot; ABM de Active Directory<br>"
               "Generado autom&aacute;ticamente por Wazuh. No responder a este correo.",
        doc_title=f"ABM - {titulo}",
        badge_kind=badge_kind,
        preheader=f"{titulo} &middot; {sujeto_corto} &middot; {equipo}",
    )

    asunto = T.subject(
        "ABM",
        _estado(clase),
        sujeto_corto,
        equipo.split(".")[0],
    )

    return html, _texto_plano(titulo, que_paso, pares, clase, fecha), asunto, badge_kind


def _estado(clase: str) -> str:
    """ESTADO del asunto a partir de la `clase` del evento: verbo, luego ambito.

    `grupo_alta` -> "ALTA GRUPO", `privilegiado_baja` -> "BAJA PRIVILEGIADO".
    Asi la primera palabra siempre dice que paso, que es lo que se filtra.
    """
    partes = clase.split("_")
    if len(partes) == 2:
        ambito, verbo = partes
        return f"{verbo.upper()} {ambito.upper()}"
    return clase.upper()


def _texto_plano(titulo, que_paso, pares, clase, fecha) -> str:
    """Equivalente real del HTML, no un placeholder.

    Un multipart/alternative asimétrico suma score de spam — ver la nota de
    `report_theme.build_message()`.
    """
    import re

    limpio = lambda s: re.sub(r"<[^>]+>", "", str(s)).replace("&nbsp;", " ")
    lineas = [f"SOC GRUPO ALEMANA - {titulo.upper()}", "=" * 60, "",
              "QUE PASO", limpio(que_paso), "", "DETALLE DEL EVENTO"]
    ancho = max(len(limpio(k)) for k, _ in pares)
    for k, v in pares:
        lineas.append(f"  {limpio(k).ljust(ancho)} : {limpio(v)}")
    lineas += ["", "QUE REVISAR"]
    for texto, _ in REVISAR.get(clase, []):
        lineas.append(f"  - {limpio(texto)}")
    lineas += [
        "",
        "ALCANCE",
        "Este correo es informativo: el cambio ya ocurrio y el SOC no ejecuta",
        "ninguna accion automatica sobre cuentas de Active Directory.",
        "",
        "-" * 60,
        "Grupo Alemana - Seguridad de la Informacion",
        f"Generado automaticamente por Wazuh el {fecha}.",
    ]
    return "\n".join(lineas)
