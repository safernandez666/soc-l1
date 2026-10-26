#!/usr/bin/env python3
"""Cablea `src/abm_mail.py` dentro del integrator de Wazuh (necesita root).

Los correos de ABM de Active Directory los sigue mandando
`/var/ossec/integrations/custom-email-unified`, que tiene su propia plantilla
HTML de 2025 y su propio formato de asunto. Este script lo hace delegar en
`src/abm_mail.py`, que usa el sistema de diseño compartido de
`src/report_theme.py` — el mismo del resto de los correos del SOC.

Por qué un script y no editar a mano: el archivo es de root, está vivo (lo
ejecuta wazuh-integratord por cada alerta) y ya acumuló seis backups sueltos
al lado. Esto hace backup con fecha, parchea de forma idempotente y verifica
que el resultado compile ANTES de dejarlo en su lugar.

    sudo /var/ossec/framework/python/bin/python3 deploy/wire-abm-integrator.py --dry-run
    sudo /var/ossec/framework/python/bin/python3 deploy/wire-abm-integrator.py

No hace falta reiniciar Wazuh: el integrator se ejecuta de nuevo por cada
alerta, así que el cambio toma efecto en la siguiente. Sí haría falta si se
tocara `ossec.conf` (ver la nota sobre 100107/100108 al final).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import difflib
import os
import py_compile
import shutil
import sys
import tempfile

TARGET = "/var/ossec/integrations/custom-email-unified"
SOC_L1_PATH = "/opt/soc-l1"

# --- Cambio 1: reglas que el integrator reconoce como Active Directory -------
# 100086 (baja de grupo GLOBAL), 100107/100108 (grupo PRIVILEGIADO) y 60113
# (cuenta de grupo modificada) los sabe renderizar abm_mail pero el integrator
# los mandaba al template genérico. 60113 sí llega hoy por ossec.conf.
DETECT_VIEJO = '''        if rule_id in {"100080", "100081", "100082", "100083", "100084", "100085", "60109", "60107", "60108"}:
            return "active_directory"'''
DETECT_NUEVO = '''        if rule_id in {"100080", "100081", "100082", "100083", "100084", "100085",
                       "100086", "100107", "100108", "60107", "60108", "60109", "60113"}:
            return "active_directory"'''

# --- Cambio 2: interceptar ABM antes del camino viejo ------------------------
BUILD_VIEJO = '''        alert_type = self._detect_alert_type(alert)
        self.logger.info(f"Procesando alerta tipo: {alert_type}")

        if alert_type == "fortigate_ips":'''
BUILD_NUEVO = '''        alert_type = self._detect_alert_type(alert)
        self.logger.info(f"Procesando alerta tipo: {alert_type}")

        if alert_type == "active_directory":
            abm = self._build_abm_message(alert)
            if abm is not None:
                return abm, abm["Subject"]

        if alert_type == "fortigate_ips":'''

# --- Cambio 3: el método que delega en el repo -------------------------------
METODO_ANCLA = "    def build_email(self, alert: Dict[str, Any]) -> Tuple[MIMEMultipart, str]:"
METODO_NUEVO = '''    SOC_L1_PATH = "%s"

    def _build_abm_message(self, alert: Dict[str, Any]):
        """Arma el correo de ABM con el sistema de diseño de SOC-L1.

        Devuelve None si el repo no está, no importa o falla: en ese caso el
        integrator sigue con su plantilla vieja. Preferimos un correo feo a
        perder el aviso de un alta en un grupo privilegiado.

        El import va acá adentro y no arriba a propósito: `src/report_theme.py`
        y `src/abm_mail.py` son stdlib puro, así que el python de Wazuh los
        levanta sin el venv — pero si eso deja de ser cierto, el fallo queda
        contenido en esta función.
        """
        try:
            if self.SOC_L1_PATH not in sys.path:
                sys.path.insert(0, self.SOC_L1_PATH)
            from src import report_theme
            from src.abm_mail import build_abm_email
        except Exception as exc:
            self.logger.warning(
                f"ABM: no pude importar src.abm_mail ({exc}); uso la plantilla vieja"
            )
            return None

        try:
            html_body, plain, subject, _badge = build_abm_email(alert)
            return report_theme.build_message(
                from_addr=self.config.get("from", "wazuh@localhost"),
                recipients=self.config.get("to", []),
                subject=subject,
                html=html_body,
                plain=plain,
                logo_bytes=report_theme.load_logo(),
            )
        except Exception as exc:
            self.logger.exception(
                f"ABM: fallo armando el correo ({exc}); uso la plantilla vieja"
            )
            return None

''' % SOC_L1_PATH


def parchear(texto: str) -> tuple[str, list[str]]:
    """Aplica los tres cambios. Idempotente: lo ya aplicado se saltea."""
    hechos: list[str] = []

    # Centinela: una regla que SOLO aparece en la version parcheada. No sirve
    # comparar contra la primera linea del bloque nuevo, que es prefijo de la
    # vieja y da "ya estaba" siempre.
    if '"100107"' in texto:
        hechos.append("1. reglas AD: ya estaba")
    elif DETECT_VIEJO in texto:
        texto = texto.replace(DETECT_VIEJO, DETECT_NUEVO, 1)
        hechos.append("1. reglas AD: +100086 +100107 +100108 +60113")
    else:
        raise SystemExit("ERROR: no encontré el bloque de _detect_alert_type. ¿Cambió el archivo?")

    if "_build_abm_message(alert)" in texto:
        hechos.append("2. intercepción en build_email: ya estaba")
    elif BUILD_VIEJO in texto:
        texto = texto.replace(BUILD_VIEJO, BUILD_NUEVO, 1)
        hechos.append("2. intercepción en build_email: agregada")
    else:
        raise SystemExit("ERROR: no encontré el arranque de build_email. ¿Cambió el archivo?")

    if "def _build_abm_message" in texto:
        hechos.append("3. método _build_abm_message: ya estaba")
    elif METODO_ANCLA in texto:
        texto = texto.replace(METODO_ANCLA, METODO_NUEVO + METODO_ANCLA, 1)
        hechos.append("3. método _build_abm_message: agregado")
    else:
        raise SystemExit("ERROR: no encontré la firma de build_email para anclar el método.")

    return texto, hechos


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true",
                    help="muestra el diff y no toca nada")
    ap.add_argument("--target", default=TARGET)
    args = ap.parse_args()

    if not args.dry_run and os.geteuid() != 0:
        print("ERROR: sin --dry-run esto necesita root (el archivo es de root).",
              file=sys.stderr)
        return 1

    with open(args.target, encoding="utf-8") as fh:
        original = fh.read()

    nuevo, hechos = parchear(original)

    print("Cambios:")
    for h in hechos:
        print("  -", h)

    if nuevo == original:
        print("\nNada que hacer: el integrator ya estaba cableado.")
        return 0

    if args.dry_run:
        diff = difflib.unified_diff(
            original.splitlines(keepends=True), nuevo.splitlines(keepends=True),
            fromfile=args.target, tofile=args.target + " (parcheado)", n=3,
        )
        print("\n" + "".join(diff))
        print("Dry-run: no se tocó nada.")
        return 0

    # Compilar ANTES de reemplazar: un integrator que no parsea deja al SOC
    # sin avisos de AD y el fallo solo se ve en el log de Wazuh.
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".py", prefix="abm-wire-")
    with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
        fh.write(nuevo)
    try:
        py_compile.compile(tmp_path, doraise=True)
    except py_compile.PyCompileError as exc:
        print(f"ERROR: el resultado no compila, no toco nada:\n{exc}", file=sys.stderr)
        os.unlink(tmp_path)
        return 1
    print("\nSintaxis del resultado: OK")

    sello = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = f"{args.target}.bak-pre-abm-{sello}"
    shutil.copy2(args.target, backup)
    print(f"Backup: {backup}")

    st = os.stat(args.target)
    shutil.copyfile(tmp_path, args.target)
    os.chmod(args.target, st.st_mode)
    os.chown(args.target, st.st_uid, st.st_gid)
    os.unlink(tmp_path)

    print(f"Aplicado sobre {args.target}")
    print("\nNo hace falta reiniciar Wazuh: el integrator se ejecuta de nuevo por alerta.")
    print("Para volver atrás:  sudo cp %s %s" % (backup, args.target))
    print(
        "\nOJO: 100107 y 100108 (alta/baja en GRUPO PRIVILEGIADO) NO están en el\n"
        "<rule_id> del bloque de integración de ossec.conf, asi que hoy no llegan\n"
        "hasta acá. Son los eventos de AD más importantes que monitoreamos. Para\n"
        "que lleguen hay que agregarlos a la lista y reiniciar wazuh-manager --\n"
        "eso sí corta ingestión unos segundos, por eso no lo hace este script."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
