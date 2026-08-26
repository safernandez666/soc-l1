#!/usr/bin/env python3
"""Rutea al integrator las reglas de AD de grupo privilegiado (necesita root).

El bloque de integración de `custom-email-unified` en `ossec.conf` lista hoy
100080-100085, 60107, 60108, 60109 y 60113. Faltan tres que el SOC sí detecta:

    100086  baja de grupo de seguridad GLOBAL          (nivel 7)
    100107  ALTA en GRUPO PRIVILEGIADO                 (nivel 13, CRITICAL)
    100108  baja de GRUPO PRIVILEGIADO                 (nivel 11)

100107 y 100108 son reglas **hijas** (`if_sid` de 100083/100084 y 100085/100086):
cuando el grupo es privilegiado dispara la hija en lugar de la padre. Como la
hija no está ruteada, el evento no genera correo — y la padre tampoco, porque
no disparó.

Esto no es teórico. El 2026-07-29 a las 15:55:33 se agregó un miembro al grupo
`Administrators` (100107, nivel 13) y `integrations.log` no registró nada en
ese minuto: no salió correo. Veinte segundos antes, dos altas de MENOR
severidad (100083 nivel 8 y 100084 nivel 10) sí lo generaron.

    sudo /var/ossec/framework/python/bin/python3 deploy/route-ad-privileged-rules.py --dry-run
    sudo /var/ossec/framework/python/bin/python3 deploy/route-ad-privileged-rules.py
    sudo /var/ossec/framework/python/bin/python3 deploy/route-ad-privileged-rules.py --restart

A diferencia del parche del integrator, este cambio SÍ necesita reiniciar
wazuh-manager para tomar efecto, y eso corta ingestión unos segundos. Por eso
el reinicio es opt-in (`--restart`) y no el default.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import difflib
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

TARGET = "/var/ossec/etc/ossec.conf"

VIEJO = "<rule_id>100080,100081,100082,100083,100084,100085,60107,60108,60109,60113</rule_id>"
NUEVO = ("<rule_id>100080,100081,100082,100083,100084,100085,100086,"
         "100107,100108,60107,60108,60109,60113</rule_id>")

COMENTARIO_VIEJO = ("<!-- MEDIO: Active Directory (100080*) y Linux (60107*) "
                    "— NO migrado a SOC-L1, se MANTIENE -->")
COMENTARIO_NUEVO = ("<!-- MEDIO: Active Directory (100080*) y Linux (60107*) "
                    "— NO migrado a SOC-L1, se MANTIENE\n"
                    "       100107/100108 (grupo PRIVILEGIADO) son reglas hijas de "
                    "100083-100086: si no estan\n"
                    "       aca explicitamente, el evento no genera correo porque la "
                    "regla padre no dispara. -->")


def validar_xml(texto: str) -> None:
    """`ossec.conf` tiene varios `<ossec_config>` de primer nivel, asi que no es
    XML valido suelto. Se envuelve en una raiz sintetica para chequearlo."""
    ET.fromstring("<wrapper>" + texto + "</wrapper>")


def parchear(texto: str) -> tuple[str, list[str]]:
    hechos: list[str] = []

    if "100107" in texto:
        hechos.append("rule_id: ya estaba")
    elif texto.count(VIEJO) == 1:
        texto = texto.replace(VIEJO, NUEVO, 1)
        hechos.append("rule_id: +100086 +100107 +100108")
    else:
        raise SystemExit(
            f"ERROR: esperaba exactamente 1 ocurrencia del <rule_id> activo, "
            f"encontre {texto.count(VIEJO)}. Reviso a mano."
        )

    if COMENTARIO_VIEJO in texto:
        texto = texto.replace(COMENTARIO_VIEJO, COMENTARIO_NUEVO, 1)
        hechos.append("comentario: documentado el porque de las hijas")

    return texto, hechos


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="muestra el diff, no toca nada")
    ap.add_argument("--restart", action="store_true",
                    help="reinicia wazuh-manager al terminar (corta ingestion unos segundos)")
    ap.add_argument("--target", default=TARGET)
    args = ap.parse_args()

    if not args.dry_run and os.geteuid() != 0:
        print("ERROR: sin --dry-run esto necesita root.", file=sys.stderr)
        return 1

    with open(args.target, encoding="utf-8") as fh:
        original = fh.read()

    nuevo, hechos = parchear(original)
    print("Cambios:")
    for h in hechos:
        print("  -", h)

    if nuevo == original:
        print("\nNada que hacer: las reglas ya estaban ruteadas.")
        return 0

    try:
        validar_xml(nuevo)
    except ET.ParseError as exc:
        print(f"ERROR: el resultado no es XML bien formado, no toco nada:\n{exc}",
              file=sys.stderr)
        return 1
    print("XML del resultado: bien formado")

    if args.dry_run:
        diff = difflib.unified_diff(
            original.splitlines(keepends=True), nuevo.splitlines(keepends=True),
            fromfile=args.target, tofile=args.target + " (parcheado)", n=4,
        )
        print("\n" + "".join(diff))
        print("Dry-run: no se toco nada.")
        return 0

    sello = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = f"{args.target}.bak-pre-adpriv-{sello}"
    shutil.copy2(args.target, backup)
    print(f"Backup: {backup}")

    st = os.stat(args.target)
    with open(args.target, "w", encoding="utf-8") as fh:
        fh.write(nuevo)
    os.chmod(args.target, st.st_mode)
    os.chown(args.target, st.st_uid, st.st_gid)
    print(f"Aplicado sobre {args.target}")

    if not args.restart:
        print(
            "\nEl cambio NO esta activo todavia: ossec.conf se lee al arrancar.\n"
            "  sudo /var/ossec/bin/wazuh-control restart\n"
            "Corta ingestion unos segundos. Para volver atras:\n"
            f"  sudo cp {backup} {args.target}   (y reiniciar)"
        )
        return 0

    print("\nReiniciando wazuh-manager...")
    r = subprocess.run(["/var/ossec/bin/wazuh-control", "restart"],
                       capture_output=True, text=True)
    print(r.stdout.strip() or r.stderr.strip())
    if r.returncode != 0:
        print(
            f"\nERROR: el restart fallo (rc={r.returncode}). El ossec.conf nuevo YA "
            f"esta en su lugar.\nSi el manager no levanta, volve atras con:\n"
            f"  sudo cp {backup} {args.target} && sudo /var/ossec/bin/wazuh-control restart",
            file=sys.stderr,
        )
        return 1
    print("\nListo. Probar con un alta real en un grupo privilegiado, o mirar")
    print("integrations.log cuando dispare la proxima 100107/100108.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
