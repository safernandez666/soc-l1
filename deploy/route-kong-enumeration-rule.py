#!/usr/bin/env python3
"""Rutea a SOC-L1 la regla de enumeración de Kong (100207). Necesita root.

Contexto
--------
El 2026-09-21 el reporte IA diario avisó "🔴 Kong: Multiple 404 errors from
213.209.159.154 – posible enumeración de endpoints". Ese reporte es un cron de
SOLO LECTURA (`~/scripts/ia/wazuh_ia.py`): recomienda, nunca actúa. Y SOC-L1
tampoco podía actuar, porque la alerta jamás le llegaba: los cuatro bloques
`custom-soc-l1` de `ossec.conf` rutean IPS de FortiGate (1962xx), VPN/identidad
y cambios de cuenta de AD — Kong no está en ninguno.

Este script agrega el bloque que falta:

    100207  Kong: Multiple 404 errors from <ip> - Possible endpoint
            enumeration or scanning                              (nivel 8)

NO se rutea 100206 (404 suelto, nivel 4, 23.157 hits en 30d): es el sustrato de
100207 vía `if_matched_sid` y sería ruido puro. Tampoco 100241 (alta tasa, nivel
7): sus 226 hits salieron todos del bridge de Docker de la POC.

Qué pasa después del deploy
---------------------------
100207 entra en MODO SOMBRA, no bloquea. En el `.env` de SOC-L1:

    FORTIGATE_OBSERVE_ONLY_RULES=100207

El auto-block la trata como candidata (dedup por IP, registro en
`fgt_observations.jsonl`, aviso por mail + Teams con "bloquearía X") pero nunca
llama a la API del FortiGate, aunque `FORTIGATE_AUTOBLOCK_ENABLED=true`. Las
reglas IPS siguen bloqueando en vivo, sin cambios.

Por qué sombra y no bloqueo directo: las 26 reglas que hoy bloquean solas son
firmas IPS de exploit (nivel 13-14). 100207 es correlación de N×404 nivel 8
contra `gateway.grupoalemana.com`, que está publicado. Un cliente legítimo de la
API con paths mal armados se comería un ban de 1h. Primero se mide a quién
bloquearía; si en un par de semanas son solo escáneres, se promueve moviendo el
ID a `FORTIGATE_AUTO_BLOCK_RULES`.

Uso
---
    sudo /var/ossec/framework/python/bin/python3 deploy/route-kong-enumeration-rule.py --dry-run
    sudo /var/ossec/framework/python/bin/python3 deploy/route-kong-enumeration-rule.py
    sudo /var/ossec/framework/python/bin/python3 deploy/route-kong-enumeration-rule.py --restart

El reinicio de wazuh-manager corta ingestión unos segundos, por eso es opt-in.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import difflib
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

TARGET = "/var/ossec/etc/ossec.conf"
REGLA = "100207"

BLOQUE = """
  <!-- soc-l1: enumeracion de endpoints en Kong (100207, nivel 8).
       Agregado 2026-09-21. Entra en MODO SOMBRA: el auto-block la evalua y avisa
       que IP bloquearia, pero NO ejecuta (FORTIGATE_OBSERVE_ONLY_RULES=100207 en
       el .env de SOC-L1). Para promoverla a bloqueo real hay que mover el ID a
       FORTIGATE_AUTO_BLOCK_RULES, no tocar este bloque.
       No se rutea 100206 (404 suelto, nivel 4): es el sustrato via if_matched_sid
       y son 23k hits en 30 dias. -->
  <integration>
    <name>custom-soc-l1</name>
    <hook_url>http://localhost:8000/webhook/wazuh-alert</hook_url>
    <api_key>{api_key}</api_key>
    <alert_format>json</alert_format>
    <rule_id>{regla}</rule_id>
  </integration>
"""


def validar_xml(texto: str) -> None:
    """`ossec.conf` tiene varios `<ossec_config>` de primer nivel, asi que no es
    XML valido suelto. Se envuelve en una raiz sintetica para chequearlo."""
    ET.fromstring("<wrapper>" + texto + "</wrapper>")


def _api_key_existente(texto: str) -> str:
    """Toma la api_key de un bloque custom-soc-l1 ya configurado.

    Se lee del archivo vivo en vez de hardcodearla: si algun dia se rota, este
    script sigue generando un bloque coherente con el resto.
    """
    m = re.search(
        r"<name>custom-soc-l1</name>.*?<api_key>([0-9a-fA-F]{16,})</api_key>",
        texto,
        re.DOTALL,
    )
    if not m:
        raise SystemExit(
            "ERROR: no encontre un bloque <integration> de custom-soc-l1 con api_key. "
            "Reviso a mano."
        )
    return m.group(1)


def parchear(texto: str) -> tuple[str, list[str]]:
    hechos: list[str] = []

    if re.search(rf"<rule_id>[^<]*\b{REGLA}\b", texto):
        hechos.append(f"rule_id {REGLA}: ya estaba ruteada")
        return texto, hechos

    cierre = "</ossec_config>"
    if texto.count(cierre) == 0:
        raise SystemExit("ERROR: no encontre ningun </ossec_config>. Reviso a mano.")

    bloque = BLOQUE.format(api_key=_api_key_existente(texto), regla=REGLA)
    # Se inserta antes del ULTIMO cierre, que es el que contiene las integraciones.
    corte = texto.rindex(cierre)
    texto = texto[:corte] + "\n" + bloque.lstrip("\n") + texto[corte:]
    hechos.append(f"integration custom-soc-l1: +{REGLA} (enumeracion Kong, modo sombra)")
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
        print("\nNada que hacer: la regla ya estaba ruteada.")
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
    backup = f"{args.target}.bak-pre-kong-{sello}"
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
    print("\nListo. La proxima 100207 deberia dejar rastro en:")
    print("  journalctl -u soc-l1.service | grep FGT-AUTOBLOCK")
    print("  tail -f /opt/soc-l1/fgt_observations.jsonl")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
