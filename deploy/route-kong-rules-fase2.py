#!/usr/bin/env python3
"""Kong Fase 2: regla de enumeración LENTA (100209) + ruteo del resto de las reglas de
ataque de Kong a SOC-L1. Necesita root (salvo --dry-run).

Contexto (2026-09-27)
---------------------
Con 100207 bloqueando en vivo desde el 22/09 quedaron dos huecos medibles:

1. **Scanners lentos.** 100207 pide 10 × 404 de la misma IP en 120 s. En 24 h hubo 5 IPs
   con ≥ 10 404 y 3 de ellas (16.5.0.236, 185.218.86.25, 94.183.174.99) los repartieron
   en ~20 h: nunca dispararon, nunca se bloquearon. Este script agrega **100209**:
   15 × 404 de la misma IP en 3600 s, nivel 8, mismos grupos que 100207. Va directo a
   `FORTIGATE_AUTO_BLOCK_RULES`: es la misma semántica (solo 404, rutas inexistentes) y
   en 5 días de 100207 en vivo los 13 bloqueos fueron scanners (/.env, /.git/config…).

2. **Reglas que solo alertan.** 100204 (5 × 401 en 60 s, fuerza bruta de API key),
   100240 (10 × 4xx en 60 s) y 100241 (20 requests en 60 s) no estaban en ningún bloque
   `custom-soc-l1`. Se rutean en **MODO SOMBRA** (`FORTIGATE_OBSERVE_ONLY_RULES`): SOC-L1
   avisa a quién bloquearía, sin tocar el FortiGate. 401 y "alta tasa" pueden venir de un
   cliente legítimo con la key mal puesta; primero se mide.

Qué toca
--------
- `/var/ossec/etc/rules/kong-rules.xml`: inserta la regla 100209 antes de `</group>`.
- `/var/ossec/etc/ossec.conf`: en el bloque `custom-soc-l1` de Kong cambia
  `<rule_id>100207</rule_id>` por `100204,100207,100209,100240,100241`.
- `/opt/soc-l1/.env`: `FORTIGATE_AUTO_BLOCK_RULES` += 100209 y
  `FORTIGATE_OBSERVE_ONLY_RULES=100204,100240,100241`.
Deja backup con timestamp de los tres archivos. No reinicia nada: eso lo hace
`implementar-kong-fase2.sh` en el orden correcto (SOC-L1 primero, wazuh después).

Uso
---
    /var/ossec/framework/python/bin/python3 deploy/route-kong-rules-fase2.py --dry-run
    sudo /var/ossec/framework/python/bin/python3 deploy/route-kong-rules-fase2.py
"""
from __future__ import annotations

import argparse
import datetime as _dt
import difflib
import os
import re
import shutil
import sys
import xml.etree.ElementTree as ET

OSSEC = "/var/ossec/etc/ossec.conf"
RULES = "/var/ossec/etc/rules/kong-rules.xml"
ENV = "/opt/soc-l1/.env"

REGLA_NUEVA = "100209"
RUTEAR = ["100204", "100207", "100209", "100240", "100241"]
BLOQUEAN = ["100209"]                       # se suman a FORTIGATE_AUTO_BLOCK_RULES
SOMBRA = ["100204", "100240", "100241"]     # FORTIGATE_OBSERVE_ONLY_RULES

REGLA_XML = """
  <!-- Enumeracion LENTA: 15 x 404 de la misma IP en 1 hora. Complementa a 100207
       (10 en 2 min), que los scanners pausados nunca disparan. Agregada 2026-09-27
       (SOC-L1 la bloquea igual que 100207). -->
  <rule id="100209" level="8" frequency="15" timeframe="3600">
    <if_matched_sid>100206</if_matched_sid>
    <same_source_ip />
    <description>Kong: Slow endpoint enumeration from $(srcip) - 15+ not-found responses in 1h</description>
    <group>kong,attack,enumeration,scanning,slow_scan</group>
  </rule>

"""


def _validar_xml(texto: str) -> None:
    ET.fromstring("<wrapper>" + texto + "</wrapper>")


def parchear_reglas(texto: str) -> tuple[str, list[str]]:
    hechos = []
    if re.search(rf'<rule id="{REGLA_NUEVA}"', texto):
        hechos.append(f"kong-rules.xml: la regla {REGLA_NUEVA} ya existe")
        return texto, hechos
    # OJO: cada regla tiene su propio <group>...</group> de etiquetas; el cierre del
    # contenedor es el ultimo `</group>` solo en su linea.
    cierres = list(re.finditer(r"^</group>\s*$", texto, re.MULTILINE))
    if len(cierres) != 1:
        raise SystemExit("ERROR: kong-rules.xml no tiene exactamente un </group> de cierre. Reviso a mano.")
    corte = cierres[0].start()
    texto = texto[:corte] + REGLA_XML.lstrip("\n") + texto[corte:]
    _validar_xml(texto)
    hechos.append(f"kong-rules.xml: +regla {REGLA_NUEVA} (15x404/1h, nivel 8)")
    return texto, hechos


def parchear_ossec(texto: str) -> tuple[str, list[str]]:
    hechos = []
    # El bloque de Kong es el custom-soc-l1 cuyo rule_id contiene 100207.
    patron = re.compile(
        r"(<name>custom-soc-l1</name>.*?<rule_id>)([^<]*\b100207\b[^<]*)(</rule_id>)",
        re.DOTALL,
    )
    m = patron.search(texto)
    if not m:
        raise SystemExit("ERROR: no encontre el bloque custom-soc-l1 con 100207. Reviso a mano.")
    actuales = [r.strip() for r in m.group(2).split(",") if r.strip()]
    nuevos = sorted(set(actuales) | set(RUTEAR), key=int)
    if nuevos == sorted(actuales, key=int):
        hechos.append("ossec.conf: el bloque de Kong ya rutea todo")
        return texto, hechos
    texto = texto[: m.start(2)] + ",".join(nuevos) + texto[m.end(2):]
    texto = texto.replace(
        "  <!-- soc-l1: enumeracion de endpoints en Kong (100207, nivel 8).",
        "  <!-- soc-l1: reglas de ataque de Kong. 2026-09-27 (Fase 2): 100207 y 100209\n"
        "       bloquean en vivo; 100204/100240/100241 en modo sombra (ver .env de SOC-L1).\n"
        "       Original (2026-09-21): enumeracion de endpoints en Kong (100207, nivel 8).",
        1,
    )
    _validar_xml(texto)
    hechos.append(f"ossec.conf: rule_id del bloque Kong → {','.join(nuevos)}")
    return texto, hechos


def parchear_env(texto: str) -> tuple[str, list[str]]:
    hechos = []
    lineas = texto.splitlines()
    vistos = {"auto": False, "sombra": False}
    for i, linea in enumerate(lineas):
        if linea.startswith("FORTIGATE_AUTO_BLOCK_RULES="):
            vistos["auto"] = True
            ids = [r.strip() for r in linea.split("=", 1)[1].split(",") if r.strip()]
            faltan = [r for r in BLOQUEAN if r not in ids]
            if faltan:
                lineas[i] = "FORTIGATE_AUTO_BLOCK_RULES=" + ",".join(ids + faltan)
                hechos.append(f".env: FORTIGATE_AUTO_BLOCK_RULES += {','.join(faltan)}")
        elif linea.startswith("FORTIGATE_OBSERVE_ONLY_RULES="):
            vistos["sombra"] = True
            ids = [r.strip() for r in linea.split("=", 1)[1].split(",") if r.strip()]
            faltan = [r for r in SOMBRA if r not in ids]
            if faltan:
                lineas[i] = "FORTIGATE_OBSERVE_ONLY_RULES=" + ",".join(ids + faltan)
                hechos.append(f".env: FORTIGATE_OBSERVE_ONLY_RULES += {','.join(faltan)}")
    if not all(vistos.values()):
        raise SystemExit(f"ERROR: faltan variables en .env: {vistos}")
    if not hechos:
        hechos.append(".env: ya tenía todo")
    nuevo = "\n".join(lineas) + ("\n" if texto.endswith("\n") else "")
    return nuevo, hechos


def _aplicar(path: str, nuevo: str, dry: bool) -> None:
    original = open(path, encoding="utf-8").read()
    if nuevo == original:
        return
    diff = difflib.unified_diff(original.splitlines(), nuevo.splitlines(),
                                fromfile=path, tofile=path + " (nuevo)", lineterm="", n=2)
    print("\n".join(list(diff)[:80]))
    if dry:
        return
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    bak = f"{path}.bak-pre-kong-fase2-{stamp}"
    shutil.copy2(path, bak)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(nuevo)
    shutil.copystat(path, tmp)
    st = os.stat(path)
    os.chown(tmp, st.st_uid, st.st_gid)
    os.replace(tmp, path)
    print(f"  escrito {path} (backup {bak})")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    if not args.dry_run and os.geteuid() != 0:
        print("ERROR: sin --dry-run esto necesita root.", file=sys.stderr)
        return 1
    for path, fn in ((RULES, parchear_reglas), (OSSEC, parchear_ossec), (ENV, parchear_env)):
        try:
            texto = open(path, encoding="utf-8").read()
        except PermissionError:
            print(f"(sin permiso de lectura para {path}; correr con sudo)")
            continue
        nuevo, hechos = fn(texto)
        for h in hechos:
            print("  -", h)
        _aplicar(path, nuevo, args.dry_run)
    print("\nDRY-RUN: no se tocó nada." if args.dry_run else "\nListo. Ahora los reinicios (ver implementar-kong-fase2.sh).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
