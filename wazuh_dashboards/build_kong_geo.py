#!/usr/bin/env python3
"""Agrega visualizaciones de PAISES al dashboard "Kong API Gateway Monitoring".

    python3 build_kong_geo.py                    # exporta el dashboard VIVO y construye
    python3 build_kong_geo.py --src archivo.ndjson   # construye sobre un export dado

Escribe improved/kong_geo.ndjson con dos visualizaciones nuevas y el dashboard
actualizado:

  - "API - Kong Consumo por Pais"  (tabla): pais, alertas y **IPs distintas**. El
    conteo de IPs unicas es lo que separa "un cliente que usa mucho la API" de "un
    pais desde el que escanean 60 maquinas distintas".
  - "API - Kong Paises (distribucion)" (pie): la foto rapida para la POC.

POR QUE NO UN MAPA: el dashboard no usa ninguna viz de tipo mapa y `region_map`
necesita el servicio de vectores de Elastic/OpenSearch, que en esta red no esta
garantizado. Una tabla que siempre renderiza vale mas que un mapa que a veces sale
en blanco. Los datos de `GeoLocation.location` estan si se quiere intentar despues.

DIFERENCIA CON build_kong.py: aquel lee un export del 2026-07-27 y su propio
comentario avisa que hay que re-exportar si el dashboard cambio. Cambio (el 12/08 se
le agrego la tabla de alertas), asi que este script **exporta el vivo por API** antes
de construir. Si no, el import pisaria el dashboard con una version vieja y se
perderia ese panel.

Requiere OPENSEARCH_USER / OPENSEARCH_PASS en el entorno (o ~/scripts/ia/.env).
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

BASE = Path(__file__).resolve().parent
DST_DIR = BASE / "improved"
DST_DIR.mkdir(exist_ok=True)
DST = DST_DIR / "kong_geo.ndjson"

KONG_DASH_ID = "55101f30-b526-11f0-b4ab-f10742cb3085"
DASHBOARD_URL = os.getenv("WAZUH_DASHBOARD_URL", "https://127.0.0.1:443")
ENV_FILE = os.path.expanduser("~/scripts/ia/.env")
CAMPO_PAIS = "GeoLocation.country_name"


def credenciales() -> tuple[str, str]:
    u, p = os.getenv("OPENSEARCH_USER"), os.getenv("OPENSEARCH_PASS")
    if u and p:
        return u, p
    try:
        with open(ENV_FILE, encoding="utf-8") as fh:
            for linea in fh:
                k, _, v = linea.strip().partition("=")
                if k in ("OPENSEARCH_USER", "OPENSEARCH_PASS"):
                    os.environ.setdefault(k, v.strip().strip("'\""))
    except OSError:
        pass
    u, p = os.getenv("OPENSEARCH_USER"), os.getenv("OPENSEARCH_PASS")
    if not (u and p):
        sys.exit("ERROR: faltan OPENSEARCH_USER / OPENSEARCH_PASS")
    return u, p


def exportar_vivo() -> str:
    """Trae el dashboard actual del Dashboards. Curl y no requests: este script
    corre con el python del sistema y no queremos dependencias."""
    u, p = credenciales()
    cuerpo = json.dumps({"objects": [{"type": "dashboard", "id": KONG_DASH_ID}],
                         "includeReferencesDeep": True})
    r = subprocess.run(
        ["curl", "-sk", "-u", f"{u}:{p}", "-X", "POST",
         f"{DASHBOARD_URL}/api/saved_objects/_export",
         "-H", "osd-xsrf: true", "-H", "Content-Type: application/json", "-d", cuerpo],
        capture_output=True, text=True, timeout=120)
    if r.returncode != 0 or not r.stdout.strip():
        sys.exit(f"ERROR exportando el dashboard vivo: {r.stderr[:300]}")
    if '"error"' in r.stdout[:200] and '"attributes"' not in r.stdout[:200]:
        sys.exit(f"ERROR del API: {r.stdout[:300]}")
    return r.stdout


def terms_agg(agg_id, campo, size, label, orderBy="1"):
    return {"id": agg_id, "enabled": True, "type": "terms", "schema": "bucket",
            "params": {"field": campo, "orderBy": orderBy, "order": "desc", "size": size,
                       "otherBucket": False, "otherBucketLabel": "Other",
                       "missingBucket": False, "missingBucketLabel": "Missing",
                       "customLabel": label}}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src", help="ndjson ya exportado (por defecto exporta el vivo)")
    args = ap.parse_args()

    crudo = Path(args.src).read_text(encoding="utf-8") if args.src else exportar_vivo()

    objs, orden = {}, []
    for linea in crudo.splitlines():
        linea = linea.strip()
        if not linea:
            continue
        o = json.loads(linea)
        if "type" in o and "id" in o:
            objs[o["id"]] = o
            orden.append(o["id"])

    if KONG_DASH_ID not in objs:
        sys.exit("ERROR: el export no trae el dashboard de Kong.")
    dash = objs[KONG_DASH_ID]

    # Plantillas: se clona una tabla y un pie que YA existen, asi las viz nuevas
    # heredan searchSourceJSON, index pattern y estilo sin inventar nada.
    def buscar(tipo_vis):
        for oid in orden:
            o = objs[oid]
            if o.get("type") != "visualization":
                continue
            if json.loads(o["attributes"]["visState"]).get("type") == tipo_vis:
                return o
        sys.exit(f"ERROR: no encontre una viz de tipo {tipo_vis} para usar de plantilla.")

    tpl_tabla, tpl_pie = buscar("table"), buscar("pie")
    nuevas = []

    # ---- tabla: pais + alertas + IPs distintas ------------------------------
    vs = json.loads(tpl_tabla["attributes"]["visState"])
    vs["title"] = "API - Kong Consumo por Pais"
    vs["aggs"] = [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Alertas"}},
        # Cardinalidad de IPs: distingue un consumidor legitimo de un barrido.
        {"id": "3", "enabled": True, "type": "cardinality", "schema": "metric",
         "params": {"field": "data.srcip", "customLabel": "IPs distintas"}},
        terms_agg("2", CAMPO_PAIS, 20, "Pais"),
    ]
    tabla = copy.deepcopy(tpl_tabla)
    tabla["id"] = str(uuid.uuid4())
    tabla["attributes"]["title"] = vs["title"]
    tabla["attributes"]["visState"] = json.dumps(vs, ensure_ascii=False)
    nuevas.append((tabla, 24, 14))   # media pantalla de ancho

    # ---- pie: distribucion --------------------------------------------------
    vsp = json.loads(tpl_pie["attributes"]["visState"])
    vsp["title"] = "API - Kong Paises (distribucion)"
    vsp["aggs"] = [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Alertas"}},
        terms_agg("2", CAMPO_PAIS, 10, "Pais"),
    ]
    pie = copy.deepcopy(tpl_pie)
    pie["id"] = str(uuid.uuid4())
    pie["attributes"]["title"] = vsp["title"]
    pie["attributes"]["visState"] = json.dumps(vsp, ensure_ascii=False)
    nuevas.append((pie, 24, 14))

    # ---- colgar los paneles debajo de todo ----------------------------------
    panels = json.loads(dash["attributes"]["panelsJSON"])
    y = max(p["gridData"]["y"] + p["gridData"]["h"] for p in panels)
    x = 0
    for viz, w, h in nuevas:
        pid = str(uuid.uuid4())
        ref = f"panel_{len(dash['references'])}"
        panels.append({"version": panels[0]["version"],
                       "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pid},
                       "panelIndex": pid, "embeddableConfig": {}, "panelRefName": ref})
        dash["references"].append({"id": viz["id"], "name": ref, "type": "visualization"})
        x += w
    dash["attributes"]["panelsJSON"] = json.dumps(panels, ensure_ascii=False)

    with open(DST, "w", encoding="utf-8") as fh:
        for viz, _, _ in nuevas:
            fh.write(json.dumps(viz, ensure_ascii=False) + "\n")
        fh.write(json.dumps(dash, ensure_ascii=False) + "\n")
        fh.write(json.dumps({"exportedCount": len(nuevas) + 1}) + "\n")

    print(f"OK: {DST}")
    for viz, _, _ in nuevas:
        print(f"  viz nueva: {viz['id']}  '{viz['attributes']['title']}'")
    print(f"  dashboard {KONG_DASH_ID}: {len(panels)} paneles (nuevos en y={y})")
    print()
    print("Importar (pisa el dashboard con el mismo id, por eso se exporto el vivo):")
    print("  curl -sk -u $OPENSEARCH_USER:$OPENSEARCH_PASS -H 'osd-xsrf: true' \\")
    print(f"    -F file=@{DST} \\")
    print(f"    '{DASHBOARD_URL}/api/saved_objects/_import?overwrite=true'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
