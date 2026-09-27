#!/usr/bin/env python3
"""Agrega la tabla combinada de alertas Kong al dashboard "Kong API Gateway Monitoring".

Uso: python3 build_kong.py
Lee:  original/export_pre_webfilter_20260727.ndjson (último export vivo del dashboard)
Escribe: improved/kong_alertas_tabla.ndjson (1 viz NUEVA + el dashboard Kong actualizado)

Contexto: el dashboard Kong ya tiene contador total ("API - Total Kong Requests"),
códigos HTTP ("API - Kong Status Codes Distribution", data.id), IPs origen
("API - Kong Top Source IPs", data.srcip) y métodos ("API - Kong HTTP Methods",
data.protocol). Lo único que faltaba era la tabla cruzada URL + IP + método + código.

OJO: el dashboard se importa con su MISMO id → requiere import con overwrite=true
(la viz es nueva, no pisa nada). Si el dashboard Kong se editó después del
2026-07-27, re-exportar antes de importar para no perder esos cambios.
"""
import copy
import json
import uuid
from pathlib import Path

BASE = Path(__file__).resolve().parent
SRC = BASE / "original" / "export_pre_webfilter_20260727.ndjson"
DST_DIR = BASE / "improved"
DST_DIR.mkdir(exist_ok=True)
DST = DST_DIR / "kong_alertas_tabla.ndjson"

KONG_DASH_ID = "55101f30-b526-11f0-b4ab-f10742cb3085"
TEMPLATE_VIS_ID = "44386790-b525-11f0-b4ab-f10742cb3085"  # API - Kong Top Source IPs (table)
INDEX_PATTERN_ID = "wazuh-alerts-*"

objs = {}
with open(SRC) as f:
    for line in f:
        line = line.strip()
        if line:
            o = json.loads(line)
            if "type" in o:
                objs[o["id"]] = o

dash = objs[KONG_DASH_ID]
tpl = objs[TEMPLATE_VIS_ID]


def terms_agg(agg_id, field, size, label):
    return {
        "id": agg_id, "enabled": True, "type": "terms", "schema": "bucket",
        "params": {"field": field, "orderBy": "1", "order": "desc", "size": size,
                   "otherBucket": False, "otherBucketLabel": "Other",
                   "missingBucket": False, "missingBucketLabel": "Missing",
                   "customLabel": label},
    }


# ---- visualización nueva: tabla URL + IP + método + código -------------------
vs = json.loads(tpl["attributes"]["visState"])
vs["title"] = "API - Kong Alertas (URL, IP, método, código)"
vs["aggs"] = [
    {"id": "1", "enabled": True, "type": "count", "schema": "metric",
     "params": {"customLabel": "Alertas"}},
    terms_agg("2", "data.url", 10, "URL"),
    terms_agg("3", "data.srcip", 5, "IP Origen"),
    terms_agg("4", "data.protocol", 3, "Método"),
    terms_agg("5", "data.id", 5, "Código HTTP"),
]

new_vis = copy.deepcopy(tpl)
new_vis["id"] = str(uuid.uuid4())
new_vis["attributes"]["title"] = vs["title"]
new_vis["attributes"]["visState"] = json.dumps(vs, ensure_ascii=False)

# ---- dashboard existente: panel nuevo debajo de todo -------------------------
panels = json.loads(dash["attributes"]["panelsJSON"])
max_y = max(p["gridData"]["y"] + p["gridData"]["h"] for p in panels)
pid = str(uuid.uuid4())
ref_name = f"panel_{len(dash['references'])}"
panels.append({
    "version": panels[0]["version"],
    "gridData": {"x": 0, "y": max_y, "w": 48, "h": 14, "i": pid},
    "panelIndex": pid,
    "embeddableConfig": {},
    "panelRefName": ref_name,
})
dash["attributes"]["panelsJSON"] = json.dumps(panels, ensure_ascii=False)
dash["references"].append({"id": new_vis["id"], "name": ref_name, "type": "visualization"})

with open(DST, "w") as f:
    f.write(json.dumps(new_vis, ensure_ascii=False) + "\n")
    f.write(json.dumps(dash, ensure_ascii=False) + "\n")
    f.write(json.dumps({"exportedCount": 2}) + "\n")

print(f"OK: {DST}")
print(f"Viz nueva: {new_vis['id']}  '{vs['title']}'")
print(f"Dashboard {KONG_DASH_ID}: {len(panels)} paneles (nuevo en y={max_y})")
print("Importar con overwrite=true (el dashboard pisa al existente con el mismo id).")
