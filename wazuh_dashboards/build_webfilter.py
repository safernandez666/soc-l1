#!/usr/bin/env python3
"""Construye el dashboard "FortiGate Web Filtering" (5 paneles nuevos).

Uso: python3 build_webfilter.py
Lee:  original/export_pre_webfilter_20260727.ndjson (export vivo del dashboard)
Escribe: improved/webfilter_dashboard.ndjson (solo objetos NUEVOS, import sin overwrite)

Campos verificados contra el indexer (2026-07-27): data.srcip, data.dstuser,
data.hostname, data.profile, data.url. OJO: data.catdesc NO viene en estos eventos.
Reglas cubiertas: 81620 (URL blocked) y 81644 (denied category).
"""
import copy
import json
import uuid
from pathlib import Path

BASE = Path(__file__).resolve().parent
SRC = BASE / "original" / "export_pre_webfilter_20260727.ndjson"
DST_DIR = BASE / "improved"
DST_DIR.mkdir(exist_ok=True)
DST = DST_DIR / "webfilter_dashboard.ndjson"

INDEX_PATTERN_ID = "wazuh-alerts-*"
OSD_VERSION = "2.19.5"

objs = {}
with open(SRC) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        o = json.loads(line)
        if "type" in o:
            objs[o["id"]] = o

by_title = {}
for o in objs.values():
    if o["type"] == "visualization":
        by_title[o["attributes"]["title"]] = o


def new_id():
    return str(uuid.uuid4())


def make_vis(title, vis_type, query, aggs, params=None, template_title=None):
    tpl = by_title.get(template_title) if template_title else None
    if tpl:
        vs = json.loads(tpl["attributes"]["visState"])
        vs["title"] = title
        vs["type"] = vis_type
        vs["aggs"] = aggs
        if params:
            vs["params"] = params
    else:
        vs = {"title": title, "type": vis_type, "aggs": aggs, "params": params or {}}
    return {
        "id": new_id(),
        "type": "visualization",
        "attributes": {
            "title": title,
            "description": "",
            "version": 1,
            "uiStateJSON": "{}",
            "visState": json.dumps(vs),
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"language": "kuery", "query": query},
                    "filter": [],
                    "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
                })
            },
        },
        "references": [{
            "id": INDEX_PATTERN_ID,
            "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
            "type": "index-pattern",
        }],
    }


def agg_count(id="1", label=None, schema="metric"):
    a = {"id": id, "enabled": True, "type": "count", "params": {}, "schema": schema}
    if label:
        a["params"]["customLabel"] = label
    return a


def agg_terms(id, field, size=10, label=None, schema="bucket", order_by="1"):
    a = {"id": id, "enabled": True, "type": "terms", "schema": schema,
         "params": {"field": field, "orderBy": order_by, "order": "desc",
                    "size": size, "otherBucket": False, "otherBucketLabel": "Other",
                    "missingBucket": False, "missingBucketLabel": "Missing"}}
    if label:
        a["params"]["customLabel"] = label
    return a


def agg_datehist(id="2", label=None, schema="segment"):
    a = {"id": id, "enabled": True, "type": "date_histogram", "schema": schema,
         "params": {"field": "timestamp", "timeRange": {"from": "now-1h", "to": "now"},
                    "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                    "interval": "auto", "drop_partials": False, "min_doc_count": 1,
                    "extended_bounds": {}}}
    if label:
        a["params"]["customLabel"] = label
    return a


PARAMS_AREA = {
    "type": "area", "grid": {"categoryLines": False}, "categoryAxes": [{
        "id": "CategoryAxis-1", "type": "category", "position": "bottom",
        "show": True, "style": {}, "scale": {"type": "linear"},
        "labels": {"show": True, "filter": True, "truncate": 100}, "title": {},
    }],
    "valueAxes": [{
        "id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left",
        "show": True, "style": {}, "scale": {"type": "linear", "mode": "normal"},
        "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
        "title": {"text": "Count"},
    }],
    "seriesParams": [{
        "show": True, "type": "area", "mode": "stacked",
        "data": {"label": "Count", "id": "1"},
        "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True,
        "lineWidth": 2, "interpolate": "linear", "showCircles": True,
    }],
    "addTooltip": True, "addLegend": True, "legendPosition": "right",
    "times": [], "addTimeMarker": False, "labels": {}, "thresholdLine": {
        "show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C",
    },
}

PARAMS_TABLE = {
    "perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
    "sort": {"columnIndex": None, "direction": None},
    "showTotal": False, "totalFunc": "sum", "percentageCol": "", "type": "table",
}

WF_QUERY = 'rule.id:("81620" OR "81644")'

vis_list = [
    make_vis("WF - Bloqueos Timeline", "area", WF_QUERY,
             [agg_count("1", "URLs bloqueadas"), agg_datehist("2", "Tiempo"),
              agg_terms("3", "data.profile", 5, "Perfil", schema="group")],
             params=copy.deepcopy(PARAMS_AREA), template_title="Net-Sec-IPsTimeline"),

    make_vis("WF - Top Hosts Origen", "table", WF_QUERY,
             [agg_count("1", "Bloqueos"),
              agg_terms("2", "data.srcip", 10, "IP Origen"),
              agg_terms("3", "data.dstuser", 3, "Usuario")],
             params=copy.deepcopy(PARAMS_TABLE), template_title="Net-Sec-Top10TiposAtaques"),

    make_vis("WF - Top Usuarios", "table", WF_QUERY,
             [agg_count("1", "Bloqueos"),
              agg_terms("2", "data.dstuser", 10, "Usuario")],
             params=copy.deepcopy(PARAMS_TABLE), template_title="Net-Sec-Top10TiposAtaques"),

    make_vis("WF - Top Dominios Bloqueados", "table", WF_QUERY,
             [agg_count("1", "Bloqueos"),
              agg_terms("2", "data.hostname", 10, "Dominio"),
              agg_terms("3", "data.profile", 3, "Perfil")],
             params=copy.deepcopy(PARAMS_TABLE), template_title="Net-Sec-Top10TiposAtaques"),

    make_vis("WF - Por Perfil", "table", WF_QUERY,
             [agg_count("1", "Bloqueos"),
              agg_terms("2", "data.profile", 10, "Perfil")],
             params=copy.deepcopy(PARAMS_TABLE), template_title="Net-Sec-Top10TiposAtaques"),
]

# ---- dashboard nuevo ---------------------------------------------------------
LAYOUT = [  # (x, y, w, h) en grilla de 48
    (0, 0, 48, 12),    # timeline
    (0, 12, 24, 14),   # top hosts
    (24, 12, 24, 14),  # top usuarios
    (0, 26, 32, 14),   # top dominios
    (32, 26, 16, 14),  # por perfil
]

panels = []
refs = []
for i, vis in enumerate(vis_list):
    pid = new_id()
    x, y, w, h = LAYOUT[i]
    panels.append({
        "version": OSD_VERSION,
        "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pid},
        "panelIndex": pid,
        "embeddableConfig": {},
        "panelRefName": f"panel_{i}",
    })
    refs.append({"id": vis["id"], "name": f"panel_{i}", "type": "visualization"})

dashboard = {
    "id": new_id(),
    "type": "dashboard",
    "attributes": {
        "title": "FortiGate Web Filtering",
        "description": "URLs bloqueadas por el web filter del FortiGate (reglas 81620/81644)",
        "hits": 0,
        "optionsJSON": json.dumps({
            "useMargins": True, "syncColors": False,
            "hidePanelTitles": False, "syncTooltips": True, "syncCursor": True,
        }),
        "panelsJSON": json.dumps(panels),
        "timeRestore": True,
        "timeFrom": "now-7d",
        "timeTo": "now",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({
                "query": {"language": "kuery", "query": ""},
                "filter": [],
            })
        },
        "version": 1,
    },
    "references": refs,
}

with open(DST, "w") as f:
    for vis in vis_list:
        f.write(json.dumps(vis, ensure_ascii=False) + "\n")
    f.write(json.dumps(dashboard, ensure_ascii=False) + "\n")
    f.write(json.dumps({"exportedCount": len(vis_list) + 1}) + "\n")

print(f"OK: {DST}")
print(f"Objetos nuevos: {len(vis_list) + 1} (5 visualizaciones + 1 dashboard)")
