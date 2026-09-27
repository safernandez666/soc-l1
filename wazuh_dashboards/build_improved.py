#!/usr/bin/env python3
"""Construye NDJSON mejorado de los 5 dashboards Wazuh a partir del export original.

Uso: python3 build_improved.py
Lee:  original/export_all.ndjson
Escribe: improved/improved_all.ndjson
"""
import copy
import json
import uuid
from pathlib import Path

BASE = Path(__file__).resolve().parent
SRC = BASE / "original" / "export_all.ndjson"
DST_DIR = BASE / "improved"
DST_DIR.mkdir(exist_ok=True)
DST = DST_DIR / "improved_all.ndjson"

INDEX_PATTERN_ID = "wazuh-alerts-*"
OSD_VERSION = "2.19.1"

objs = {}
export_marker = None
with open(SRC) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        o = json.loads(line)
        if "type" in o:
            objs[o["id"]] = o
        else:
            export_marker = o

by_title = {}
for o in objs.values():
    if o["type"] == "visualization":
        by_title[o["attributes"]["title"]] = o


def new_id():
    return str(uuid.uuid4())


def make_vis(title, vis_type, query, aggs, params=None, template_title=None):
    """Crea una visualización nueva. Si se da template_title, clona su visState.params."""
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
    vis = {
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
    objs[vis["id"]] = vis
    return vis


def set_query(vis, query, filters=None):
    meta = json.loads(vis["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
    meta["query"] = {"language": "kuery", "query": query}
    if filters is not None:
        meta["filter"] = filters
    vis["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"] = json.dumps(meta)


def get_aggs(vis):
    return json.loads(vis["attributes"]["visState"])["aggs"]


def set_aggs(vis, aggs):
    vs = json.loads(vis["attributes"]["visState"])
    vs["aggs"] = aggs
    vis["attributes"]["visState"] = json.dumps(vs)


# ---- aggs helpers -----------------------------------------------------------

def agg_count(id="1", label=None, schema="metric"):
    a = {"id": id, "enabled": True, "type": "count", "params": {}, "schema": schema}
    if label:
        a["params"]["customLabel"] = label
    return a


def agg_terms(id, field, size=10, label=None, schema="bucket", order_by="1"):
    a = {
        "id": id, "enabled": True, "type": "terms", "schema": schema,
        "params": {
            "field": field, "orderBy": order_by,
            "order": "desc", "size": size,
            "otherBucket": False, "otherBucketLabel": "Other",
            "missingBucket": False, "missingBucketLabel": "Missing",
        },
    }
    if label:
        a["params"]["customLabel"] = label
    return a


def agg_datehist(id="2", label=None, schema="segment"):
    a = {
        "id": id, "enabled": True, "type": "date_histogram", "schema": schema,
        "params": {
            "field": "timestamp", "timeRange": {"from": "now-1h", "to": "now"},
            "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
            "interval": "auto", "drop_partials": False, "min_doc_count": 1,
            "extended_bounds": {},
        },
    }
    if label:
        a["params"]["customLabel"] = label
    return a


# ---- plantillas de params por tipo ------------------------------------------
PARAMS_LINE = {
    "type": "line", "grid": {"categoryLines": False}, "categoryAxes": [{
        "id": "CategoryAxis-1", "type": "category", "position": "bottom",
        "show": True, "style": {}, "scale": {"type": "linear"},
        "labels": {"show": True, "filter": True, "truncate": 100},
        "title": {},
    }],
    "valueAxes": [{
        "id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
        "position": "left", "show": True, "style": {},
        "scale": {"type": "linear", "mode": "normal"},
        "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
        "title": {"text": "Count"},
    }],
    "seriesParams": [{
        "show": True, "type": "line", "mode": "normal",
        "data": {"label": "Count", "id": "1"},
        "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True,
        "lineWidth": 2, "interpolate": "linear", "showCircles": True,
    }],
    "addTooltip": True, "addLegend": True, "legendPosition": "right",
    "times": [], "addTimeMarker": False, "labels": {}, "thresholdLine": {
        "show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C",
    },
}

PARAMS_AREA = copy.deepcopy(PARAMS_LINE)
PARAMS_AREA["type"] = "area"
PARAMS_AREA["seriesParams"] = [{
    "show": True, "type": "area", "mode": "stacked",
    "data": {"label": "Count", "id": "1"},
    "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True,
    "lineWidth": 2, "interpolate": "linear", "showCircles": True,
}]

PARAMS_TABLE = {
    "perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
    "sort": {"columnIndex": None, "direction": None},
    "showTotal": False, "totalFunc": "sum", "percentageCol": "",
    "type": "table",
}

PARAMS_METRIC = {
    "addTooltip": True, "addLegend": False, "type": "metric",
    "metric": {
        "percentageMode": False, "useRanges": False,
        "colorSchema": "Green to Red", "metricColorMode": "None",
        "colorsRange": [{"from": 0, "to": 10000}],
        "labels": {"show": True}, "invertColors": False,
        "style": {"bgFill": "#000", "bgColor": False, "labelColor": False,
                  "subText": "", "fontSize": 48},
    },
}

# =====================================================================
# 1) MODIFICACIONES a visualizaciones existentes
# =====================================================================

# VPN: alertas de seguridad incluye logins fallidos SSL
set_query(by_title["VPN-Gen-AlertasSeguridad"],
          'rule.groups:"fortigate" AND (rule.level >= 8 OR data.action:"ssl-login-fail")')

# AD: paneles con reglas inexistentes -> queries por Event ID reales
set_query(by_title["AD - Brute Force Attempts"],
          'data.win.system.eventID:"4625"')
set_aggs(by_title["AD - Brute Force Attempts"], [
    agg_count("1", "Logons fallidos (4625)"),
    agg_datehist("2", "Tiempo"),
])

set_query(by_title["AD Summary - Usuarios Creados"],
          'data.win.system.eventID:"4720"')

set_query(by_title["AD - Grupos Privilegiados"],
          'data.win.system.eventID:("4728" OR "4732" OR "4756")')

set_query(by_title["AD - Audit & Log Tampering"],
          'data.win.system.eventID:"1102"')

# SQL: quitar filtros rotos (value None) y acotar a la regla MS SQL
set_query(by_title["SQL Top IPs"], 'rule.id:"61072"', filters=[])

# =====================================================================
# 2) NUEVAS visualizaciones
# =====================================================================

NO_SCANNERS = ('data.subtype:"ips" AND NOT (data.attack:"Masscan.Scanner" OR '
               'data.attack:"ZGrab.Scanner" OR data.attack:"Censys.io.Scanner" OR '
               'data.attack:"Nmap.Script.Scanner")')

new_by_dashboard = {}  # dashboard_title -> [vis_id,...]

def add(dash_title, vis):
    new_by_dashboard.setdefault(dash_title, []).append(vis)

# --- VPN ---
add("Dashboard VPN", make_vis(
    "VPN - Logins Fallidos SSL", "table", 'data.action:"ssl-login-fail"',
    [agg_count("1", "Intentos fallidos"),
     agg_terms("2", "data.dstuser", 10, "Usuario"),
     agg_terms("3", "data.remip", 10, "IP Origen", order_by="1"),
     agg_terms("4", "data.srccountry", 5, "Pais", order_by="1")],
    params=PARAMS_TABLE, template_title="VPN-Gen-TablaUsuarios"))

add("Dashboard VPN", make_vis(
    "VPN - Logins Fallidos Timeline", "line", 'data.action:"ssl-login-fail"',
    [agg_count("1", "Logins fallidos"), agg_datehist("2", "Tiempo")],
    params=PARAMS_LINE, template_title="VPN-Gen-Timeline-Conexiones"))

add("Dashboard VPN", make_vis(
    "VPN - Tuneles Up vs Down", "area",
    'data.action:"tunnel-up" OR data.action:"tunnel-down"',
    [agg_count("1", "Eventos"), agg_datehist("2", "Tiempo"),
     agg_terms("3", "data.action", 2, "Accion", schema="group")],
    params=PARAMS_AREA, template_title="VPN-Gen-Timeline-Conexiones"))

# --- NetSecOps ---
add("Dashboard NetSecOps", make_vis(
    "NetSec - Eventos No-Scanner", "metric", NO_SCANNERS,
    [agg_count("1", "Eventos IPS sin scanners conocidos")],
    params=PARAMS_METRIC, template_title="Net-Sec-IPSEventsCount"))

add("Dashboard NetSecOps", make_vis(
    "NetSec - Ataques Reales (sin scanners)", "table", NO_SCANNERS,
    [agg_count("1", "Eventos"),
     agg_terms("2", "data.attack", 10, "Ataque"),
     agg_terms("3", "data.srcip", 10, "IP Origen", order_by="1")],
    params=PARAMS_TABLE, template_title="Net-Sec-Top10TiposAtaques"))

add("Dashboard NetSecOps", make_vis(
    "NetSec - Severidad Media-Alta Timeline", "area",
    'data.subtype:"ips" AND (data.severity:"medium" OR data.severity:"high" OR data.severity:"critical")',
    [agg_count("1", "Eventos"), agg_datehist("2", "Tiempo"),
     agg_terms("3", "data.severity", 3, "Severidad", schema="group")],
    params=PARAMS_AREA, template_title="Net-Sec-IPsTimeline"))

# --- Active Directory ---
add("Dashboard Active Directory", make_vis(
    "AD - DCSync Real (sin MSOL)", "area",
    'rule.id:"100123" AND NOT data.win.eventdata.subjectUserName:MSOL_*',
    [agg_count("1", "Eventos DCSync"), agg_datehist("2", "Tiempo"),
     agg_terms("3", "data.win.eventdata.subjectUserName", 5, "Cuenta", schema="group")],
    params=PARAMS_AREA, template_title="AD - Timeline por Rule ID"))

add("Dashboard Active Directory", make_vis(
    "AD - DCSync Benigno filtrado (MSOL)", "metric",
    'rule.id:"100123" AND data.win.eventdata.subjectUserName:MSOL_*',
    [agg_count("1", "Eventos DCSync benignos (Azure AD Connect)")],
    params=PARAMS_METRIC, template_title="AD - Audit & Log Tampering"))

# --- SQL ---
add("Ranking SQL Access", make_vis(
    "SQL - Logons Exitosos", "metric", 'data.win.system.eventID:"18454"',
    [agg_count("1", "Logons exitosos")],
    params=PARAMS_METRIC, template_title="AD - Audit & Log Tampering"))

add("Ranking SQL Access", make_vis(
    "SQL - Logons Fallidos", "metric", 'data.win.system.eventID:"18453"',
    [agg_count("1", "Logons fallidos")],
    params=PARAMS_METRIC, template_title="AD - Audit & Log Tampering"))

add("Ranking SQL Access", make_vis(
    "SQL - Logons Timeline", "area", 'rule.id:"61072"',
    [agg_count("1", "Logons"), agg_datehist("2", "Tiempo"),
     agg_terms("3", "data.win.system.eventID", 4, "Evento", schema="group")],
    params=PARAMS_AREA, template_title="AD - Timeline por Rule ID"))

add("Ranking SQL Access", make_vis(
    "SQL - Accesos con sa", "table", 'rule.id:"61072" AND data.win.eventdata.data:sa*',
    [agg_count("1", "Logons"),
     agg_terms("2", "data.win.eventdata.data", 10, "Usuario + Cliente")],
    params=PARAMS_TABLE, template_title="Net-Sec-Top10TiposAtaques"))

# --- Kong: markdown de aviso (no hay datos) ---
md_text = (
    "## Sin datos de Kong\\n\\n"
    "Este dashboard no recibe datos: **no hay alertas ni eventos de Kong en Wazuh** "
    "(verificado en `wazuh-alerts-*` y `wazuh-archives-*`, ultimos 90 dias).\\n\\n"
    "Para activarlo hay que:\\n"
    "1. Enviar los logs de Kong (access/error) a un agente Wazuh (`<localfile>` en `ossec.conf`).\\n"
    "2. Crear/activar el decoder y las reglas `kong` (100203-100208).\\n"
    "3. Verificar que las alertas lleguen al indexer con `rule.groups:kong`.\\n\\n"
    "*Aviso generado automaticamente - Jul 2026*"
)
kong_md = make_vis(
    "Kong - Aviso sin datos", "markdown", "",
    [],
    params={"type": "markdown", "fontSize": 12, "openLinksInNewTab": False,
            "markdown": md_text.replace("\\n", "\n")},
)
add("Kong API Gateway Monitoring", kong_md)

# =====================================================================
# 3) Actualizar dashboards: time range default + paneles nuevos
# =====================================================================

dash_by_title = {o["attributes"]["title"].strip(): o
                 for o in objs.values() if o["type"] == "dashboard"}

LAYOUTS = {
    "Dashboard VPN": [(24, 12), (24, 12), (48, 12)],
    "Dashboard NetSecOps": [(16, 12), (32, 12), (48, 12)],
    "Dashboard Active Directory": [(32, 12), (16, 12)],
    "Ranking SQL Access": [(12, 10), (12, 10), (24, 10), (48, 12)],
    "Kong API Gateway Monitoring": [(48, 8)],
}

for dash_title, vis_list in new_by_dashboard.items():
    dash = dash_by_title[dash_title]
    a = dash["attributes"]
    a["timeRestore"] = True
    a["timeFrom"] = "now-7d"
    a["timeTo"] = "now"
    panels = json.loads(a["panelsJSON"])
    max_y = max(p["gridData"]["y"] + p["gridData"]["h"] for p in panels) if panels else 0
    n_refs = len(dash["references"])
    x = 0
    y = max_y
    for i, vis in enumerate(vis_list):
        w, h = LAYOUTS[dash_title][i]
        if x + w > 48:
            x = 0
            y += h
        pid = new_id()
        ref_name = f"panel_{n_refs + i}"
        panels.append({
            "version": OSD_VERSION,
            "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pid},
            "panelIndex": pid,
            "embeddableConfig": {},
            "panelRefName": ref_name,
        })
        dash["references"].append({"id": vis["id"], "name": ref_name, "type": "visualization"})
        x += w
    a["panelsJSON"] = json.dumps(panels)

# time range default para los 5 dashboards
for dash in dash_by_title.values():
    a = dash["attributes"]
    a["timeRestore"] = True
    a.setdefault("timeFrom", "now-7d")
    a["timeFrom"] = "now-7d"
    a["timeTo"] = "now"

# =====================================================================
# 4) Escribir NDJSON mejorado
# =====================================================================

with open(DST, "w") as f:
    for o in objs.values():
        f.write(json.dumps(o, ensure_ascii=False) + "\n")
    f.write(json.dumps(export_marker or {"exportedCount": len(objs)}) + "\n")

print(f"OK: {DST}")
print(f"Objetos totales: {len(objs)}")
nuevas = sum(len(v) for v in new_by_dashboard.values())
print(f"Visualizaciones nuevas: {nuevas}")
for dt, vl in new_by_dashboard.items():
    print(f"  {dt}: +{len(vl)}")
