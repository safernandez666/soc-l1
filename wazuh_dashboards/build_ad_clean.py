#!/usr/bin/env python3
"""Reconstruye 'Dashboard Active Directory' limpio y por secciones.

- Reutiliza las visualizaciones existentes que aportan (por título).
- Crea KPIs (metric) + encabezados de sección (markdown) clonando el visState real
  de este OSD (garantiza compatibilidad).
- Descarta los paneles 'todo Windows' (scope leak) y el 'Event ID Distribution' redundante.
- Reescribe panelsJSON + references con un grid ordenado.

Entrada:  scratchpad/kib_live.json  (dump live de dashboards+visualizations)
Salida:   wazuh_dashboards/ad_clean.ndjson  (para import con overwrite, SIN header securitytenant)
"""
import json, copy

SP = "/tmp/claude-1000/-opt-soc-l1/ae188f15-8ff4-4cb5-ac69-1c2af0687c36/scratchpad/kib_live.json"
OUT = "/opt/soc-l1/wazuh_dashboards/ad_clean.ndjson"
IDX = "wazuh-alerts-*"

live = json.load(open(SP))
viz_by_title, dash_ad, idx_obj = {}, None, None
for h in live["hits"]["hits"]:
    s = h["_source"]
    if s["type"] == "visualization":
        viz_by_title[s["visualization"]["title"]] = h
    elif s["type"] == "dashboard" and "Active Directory" in s["dashboard"].get("title", ""):
        dash_ad = h
    elif s["type"] == "index-pattern" and s.get("index-pattern", {}).get("title") == IDX:
        idx_obj = h

assert dash_ad, "no encontré el dashboard AD"

# Plantilla metric (de una viz metric real)
_metric_tpl = json.loads(viz_by_title["AD Summary - Usuarios Creados"]["_source"]["visualization"]["visState"])

def new_metric(vid, title, label, query, color_from=0, color_to=100):
    vs = copy.deepcopy(_metric_tpl)
    vs["title"] = title
    vs["aggs"][0]["params"]["customLabel"] = label
    vs["params"]["metric"]["colorsRange"] = [{"from": color_from, "to": color_to}]
    vs["params"]["metric"]["style"]["fontSize"] = 48
    return {
        "_id": f"visualization:{vid}", "_source": {
            "type": "visualization", "references": [
                {"id": IDX, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}],
            "visualization": {
                "title": title, "visState": json.dumps(vs, ensure_ascii=False),
                "uiStateJSON": "{}", "description": "",
                "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                    {"query": {"language": "kuery", "query": query}, "filter": [],
                     "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"}, ensure_ascii=False)},
            }, "migrationVersion": {"visualization": "7.10.0"},
        }}

def new_markdown(vid, md):
    vs = {"title": vid, "type": "markdown", "aggs": [],
          "params": {"type": "markdown", "fontSize": 12, "openLinksInNewTab": False, "markdown": md}}
    return {"_id": f"visualization:{vid}", "_source": {
        "type": "visualization", "references": [],
        "visualization": {"title": vid, "visState": json.dumps(vs, ensure_ascii=False),
            "uiStateJSON": "{}", "description": "",
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})}},
        "migrationVersion": {"visualization": "7.10.0"}}}

# ---- KPIs nuevos (los que no existen como metric) ----
new_objs = [
    new_markdown("ad-hdr-kpi", "### 🛡️ Active Directory — resumen (rango por defecto: 90 días)"),
    new_metric("ad-kpi-4625", "AD KPI - Logons Fallidos", "Logons fallidos (4625)",
               'data.win.system.eventID:"4625"', 0, 500),
    new_metric("ad-kpi-4740", "AD KPI - Lockouts", "Cuentas bloqueadas (4740)",
               'data.win.system.eventID:"4740"', 0, 100),
    new_metric("ad-kpi-dcsync", "AD KPI - DCSync Real", "DCSync sospechoso (no MSOL/DC)",
               'rule.id:"100123" AND NOT data.win.eventdata.subjectUserName:MSOL_* '
               'AND NOT data.win.eventdata.subjectUserName:(SRVDC1* OR SRVDCVELEZ01* OR SRVDC2*)', 0, 10),
    new_markdown("ad-hdr-auth", "### 🔐 Autenticación"),
    new_markdown("ad-hdr-acct", "### 👤 Gestión de cuentas y grupos"),
    new_markdown("ad-hdr-crit", "### 🚨 Eventos críticos / Ataque"),
]

# ---- viz existentes reutilizadas (por título) → devuelvo (title, id) ----
def vid_of(title):
    h = viz_by_title[title]
    return h["_id"].split(":", 1)[1] if ":" in h["_id"] else h["_id"]

reuse_titles = [
    "AD Summary - Usuarios Creados", "AD - Grupos Privilegiados", "AD - Audit & Log Tampering",
    "AD - Autenticación Heatmap", "AD - Brute Force Attempts",
    "AD - Password Changes & Resets", "AD - Cambios en Grupos", "AD - Top Usuarios Actividad",
    "AD - DCSync Real (sin MSOL)", "AD - DCSync Benigno filtrado (MSOL)", "AD - Alertas por Severidad",
]

# ---- Layout (grid 48 col) ----
# helper: cada panel referencia una viz por id
panels, refs = [], []
_pi = [0]
def add(vid, x, y, w, h):
    _pi[0] += 1
    name = f"panel_{_pi[0]}"
    refs.append({"name": name, "type": "visualization", "id": vid})
    panels.append({"version": "2.19.5", "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(_pi[0])},
                   "panelIndex": str(_pi[0]), "embeddableConfig": {}, "panelRefName": name})

# fila 0: header resumen
add("ad-hdr-kpi", 0, 0, 48, 3)
# fila KPI (6 tiles de 8 de ancho)
add(vid_of("AD - Brute Force Attempts") if False else "ad-kpi-4625", 0, 3, 8, 8)
add("ad-kpi-4625", 0, 3, 8, 8) if False else None
add(vid_of("AD Summary - Usuarios Creados"), 8, 3, 8, 8)
add(vid_of("AD - Grupos Privilegiados"), 16, 3, 8, 8)
add("ad-kpi-dcsync", 24, 3, 8, 8)
add(vid_of("AD - Audit & Log Tampering"), 32, 3, 8, 8)
add("ad-kpi-4740", 40, 3, 8, 8)
# Autenticación
add("ad-hdr-auth", 0, 11, 48, 3)
add(vid_of("AD - Autenticación Heatmap"), 0, 14, 24, 15)
add(vid_of("AD - Brute Force Attempts"), 24, 14, 24, 15)
# Cuentas y grupos
add("ad-hdr-acct", 0, 29, 48, 3)
add(vid_of("AD - Password Changes & Resets"), 0, 32, 16, 14)
add(vid_of("AD - Cambios en Grupos"), 16, 32, 16, 14)
add(vid_of("AD - Top Usuarios Actividad"), 32, 32, 16, 14)
# Críticos
add("ad-hdr-crit", 0, 46, 48, 3)
add(vid_of("AD - DCSync Real (sin MSOL)"), 0, 49, 24, 14)
add(vid_of("AD - DCSync Benigno filtrado (MSOL)"), 24, 49, 12, 14)
add(vid_of("AD - Alertas por Severidad"), 36, 49, 12, 14)

# fix: el primer KPI quedó duplicado por el patrón de arriba; reconstruyo panels limpio
panels, refs, _pi = [], [], [0]
add("ad-hdr-kpi", 0, 0, 48, 3)
add("ad-kpi-4625", 0, 3, 8, 8)
add(vid_of("AD Summary - Usuarios Creados"), 8, 3, 8, 8)
add(vid_of("AD - Grupos Privilegiados"), 16, 3, 8, 8)
add("ad-kpi-dcsync", 24, 3, 8, 8)
add(vid_of("AD - Audit & Log Tampering"), 32, 3, 8, 8)
add("ad-kpi-4740", 40, 3, 8, 8)
add("ad-hdr-auth", 0, 11, 48, 3)
add(vid_of("AD - Autenticación Heatmap"), 0, 14, 24, 15)
add(vid_of("AD - Brute Force Attempts"), 24, 14, 24, 15)
add("ad-hdr-acct", 0, 29, 48, 3)
add(vid_of("AD - Password Changes & Resets"), 0, 32, 16, 14)
add(vid_of("AD - Cambios en Grupos"), 16, 32, 16, 14)
add(vid_of("AD - Top Usuarios Actividad"), 32, 32, 16, 14)
add("ad-hdr-crit", 0, 46, 48, 3)
add(vid_of("AD - DCSync Real (sin MSOL)"), 0, 49, 24, 14)
add(vid_of("AD - DCSync Benigno filtrado (MSOL)"), 24, 49, 12, 14)
add(vid_of("AD - Alertas por Severidad"), 36, 49, 12, 14)

# ---- dashboard object ----
dsrc = copy.deepcopy(dash_ad["_source"])
db = dsrc["dashboard"]
db["title"] = "Dashboard Active Directory"
db["description"] = "AD: autenticación, gestión de cuentas/grupos y eventos críticos. Rango 90d. Reordenado 2026-07-21."
db["panelsJSON"] = json.dumps(panels, ensure_ascii=False)
db["timeRestore"] = True
db["timeFrom"] = "now-90d"
db["timeTo"] = "now"
dsrc["references"] = refs
dash_out = {"_id": dash_ad["_id"], "_source": dsrc}

# ---- escribir ndjson (formato import: attributes/id/type/references top-level) ----
def to_import(obj):
    _id = obj["_id"].split(":", 1)[1] if ":" in obj["_id"] else obj["_id"]
    s = obj["_source"]
    t = s["type"]
    out = {"id": _id, "type": t, "attributes": s[t], "references": s.get("references", [])}
    if "migrationVersion" in s: out["migrationVersion"] = s["migrationVersion"]
    return out

lines = []
if idx_obj: lines.append(to_import(idx_obj))
# viz reutilizadas
for tt in reuse_titles:
    lines.append(to_import(viz_by_title[tt]))
# viz nuevas
for o in new_objs:
    lines.append(to_import(o))
# dashboard
lines.append(to_import(dash_out))

with open(OUT, "w") as f:
    for l in lines:
        f.write(json.dumps(l, ensure_ascii=False) + "\n")

print(f"OK -> {OUT}  ({len(lines)} objetos)")
print(f"  paneles: {len(panels)}  refs: {len(refs)}  viz nuevas: {len(new_objs)}")
print(f"  reutilizadas: {len(reuse_titles)}")
