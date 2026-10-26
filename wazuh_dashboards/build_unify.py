#!/usr/bin/env python3
"""Unifica y mejora los 6 dashboards de Wazuh (OpenSearch Dashboards) — 2026-09-27.

    python3 build_unify.py                 # exporta el vivo, construye improved/unify.ndjson
    python3 build_unify.py --import        # además importa (overwrite) y borra huérfanas
    python3 build_unify.py --src X.ndjson  # construye sobre un export dado

CONVENCIÓN DE NOMBRES (la razón de ser de este script)
------------------------------------------------------
Había cinco estilos distintos: "Dashboard VPN", "Ranking SQL Access", "VPN-Gen-Metric-Paises",
"Net-Sec-IPsTimeline", "AD KPI - Lockouts", "ad-hdr-kpi" (un id interno mostrado como título)…
Queda UNA regla:

  Dashboards:        "SOC · <Fuente>"            → SOC · Active Directory, SOC · FortiGate IPS,
                                                   SOC · FortiGate VPN, SOC · FortiGate Web Filter,
                                                   SOC · Kong API Gateway, SOC · SQL Server
  Visualizaciones:   "<PFX> · <Qué muestra>"     → AD · Logons fallidos (4625), IPS · IPs atacantes,
                                                   VPN · Conexiones por hora, WF · Dominios bloqueados,
                                                   Kong · Requests, SQL · Logons fallidos (18453)
  Encabezados:       "<PFX> · § <Sección>"       (markdown; el título del panel va OCULTO)
  Nota al pie:       "<PFX> · Cómo leer este tablero"  en todos, con fuente, reglas y límites.

El prefijo es lo que uno escribe en el buscador de visualizaciones para ver solo las de una
fuente. El "·" separa igual que en los correos y en /ui.

QUÉ MEJORA, POR TABLERO (todo verificado contra el indexer el 2026-09-27)
-------------------------------------------------------------------------
AD   Rango 90d→30d (alcanza y carga 3x más rápido). Se saca "DCSync Benigno (MSOL)": desde el
     tuning del 21/07 la regla 100123 ya no dispara por MSOL, el panel era un 0 permanente.
     Nuevo: "Alertas por regla por día" (100122 GPO modificada = 1.433/30d, la más ruidosa y
     no se veía), "GPO modificadas: quién", "Logons fallidos por host y cuenta" (el 95% de los
     4625 son .\\webuser_local en TECO-TST-WEB-01: una cuenta local rota, no un ataque a AD).
IPS  Fila de KPIs (eventos, críticos+altos, IPs atacantes, destinos). Lista de scanners suma
     Nmap.Script.Scanner (99/30d). Nota: 80% de los eventos van contra Kong (.62).
VPN  Recupera dos vistas huérfanas útiles (usuarios con varias IPs / varios países). Nuevo:
     "Conexiones desde fuera de Argentina" y "Logins fallidos por usuario y motivo" (172 de 174
     son permission_denied: usuarios válidos SIN permiso VPN, no adivinación de passwords).
     Corrige "IPs únicas", que contaba TODO el índice (query vacía).
WF   La regla 81620 NO es web filter: son anomalías SSL (certificate-inspection) y firmas WAF.
     Los 5 paneles pasan a 81644 (bloqueo por categoría, el dato real) y 81620 va a su propia
     sección "SSL / WAF", separada. KPIs arriba.
Kong Solo nombres (ya rearmado hoy por build_kong_v2.py).
SQL  SRVSQLPRODA dejó de emitir 18454/18453 (logon OK) el 2026-07-27 10:47, pero los fallidos
     18456 (regla 61071) siguen llegando: el login auditing volvió a "Failed only". OJO: 18453 NO
     es fallido (es logon OK por Windows auth), el tablero viejo lo contaba mal. Se agregan fallidos
     por día y tabla de cuenta/motivo/cliente (funcionan con cualquier rango); los de exitosos dan 0
     con menos de ~60d y el tablero lo explica arriba. Rango 90d para que se vea el último dato.

Idempotente: se puede volver a correr contra el vivo. rename() guarda el título original en
visState._orig_title (así _by_title lo encuentra) y clone() reutiliza el id si ya hay una viz con
ese título.

Se borran 10 visualizaciones huérfanas (no colgadas de ningún dashboard): copias y descartes de
la limpieza de julio. Las 2 de VPN vuelven a usarse. Backup del estado previo en
original/export_all_pre_unify_20260927.ndjson (importar con overwrite para volver atrás).
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

BASE = Path(__file__).resolve().parent
DST = BASE / "improved" / "unify.ndjson"
DASHBOARD_URL = os.getenv("WAZUH_DASHBOARD_URL", "https://127.0.0.1:443")
ENV_FILE = os.path.expanduser("~/scripts/ia/.env")
GRAFANA_KONG = "https://monitoring.grupoalemana.com/d/kong-alemana/kong-alemana"

D_AD = "89a1ac90-a384-11f0-b4ab-f10742cb3085"
D_IPS = "b63c34c0-a067-11f0-b4ab-f10742cb3085"
D_VPN = "fd165d80-a04e-11f0-b4ab-f10742cb3085"
D_WF = "e281a415-ad08-480a-8ae8-9b2f0029b977"
D_KONG = "55101f30-b526-11f0-b4ab-f10742cb3085"
D_SQL = "669d0e70-5e8b-11f1-97f5-7f14013da149"

# Plantillas (visState real de este OSD, así lo nuevo hereda estilo y compatibilidad)
T_METRIC = "dcce19b0-b524-11f0-b4ab-f10742cb3085"   # Kong · Requests
T_TABLE = "44386790-b525-11f0-b4ab-f10742cb3085"    # Kong · IPs atacantes
T_BARS = "1ba76ce0-b525-11f0-b4ab-f10742cb3085"     # Kong · Requests por código (histograma por día)
T_MD = "bebd1076-9c0d-4670-b8f0-68ae7aeff267"       # Kong · Cómo leer este tablero

HUERFANAS_BORRAR = [
    "9b0b2ed0-a383-11f0-b4ab-f10742cb3085",  # AD - Cambios Grupos Privilegiados (1 doc/90d)
    "1b2a5990-a930-11f0-b4ab-f10742cb3085",  # AD - Distribución por Severidad (dup)
    "198e3d30-a387-11f0-b4ab-f10742cb3085",  # AD - Event ID Distribution (descartada 21/07)
    "234827e0-a383-11f0-b4ab-f10742cb3085",  # AD - Eventos Críticos Detalle
    "40c2fbd0-a930-11f0-b4ab-f10742cb3085",  # AD - Hosts Más Ruidosos (scope Windows)
    "f0ceb100-a92f-11f0-b4ab-f10742cb3085",  # AD - Timeline por Rule ID (se rehace acotada)
    "6125f540-a92f-11f0-b4ab-f10742cb3085",  # AD - Top Rules Windows (scope Windows)
    "10cb73b0-5e8b-11f1-97f5-7f14013da149",  # Ranking SQL Access (viz suelta, query vacía)
    "2c9352d0-5eda-11f1-97f5-7f14013da149",  # SQL Top IPs (copy)
    "7a69af57-5f8d-40ae-aa14-4c81612e080d",  # AD - DCSync Benigno filtrado (MSOL): 0 fijo desde el tuning del 21/07
]
V_VPN_MULTI_IP = "92f377f0-a051-11f0-b4ab-f10742cb3085"
V_VPN_MULTI_PAIS = "d361c300-a051-11f0-b4ab-f10742cb3085"

SCANNERS = ("Masscan.Scanner", "ZGrab.Scanner", "Censys.io.Scanner", "Nmap.Script.Scanner")
Q_IPS = 'data.subtype:"ips"'
Q_IPS_SIN_SCAN = Q_IPS + " AND NOT (" + " OR ".join(f'data.attack:"{s}"' for s in SCANNERS) + ")"
Q_WF = "rule.id:81644"
Q_SSLWAF = "rule.id:81620"
Q_VPN_UP = 'data.action:"tunnel-up"'
Q_VPN_FAIL = 'data.action:"ssl-login-fail"'
Q_SQL = "rule.id:(61071 OR 61072)"        # logon fallido (18456) + logon OK (18454/18453)
Q_SQL_FAIL = "rule.id:61071"


# ------------------------------------------------------------------ infra ----
def credenciales() -> tuple[str, str]:
    u, p = os.getenv("OPENSEARCH_USER"), os.getenv("OPENSEARCH_PASS")
    if not (u and p):
        try:
            for linea in open(ENV_FILE, encoding="utf-8"):
                k, _, v = linea.strip().partition("=")
                if k in ("OPENSEARCH_USER", "OPENSEARCH_PASS"):
                    os.environ.setdefault(k, v.strip().strip("'\""))
        except OSError:
            pass
        u, p = os.getenv("OPENSEARCH_USER"), os.getenv("OPENSEARCH_PASS")
    if not (u and p):
        sys.exit("ERROR: faltan OPENSEARCH_USER / OPENSEARCH_PASS")
    return u, p


def curl(args: list[str]) -> str:
    u, p = credenciales()
    r = subprocess.run(["curl", "-sk", "-u", f"{u}:{p}", "-H", "osd-xsrf: true", *args],
                       capture_output=True, text=True, timeout=180)
    if r.returncode != 0:
        sys.exit(f"ERROR curl: {r.stderr[:300]}")
    return r.stdout


def exportar_vivo() -> str:
    out = curl(["-X", "POST", f"{DASHBOARD_URL}/api/saved_objects/_export",
                "-H", "Content-Type: application/json",
                "-d", json.dumps({"type": ["dashboard", "visualization"],
                                  "includeReferencesDeep": True})])
    bak = BASE / "original" / f"export_all_pre_unify_{dt.date.today():%Y%m%d}.ndjson"
    if not bak.exists():
        bak.write_text(out, encoding="utf-8")
        print(f"backup del vivo: {bak}")
    return out


# --------------------------------------------------------------- helpers -----
class Builder:
    def __init__(self, objs: dict[str, dict]):
        self.objs = objs
        self.out: dict[str, dict] = {}     # id -> objeto a escribir

    # -- lectura/escritura de visState ---------------------------------------
    def vis(self, vid: str) -> dict:
        if vid not in self.out:
            v = copy.deepcopy(self.objs[vid])
            v.pop("version", None); v.pop("updated_at", None)
            self.out[vid] = v
        return self.out[vid]

    @staticmethod
    def state(v: dict) -> dict:
        return json.loads(v["attributes"]["visState"])

    @staticmethod
    def save(v: dict, vs: dict) -> None:
        v["attributes"]["visState"] = json.dumps(vs, ensure_ascii=False)

    def rename(self, vid: str, title: str, desc: str | None = None) -> str:
        v = self.vis(vid); vs = self.state(v)
        # guarda el título original: así _by_title lo encuentra al re-correr contra el vivo
        vs.setdefault("_orig_title", self.objs[vid]["attributes"]["title"])
        vs["title"] = title; v["attributes"]["title"] = title
        if desc is not None:
            v["attributes"]["description"] = desc
        self.save(v, vs)
        return vid

    def setq(self, vid: str, query: str) -> str:
        v = self.vis(vid)
        ss = json.loads(v["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
        ss["query"] = {"query": query, "language": "kuery"}
        v["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"] = json.dumps(ss)
        return vid

    def edit(self, vid: str, fn) -> str:
        v = self.vis(vid); vs = self.state(v); fn(vs); self.save(v, vs)
        return vid

    def clone(self, tpl: str, title: str, query: str, aggs: list[dict], *,
              desc: str = "", params: dict | None = None) -> str:
        nuevo = copy.deepcopy(self.objs[tpl])
        # si el vivo ya tiene una viz con este título (re-run), se pisa en lugar de duplicarla
        previo = next((k for k, o in self.objs.items()
                       if o.get("type") == "visualization" and o["attributes"]["title"] == title), None)
        nuevo["id"] = previo or str(uuid.uuid4())
        nuevo.pop("version", None); nuevo.pop("updated_at", None)
        vs = json.loads(nuevo["attributes"]["visState"])
        vs["title"] = title; vs["aggs"] = aggs
        if params:
            vs["params"].update(params)
        nuevo["attributes"]["title"] = title
        nuevo["attributes"]["description"] = desc
        nuevo["attributes"]["visState"] = json.dumps(vs, ensure_ascii=False)
        self.out[nuevo["id"]] = nuevo
        self.setq(nuevo["id"], query)
        return nuevo["id"]

    def markdown(self, title: str, md: str, existing: str | None = None) -> str:
        if existing:
            vid = self.rename(existing, title)
            return self.edit(vid, lambda vs: vs["params"].update({"markdown": md, "fontSize": 12}))
        vid = self.clone(T_MD, title, "", [])
        return self.edit(vid, lambda vs: vs["params"].update({"markdown": md, "fontSize": 12,
                                                              "openLinksInNewTab": True}))

    # -- dashboard -----------------------------------------------------------
    def dashboard(self, did: str, title: str, desc: str, layout: list, *,
                  time_from: str) -> None:
        d = copy.deepcopy(self.objs[did]); d.pop("version", None); d.pop("updated_at", None)
        version = json.loads(d["attributes"]["panelsJSON"])[0]["version"]
        panels, refs = [], []
        for i, item in enumerate(layout):
            vid, x, y, w, h = item[:5]
            hide = len(item) > 5 and item[5]
            pid = str(uuid.uuid4())
            cfg = {"hidePanelTitles": True} if hide else {}
            panels.append({"version": version, "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pid},
                           "panelIndex": pid, "embeddableConfig": cfg, "panelRefName": f"panel_{i}"})
            refs.append({"id": vid, "name": f"panel_{i}", "type": "visualization"})
            if vid not in self.out:
                self.vis(vid)  # asegura que existe
        d["attributes"]["title"] = title
        d["attributes"]["description"] = desc
        d["attributes"]["panelsJSON"] = json.dumps(panels, ensure_ascii=False)
        d["attributes"]["timeFrom"] = time_from
        d["attributes"]["timeTo"] = "now"
        d["attributes"]["timeRestore"] = True
        d["references"] = refs
        self.out[did] = d


# aggs cortos
def count(label="Eventos"):
    return {"id": "1", "enabled": True, "type": "count", "schema": "metric",
            "params": {"customLabel": label}}


def card(agg_id, field, label):
    return {"id": agg_id, "enabled": True, "type": "cardinality", "schema": "metric",
            "params": {"field": field, "customLabel": label}}


def maxdate(agg_id, label="Último"):
    return {"id": agg_id, "enabled": True, "type": "max", "schema": "metric",
            "params": {"field": "timestamp", "customLabel": label}}


def terms(agg_id, field, size, label, schema="bucket", other=False):
    return {"id": agg_id, "enabled": True, "type": "terms", "schema": schema,
            "params": {"field": field, "orderBy": "1", "order": "desc", "size": size,
                       "otherBucket": other, "otherBucketLabel": "Otros",
                       "missingBucket": False, "missingBucketLabel": "Sin dato",
                       "customLabel": label}}


def por_dia(agg_id="2", interval="d"):
    return {"id": agg_id, "enabled": True, "type": "date_histogram", "schema": "segment",
            "params": {"field": "timestamp", "timeRange": {"from": "now-7d", "to": "now"},
                       "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                       "interval": interval, "drop_partials": False, "min_doc_count": 1,
                       "extended_bounds": {}, "customLabel": "Día"}}


def a_barras(vs: dict) -> None:
    vs["type"] = "histogram"; vs["params"]["type"] = "histogram"
    for sp in vs["params"].get("seriesParams", []):
        sp["type"] = "histogram"; sp["mode"] = "stacked"; sp.pop("interpolate", None)


def hdr(b: Builder, pfx: str, texto: str, existing: str | None = None) -> str:
    return b.markdown(f"{pfx} · § {texto}", f"### {texto}", existing)


# ================================================================ AD ==========
def build_ad(b: Builder) -> None:
    P = "AD"
    kpi_hdr = b.markdown(f"{P} · § Resumen",
                         "### 🛡️ Active Directory — resumen (rango por defecto: 30 días)",
                         existing=_by_title(b, "ad-hdr-kpi"))
    auth_hdr = hdr(b, P, "🔐 Autenticación", existing=_by_title(b, "ad-hdr-auth"))
    acct_hdr = hdr(b, P, "👤 Gestión de cuentas y grupos", existing=_by_title(b, "ad-hdr-acct"))
    crit_hdr = hdr(b, P, "🚨 Eventos críticos / ataque", existing=_by_title(b, "ad-hdr-crit"))

    k_4625 = b.rename(_by_title(b, "AD KPI - Logons Fallidos"), f"{P} · Logons fallidos (4625)")
    k_4720 = b.rename(_by_title(b, "AD Summary - Usuarios Creados"), f"{P} · Usuarios creados (4720)")
    k_grp = b.rename(_by_title(b, "AD - Grupos Privilegiados"), f"{P} · Altas en grupos (4728/4732)")
    k_dcs = b.rename(_by_title(b, "AD KPI - DCSync Real"), f"{P} · DCSync (100123, sin MSOL)",
                     "Desde el tuning del 2026-07-21 la 100123 ya excluye MSOL_*. Cualquier valor > 0 es para mirar.")
    k_1102 = b.rename(_by_title(b, "AD - Audit & Log Tampering"), f"{P} · Borrado de logs (1102)",
                      "Debe ser 0. Un 1102 es alguien limpiando el Security log de un DC.")
    k_4740 = b.rename(_by_title(b, "AD KPI - Lockouts"), f"{P} · Bloqueos de cuenta (4740)")

    heat = b.rename(_by_title(b, "AD - Autenticación Heatmap"),
                    f"{P} · Autenticación Windows por hora (todos los agentes)",
                    "Grupos authentication_success/failed de TODOS los agentes Windows, no solo DCs.")
    bf = b.edit(b.rename(_by_title(b, "AD - Brute Force Attempts"), f"{P} · Logons fallidos por día (4625)"), a_barras)
    t_4625 = b.clone(T_TABLE, f"{P} · Logons fallidos por host y cuenta", 'data.win.system.eventID:"4625"',
                     [count("Fallos"), maxdate("5"), terms("2", "agent.name", 8, "Host"),
                      terms("3", "data.win.eventdata.targetUserName", 3, "Cuenta"),
                      terms("4", "data.win.eventdata.ipAddress", 2, "IP origen")],
                     desc="Separa el ruido (una cuenta local rota en un servidor de test) de un ataque real contra AD.",
                     params={"perPage": 12})

    pw = b.rename(_by_title(b, "AD - Password Changes & Resets"), f"{P} · Cambios y reseteos de contraseña (por quién)")
    grp_k = b.rename(_by_title(b, "AD - Cambios en Grupos"), f"{P} · Cambios en grupos (100083-100086)")
    top_u = b.rename(_by_title(b, "AD - Top Usuarios Actividad"), f"{P} · Usuarios con más actividad")
    t_grp = b.clone(T_TABLE, f"{P} · Cambios de grupo: quién y qué grupo",
                    "rule.id: (100083 OR 100084 OR 100085 OR 100086 OR 100107 OR 100108)",
                    [count("Cambios"), maxdate("4"), terms("2", "data.win.eventdata.subjectUserName", 10, "Quién"),
                     terms("3", "rule.description", 3, "Qué")],
                    desc="100107/100108 = grupos PRIVILEGIADOS (nivel 13), también ruteados a SOC-L1.",
                    params={"perPage": 10})
    t_4740 = b.clone(T_TABLE, f"{P} · Bloqueos de cuenta: quién", 'data.win.system.eventID:"4740"',
                     [count("Bloqueos"), maxdate("3"), terms("2", "data.win.eventdata.targetUserName", 10, "Cuenta")],
                     params={"perPage": 10})

    dcs = b.rename(_by_title(b, "AD - DCSync Real (sin MSOL)"), f"{P} · DCSync por cuenta (por día)")
    sev = b.rename(_by_title(b, "AD - Alertas por Severidad"), f"{P} · Alertas por nivel")
    reglas = b.clone(T_BARS, f"{P} · Alertas por regla (por día)", 'rule.groups: "active_directory"',
                     [count("Alertas"), por_dia("2"), terms("3", "rule.id", 8, "Regla", schema="group", other=True)],
                     desc="100122 = GPO modificada (la más frecuente), 100125 = cuenta de equipo cambiada, "
                          "100111/100112 = password, 10008x = grupos, 100123 = DCSync.")
    t_gpo = b.clone(T_TABLE, f"{P} · GPO modificadas (100122): quién y desde qué DC", "rule.id: 100122",
                    [count("Cambios"), maxdate("4"), terms("2", "data.win.eventdata.subjectUserName", 10, "Quién"),
                     terms("3", "agent.name", 3, "DC")],
                    desc="1.433 en 30 días: si es siempre la misma cuenta de servicio, es candidata a tuning.",
                    params={"perPage": 10})

    nota = b.markdown(f"{P} · Cómo leer este tablero", f"""### Cómo leer este tablero
**Fuente.** Security log de los DCs (`SRVDC2`, `SRVDCVELEZ01`, `SRVDCFICO1`) por agente Wazuh. Reglas propias
**100080–100126** (grupo `active_directory`) sobre los Event IDs de Windows; los KPIs de 4625/4720/4740/1102
usan el Event ID directo.

**Qué pasa con lo que se ve.** Las reglas de cuentas y grupos (100080–100086) y las de grupos privilegiados
(100107/100108) están **ruteadas a SOC-L1**: notificación + respuesta con aprobación. DCSync (100123) ya excluye
`MSOL_*` (Azure AD Connect) desde el 2026-07-21; el panel de "benigno filtrado" se retiró porque quedó en 0 fijo.

**Ojo.** La autenticación por hora y "usuarios con más actividad" miran **todos los agentes Windows**, no solo
DCs. Los 4625 de hoy son en su mayoría `.\\webuser_local` en `TECO-TST-WEB-01`: cuenta local rota, no AD.

*Unificado 2026-09-27 (`wazuh_dashboards/build_unify.py`).*""")

    y = 0
    L = [(kpi_hdr, 0, y, 48, 3, True)]; y += 3
    for i, v in enumerate((k_4625, k_4720, k_grp, k_dcs, k_1102, k_4740)):
        L.append((v, i * 8, y, 8, 7))
    y += 7
    L.append((auth_hdr, 0, y, 48, 3, True)); y += 3
    L += [(heat, 0, y, 24, 14), (bf, 24, y, 24, 14)]; y += 14
    L += [(t_4625, 0, y, 48, 12)]; y += 12
    L.append((acct_hdr, 0, y, 48, 3, True)); y += 3
    L += [(pw, 0, y, 16, 13), (grp_k, 16, y, 8, 13), (top_u, 24, y, 24, 13)]; y += 13
    L += [(t_grp, 0, y, 32, 12), (t_4740, 32, y, 16, 12)]; y += 12
    L.append((crit_hdr, 0, y, 48, 3, True)); y += 3
    L += [(reglas, 0, y, 24, 13), (dcs, 24, y, 24, 13)]; y += 13
    L += [(t_gpo, 0, y, 32, 12), (sev, 32, y, 16, 12)]; y += 12
    L += [(nota, 0, y, 48, 9)]
    b.dashboard(D_AD, "SOC · Active Directory",
                "Active Directory: autenticación, cuentas y grupos, GPO, DCSync y borrado de logs. "
                "Reglas 100080-100126 sobre los DCs. Unificado 2026-09-27.", L, time_from="now-30d")


# ================================================================ IPS =========
def build_ips(b: Builder) -> None:
    P = "IPS"
    total = b.rename(_by_title(b, "Net-Sec-IPSEventsCount"), f"{P} · Eventos")
    k_crit = b.clone(T_METRIC, f"{P} · Críticos y altos", Q_IPS + ' AND data.severity:("critical" OR "high")',
                     [count("Críticos + altos")])
    k_ips = b.clone(T_METRIC, f"{P} · IPs atacantes", Q_IPS, [card("1", "data.srcip", "IPs atacantes")])
    k_dst = b.clone(T_METRIC, f"{P} · Destinos internos", Q_IPS, [card("1", "data.dstip", "Destinos")])
    sin_scan = b.setq(b.rename(_by_title(b, "NetSec - Eventos No-Scanner"), f"{P} · Eventos sin scanners",
                               "Excluye Masscan, ZGrab, Censys y Nmap: ruido de Internet que no apunta a nadie."),
                      Q_IPS_SIN_SCAN)
    paises = b.rename(_by_title(b, "Net-Sec-PaisesAtacantes"), f"{P} · Países de origen")
    tl = b.rename(_by_title(b, "Net-Sec-IPsTimeline"), f"{P} · Eventos por severidad (por día)")
    sev = b.rename(_by_title(b, "Net-Sec-IPSSeverityDistribution"), f"{P} · Distribución por severidad")
    dst = b.rename(_by_title(b, "Net-Sec-TopTargetIPs"), f"{P} · Destinos internos más atacados",
                   "192.168.38.62 es Kong (gateway.grupoalemana.com): concentra ~80% de los eventos.")
    firmas = b.rename(_by_title(b, "Net-Sec-Top10TiposAtaques"), f"{P} · Firmas más frecuentes")
    top_ips = b.rename(_by_title(b, "Net-Sec-TopIPsAtacantes"), f"{P} · IPs atacantes (top)")
    acc = b.rename(_by_title(b, "Net-Sec-IPsAcciones"), f"{P} · Acción del FortiGate")
    reales = b.setq(b.rename(_by_title(b, "NetSec - Ataques Reales (sin scanners)"), f"{P} · Ataques reales (sin scanners)"),
                    Q_IPS_SIN_SCAN)
    medalta = b.rename(_by_title(b, "NetSec - Severidad Media-Alta Timeline"), f"{P} · Media, alta y crítica (por día)")
    nota = b.markdown(f"{P} · Cómo leer este tablero", """### Cómo leer este tablero
**Fuente.** Logs UTM/IPS del FortiGate `FG-100F-VEL` por syslog (`data.subtype: ips`), reglas **196xxx**.
Todo lo que aparece acá el FortiGate ya lo **dropeó** inline (`data.action: dropped`).

**Qué pasa con lo que se ve.** SOC-L1 recibe 27 reglas IPS (196201…196230, 196100/196101/196112) y pone la IP origen
en **cuarentena (banned, TTL 1 h)**, abre y cierra ticket y avisa por correo/Teams. Los scanners (Masscan, ZGrab,
Censys, Nmap) se excluyen de los paneles "sin scanners" porque son ruido de Internet sin objetivo.

**Ojo.** ~80% de los eventos apuntan a **192.168.38.62 (Kong)**: el ataque real a la API se mira en *SOC · Kong API
Gateway*. La cuarentena frena sesiones NUEVAS; una conexión ya abierta sigue hasta cortarse (hallazgo 2026-09-27).

*Unificado 2026-09-27 (`wazuh_dashboards/build_unify.py`).*""")
    y = 0
    L = [(total, 0, y, 10, 7), (k_crit, 10, y, 10, 7), (k_ips, 20, y, 9, 7), (k_dst, 29, y, 9, 7), (sin_scan, 38, y, 10, 7)]; y += 7
    L += [(tl, 0, y, 32, 13), (sev, 32, y, 16, 13)]; y += 13
    L += [(top_ips, 0, y, 24, 14), (firmas, 24, y, 24, 14)]; y += 14
    L += [(dst, 0, y, 24, 14), (paises, 24, y, 12, 14), (acc, 36, y, 12, 14)]; y += 14
    L += [(reales, 0, y, 48, 12)]; y += 12
    L += [(medalta, 0, y, 48, 10)]; y += 10
    L += [(nota, 0, y, 48, 9)]
    b.dashboard(D_IPS, "SOC · FortiGate IPS",
                "Eventos IPS del FortiGate: severidad, firmas, IPs atacantes, destinos internos y países. "
                "Paneles 'sin scanners' separan el ruido de Internet. Unificado 2026-09-27.", L, time_from="now-7d")


# ================================================================ VPN =========
def build_vpn(b: Builder) -> None:
    P = "VPN"
    k_pais = b.rename(_by_title(b, "VPN-Gen-Metric-Paises"), f"{P} · Países de origen")
    k_ips = b.setq(b.rename(_by_title(b, "VPN-Gen-Metric-IPsUnicas"), f"{P} · IPs únicas"), Q_VPN_UP)
    k_tot = b.rename(_by_title(b, "VPN-Gen-Metric-TotalConexiones"), f"{P} · Conexiones")
    k_usr = b.rename(_by_title(b, "VPN-Gen-Metric-UsuariosActivos"), f"{P} · Usuarios activos")
    k_fail = b.clone(T_METRIC, f"{P} · Logins fallidos", Q_VPN_FAIL, [count("Logins fallidos")])
    k_ext = b.clone(T_METRIC, f"{P} · Conexiones fuera de Argentina", Q_VPN_UP + ' AND NOT data.srccountry:"Argentina"',
                    [count("Fuera de AR")], desc="Viaje legítimo o credencial compartida: siempre vale una mirada.")
    tipos = b.rename(_by_title(b, "VPN-Gen-TiposTunel"), f"{P} · Tipos de túnel")
    tl = b.rename(_by_title(b, "VPN-Gen-Timeline-Conexiones"), f"{P} · Conexiones por usuario (timeline)")
    pdia = b.rename(_by_title(b, "VPN-Gen-ConexionesPorDia"), f"{P} · Conexiones por día")
    phora = b.rename(_by_title(b, "VPN-Gen-ConexionesPorHora"), f"{P} · Conexiones por hora")
    alertas = b.rename(_by_title(b, "VPN-Gen-AlertasSeguridad"), f"{P} · Alertas de seguridad (FortiGate ≥ 8 y logins fallidos)")
    top20 = b.rename(_by_title(b, "VPN-Gen-Top20Usuarios"), f"{P} · Usuarios con más conexiones")
    tabla = b.rename(_by_title(b, "VPN-Gen-TablaUsuarios"), f"{P} · Usuarios: conexiones, IPs, países, última vez")
    fail_t = b.edit(b.rename(_by_title(b, "VPN - Logins Fallidos SSL"), f"{P} · Logins fallidos por usuario, IP y motivo"),
                    lambda vs: vs["aggs"].append(terms("9", "data.reason", 2, "Motivo"))
                    if not any(a.get("id") == "9" for a in vs["aggs"]) else None)  # idempotente en re-run
    fail_tl = b.edit(b.rename(_by_title(b, "VPN - Logins Fallidos Timeline"), f"{P} · Logins fallidos por día"), a_barras)
    updown = b.rename(_by_title(b, "VPN - Tuneles Up vs Down"), f"{P} · Túneles arriba vs abajo")
    multi_ip = b.setq(b.rename(V_VPN_MULTI_IP, f"{P} · Usuarios con varias IPs de origen"), Q_VPN_UP)
    multi_pais = b.rename(V_VPN_MULTI_PAIS, f"{P} · Usuarios desde varios países")
    ext = b.clone(T_TABLE, f"{P} · Conexiones fuera de Argentina: quién y desde dónde",
                  Q_VPN_UP + ' AND NOT data.srccountry:"Argentina"',
                  [count("Conexiones"), maxdate("5"), terms("2", "data.dstuser", 10, "Usuario"),
                   terms("3", "data.srccountry", 3, "País"), terms("4", "data.remip", 3, "IP")],
                  params={"perPage": 10})
    nota = b.markdown(f"{P} · Cómo leer este tablero", """### Cómo leer este tablero
**Fuente.** Eventos VPN SSL del FortiGate por syslog: `tunnel-up` / `tunnel-down` (reglas 81622/81624) y
`ssl-login-fail` (81614). Usuario en `data.dstuser`, IP pública en `data.remip`, país en `data.srccountry`.

**Qué pasa con lo que se ve.** Las conexiones VPN alimentan el **pipeline de identidad de SOC-L1** (Fase 0):
notificación y respuesta en AD con aprobación. Los logins fallidos son casi todos `permission_denied`: usuario
válido **sin permiso de VPN** (grupo/política), no adivinación de contraseñas; `unknown_user` es el que hay que mirar.

**Ojo.** "Alertas de seguridad" mezcla todo FortiGate de nivel ≥ 8 (incluye IPS), no solo VPN. Las conexiones
desde fuera de Argentina suelen ser viajes; dos países el mismo día para el mismo usuario, no.

*Unificado 2026-09-27 (`wazuh_dashboards/build_unify.py`).*""")
    y = 0
    L = [(k_tot, 0, y, 8, 7), (k_usr, 8, y, 8, 7), (k_ips, 16, y, 8, 7), (k_pais, 24, y, 8, 7), (k_fail, 32, y, 8, 7), (k_ext, 40, y, 8, 7)]; y += 7
    L += [(tl, 0, y, 32, 13), (tipos, 32, y, 16, 13)]; y += 13
    L += [(pdia, 0, y, 24, 12), (phora, 24, y, 24, 12)]; y += 12
    L += [(fail_t, 0, y, 24, 13), (fail_tl, 24, y, 24, 13)]; y += 13
    L += [(ext, 0, y, 24, 13), (multi_pais, 24, y, 12, 13), (multi_ip, 36, y, 12, 13)]; y += 13
    L += [(top20, 0, y, 24, 14), (alertas, 24, y, 24, 14)]; y += 14
    L += [(tabla, 0, y, 48, 24)]; y += 24
    L += [(updown, 0, y, 48, 10)]; y += 10
    L += [(nota, 0, y, 48, 9)]
    b.dashboard(D_VPN, "SOC · FortiGate VPN",
                "VPN SSL del FortiGate: conexiones, usuarios, IPs y países, logins fallidos con motivo, "
                "usuarios con varias IPs/países y conexiones fuera de Argentina. Unificado 2026-09-27.", L, time_from="now-7d")


# ================================================================ WF ==========
def build_wf(b: Builder) -> None:
    P = "WF"
    tl = b.setq(b.rename(_by_title(b, "WF - Bloqueos Timeline"), f"{P} · Bloqueos por categoría por día (81644)"), Q_WF)
    hosts = b.setq(b.rename(_by_title(b, "WF - Top Hosts Origen"), f"{P} · Hosts de origen (con usuario)"), Q_WF)
    users = b.setq(b.rename(_by_title(b, "WF - Top Usuarios"), f"{P} · Usuarios con más bloqueos"), Q_WF)
    doms = b.setq(b.rename(_by_title(b, "WF - Top Dominios Bloqueados"), f"{P} · Dominios bloqueados"), Q_WF)
    perfil = b.setq(b.rename(_by_title(b, "WF - Por Perfil"), f"{P} · Bloqueos por perfil"), Q_WF)
    k_tot = b.clone(T_METRIC, f"{P} · Bloqueos por categoría", Q_WF, [count("Bloqueos (81644)")])
    k_usr = b.clone(T_METRIC, f"{P} · Usuarios afectados", Q_WF, [card("1", "data.dstuser", "Usuarios")])
    k_host = b.clone(T_METRIC, f"{P} · Hosts de origen", Q_WF, [card("1", "data.srcip", "Hosts")])
    k_dom = b.clone(T_METRIC, f"{P} · Dominios distintos", Q_WF, [card("1", "data.hostname", "Dominios")])
    ssl_hdr = hdr(b, P, "🔒 SSL y WAF (regla 81620: no es filtrado por categoría)")
    ssl_tl = b.clone(T_BARS, f"{P} · SSL/WAF por tipo (por día)", Q_SSLWAF,
                     [count("Bloqueos"), por_dia("2"), terms("3", "data.subtype", 3, "Tipo", schema="group")],
                     desc="ssl = anomalía de certificado (certificate-inspection); waf = firma del WAF (WAF_APP_Gateway).")
    ssl_t = b.clone(T_TABLE, f"{P} · SSL/WAF: destino, perfil y origen", Q_SSLWAF,
                    [count("Bloqueos"), card("5", "data.srcip", "Orígenes"), terms("2", "data.hostname", 12, "Destino"),
                     terms("3", "data.subtype", 2, "Tipo"), terms("4", "data.profile", 2, "Perfil")],
                    params={"perPage": 12})
    nota = b.markdown(f"{P} · Cómo leer este tablero", """### Cómo leer este tablero
**Fuente.** Logs UTM del FortiGate por syslog. **81644** = *URL denegada por categoría* (`data.subtype: webfilter`,
perfil `WF_VIP`): es el web filter de verdad, con usuario (`data.dstuser`), host (`data.srcip`) y dominio
(`data.hostname`). **81620** = *URL Blocked by Firewall*, pero en estos logs son **anomalías SSL**
(`certificate-inspection`: certificados inválidos, `www.google.com` incluido) y **firmas WAF** (`WAF_APP_Gateway`),
no categorías. Por eso van en secciones separadas: antes se sumaban y el 70% del "web filter" era SSL.

**Límite.** `data.catdesc` (la categoría) no viene en estos eventos; el dominio es lo más fino que se puede mostrar.

*Unificado 2026-09-27 (`wazuh_dashboards/build_unify.py`).*""")
    y = 0
    L = [(k_tot, 0, y, 12, 7), (k_usr, 12, y, 12, 7), (k_host, 24, y, 12, 7), (k_dom, 36, y, 12, 7)]; y += 7
    L += [(tl, 0, y, 48, 11)]; y += 11
    L += [(doms, 0, y, 24, 14), (users, 24, y, 12, 14), (perfil, 36, y, 12, 14)]; y += 14
    L += [(hosts, 0, y, 48, 12)]; y += 12
    L += [(ssl_hdr, 0, y, 48, 3, True)]; y += 3
    L += [(ssl_tl, 0, y, 24, 12), (ssl_t, 24, y, 24, 12)]; y += 12
    L += [(nota, 0, y, 48, 8)]
    b.dashboard(D_WF, "SOC · FortiGate Web Filter",
                "Web filter del FortiGate: bloqueos por categoría (81644) por usuario, host y dominio; "
                "anomalías SSL y WAF (81620) en sección aparte. Unificado 2026-09-27.", L, time_from="now-7d")


# ================================================================ KONG ========
def build_kong(b: Builder) -> None:
    d = b.objs[D_KONG]
    refs = {r["name"]: r["id"] for r in d["references"]}
    panels = json.loads(d["attributes"]["panelsJSON"])
    ren = {"API - Kong Consumo por Pais": "Kong · Consumo por país (alertas e IPs)",
           "API - Kong Paises (distribucion)": "Kong · Países (distribución)",
           "API - Kong Alertas (URL, IP, método, código)": "Kong · Detalle (URL, IP, método, código)"}
    L = []
    for p in sorted(panels, key=lambda p: (p["gridData"]["y"], p["gridData"]["x"])):
        vid = refs[p["panelRefName"]]
        t = b.objs[vid]["attributes"]["title"]
        if t in ren:
            b.rename(vid, ren[t])
        g = p["gridData"]
        L.append((vid, g["x"], g["y"], g["w"], g["h"]))
    b.dashboard(D_KONG, "SOC · Kong API Gateway", d["attributes"].get("description", ""), L, time_from="now-7d")


# ================================================================ SQL =========
def build_sql(b: Builder) -> None:
    P = "SQL"
    top = b.setq(b.rename(_by_title(b, "SQL Top IPs"), f"{P} · IPs de origen (logons OK y fallidos)"), Q_SQL)
    ok = b.setq(b.rename(_by_title(b, "SQL - Logons Exitosos"), f"{P} · Logons OK por SQL auth (18454)"),
                'data.win.system.eventID:"18454"')
    okw = b.clone(T_METRIC, f"{P} · Logons OK por Windows auth (18453)", 'data.win.system.eventID:"18453"',
                  [count("Logons OK (Windows)")])
    fail = b.setq(b.rename(_by_title(b, "SQL - Logons Fallidos"), f"{P} · Logons fallidos (18456)"),
                  'data.win.system.eventID:"18456"')
    tl = b.setq(b.rename(_by_title(b, "SQL - Logons Timeline"),
                         f"{P} · Logons por día (18454 SQL auth / 18453 Windows / 18456 fallido)"), Q_SQL)
    fail_tl = b.clone(T_BARS, f"{P} · Logons fallidos por día (18456)", Q_SQL_FAIL,
                      [count("Fallidos"), por_dia("2")],
                      desc="Regla 61071. Sigue llegando aunque el auditing de exitosos esté apagado.")
    fail_t = b.clone(T_TABLE, f"{P} · Logons fallidos: cuenta, motivo y cliente", Q_SQL_FAIL,
                     [count("Intentos"), maxdate("3"), terms("2", "data.win.eventdata.data", 15, "Cuenta, motivo, [CLIENTE: ip]")],
                     params={"perPage": 15})
    sa = b.setq(b.rename(_by_title(b, "SQL - Accesos con sa"), f"{P} · Accesos con 'sa' (OK y fallidos, IP cliente)"),
                Q_SQL + " AND data.win.eventdata.data:sa*")
    aviso = b.markdown(f"{P} · § Estado de la fuente", """### ⚠️ Sin logons exitosos desde el 2026-07-27 10:47
`SRVSQLPRODA` **dejó de emitir 18454/18453** (logon exitoso por SQL auth / Windows auth) ese día. Los **fallidos (18456)
siguen llegando**, así que el agente está bien: el *Login auditing* del SQL Server volvió al valor por defecto
(*Failed logins only*) en vez de *Both failed and successful logins* (Propiedades del servidor → Seguridad). Avisar al DBA.

**Por eso, con un rango menor a ~60 días los paneles de exitosos y de `sa` dan 0**: no es un error del tablero, no hay
datos. El rango por defecto es 90 días para que se vea el último período con datos; a partir del 25/10 tampoco alcanza.
Los paneles de **fallidos** sí funcionan con cualquier rango.""")
    nota = b.markdown(f"{P} · Cómo leer este tablero", """### Cómo leer este tablero
**Fuente.** Application log de `SRVSQLPRODA`, proveedor `MSSQLSERVER`. Regla Wazuh **61072** = logon OK
(**18454** SQL auth, **18453** Windows auth) y **61071** = logon fallido (**18456**, trae el motivo). La IP cliente
viene dentro de `data.win.eventdata.data` (`usuario, [CLIENTE: ip]`), por eso los rankings muestran ese campo tal cual.

**Para qué sirve.** Ver quién entra a la base y desde dónde, y quién falla y por qué. El hallazgo de julio: **`sa` era
~78% de los logons**, desde 192.168.38.27 y 10.3.50.36 entre otros. Mala práctica: migrar a cuentas de servicio y
deshabilitar `sa` por red. En los fallidos, `sa` con contraseña inválida desde *local machine* = algo en el propio
servidor con credenciales viejas.

*Unificado 2026-09-27 (`wazuh_dashboards/build_unify.py`).*""")
    y = 0
    L = [(aviso, 0, y, 48, 7, True)]; y += 7
    L += [(ok, 0, y, 8, 8), (okw, 8, y, 8, 8), (fail, 16, y, 8, 8), (tl, 24, y, 24, 8)]; y += 8
    L += [(fail_tl, 0, y, 24, 10), (fail_t, 24, y, 24, 10)]; y += 10
    L += [(top, 0, y, 24, 16), (sa, 24, y, 24, 16)]; y += 16
    L += [(nota, 0, y, 48, 9)]
    b.dashboard(D_SQL, "SOC · SQL Server",
                "Accesos a MS SQL Server (SRVSQLPRODA): logons OK (18454/18453) y fallidos (18456), IPs de origen y uso "
                "de 'sa'. Exitosos SIN DATOS desde 2026-07-27 (login auditing en 'Failed only'). Unificado 2026-09-27.",
                L, time_from="now-90d")


def _by_title(b: Builder, title: str) -> str:
    for k, v in b.objs.items():
        if v.get("type") != "visualization":
            continue
        if v["attributes"]["title"] == title:
            return k
        try:  # re-run contra el vivo: la viz ya fue renombrada, matchea por el título original
            if json.loads(v["attributes"]["visState"]).get("_orig_title") == title:
                return k
        except (ValueError, KeyError):
            pass
    sys.exit(f"ERROR: no encontré la visualización {title!r} en el export")


# ================================================================ main ========
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src")
    ap.add_argument("--import", dest="importar", action="store_true")
    args = ap.parse_args()
    crudo = Path(args.src).read_text(encoding="utf-8") if args.src else exportar_vivo()
    objs = {}
    for linea in crudo.splitlines():
        if linea.strip():
            o = json.loads(linea)
            if "type" in o and "id" in o:
                objs[o["id"]] = o
    # Primer re-run contra un vivo ya unificado (27/09) que todavía no guarda _orig_title:
    # se siembra desde el export previo a la unificación (los ids renombrados son los mismos).
    pre = BASE / "original" / "export_all_pre_unify_20260927.ndjson"
    if pre.exists():
        sembrados = 0
        for linea in pre.read_text(encoding="utf-8").splitlines():
            if not linea.strip():
                continue
            o = json.loads(linea)
            if o.get("type") != "visualization" or o["id"] not in objs:
                continue
            vivo = objs[o["id"]]
            try:
                vs = json.loads(vivo["attributes"]["visState"])
            except (ValueError, KeyError):
                continue
            if "_orig_title" not in vs and vivo["attributes"]["title"] != o["attributes"]["title"]:
                vs["_orig_title"] = o["attributes"]["title"]
                vivo["attributes"]["visState"] = json.dumps(vs, ensure_ascii=False)
                sembrados += 1
        if sembrados:
            print(f"títulos originales sembrados desde {pre.name}: {sembrados}")
    b = Builder(objs)
    build_ad(b); build_ips(b); build_vpn(b); build_wf(b); build_kong(b); build_sql(b)

    # sanity: ningún dashboard referencia una viz que no salga en el archivo o no exista
    for o in b.out.values():
        if o["type"] == "dashboard":
            for r in o["references"]:
                assert r["id"] in b.out or r["id"] in objs, (o["attributes"]["title"], r["id"])
    DST.parent.mkdir(exist_ok=True)
    with open(DST, "w", encoding="utf-8") as fh:
        for o in b.out.values():
            fh.write(json.dumps(o, ensure_ascii=False) + "\n")
        fh.write(json.dumps({"exportedCount": len(b.out)}) + "\n")
    nd = sum(1 for o in b.out.values() if o["type"] == "dashboard")
    nv = len(b.out) - nd
    nuevas = sum(1 for k in b.out if k not in objs)
    print(f"OK: {DST}  ({nd} dashboards, {nv} visualizaciones: {nv - nuevas} editadas, {nuevas} nuevas)")
    for o in b.out.values():
        if o["type"] == "dashboard":
            print(f"   {o['attributes']['title']:<32} paneles={len(o['references'])} rango={o['attributes']['timeFrom']}")

    if not args.importar:
        print("Para importar: python3 build_unify.py --import")
        return 0
    out = curl(["-F", f"file=@{DST}", f"{DASHBOARD_URL}/api/saved_objects/_import?overwrite=true"])
    r = json.loads(out)
    print(f"import: success={r.get('success')} count={r.get('successCount')} errors={r.get('errors', [])[:3]}")
    if not r.get("success"):
        return 1
    borradas = 0
    for vid in HUERFANAS_BORRAR:
        if vid in objs:
            out = curl(["-X", "DELETE", f"{DASHBOARD_URL}/api/saved_objects/visualization/{vid}"])
            borradas += 1 if out.strip() in ("", "{}") else 0
    print(f"huérfanas borradas: {borradas}/{len(HUERFANAS_BORRAR)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
