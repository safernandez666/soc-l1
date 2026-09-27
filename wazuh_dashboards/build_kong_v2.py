#!/usr/bin/env python3
"""Rearma el dashboard de Wazuh "Kong API Gateway Monitoring" (v2, 2026-09-27).

    python3 build_kong_v2.py            # exporta el vivo, construye improved/kong_v2.ndjson
    python3 build_kong_v2.py --import   # ademas lo importa (overwrite=true)
    python3 build_kong_v2.py --src archivo.ndjson   # construye sobre un export dado

POR QUE
-------
El dashboard tenia un panel "Kong - Aviso sin datos" (jul/2026) que decia que Wazuh no
recibia nada de Kong. Era cierto entonces (el syslog estuvo cortado dic-2025 → ago-2026)
y es FALSO ahora: al 2026-09-27 hay ~24.000 alertas de Kong en 30 dias, de 1.783 IPs
distintas, y la regla de enumeracion 100207 ya dispara el bloqueo automatico en
FortiGate via SOC-L1. Ademas, los paneles contaban "requests" mezclando los eventos
de acceso con las alertas de correlacion (100207 suma una alerta cada 10 404 de la
misma IP), y no habia ninguna vista de QUIEN ataca ni de que busca.

QUE CAMBIA
----------
- Se elimina el aviso falso; en su lugar va una nota de "como leer este tablero" con
  la cadena real (Kong → syslog → decoder → reglas → SOC-L1 → FortiGate).
- KPIs arriba: requests, IPs distintas, ataques detectados, IPs atacantes, 401, 429.
  "Requests" excluye las reglas de correlacion (100204/100207/100211/100240/100241)
  para que cuente eventos de acceso y no alertas derivadas.
- Timelines en barras por dia: requests por codigo HTTP, y ataques por regla.
- Tabla "IPs atacantes": IP, pais, alertas y ultimo visto. Es la lista de lo que
  SOC-L1 manda a cuarentena (100207) y de lo que hoy NO se rutea (100204/100240/100241).
- "Rutas buscadas con 404": que buscan los scanners (/.env, /.git/config, ...).
- "Uso legitimo (2xx) por ruta": el trafico con API key valida, separado del ruido.
- Se conservan las vistas de paises (build_kong_geo.py) y la tabla de detalle.

Las visualizaciones EXISTENTES se editan en su lugar (mismo id) para que otros
dashboards o links guardados no se rompan; las nuevas se crean con uuid4. Antes de
construir se exporta el dashboard vivo y se guarda copia en original/ para volver atras:

    curl -sk -u $OPENSEARCH_USER:$OPENSEARCH_PASS -H 'osd-xsrf: true' \
      -F file=@original/kong_pre_v2_<fecha>.ndjson \
      'https://127.0.0.1:443/api/saved_objects/_import?overwrite=true'

Requiere OPENSEARCH_USER / OPENSEARCH_PASS en el entorno (o ~/scripts/ia/.env).
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
DST_DIR = BASE / "improved"
DST_DIR.mkdir(exist_ok=True)
DST = DST_DIR / "kong_v2.ndjson"
ORIG_DIR = BASE / "original"

KONG_DASH_ID = "55101f30-b526-11f0-b4ab-f10742cb3085"
DASHBOARD_URL = os.getenv("WAZUH_DASHBOARD_URL", "https://127.0.0.1:443")
ENV_FILE = os.path.expanduser("~/scripts/ia/.env")
GRAFANA_URL = "http://192.168.38.62:3000/d/kong-alemana/kong-alemana"

# Reglas de correlacion: una alerta cada N eventos, NO son requests.
CORRELACION = "100204 OR 100207 OR 100211 OR 100240 OR 100241"
Q_KONG = "rule.groups: kong"
Q_REQUESTS = f"rule.groups: kong AND NOT rule.id: ({CORRELACION})"
Q_ATAQUES = "rule.groups: kong AND rule.groups: attack"

# ids de las visualizaciones que ya existen y se editan en su lugar
V_TOTAL = "dcce19b0-b524-11f0-b4ab-f10742cb3085"      # metric  Total Kong Requests
V_RATELIMIT = "19a31bf0-b526-11f0-b4ab-f10742cb3085"  # metric  Rate Limit Hits
V_SECURITY = "c0aa9eb0-b525-11f0-b4ab-f10742cb3085"   # metric  Security Alerts
V_TIMELINE = "1ba76ce0-b525-11f0-b4ab-f10742cb3085"   # line    Requests Timeline
V_CODES_PIE = "fcd51b00-b524-11f0-b4ab-f10742cb3085"  # pie     Status Codes
V_METHODS = "732f6a30-b525-11f0-b4ab-f10742cb3085"    # histo   HTTP Methods
V_ERRORS = "01070f70-b526-11f0-b4ab-f10742cb3085"     # area    Errors 4xx vs 5xx
V_TOP_URLS = "9e6b3990-b525-11f0-b4ab-f10742cb3085"   # table   Top URLs
V_TOP_IPS = "44386790-b525-11f0-b4ab-f10742cb3085"    # table   Top Source IPs
V_AUTH_TL = "331a4630-b526-11f0-b4ab-f10742cb3085"    # line    Auth Failures Timeline
V_AVISO = "bebd1076-9c0d-4670-b8f0-68ae7aeff267"      # markdown Aviso sin datos (FALSO)
V_DETALLE = "3e548009-9e06-4206-8e04-9cf656293830"    # table   URL, IP, metodo, codigo
V_PAIS_TABLA = "d74a763c-2531-46d6-ba18-61aea3690533"  # table  Consumo por pais
V_PAIS_PIE = "6cc88125-4d87-4497-b833-e2c7d8d0f3d4"   # pie     Paises


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


def curl(args: list[str]) -> str:
    u, p = credenciales()
    r = subprocess.run(["curl", "-sk", "-u", f"{u}:{p}", "-H", "osd-xsrf: true", *args],
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0 or not r.stdout.strip():
        sys.exit(f"ERROR curl: {r.stderr[:300]}")
    return r.stdout


def exportar_vivo() -> str:
    cuerpo = json.dumps({"objects": [{"type": "dashboard", "id": KONG_DASH_ID}],
                         "includeReferencesDeep": True})
    out = curl(["-X", "POST", f"{DASHBOARD_URL}/api/saved_objects/_export",
                "-H", "Content-Type: application/json", "-d", cuerpo])
    if '"error"' in out[:200] and '"attributes"' not in out[:200]:
        sys.exit(f"ERROR del API: {out[:300]}")
    ORIG_DIR.mkdir(exist_ok=True)
    bak = ORIG_DIR / f"kong_pre_v2_{dt.date.today():%Y%m%d}.ndjson"
    if not bak.exists():
        bak.write_text(out, encoding="utf-8")
        print(f"backup del vivo: {bak}")
    return out


# ----------------------------------------------------------------- helpers ----
def count(label: str) -> dict:
    return {"id": "1", "enabled": True, "type": "count", "schema": "metric",
            "params": {"customLabel": label}}


def cardinality(agg_id: str, campo: str, label: str) -> dict:
    return {"id": agg_id, "enabled": True, "type": "cardinality", "schema": "metric",
            "params": {"field": campo, "customLabel": label}}


def maxdate(agg_id: str, label: str) -> dict:
    return {"id": agg_id, "enabled": True, "type": "max", "schema": "metric",
            "params": {"field": "timestamp", "customLabel": label}}


def terms(agg_id: str, campo: str, size: int, label: str, schema: str = "bucket",
          other: bool = False) -> dict:
    return {"id": agg_id, "enabled": True, "type": "terms", "schema": schema,
            "params": {"field": campo, "orderBy": "1", "order": "desc", "size": size,
                       "otherBucket": other, "otherBucketLabel": "Otros",
                       "missingBucket": False, "missingBucketLabel": "Sin dato",
                       "customLabel": label}}


def por_dia(agg_id: str = "2") -> dict:
    return {"id": agg_id, "enabled": True, "type": "date_histogram", "schema": "segment",
            "params": {"field": "timestamp", "timeRange": {"from": "now-7d", "to": "now"},
                       "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                       "interval": "d", "drop_partials": False, "min_doc_count": 1,
                       "extended_bounds": {}, "customLabel": "Día"}}


def set_query(vis: dict, query: str) -> None:
    ss = json.loads(vis["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
    ss["query"] = {"query": query, "language": "kuery"}
    vis["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"] = json.dumps(ss)


def set_state(vis: dict, title: str, vs: dict, description: str = "") -> None:
    vs["title"] = title
    vis["attributes"]["title"] = title
    vis["attributes"]["description"] = description
    vis["attributes"]["visState"] = json.dumps(vs, ensure_ascii=False)


def state(vis: dict) -> dict:
    return json.loads(vis["attributes"]["visState"])


def clonar(tpl: dict) -> dict:
    nuevo = copy.deepcopy(tpl)
    nuevo["id"] = str(uuid.uuid4())
    nuevo.pop("version", None)
    nuevo.pop("updated_at", None)
    return nuevo


def a_barras(vs: dict, stacked: bool = True) -> dict:
    """Convierte un line/area de vislib en histograma (barras). Los timelines por dia
    se leen mejor en barras: una linea entre 30 puntos diarios sugiere continuidad
    que no existe y esconde los dias en cero."""
    vs["type"] = "histogram"
    vs["params"]["type"] = "histogram"
    for sp in vs["params"].get("seriesParams", []):
        sp["type"] = "histogram"
        sp["mode"] = "stacked" if stacked else "normal"
        sp.pop("interpolate", None)
    vs["params"]["legendPosition"] = "right"
    return vs


NOTA_MD = f"""### Cómo leer este tablero

**De dónde salen los datos.** Kong (Docker en `seg-vs85-prod02`, 192.168.38.62) manda su log de
acceso por **syslog UDP 514** al manager de Wazuh. El decoder `kong-decoder` saca **IP origen, método,
ruta y código HTTP**; las reglas **100200–100241** clasifican cada request y correlacionan ataques:
**100207** = 10 × 404 de la misma IP en 2 min (enumeración) · **100204** = 5 × 401 en 1 min (fuerza bruta)
· **100241** = 20 requests en 1 min · **100240** = 10 × 4xx en 1 min · **100222** = DELETE.

**Qué pasa con lo que se ve acá.** La regla **100207 está ruteada a SOC-L1** (desde el 2026-09-22):
cada disparo pone la IP en **cuarentena en el FortiGate (banned, TTL 1 h)**, abre y cierra ticket
en InvGate y avisa por correo y Teams. **100204 / 100240 / 100241 solo alertan**, no bloquean.

**Lo que este tablero NO ve.** Solo llegan alertas de nivel ≥ 3 (todas las de Kong lo son). El decoder
no extrae user-agent ni Host: para eso está el **log de acceso crudo en Grafana** →
[{GRAFANA_URL}]({GRAFANA_URL}) (sección *¿Qué le está pegando?*, filtrable por IP).

**Cifras.** "Requests" excluye las alertas de correlación para contar eventos de acceso reales.
"Ataques detectados" cuenta disparos de las reglas de correlación (un disparo = un lote de requests).

*Rearmado 2026-09-27 (`wazuh_dashboards/build_kong_v2.py`). El aviso "Sin datos" de julio quedó
obsoleto: el syslog de Kong se restableció el 2026-08-26.*
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src", help="ndjson ya exportado (por defecto exporta el vivo)")
    ap.add_argument("--import", dest="importar", action="store_true",
                    help="importa el resultado con overwrite=true")
    args = ap.parse_args()

    crudo = Path(args.src).read_text(encoding="utf-8") if args.src else exportar_vivo()
    objs: dict[str, dict] = {}
    for linea in crudo.splitlines():
        linea = linea.strip()
        if linea:
            o = json.loads(linea)
            if "type" in o and "id" in o:
                objs[o["id"]] = o
    faltan = [v for v in (V_TOTAL, V_RATELIMIT, V_SECURITY, V_TIMELINE, V_CODES_PIE, V_METHODS,
                          V_ERRORS, V_TOP_URLS, V_TOP_IPS, V_AUTH_TL, V_AVISO, V_DETALLE,
                          V_PAIS_TABLA, V_PAIS_PIE, KONG_DASH_ID) if v not in objs]
    if faltan:
        sys.exit(f"ERROR: el export no trae {faltan}")
    dash = objs[KONG_DASH_ID]

    salida: list[dict] = []          # visualizaciones a escribir (editadas + nuevas)
    layout: list[tuple[str, int, int, int, int]] = []   # (vis_id, x, y, w, h)

    def usar(vis: dict, x: int, y: int, w: int, h: int) -> None:
        salida.append(vis)
        layout.append((vis["id"], x, y, w, h))

    # ------------------------------------------------------ fila 0: KPIs (h=7) --
    y = 0
    v = objs[V_TOTAL]
    vs = state(v)
    vs["aggs"] = [count("Requests (eventos de acceso)")]
    set_query(v, Q_REQUESTS)
    set_state(v, "Kong · Requests", vs,
              "Eventos de acceso vistos por Wazuh. Excluye las reglas de correlación "
              "(100204/100207/100211/100240/100241), que no son requests.")
    usar(v, 0, y, 8, 7)

    v = clonar(objs[V_TOTAL])
    vs = state(v)
    vs["aggs"] = [cardinality("1", "data.srcip", "IPs distintas")]
    set_query(v, Q_REQUESTS)
    set_state(v, "Kong · IPs distintas", vs, "Cardinalidad de data.srcip (aproximada).")
    usar(v, 8, y, 8, 7)

    v = objs[V_SECURITY]
    vs = state(v)
    vs["aggs"] = [count("Ataques detectados")]
    set_query(v, Q_ATAQUES)
    set_state(v, "Kong · Ataques detectados", vs,
              "Disparos de las reglas de correlación (grupo attack): 100207 enumeración, "
              "100204 fuerza bruta, 100240 múltiples 4xx, 100241 alta frecuencia.")
    usar(v, 16, y, 8, 7)

    v = clonar(objs[V_SECURITY])
    vs = state(v)
    vs["aggs"] = [cardinality("1", "data.srcip", "IPs atacantes")]
    set_query(v, Q_ATAQUES)
    set_state(v, "Kong · IPs atacantes", vs, "IPs distintas con al menos un ataque detectado.")
    usar(v, 24, y, 8, 7)

    v = clonar(objs[V_RATELIMIT])
    vs = state(v)
    vs["aggs"] = [count("401 sin API key")]
    set_query(v, "rule.id: 100203")
    set_state(v, "Kong · 401 (auth fallida)", vs,
              "Requests rechazados por key-auth. Muchos 401 de una misma IP = 100204.")
    usar(v, 32, y, 8, 7)

    v = objs[V_RATELIMIT]
    vs = state(v)
    vs["aggs"] = [count("429 rate-limit")]
    set_query(v, "rule.id: 100208")
    set_state(v, "Kong · 429 (rate-limit)", vs,
              "El plugin rate-limiting cortando. Si siempre es 0, el límite está alto.")
    usar(v, 40, y, 8, 7)
    y += 7

    # -------------------------------------------- fila 1: timelines por dia (h=12) --
    v = objs[V_TIMELINE]
    vs = a_barras(state(v))
    vs["aggs"] = [count("Requests"), por_dia("2"),
                  terms("3", "data.id", 6, "Código HTTP", schema="group", other=True)]
    set_query(v, Q_REQUESTS)
    set_state(v, "Kong · Requests por código HTTP (por día)", vs,
              "Barras apiladas por código de respuesta. 404 = ruta inexistente (scanners), "
              "401 = sin API key, 200 = uso legítimo.")
    usar(v, 0, y, 24, 12)

    v = objs[V_ERRORS]
    vs = a_barras(state(v))
    vs["aggs"] = [count("Ataques"), por_dia("2"),
                  terms("3", "rule.id", 6, "Regla", schema="group")]
    set_query(v, Q_ATAQUES)
    set_state(v, "Kong · Ataques detectados por regla (por día)", vs,
              "100207 enumeración (bloquea en FortiGate vía SOC-L1) · 100204 fuerza bruta · "
              "100240 múltiples 4xx · 100241 alta frecuencia.")
    usar(v, 24, y, 24, 12)
    y += 12

    # ------------------------------------- fila 2: quien ataca / que buscan (h=15) --
    v = objs[V_TOP_IPS]
    vs = state(v)
    vs["aggs"] = [count("Alertas de ataque"), maxdate("4", "Último visto"),
                  terms("2", "data.srcip", 15, "IP atacante"),
                  terms("3", "GeoLocation.country_name", 1, "País")]
    vs["params"]["perPage"] = 15
    set_query(v, Q_ATAQUES)
    set_state(v, "Kong · IPs atacantes (qué bloquea SOC-L1)", vs,
              "IPs con reglas de correlación disparadas. Las de 100207 van a cuarentena "
              "FortiGate (TTL 1 h) automáticamente; el resto solo alerta.")
    usar(v, 0, y, 24, 15)

    v = objs[V_TOP_URLS]
    vs = state(v)
    vs["aggs"] = [count("404"), cardinality("3", "data.srcip", "IPs"),
                  terms("2", "data.url", 15, "Ruta buscada")]
    vs["params"]["perPage"] = 15
    set_query(v, "rule.groups: kong AND data.id: 404")
    set_state(v, "Kong · Rutas buscadas con 404 (qué buscan los scanners)", vs,
              "/.env, /.git/config, /wp-login.php... Ninguna existe en el gateway: "
              "que aparezcan es enumeración, no uso.")
    usar(v, 24, y, 24, 15)
    y += 15

    # --------------------------------------------- fila 3: paises (se conservan) --
    # Solo el nombre, para respetar la convencion "Kong · ..." de build_unify.py.
    v = objs[V_PAIS_TABLA]; vs = state(v)
    set_state(v, "Kong · Consumo por país (alertas e IPs)", vs)
    usar(v, 0, y, 24, 14)
    v = objs[V_PAIS_PIE]; vs = state(v)
    set_state(v, "Kong · Países (distribución)", vs)
    usar(v, 24, y, 24, 14)
    y += 14

    # ------------------------------------- fila 4: legitimo vs ruido (h=12) --
    v = clonar(objs[V_TOP_URLS])
    vs = state(v)
    vs["aggs"] = [count("Requests 2xx"), cardinality("4", "data.srcip", "IPs"),
                  terms("2", "data.url", 10, "Ruta"), terms("3", "data.protocol", 3, "Método")]
    vs["params"]["perPage"] = 10
    set_query(v, "rule.groups: kong AND data.id: 2*")
    set_state(v, "Kong · Uso legítimo (2xx) por ruta", vs,
              "Lo que pasó el key-auth y llegó al backend. Es la parte del tráfico que "
              "importa para capacidad y para detectar abuso con credenciales válidas.")
    usar(v, 0, y, 24, 12)

    v = objs[V_CODES_PIE]
    vs = state(v)
    vs["aggs"] = [count("Requests"), terms("2", "data.id", 10, "Código HTTP", schema="segment")]
    set_query(v, Q_REQUESTS)
    set_state(v, "Kong · Distribución de códigos HTTP", vs)
    usar(v, 24, y, 12, 12)

    v = objs[V_METHODS]
    vs = state(v)
    for a in vs["aggs"]:
        if a["type"] == "terms":
            a["params"]["customLabel"] = "Método"
            a["params"]["size"] = 8
    set_query(v, Q_REQUESTS)
    set_state(v, "Kong · Métodos HTTP", vs,
              "DELETE/PUT/PROPFIND desde Internet contra un gateway de solo lectura "
              "son sondeos (regla 100222 para DELETE).")
    usar(v, 36, y, 12, 12)
    y += 12

    # --------------------------------------------- fila 5: auth + detalle --
    v = objs[V_AUTH_TL]
    vs = a_barras(state(v))
    vs["aggs"] = [count("401 / fuerza bruta"), por_dia("2"),
                  terms("3", "rule.id", 2, "Regla", schema="group")]
    set_query(v, "rule.id: 100203 OR rule.id: 100204")
    set_state(v, "Kong · Fallos de autenticación (por día)", vs,
              "100203 = un 401 · 100204 = 5 × 401 de la misma IP en 1 min.")
    usar(v, 0, y, 24, 12)

    v = clonar(objs[V_TOP_IPS])
    vs = state(v)
    vs["aggs"] = [count("Requests"), maxdate("4", "Último visto"),
                  terms("2", "data.srcip", 10, "IP"),
                  terms("3", "GeoLocation.country_name", 1, "País")]
    vs["params"]["perPage"] = 10
    set_query(v, Q_REQUESTS)
    set_state(v, "Kong · Top IPs por volumen", vs,
              "Todas las IPs, ataquen o no. Una IP con mucho volumen y 2xx es un cliente; "
              "con mucho volumen y 404 es un scanner que la 100207 debería haber tomado.")
    usar(v, 24, y, 24, 12)
    y += 12

    v = objs[V_DETALLE]; vs = state(v)
    set_state(v, "Kong · Detalle (URL, IP, método, código)", vs)
    usar(v, 0, y, 48, 14)
    y += 14

    # ----------------------------------------------------- pie: nota (reemplaza el aviso) --
    v = objs[V_AVISO]
    vs = state(v)
    vs["params"]["markdown"] = NOTA_MD
    vs["params"]["fontSize"] = 12
    set_state(v, "Kong · Cómo leer este tablero", vs)
    usar(v, 0, y, 48, 11)
    y += 11

    # ---------------------------------------------------------------- dashboard --
    version = json.loads(dash["attributes"]["panelsJSON"])[0]["version"]
    panels, refs = [], []
    for i, (vid, x, py, w, h) in enumerate(layout):
        pid = str(uuid.uuid4())
        panels.append({"version": version,
                       "gridData": {"x": x, "y": py, "w": w, "h": h, "i": pid},
                       "panelIndex": pid, "embeddableConfig": {}, "panelRefName": f"panel_{i}"})
        refs.append({"id": vid, "name": f"panel_{i}", "type": "visualization"})
    dash["attributes"]["panelsJSON"] = json.dumps(panels, ensure_ascii=False)
    dash["attributes"]["title"] = "SOC · Kong API Gateway"   # convencion de build_unify.py
    dash["attributes"]["description"] = (
        "Tráfico y ataques contra gateway.grupoalemana.com vistos por Wazuh (reglas 100200-100241). "
        "100207 bloquea en FortiGate vía SOC-L1. Rearmado 2026-09-27.")
    dash["attributes"]["timeFrom"] = "now-7d"
    dash["attributes"]["timeTo"] = "now"
    dash["attributes"]["timeRestore"] = True
    dash["references"] = refs
    dash.pop("version", None)
    dash.pop("updated_at", None)

    with open(DST, "w", encoding="utf-8") as fh:
        for viz in salida:
            fh.write(json.dumps(viz, ensure_ascii=False) + "\n")
        fh.write(json.dumps(dash, ensure_ascii=False) + "\n")
        fh.write(json.dumps({"exportedCount": len(salida) + 1}) + "\n")
    editadas = sum(1 for v in salida if v["id"] in objs)
    print(f"OK: {DST}  ({len(salida)} visualizaciones: {editadas} editadas, "
          f"{len(salida) - editadas} nuevas; {len(panels)} paneles, alto {y})")

    if args.importar:
        out = curl(["-F", f"file=@{DST}",
                    f"{DASHBOARD_URL}/api/saved_objects/_import?overwrite=true"])
        try:
            r = json.loads(out)
        except json.JSONDecodeError:
            sys.exit(f"ERROR import: {out[:300]}")
        print(f"import: success={r.get('success')} count={r.get('successCount')} "
              f"errors={r.get('errors', [])[:3]}")
        return 0 if r.get("success") else 1
    print("Para importar: python3 build_kong_v2.py --import")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
