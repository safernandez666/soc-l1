#!/usr/bin/env python3
"""Rearma el dashboard de Grafana "Kong Alemana" ordenado para un administrador.

    python3 build_kong_dashboard.py                 # escribe kong-alemana.json
    python3 build_kong_dashboard.py --push          # ademas lo sube por API
    GRAFANA_URL=... GRAFANA_USER=... GRAFANA_PASS=... python3 build_kong_dashboard.py --push

POR QUE SE REARMA
-----------------
El dashboard que habia (43 paneles, uid kong-alemana) era el oficial de Kong
importado tal cual MAS una fila "POC - Metricas clave" pegada encima que repetia lo
mismo: 15 queries distintas de RPS, 30 de percentiles de latencia, 5 de bandwidth.
Para responder "esta sano?" habia que mirar en dos lugares y elegir cual creer.

EL ORDEN: las preguntas que hace un administrador, en el orden en que las hace
-----------------------------------------------------------------------------
  1. Esta vivo?      -> fila de estado, siempre arriba, sin scroll
  2. Esta sano?      -> errores, y sobre todo DE QUIEN es la culpa (Kong o upstream)
  3. Esta rapido?    -> latencia, y donde se va el tiempo
  4. Quien lo usa?   -> trafico por servicio/ruta
  5. Va a aguantar?  -> capacidad: memoria, conexiones, timers
  6. Los upstreams?  -> health checks

El panel que mas valor agrega y no estaba: **errores por `source`**. Kong etiqueta
cada request con source=kong (lo respondio el gateway: auth, rate-limit, ruta
inexistente) o source=service (lo respondio el backend). Un 401 con source=kong es
key-auth funcionando bien; un 500 con source=service es el backend caido. Sin ese
corte, "% de error" mezcla las dos cosas y no se puede accionar.

LIMITE IMPORTANTE (leer antes de sacar conclusiones del dashboard)
------------------------------------------------------------------
El plugin de Prometheus NO esta viendo el trafico de Internet. Comprobado el
2026-09-21 contra la API de Prometheus: en 30 dias hay 49 requests, todos de
`httpbin-service` y `admin-api` (los servicios de prueba de la POC), y **cero 404
historicos**. Mientras tanto Wazuh registra 2.041 alertas de enumeracion (regla
100207) y 23.157 de 404 en el mismo periodo, desde 71 IPs distintas.

O sea: lo que entra por `gateway.grupoalemana.com` no queda instrumentado. Hasta que
el plugin de Prometheus se habilite de forma global, este dashboard describe la POC,
no el gateway publicado. Los paneles de seguridad de verdad viven hoy en el dashboard
de OpenSearch "Kong API Gateway Monitoring" (ver wazuh_dashboards/build_kong_geo.py).

Retencion de Prometheus: 15 dias (`storageRetention`). Cualquier rango mayor sale
vacio; por eso el dashboard arranca en 6h y el selector no ofrece mas de 7d.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

UID = "kong-alemana"
DS = {"type": "prometheus", "uid": "prometheus"}

# Paleta: verde para lo bueno, ambar para lo que hay que mirar, rojo para lo roto.
VERDE, AMBAR, ROJO, AZUL = "green", "orange", "red", "blue"

_id = 0


def nid() -> int:
    global _id
    _id += 1
    return _id


def target(expr: str, legend: str = "", instant: bool = False) -> dict:
    return {
        "datasource": DS,
        "expr": expr,
        "legendFormat": legend or "__auto",
        "refId": chr(65 + (nid() % 26)),
        "instant": instant,
        "range": not instant,
    }


def row(title: str, y: int, collapsed: bool = False) -> dict:
    return {
        "type": "row", "title": title, "id": nid(), "collapsed": collapsed,
        "gridPos": {"h": 1, "w": 24, "x": 0, "y": y}, "panels": [],
    }


def stat(title: str, expr: str, x: int, y: int, w: int = 4, h: int = 4, *,
         unit: str = "short", decimals: int | None = None,
         thresholds: list | None = None, mappings: list | None = None,
         desc: str = "") -> dict:
    return {
        "type": "stat", "title": title, "id": nid(), "datasource": DS,
        "description": desc,
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "targets": [target(expr, instant=True)],
        "options": {
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "textMode": "auto", "colorMode": "value", "graphMode": "area",
            "justifyMode": "auto",
        },
        "fieldConfig": {
            "defaults": {
                "unit": unit, "decimals": decimals,
                "mappings": mappings or [],
                "thresholds": {
                    "mode": "absolute",
                    "steps": thresholds or [{"color": VERDE, "value": None}],
                },
            },
            "overrides": [],
        },
    }


def ts(title: str, targets: list[dict], x: int, y: int, w: int = 12, h: int = 8, *,
       unit: str = "short", desc: str = "", stack: bool = False,
       legend_bottom: bool = True, min_: float | None = 0) -> dict:
    return {
        "type": "timeseries", "title": title, "id": nid(), "datasource": DS,
        "description": desc,
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "targets": targets,
        "options": {
            "legend": {
                "displayMode": "table" if not legend_bottom else "list",
                "placement": "bottom", "showLegend": True,
                "calcs": ["mean", "max"] if not legend_bottom else [],
            },
            "tooltip": {"mode": "multi", "sort": "desc"},
        },
        "fieldConfig": {
            "defaults": {
                "unit": unit, "min": min_,
                "custom": {
                    "drawStyle": "line", "lineWidth": 2, "fillOpacity": 12 if not stack else 40,
                    "showPoints": "never", "spanNulls": True,
                    "stacking": {"mode": "normal" if stack else "none", "group": "A"},
                },
                "thresholds": {"mode": "absolute", "steps": [{"color": VERDE, "value": None}]},
            },
            "overrides": [],
        },
    }


def table(title: str, targets: list[dict], x: int, y: int, w: int = 12, h: int = 8, *,
          desc: str = "", overrides: list | None = None, transformations: list | None = None) -> dict:
    return {
        "type": "table", "title": title, "id": nid(), "datasource": DS,
        "description": desc,
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "targets": targets,
        "transformations": transformations or [],
        "options": {"showHeader": True, "cellHeight": "sm",
                    "footer": {"show": False, "reducer": ["sum"]}},
        "fieldConfig": {
            "defaults": {"custom": {"align": "auto", "filterable": True}},
            "overrides": overrides or [],
        },
    }


def bargauge(title: str, targets: list[dict], x: int, y: int, w: int = 12, h: int = 8, *,
             unit: str = "short", decimals: int | None = 0, desc: str = "",
             thresholds: list | None = None) -> dict:
    """Ranking horizontal. Se usa donde antes habia tablas.

    Por que no una tabla: Prometheus devuelve por la API frames `numeric-multi`, un
    frame por serie con los labels colgados del campo Value. El panel Table no los
    convierte en columnas solo: hace falta encadenar labelsToFields + merge + organize,
    y cualquier cambio en los labels lo desarma en silencio. Un bargauge consume esas
    series tal cual, usa legendFormat para el nombre de la fila y ademas ORDENA visual-
    mente, que es lo unico que se le pide a un top-N. Las queries llevan topk() para que
    no crezca sin limite.
    """
    return {
        "type": "bargauge", "title": title, "id": nid(), "datasource": DS,
        "description": desc,
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "targets": targets,
        "options": {
            "orientation": "horizontal", "displayMode": "gradient",
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "showUnfilled": True, "valueMode": "color",
            "minVizWidth": 8, "minVizHeight": 12, "maxVizHeight": 300,
            "namePlacement": "left", "sizing": "auto",
        },
        "fieldConfig": {
            "defaults": {
                "unit": unit, "decimals": decimals, "min": 0,
                "thresholds": {"mode": "absolute",
                               "steps": thresholds or [{"color": AZUL, "value": None}]},
            },
            "overrides": [],
        },
    }


def texto(title: str, md: str, x: int, y: int, w: int = 24, h: int = 4) -> dict:
    return {
        "type": "text", "title": title, "id": nid(),
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "options": {"mode": "markdown", "content": md},
    }


def build() -> dict:
    P: list[dict] = []
    y = 0

    # ---------------------------------------------------------------- 1. vivo --
    # Sin row: la primera pantalla no se colapsa ni se scrollea.
    P.append(stat(
        "Kong", 'up{job="kong"}', 0, y, w=3,
        mappings=[{"type": "value", "options": {
            "0": {"text": "CAIDO", "color": ROJO, "index": 0},
            "1": {"text": "ARRIBA", "color": VERDE, "index": 1}}}],
        desc="Prometheus alcanza el endpoint de metricas de Kong (:8100).",
    ))
    P.append(stat(
        "Datastore", "kong_datastore_reachable", 3, y, w=3,
        mappings=[{"type": "value", "options": {
            "0": {"text": "NO", "color": ROJO, "index": 0},
            "1": {"text": "OK", "color": VERDE, "index": 1}}}],
        desc="Kong llega a Postgres. En NO, Kong sirve con la config cacheada "
             "pero no toma cambios nuevos.",
    ))
    P.append(stat(
        "RPS (5m)", "sum(rate(kong_http_requests_total[5m])) or vector(0)", 6, y, w=3,
        unit="reqps", decimals=2,
    ))
    P.append(stat(
        "Error 5xx (5m)",
        '100 * (sum(rate(kong_http_requests_total{code=~"5.."}[5m])) or vector(0)) '
        '/ clamp_min(sum(rate(kong_http_requests_total[5m])) or vector(0), 0.001)',
        9, y, w=3, unit="percent", decimals=2,
        thresholds=[{"color": VERDE, "value": None},
                    {"color": AMBAR, "value": 1},
                    {"color": ROJO, "value": 5}],
        desc="`or vector(0)` porque sum() sobre un vector vacio devuelve VACIO, no 0: "
             "sin eso el panel dice 'No data' cuando en realidad hay 0% de error, que "
             "es justo lo contrario. clamp_min evita el 0/0.",
    ))
    P.append(stat(
        "p99 latencia (5m)",
        "histogram_quantile(0.99, sum by (le) (rate(kong_request_latency_ms_bucket[5m])))",
        12, y, w=3, unit="ms", decimals=0,
        thresholds=[{"color": VERDE, "value": None},
                    {"color": AMBAR, "value": 500},
                    {"color": ROJO, "value": 2000}],
        desc="Un guion o NaN significa que no hubo requests en la ventana: no hay "
             "latencia que reportar. A proposito NO se fuerza a 0 con `or vector(0)` "
             "como en los otros stats — un 0 ms ahi se leeria como 'responde "
             "instantaneo', que es lo contrario de la verdad.",
    ))
    P.append(stat(
        "Rate-limited (5m)",
        'sum(rate(kong_http_requests_total{code="429"}[5m])) or vector(0)',
        15, y, w=3, unit="reqps", decimals=2,
        thresholds=[{"color": AZUL, "value": None}],
        desc="429 = el plugin rate-limiting cortando. Util para calibrarlo: si es 0 "
             "siempre, el limite esta muy alto para servir de algo.",
    ))
    P.append(stat(
        "Conexiones activas",
        'sum(kong_nginx_connections_total{state="active"}) or vector(0)', 18, y, w=3,
    ))
    P.append(stat(
        "Nodos Kong", 'count(up{job="kong"} == 1) or vector(0)', 21, y, w=3,
    ))
    y += 4

    # --------------------------------------------------------------- 2. sano --
    P.append(row("¿Está sano? — errores y de quién es la culpa", y)); y += 1
    P.append(ts(
        "Requests por clase de código",
        [target(f'sum(rate(kong_http_requests_total{{code=~"{c}.."}}[$__rate_interval]))', n)
         for c, n in (("2", "2xx OK"), ("3", "3xx redirect"),
                      ("4", "4xx cliente"), ("5", "5xx servidor"))],
        0, y, w=12, unit="reqps",
        desc="Un pico de 4xx sin 5xx suele ser alguien probando rutas que no existen, "
             "no una falla del servicio.",
    ))
    P.append(ts(
        "¿Quién devolvió el error? Kong vs upstream",
        [target('sum(rate(kong_http_requests_total{source="kong", code=~"[45].."}'
                "[$__rate_interval]))", "Kong (auth, rate-limit, ruta inexistente)"),
         target('sum(rate(kong_http_requests_total{source="service", code=~"[45].."}'
                "[$__rate_interval]))", "Upstream (el backend)")],
        12, y, w=12, unit="reqps",
        desc="EL panel para no perder tiempo. source=kong: el gateway rechazó antes de "
             "llegar al backend (403/401/429/404 de ruta). source=service: el backend "
             "respondió mal y hay que mirar la aplicación, no Kong.",
    ))
    y += 8
    P.append(bargauge(
        "Rutas con más errores (rango visible)",
        [target('topk(10, sum by (service, route, code) '
                '(increase(kong_http_requests_total{code=~"[45].."}[$__range])))',
                "{{service}} · {{route}} · {{code}}", instant=True)],
        0, y, w=12,
        desc="Top 10 por volumen de error en el rango que estés mirando. Vacío = no "
             "hubo errores, que es la respuesta correcta.",
    ))
    P.append(ts(
        "Códigos de estado en detalle",
        [target("sum by (code) (rate(kong_http_requests_total[$__rate_interval]))", "{{code}}")],
        12, y, w=12, unit="reqps", stack=True,
    ))
    y += 8

    # -------------------------------------------------------------- 3. rapido --
    P.append(row("¿Está rápido? — y dónde se va el tiempo", y)); y += 1
    P.append(ts(
        "Latencia total del request (percentiles)",
        [target(f"histogram_quantile({q}, sum by (le) "
                "(rate(kong_request_latency_ms_bucket[$__rate_interval])))", n)
         for q, n in ((0.50, "p50"), (0.90, "p90"), (0.99, "p99"))],
        0, y, w=12, unit="ms",
        desc="Lo que percibe el cliente: Kong + red + upstream.",
    ))
    P.append(ts(
        "¿El tiempo es de Kong o del upstream?",
        [target("sum(rate(kong_kong_latency_ms_sum[$__rate_interval])) "
                "/ clamp_min(sum(rate(kong_kong_latency_ms_count[$__rate_interval])), 0.001)",
                "Kong (plugins, routing)"),
         target("sum(rate(kong_upstream_latency_ms_sum[$__rate_interval])) "
                "/ clamp_min(sum(rate(kong_upstream_latency_ms_count[$__rate_interval])), 0.001)",
                "Upstream (el backend)")],
        12, y, w=12, unit="ms",
        desc="Promedios, no percentiles: la pregunta acá es la proporción. Si Kong sube "
             "y el upstream no, el costo está en los plugins.",
    ))
    y += 8
    P.append(bargauge(
        "p99 por ruta (rango visible)",
        [target("topk(10, histogram_quantile(0.99, sum by (le, service, route) "
                "(rate(kong_request_latency_ms_bucket[$__range]))))",
                "{{service}} · {{route}}", instant=True)],
        0, y, w=24, h=7, unit="ms",
        thresholds=[{"color": VERDE, "value": None},
                    {"color": AMBAR, "value": 500},
                    {"color": ROJO, "value": 2000}],
        desc="Qué ruta arrastra la latencia. Verde bajo 500 ms, ámbar hasta 2 s, rojo "
             "arriba. Vacío = no hubo tráfico en el rango.",
    ))
    y += 7

    # --------------------------------------------------------------- 4. quien --
    P.append(row("¿Quién lo usa?", y)); y += 1
    P.append(ts(
        "Tráfico por servicio",
        [target("sum by (service) (rate(kong_http_requests_total[$__rate_interval]))",
                "{{service}}")],
        0, y, w=12, unit="reqps", stack=True,
    ))
    P.append(ts(
        "Tráfico por ruta",
        [target("sum by (route) (rate(kong_http_requests_total[$__rate_interval]))",
                "{{route}}")],
        12, y, w=12, unit="reqps", stack=True,
    ))
    y += 8
    P.append(ts(
        "Ancho de banda",
        [target("sum by (direction) (rate(kong_bandwidth_bytes[$__rate_interval]))",
                "{{direction}}")],
        0, y, w=12, unit="Bps",
    ))
    P.append(bargauge(
        "Requests por ruta (rango visible)",
        [target("topk(10, sum by (service, route) "
                "(increase(kong_http_requests_total[$__range])))",
                "{{service}} · {{route}}", instant=True)],
        12, y, w=12,
        desc="Top 10 rutas por volumen en el rango visible.",
    ))
    y += 8

    # ------------------------------------------------------------ 5. capacidad --
    P.append(row("¿Va a aguantar? — capacidad del nodo", y, collapsed=True)); y += 1
    cap = [
        ts("Memoria compartida por diccionario (%)",
           [target("100 * kong_memory_lua_shared_dict_bytes "
                   "/ kong_memory_lua_shared_dict_total_bytes", "{{shared_dict}}")],
           0, y, w=12, unit="percent",
           desc="kong_db_cache cerca del 100% = Kong evicta config y empieza a pegarle "
                "a Postgres en cada request."),
        ts("Memoria Lua por worker",
           [target("kong_memory_workers_lua_vms_bytes", "worker {{pid}}")],
           12, y, w=12, unit="bytes"),
        ts("Conexiones nginx por estado",
           [target('sum by (state) (kong_nginx_connections_total{state=~"active|reading|writing|waiting"})',
                   "{{state}}")],
           0, y + 8, w=12),
        ts("Timers de nginx (pendientes vs corriendo)",
           [target("kong_nginx_timers", "{{state}}")],
           12, y + 8, w=12,
           desc="Timers pendientes creciendo sin bajar = Kong no da abasto."),
    ]
    P[-1]["panels"] = cap
    y += 1

    # ------------------------------------------------------------- 6. upstream --
    P.append(row("Salud de los upstreams", y, collapsed=True)); y += 1
    # Un tile por target en vez de una tabla: kong_upstream_target_health emite UNA
    # serie por cada estado posible (healthy, unhealthy, dns_error, healthchecks_off)
    # y solo una vale 1. Filtrando a state="healthy" el valor ya es la respuesta —
    # 1 sano, 0 no — y se lee sin interpretar cuatro filas por target.
    P[-1]["panels"] = [
        stat("Targets de los upstreams",
             'kong_upstream_target_health{state="healthy"}', 0, y, w=12, h=6,
             mappings=[{"type": "value", "options": {
                 "0": {"text": "CAIDO", "color": ROJO, "index": 0},
                 "1": {"text": "SANO", "color": VERDE, "index": 1}}}],
             desc="Filtra state=healthy: su valor es directamente la respuesta. "
                  "Si marca CAIDO pero el backend responde, lo que está mal es el "
                  "health check, no el target."),
        table("Detalle por estado",
              [target('kong_upstream_target_health{state!="healthy"} == 1',
                      "{{upstream}} → {{target}}: {{state}}", instant=True)],
              12, y, w=12, h=6,
              desc="Solo los estados anómalos que estén activos (== 1). Vacío es lo "
                   "que se espera ver."),
    ]
    y += 1

    # ------------------------------------------------------------------ notas --
    P.append(texto(
        "Antes de sacar conclusiones",
        "**El plugin de Prometheus no está viendo el tráfico de Internet.** "
        "Verificado el 2026-09-21: en 30 días hay **49 requests** en total, todos de "
        "`httpbin-service` y `admin-api` (los servicios de prueba de la POC), y "
        "**cero 404 históricos**. En el mismo período Wazuh registró **2.041 alertas "
        "de enumeración** (regla 100207) y **23.157 de 404**, desde **71 IPs distintas**.\n\n"
        "Es decir: lo que entra por `gateway.grupoalemana.com` **no queda instrumentado "
        "acá**. Hasta habilitar el plugin de forma global, este dashboard describe la POC, "
        "no el gateway publicado. La vista de seguridad real está hoy en el dashboard de "
        "OpenSearch *Kong API Gateway Monitoring*.\n\n"
        "**Retención de Prometheus: 15 días.** Rangos mayores salen vacíos.",
        0, y, w=24, h=5,
    ))

    return {
        "uid": UID,
        "title": "Kong Alemana",
        "description": "Estado operativo de Kong, ordenado por las preguntas que hace "
                       "un administrador. Ver el panel de notas al pie: el plugin de "
                       "Prometheus no cubre el tráfico de Internet.",
        "tags": ["kong", "api-gateway", "soc"],
        "timezone": "browser",
        "editable": True,
        "graphTooltip": 1,  # cursor compartido entre paneles: alinea picos a simple vista
        "time": {"from": "now-6h", "to": "now"},
        "timepicker": {
            # Prometheus retiene 15d: ofrecer 30d/90d solo invita a paneles vacios.
            "refresh_intervals": ["30s", "1m", "5m", "15m"],
            "time_options": ["15m", "1h", "6h", "12h", "24h", "2d", "7d"],
        },
        "refresh": "1m",
        "schemaVersion": 39,
        "panels": P,
        "templating": {"list": []},
        "annotations": {"list": []},
    }


def push(dash: dict) -> None:
    url = os.environ.get("GRAFANA_URL", "http://192.168.38.62:3000")
    user = os.environ.get("GRAFANA_USER", "admin")
    pw = os.environ.get("GRAFANA_PASS")
    if not pw:
        sys.exit("ERROR: falta GRAFANA_PASS en el entorno.")
    payload = json.dumps({
        "dashboard": dash, "overwrite": True,
        "message": "Rearmado: ordenado por preguntas de administrador, sin duplicados",
    }).encode()
    req = urllib.request.Request(
        f"{url}/api/dashboards/db", data=payload, method="POST",
        headers={"Content-Type": "application/json"},
    )
    import base64
    req.add_header("Authorization", "Basic " +
                   base64.b64encode(f"{user}:{pw}".encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            print("  ", json.loads(r.read().decode()))
    except urllib.error.HTTPError as e:
        sys.exit(f"ERROR {e.code}: {e.read().decode()[:400]}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--push", action="store_true", help="sube el dashboard por API")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__),
                                                  "kong-alemana.json"))
    args = ap.parse_args()

    dash = build()
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(dash, fh, ensure_ascii=False, indent=2)
    n = sum(1 + len(p.get("panels", [])) for p in dash["panels"] if p["type"] == "row")
    n += sum(1 for p in dash["panels"] if p["type"] != "row")
    print(f"Escrito {args.out}: {n} paneles (antes: 43)")

    if args.push:
        push(dash)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
