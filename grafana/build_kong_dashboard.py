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
# Logs de acceso de Kong (Loki + Alloy en el mismo host, ver logs/). Es la unica
# fuente que ve el trafico de Internet: el plugin de Prometheus no lo instrumenta.
LOKI = {"type": "loki", "uid": "loki"}
# Dashboard de OpenSearch "Kong API Gateway Monitoring" (wazuh_dashboards/build_kong_v2.py):
# destino de los links por IP. Es el SIEM (seg-vs85-prod01).
WAZUH_DASH_URL = ("https://siem.grupoalemana.com/app/dashboards#/view/"
                  "55101f30-b526-11f0-b4ab-f10742cb3085")

# Parseo de la linea de acceso de nginx/Kong al consultar (no como labels: IP, ruta
# y user-agent tienen cardinalidad ilimitada y Loki se degrada si van en el indice).
# El filtro de linea ancla la variable $ip al comienzo: vacia = todo, "213.209." =
# ese rango, IP completa = esa IP (para pivotear desde el correo de bloqueo).
LOG_SEL = '{job="kong", kind="acceso"} |~ `^${ip:regex}`'
LOG_RE = ('| regexp `^(?P<ip>\\S+) \\S+ \\S+ \\[[^\\]]+\\] '
          '"(?P<method>\\S+) (?P<path>[^ "]+)[^"]*" (?P<status>\\d{3}) \\S+ '
          '"[^"]*" "(?P<ua>[^"]*)"`')

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


def ltarget(expr: str, legend: str = "", instant: bool = False) -> dict:
    """Target de Loki. Instant para los top-N (una cifra por rango visible)."""
    return {
        "datasource": LOKI,
        "expr": expr,
        "legendFormat": legend or "__auto",
        "refId": chr(65 + (nid() % 26)),
        "queryType": "instant" if instant else "range",
    }


def row(title: str, y: int, collapsed: bool = False) -> dict:
    return {
        "type": "row", "title": title, "id": nid(), "collapsed": collapsed,
        "gridPos": {"h": 1, "w": 24, "x": 0, "y": y}, "panels": [],
    }


def stat(title: str, expr: str, x: int, y: int, w: int = 4, h: int = 4, *,
         unit: str = "short", decimals: int | None = None,
         thresholds: list | None = None, mappings: list | None = None,
         desc: str = "", ds: dict = DS) -> dict:
    tgt = ltarget(expr, instant=True) if ds is LOKI else target(expr, instant=True)
    return {
        "type": "stat", "title": title, "id": nid(), "datasource": ds,
        "description": desc,
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "targets": [tgt],
        "options": {
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "textMode": "auto", "colorMode": "value", "graphMode": "area",
            "justifyMode": "auto",
            # Fija la tipografia: con auto-size, 8 tiles con valores de largo distinto
            # ("1" vs "ARRIBA" vs "0.00") quedan cada uno con un tamaño diferente.
            "text": {"valueSize": 26, "titleSize": 12},
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
       legend_bottom: bool = True, min_: float | None = 0, bars: bool = False) -> dict:
    return {
        "type": "timeseries", "title": title, "id": nid(),
        "datasource": targets[0]["datasource"],
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
                    "drawStyle": "bars" if bars else "line", "lineWidth": 2,
                    "fillOpacity": 70 if bars else (12 if not stack else 40),
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
    # Loki NO llega como Prometheus: el frontend junta las N series instant en UNA
    # tabla (Time, <label>, Value). Reducida con lastNotNull da un solo numero — el de
    # la ultima fila — sin nombre. Para Loki: una barra por fila, ordenadas a mano.
    es_loki = targets[0]["datasource"] is LOKI
    return {
        "type": "bargauge", "title": title, "id": nid(),
        "datasource": targets[0]["datasource"],
        "description": desc,
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "targets": targets,
        "transformations": [
            {"id": "sortBy", "options": {"sort": [{"field": "Value #" + targets[0]["refId"], "desc": True}]}},
        ] if es_loki else [],
        "options": {
            "orientation": "horizontal", "displayMode": "gradient",
            "reduceOptions": {"calcs": ["lastNotNull"], "values": es_loki,
                              "fields": ""},
            "showUnfilled": True, "valueMode": "color",
            "minVizWidth": 8, "minVizHeight": 10, "maxVizHeight": 26,
            "namePlacement": "left",
            # sizing manual + text.*: sin esto Grafana auto-escala la tipografia hasta
            # llenar el panel, y con 2-3 barras en 12-24 columnas queda gigante.
            "sizing": "manual",
            "text": {"valueSize": 18, "titleSize": 12},
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


def logs(title: str, expr: str, x: int, y: int, w: int = 24, h: int = 10, *,
         desc: str = "") -> dict:
    return {
        "type": "logs", "title": title, "id": nid(), "datasource": LOKI,
        "description": desc,
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "targets": [ltarget(expr)],
        "options": {"showTime": True, "wrapLogMessage": False, "sortOrder": "Descending",
                    "enableLogDetails": True, "dedupStrategy": "none",
                    "prettifyLogMessage": False},
    }


def links_ip() -> list[dict]:
    """Data links para los rankings por IP (frames de tabla de Loki: la IP viene como
    columna, por eso ${__data.fields.ip} y no ${__field.labels.ip})."""
    ip = "${__data.fields.ip}"
    return [
        {"title": "Filtrar el tablero a esta IP",
         "url": f"/d/{UID}/kong-alemana?var-ip={ip}&${{__url_time_range}}",
         "targetBlank": False},
        {"title": "Ver en Wazuh (alertas, país, reglas)",
         "url": (f"{WAZUH_DASH_URL}?_g=(time:(from:now-7d,to:now))"
                 f"&_a=(query:(language:kuery,query:'data.srcip:\"{ip}\"'))"),
         "targetBlank": True},
    ]


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
        "RPS en rutas (5m)", "sum(rate(kong_http_requests_total[5m])) or vector(0)", 6, y, w=3,
        unit="reqps", decimals=2,
        desc="Solo requests que matchearon una ruta (uso del API). Prometheus NO cuenta "
             "los 404 sin ruta, que es casi todo lo que llega de Internet (scanners): "
             "para eso mirar 'Internet (5m)' y la sección de logs de acceso.",
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
        "Conexiones de clientes",
        'clamp_min(sum(kong_nginx_connections_total{state="active"}) '
        '- count(kong_memory_workers_lua_vms_bytes) - 1, 0) or vector(0)', 18, y, w=3,
        desc="Conexiones activas de nginx MENOS el piso interno: cada worker de Kong "
             "mantiene una conexión fija al socket de eventos (/usr/local/kong/sockets/we) "
             "y el scrape de Prometheus suma otra. Sin restar, en reposo marca 5 "
             "(4 workers + scrape) sin ningún cliente.",
    ))
    P.append(stat(
        "Internet (5m)",
        'sum(count_over_time({job="kong", kind="acceso"} [5m])) or vector(0)', 21, y, w=3,
        ds=LOKI, thresholds=[{"color": AZUL, "value": None}],
        desc="Requests que llegaron al gateway en los últimos 5 min según el log de "
             "acceso, con o sin ruta. Es el número que Prometheus no ve.",
    ))
    y += 4

    # ------------------------------------------------ 1b. que le esta pegando --
    # La seccion que faltaba: lo que entra de Internet por gateway.grupoalemana.com.
    # Sale de los LOGS de acceso (Loki), no de Prometheus, que no ve este trafico.
    P.append(row("¿Qué le está pegando? — tráfico real de Internet (logs de acceso)", y))
    y += 1
    rango = f"{LOG_SEL} {LOG_RE}"
    # Selector de 404 reutilizado por varios paneles: filtra por label (barato) y
    # despues por el status parseado (exacto).
    sel_404 = (f'{{job="kong", kind="acceso", status_class="4xx"}} |~ `^${{ip:regex}}` '
               f'{LOG_RE} | status="404"')
    P.append(stat(
        "Requests de Internet", f"sum(count_over_time({LOG_SEL} [$__range])) or vector(0)",
        0, y, w=4, ds=LOKI, thresholds=[{"color": AZUL, "value": None}],
        desc="Todas las líneas de acceso del rango visible, sin el tráfico interno de "
             "Docker (172.x: Konga, health checks). Filtrable por la variable IP.",
    ))
    P.append(stat(
        "IPs distintas", f"count(sum by (ip) (count_over_time({rango} [$__range]))) or vector(0)",
        4, y, w=4, ds=LOKI, thresholds=[{"color": AZUL, "value": None}],
    ))
    P.append(stat(
        "Respuestas 404",
        f"sum(count_over_time({sel_404} [$__range])) or vector(0)",
        8, y, w=4, ds=LOKI,
        thresholds=[{"color": VERDE, "value": None}, {"color": AMBAR, "value": 100},
                    {"color": ROJO, "value": 1000}],
        desc="Rutas inexistentes. Es la materia prima de la regla Wazuh 100207 "
             "(N x 404 = enumeración), que SOC-L1 bloquea en FortiGate.",
    ))
    P.append(stat(
        "IPs sobre el umbral de bloqueo",
        f"count(sum by (ip) (count_over_time({sel_404} [$__range])) >= 10) or vector(0)",
        12, y, w=4, ds=LOKI,
        thresholds=[{"color": VERDE, "value": None}, {"color": AMBAR, "value": 1},
                    {"color": ROJO, "value": 5}],
        desc="IPs con 10 o más 404 en el rango visible: el mismo umbral que la regla "
             "Wazuh 100207 (10 × 404 en 2 min), que manda la IP a cuarentena en el "
             "FortiGate vía SOC-L1. Aproximación: la regla mira una ventana de 2 min, "
             "este panel todo el rango, así que puede contar de más, nunca de menos.",
    ))
    P.append(stat(
        "Requests 2xx (uso legítimo)",
        f'sum(count_over_time({{job="kong", kind="acceso", status_class="2xx"}} '
        f'|~ `^${{ip:regex}}` [$__range])) or vector(0)',
        16, y, w=4, ds=LOKI, thresholds=[{"color": VERDE, "value": None}],
        desc="Requests que pasaron el key-auth y llegaron al backend.",
    ))
    P.append(stat(
        "% respondido 2xx",
        f'100 * (sum(count_over_time({{job="kong", kind="acceso", status_class="2xx"}} '
        f'|~ `^${{ip:regex}}` [$__range])) or vector(0)) / '
        f"sum(count_over_time({LOG_SEL} [$__range]))",
        20, y, w=4, ds=LOKI, unit="percent", decimals=1,
        thresholds=[{"color": AMBAR, "value": None}, {"color": VERDE, "value": 20}],
        desc="Qué parte del tráfico es uso legítimo con API key válida. Bajo = la "
             "mayoría es ruido de scanners que Kong ya rechaza (401/404).",
    ))
    y += 4
    P.append(ts(
        "Requests de Internet por código",
        [ltarget(f'sum by (status_class) (count_over_time({{job="kong", kind="acceso"}} '
                 f'|~ `^${{ip:regex}}` [$__interval]))', "{{status_class}}")],
        0, y, w=24, h=7, stack=True, bars=True,
        desc="2xx = uso con API key válida · 4xx = rechazado por Kong (401 sin key, "
             "404 ruta inexistente, 429 rate-limit) · 5xx = falla del backend.",
    ))
    # Sin piso de intervalo, en 24h Loki devuelve buckets de ~1 min con 0-2 hits y
    # las barras quedan de un pixel. 10m da ~150 barras legibles en 24h.
    P[-1]["interval"] = "10m"
    P[-1]["fieldConfig"]["overrides"] = [
        {"matcher": {"id": "byName", "options": c},
         "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": col}}]}
        for c, col in (("2xx", VERDE), ("3xx", AZUL), ("4xx", AMBAR), ("5xx", ROJO))
    ]
    y += 7
    P.append(bargauge(
        "Top IPs (rango visible)",
        [ltarget(f"topk(10, sum by (ip) (count_over_time({rango} [$__range])))",
                 "{{ip}}", instant=True)],
        0, y, w=8, h=9,
        desc="Quién más le pega. Click en una barra: filtrar el tablero a esa IP, o "
             "abrirla en el dashboard de Wazuh (alertas, país, qué reglas disparó).",
    ))
    P[-1]["fieldConfig"]["defaults"]["links"] = links_ip()
    P.append(bargauge(
        "Rutas más buscadas con 404",
        [ltarget(f'topk(10, sum by (path) (count_over_time({rango} | status="404" '
                 f"[$__range])))", "{{path}}", instant=True)],
        8, y, w=8, h=9, thresholds=[{"color": AMBAR, "value": None}],
        desc="Qué buscan los scanners: /.git/config, /.env, /admin/... Ninguna existe "
             "en el gateway; que aparezcan acá es enumeración, no uso.",
    ))
    P.append(bargauge(
        "User-agents (rango visible)",
        [ltarget(f"topk(10, sum by (ua) (count_over_time({rango} [$__range])))",
                 "{{ua}}", instant=True)],
        16, y, w=8, h=9,
        desc="Un user-agent vacío (\"-\"), zgrab, curl o python-requests desde Internet "
             "casi nunca es un cliente real de la API.",
    ))
    y += 9
    P.append(bargauge(
        "IPs con más 404 (candidatas a bloqueo)",
        [ltarget(f"topk(10, sum by (ip) (count_over_time({sel_404} [$__range])))",
                 "{{ip}}", instant=True)],
        0, y, w=8, h=8,
        thresholds=[{"color": AZUL, "value": None}, {"color": AMBAR, "value": 10},
                    {"color": ROJO, "value": 50}],
        desc="Solo 404: la señal de enumeración. Desde 10 (ámbar) la regla 100207 ya "
             "debería haber mandado la IP a cuarentena; si sigue sumando después, la "
             "cuarentena no la está cortando. Click: filtrar o ver en Wazuh.",
    ))
    P[-1]["fieldConfig"]["defaults"]["links"] = links_ip()
    P.append(bargauge(
        "Métodos HTTP",
        [ltarget(f"topk(8, sum by (method) (count_over_time({rango} [$__range])))",
                 "{{method}}", instant=True)],
        8, y, w=8, h=8,
        desc="GET es lo esperado. POST/PUT/DELETE/PROPFIND desde Internet contra un "
             "gateway de solo lectura son sondeos. Un 'método' con basura adentro es "
             "un exploit mandado como primera línea HTTP (p.ej. el downloader de Mozi).",
    ))
    P.append(bargauge(
        "Rutas con 2xx (uso legítimo)",
        [ltarget(f'topk(10, sum by (method, path) (count_over_time({{job="kong", '
                 f'kind="acceso", status_class="2xx"}} |~ `^${{ip:regex}}` {LOG_RE} '
                 f"[$__range])))", "{{method}} {{path}}", instant=True)],
        16, y, w=8, h=8, thresholds=[{"color": VERDE, "value": None}],
        desc="Lo que pasó el key-auth y llegó al backend. Vacío = nadie usó la API con "
             "credenciales válidas en el rango, que hoy es lo normal en la POC.",
    ))
    y += 8
    # label_format detected_level: Loki 3 ya guarda detected_level=unknown al ingerir
    # y Grafana lo prioriza sobre `level`, por eso se pisa ese. Sin esto dice
    # "UNK" en cada linea. Se deriva de la clase de status: 4xx ambar, 5xx rojo.
    nivel = ('| label_format detected_level=`{{ if eq .status_class "5xx" }}error'
             '{{ else if eq .status_class "4xx" }}warning{{ else }}info{{ end }}`')
    P.append(logs(
        "Log de acceso en vivo", f"{LOG_SEL} {nivel}", 0, y, w=24, h=12,
        desc="Líneas crudas de Kong, la más nueva arriba. Click en una línea para ver "
             "IP, método, ruta, status y user-agent parseados.",
    ))
    y += 12

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

    # ------------------------------------------------------------ 4b. consumidor --
    # Requiere per_consumer=true en el plugin prometheus (activado 21/10). Solo ve requests
    # que pasaron key-auth: scanners y 401 no tienen consumidor. La latencia NO se etiqueta
    # por consumidor en Kong, por eso no hay panel de latencia aca.
    P.append(row("¿Quién lo usa? — por consumidor", y)); y += 1
    cons = 'consumer!=""'
    P.append(ts(
        "Tráfico por consumidor",
        [target(f"sum by (consumer) (rate(kong_http_requests_total{{{cons}}}[$__rate_interval]))",
                "{{consumer}}")],
        0, y, w=12, unit="reqps", stack=True,
        desc="Requests/s por consumidor de Kong (key-auth). Solo cuenta requests que "
             "presentaron una key valida; los scanners (sin key) no aparecen aca.",
    ))
    P.append(ts(
        "Errores por consumidor (4xx/5xx)",
        [target("sum by (consumer, code) "
                f'(rate(kong_http_requests_total{{{cons},code=~"[45].."}}[$__rate_interval]))',
                "{{consumer}} · {{code}}")],
        12, y, w=12, unit="reqps",
        desc="Que consumidor recibe errores y de que tipo. Un 401 del backend (Bearer) "
             "es normal antes del login ERP; un 429 es rate-limit.",
    ))
    y += 8
    P.append(bargauge(
        "Requests por consumidor (rango visible)",
        [target(f"topk(10, sum by (consumer) (increase(kong_http_requests_total{{{cons}}}[$__range])))",
                "{{consumer}}", instant=True)],
        0, y, w=8,
    ))
    P.append(ts(
        "Ancho de banda por consumidor",
        [target(f"sum by (consumer, direction) (rate(kong_bandwidth_bytes{{{cons}}}[$__rate_interval]))",
                "{{consumer}} · {{direction}}")],
        8, y, w=16, unit="Bps",
    ))
    y += 8
    tgt = target(f"sum by (consumer, service, route, code) "
                 f"(increase(kong_http_requests_total{{{cons}}}[$__range]))", instant=True)
    tgt["format"] = "table"
    P.append(table(
        "Consumidor × servicio × ruta (rango visible)", [tgt], 0, y, w=24, h=9,
        desc="Detalle completo de uso: quien llamo a que servicio y ruta, con que codigo.",
        transformations=[
            {"id": "organize", "options": {
                "excludeByName": {"Time": True},
                "renameByName": {"consumer": "Consumidor", "service": "Servicio",
                                 "route": "Ruta", "code": "Código", "Value": "Requests"}}},
            {"id": "sortBy", "options": {"sort": [{"field": "Requests", "desc": True}]}},
        ],
    ))
    y += 9

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
           0, y + 8, w=12,
           desc="Piso en reposo: active=5, writing=5 (4 workers conectados al socket de "
                "eventos + el scrape). Lo que suba por encima de eso son clientes."),
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
        "Por eso el tráfico real de `gateway.grupoalemana.com` se muestra desde los "
        "**logs de acceso** (sección *¿Qué le está pegando?*, datasource Loki): esa sí "
        "ve cada request de Internet. Las filas de métricas de abajo siguen describiendo "
        "la POC hasta que el plugin se habilite de forma global.\n\n"
        "**Qué se hace con lo que se ve.** Wazuh correlaciona el mismo log (reglas "
        "100200–100241) y la **100207** (10 × 404 de una IP en 2 min) dispara en SOC-L1 "
        "una **cuarentena en el FortiGate (TTL 1 h)** + ticket + correo/Teams. "
        f"[Dashboard de Wazuh]({WAZUH_DASH_URL}) con ataques por regla, IPs atacantes y país; "
        "desde los rankings por IP de arriba se salta con un click.\n\n"
        "**Retención: 15 días** en Prometheus y en Loki. Rangos mayores salen vacíos.",
        0, y, w=24, h=6,
    ))

    return {
        "uid": UID,
        "title": "Kong Alemana",
        "description": "Estado operativo de Kong, ordenado por las preguntas que hace "
                       "un administrador. El tráfico de Internet sale de los logs de "
                       "acceso (Loki); las métricas de Prometheus cubren solo la POC.",
        "tags": ["kong", "api-gateway", "soc"],
        "timezone": "browser",
        "editable": True,
        "graphTooltip": 1,  # cursor compartido entre paneles: alinea picos a simple vista
        # 24h y no 6h: la seccion de logs es la que se mira, y un scanner tipico pega
        # una vez por dia; en 6h la mitad de las visitas quedan fuera de la foto.
        "time": {"from": "now-24h", "to": "now"},
        "timepicker": {
            # Prometheus retiene 15d: ofrecer 30d/90d solo invita a paneles vacios.
            "refresh_intervals": ["30s", "1m", "5m", "15m"],
            "time_options": ["15m", "1h", "6h", "12h", "24h", "2d", "7d"],
        },
        "refresh": "1m",
        "schemaVersion": 39,
        "panels": P,
        "templating": {"list": [{
            "type": "textbox", "name": "ip", "label": "IP (o prefijo)",
            "query": "", "current": {"text": "", "value": ""},
            "description": "Filtra la sección de logs. Vacío = todo; '213.209.' = ese "
                           "rango; una IP completa = solo esa (ej. la del correo de bloqueo).",
        }]},
        "annotations": {"list": []},
    }


def push(dash: dict) -> None:
    url = os.environ.get("GRAFANA_URL", "https://monitoring.grupoalemana.com")
    user = os.environ.get("GRAFANA_USER", "admin")
    pw = os.environ.get("GRAFANA_PASS")
    if not pw:
        sys.exit("ERROR: falta GRAFANA_PASS en el entorno.")
    payload = json.dumps({
        "dashboard": dash, "overwrite": True,
        "message": os.environ.get("GRAFANA_MSG", "build_kong_dashboard.py"),
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
        # El host re-aprovisiona este uid desde un archivo al reiniciar Grafana: si no
        # se actualiza, el próximo restart revierte lo que se acaba de subir (13/10).
        print("   OJO: copiar tambien el JSON a seg-vs85-prod02:"
              "~/kong-setup/grafana/provisioning/dashboards/kong-alemana.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
