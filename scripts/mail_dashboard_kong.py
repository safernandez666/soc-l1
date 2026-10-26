#!/usr/bin/env python3
"""Arma el correo HTML que presenta el dashboard "Kong Alemana" de Grafana.

Toma las cifras de Internet de las ultimas 24 h de Grafana (Loki) y genera
mails/08-dashboard-grafana-kong-escalar-apis.html con el tema del SOC. No envia nada.

  GRAFANA_PASS=... python3 scripts/mail_dashboard_kong.py
"""
import argparse
import base64
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from src import report_theme as T  # noqa: E402

URL = os.environ.get("GRAFANA_URL", "https://monitoring.grupoalemana.com")  # API de datos
PUBLIC_URL = os.environ.get("GRAFANA_PUBLIC_URL", "https://monitoring.grupoalemana.com")  # links del correo
LOKI = {"type": "loki", "uid": "loki"}
ASUNTO = "Gateway de APIs: cómo se ve hoy el monitoreo y cómo crece al sumar APIs"
ACC = '{job="kong", kind="acceso"}'
ARGS = (r'| regexp `^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?P<m>\S+) (?P<p>[^ "]+)[^"]*" (?P<status>\d{3})`')


def loki(expr: str) -> float | None:
    pw = os.environ.get("GRAFANA_PASS")
    if not pw:
        return None
    now = int(time.time() * 1000)
    body = {"queries": [{"refId": "A", "datasource": LOKI, "expr": expr, "queryType": "instant",
                         "instant": True}], "from": str(now - 86400000), "to": str(now)}
    req = urllib.request.Request(
        URL + "/api/ds/query", data=json.dumps(body).encode(),
        headers={"Authorization": "Basic " + base64.b64encode(f"admin:{pw}".encode()).decode(),
                 "Content-Type": "application/json"})
    try:
        r = json.load(urllib.request.urlopen(req, timeout=40))["results"]["A"]
        return float(r["frames"][0]["data"]["values"][-1][-1])
    except Exception:
        return None


def cifras() -> dict:
    n = lambda v: T.num(int(v)) if v is not None else "—"
    total = loki(f"sum(count_over_time({ACC} [24h]))")
    ips = loki(f"count(sum by (ip) (count_over_time({ACC} {ARGS} [24h])))")
    c404 = loki(f'sum(count_over_time({ACC} {ARGS} | status="404" [24h]))')
    return {"total": n(total), "ips": n(ips), "c404": n(c404)}


def p(txt: str) -> str:
    return (f'<div style="font-family:{T.FONT};font-size:13px;line-height:20px;'
            f'color:{T.C_TEXT};padding:0 0 10px 0;">{txt}</div>')


def datos_reales() -> str:
    """Secciones con datos de las ultimas 24 h (las mismas del resumen diario). '' si no hay acceso."""
    try:
        sys.path.insert(0, str(ROOT / "scripts"))
        import kong_daily_report as KD
        return KD.build(KD.collect(), only_body=True)[0]
    except Exception as e:  # sin credenciales o Grafana caido: el correo sale igual, sin datos
        print(f"AVISO: sin datos reales ({e})", file=sys.stderr)
        return ""


def build() -> tuple[str, str]:
    c = cifras()
    real = datos_reales()
    cards = T.metric_row([
        T.metric_card("Requests (24 h)", c["total"], T.C_GREEN, "llegaron al gateway"),
        T.metric_card("IPs distintas", c["ips"], T.C_GREEN, "origenes en Internet"),
        T.metric_card("Respuestas 404", c["c404"], T.C_HIGH, "escaneos de rutas"),
        T.metric_card("Llegaron al backend", "0", T.C_GREEN, "de los 404"),
    ])
    preguntas = [
        ("¿Está arriba?", "Estado de Kong y su base, requests/s, errores 5xx, latencia p99, rate limit."),
        ("¿Qué le pega desde Internet?", "Tráfico real, incluido el que no es de ninguna API: ranking de IPs, "
         "rutas buscadas, user-agents y log en vivo. Las IPs sobre el umbral las corta el SIEM."),
        ("¿Está sano?", "Errores por clase de código y de quién es la culpa: Kong o el backend."),
        ("¿Está rápido?", "Percentiles p50/p90/p99 y cuánto tiempo se va en Kong y cuánto en el backend."),
        ("¿Quién lo usa?", "Tráfico por servicio y por ruta, ancho de banda y ranking de rutas."),
        ("¿Quién lo usa, por consumidor? (nuevo)", "Uso, errores y una tabla consumidor × servicio × ruta."),
        ("¿Va a aguantar?", "Memoria, conexiones y timers del nodo, y estado de los upstreams."),
    ]
    t = T.table_open([("Pregunta", 230, "left"), ("Qué responde", None, "left")])
    t += "".join(T.table_row([(f"<b>{a}</b>", "left", ""), (b, "left", "")], i)
                 for i, (a, b) in enumerate(preguntas))
    t += T.TABLE_CLOSE

    altas = [("Servicio nuevo", "Tráfico por servicio, tabla de uso"),
             ("Ruta nueva", "Tráfico por ruta, p99 por ruta, errores"),
             ("Consumidor (cliente) + key", "Sección por consumidor, tabla de uso"),
             ("Upstream nuevo", "Salud de los upstreams")]
    t2 = T.table_open([("Alta en Kong", 230, "left"), ("Dónde aparece sola", None, "left")])
    t2 += "".join(T.table_row([(a, "left", ""), (b, "left", "")], i) for i, (a, b) in enumerate(altas))
    t2 += T.TABLE_CLOSE

    body = "".join([
        T.callout("Les paso lo que ya tenemos en Grafana para el gateway de APIs y cómo va a quedar al "
                  "sumar más APIs. Hoy publicamos una sola (Órdenes), así que algunas secciones se ven con "
                  "poco volumen: el tablero ya está armado para crecer.", "Resumen"),
        T.spacer(),
        (real + T.spacer()) if real else
        T.section("Internet, últimas 24 horas",
                  "Lo que llega al gateway, con o sin API detrás", cards + T.spacer(10) +
                  p("Los 404 son escaneos buscando rutas que no existen: Kong los corta y no llegan al "
                    "backend. Las IPs que superan el umbral de bloqueo las pone en cuarentena el SIEM "
                    "automáticamente.")) + T.spacer(),
        T.section("Qué se ve hoy", "Dashboard «Kong Alemana», ordenado por preguntas del administrador", t),
        T.spacer(),
        T.section("Qué pasa cuando sumemos APIs",
                  "No hay que tocar el dashboard: los paneles agrupan por servicio, ruta y consumidor",
                  t2 + T.spacer(10) +
                  p("Con 5 APIs y 10 clientes, «Tráfico por consumidor» muestra quién consume más y «Errores "
                    "por consumidor» quién tiene un problema de integración (por ejemplo 401 repetidos). "
                    "<b>Condición:</b> cada cliente con su propia key; si dos comparten, el tablero los ve "
                    "como uno.")),
        T.spacer(),
        T.section("Qué hay que tener en cuenta", "", T.bullet_list([
            "La latencia se ve por servicio y por ruta, no por consumidor (Kong no la etiqueta así).",
            "Los datos por consumidor empiezan el 21/10; no hay historia anterior.",
            "El historial de métricas se guarda 90 días.",
            "El tráfico sin key (escaneos) no tiene consumidor: se ve en la sección de Internet y en el SIEM.",
        ], T.C_HIGH)),
        T.spacer(),
        T.section("Relación con el SIEM", "", p(
            "Los logs de Kong también van a Wazuh con reglas propias (fuerza bruta, enumeración de "
            "endpoints, exceso de rate limit, tasas anómalas por IP). Grafana responde <i>cómo está "
            "funcionando</i>; Wazuh, <i>qué intentó alguien</i>. Cada IP sospechosa en Grafana tiene un "
            "link a su detalle en Wazuh.")),
        T.spacer(),
        T.section("Acceso", "", T.kv_rows([
            ("Grafana", f'<a href="{PUBLIC_URL}" style="color:{T.C_GREEN_DK};">{PUBLIC_URL}</a>'),
            ("Dashboard", "Kong Alemana"),
            ("SIEM", f'<a href="https://siem.grupoalemana.com" style="color:{T.C_GREEN_DK};">'
                     "siem.grupoalemana.com</a>"),
        ])),
    ])
    html = T.document(title="Monitoreo del gateway de APIs", subtitle="Dashboard Kong Alemana",
                      body=body, badge_kind="info", doc_title=ASUNTO,
                      preheader="Qué se ve hoy en Grafana y cómo crece al sumar APIs.",
                      logo_src=T.logo_data_uri() or "")
    plain = (ROOT / "mails/08-dashboard-grafana-kong-escalar-apis.txt").read_text()
    return html, plain


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.parse_args()
    html, plain = build()
    out = ROOT / "mails/08-dashboard-grafana-kong-escalar-apis.html"
    out.write_text(html)
    print(f"Escrito {out} ({len(html) // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
