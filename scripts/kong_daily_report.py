#!/usr/bin/env python3
"""Resumen diario del gateway Kong (ultimas 24 h) en HTML.

Consumo de las APIs (Prometheus) + trafico/ataques de Internet (Loki), ambos via la API de
datasources de Grafana. Por defecto solo escribe el HTML; --email lo envia.

  GRAFANA_PASS=... python3 scripts/kong_daily_report.py                      # escribe el HTML
  GRAFANA_PASS=... python3 scripts/kong_daily_report.py --email --to a@x.com # lo envia
"""
import argparse
import base64
import ipaddress
import json
import os
import re
import sys
import time
import urllib.request
from collections import defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from src import report_theme as T  # noqa: E402

URL = os.environ.get("GRAFANA_URL", "https://monitoring.grupoalemana.com")  # API de datos
PUBLIC_URL = os.environ.get("GRAFANA_PUBLIC_URL", "https://monitoring.grupoalemana.com")  # el que va en los links
EMAIL_CONFIG_FILE = os.getenv("KONG_EMAIL_CONFIG", "/var/ossec/etc/email-config.json")
PROM = {"type": "prometheus", "uid": "prometheus"}
LOKI = {"type": "loki", "uid": "loki"}
UMBRAL_404 = 10  # mismo umbral que la regla de bloqueo y el panel del dashboard
ACC = '{job="kong", kind="acceso"}'
PARSE = (r'| regexp `^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?P<method>\S+) (?P<path>[^ "]+)[^"]*" '
         r'(?P<status>\d{3}) \S+ "[^"]*" "(?P<ua>[^"]*)"`')
FONT = T.FONT
# IPs propias (pruebas, monitoreo) que no son ataques: se listan aparte. Las privadas se detectan solas.
KNOWN_IPS = {x.strip() for x in os.getenv("KONG_KNOWN_IPS", "").split(",") if x.strip()}


def propia(ip: str) -> str:
    """'interna' | 'conocida' | '' (externa desconocida)."""
    try:
        if ipaddress.ip_address(ip).is_private:
            return "interna"
    except ValueError:
        pass
    return "conocida" if ip in KNOWN_IPS else ""


def _auth() -> str:
    pw = os.environ.get("GRAFANA_PASS")
    if not pw:
        sys.exit("ERROR: falta GRAFANA_PASS en el entorno.")
    return "Basic " + base64.b64encode(f"{os.environ.get('GRAFANA_USER', 'admin')}:{pw}".encode()).decode()


def q(ds: dict, expr: str) -> list[tuple[dict, float]]:
    """Consulta instantanea -> [(labels, valor)]. Lista vacia si no hay datos."""
    now = int(time.time() * 1000)
    body = {"queries": [{"refId": "A", "datasource": ds, "expr": expr, "instant": True,
                         "queryType": "instant", "intervalMs": 60000, "maxDataPoints": 500}],
            "from": str(now - 86_400_000), "to": str(now)}
    req = urllib.request.Request(URL + "/api/ds/query", data=json.dumps(body).encode(),
                                 headers={"Authorization": _auth(), "Content-Type": "application/json"})
    r = json.load(urllib.request.urlopen(req, timeout=60))["results"]["A"]
    if r.get("error"):
        raise RuntimeError(f"{expr[:60]}: {r['error']}")
    out = []
    for f in r.get("frames", []):
        vals = f["data"]["values"]
        if vals and vals[-1] and vals[-1][-1] is not None:  # NaN llega como None
            out.append((f["schema"]["fields"][-1].get("labels") or {}, float(vals[-1][-1])))
    return out


def one(ds, expr) -> float:
    r = q(ds, expr)
    return r[0][1] if r else 0.0


def fmt_ms(v) -> str:
    return "—" if v != v or v <= 0 else (f"{v:.0f} ms" if v < 1000 else f"{v / 1000:.1f} s")


def collect() -> dict:
    d = {}
    # --- consumo de las APIs (Prometheus) ---
    rows = q(PROM, "sum by (service, route, consumer, code) (increase(kong_http_requests_total[24h]))")
    d["rows"] = [(l.get("service", "-"), l.get("route", "-"), l.get("consumer", "") or "—",
                  l.get("code", "?"), v) for l, v in rows if v >= 0.5]
    d["p99"] = one(PROM, "histogram_quantile(0.99, sum by (le) (rate(kong_request_latency_ms_bucket[24h])))")
    d["kong_up"] = one(PROM, 'count(up{job="kong"} == 1)')
    d["rate_limited"] = one(PROM, 'sum(increase(kong_http_requests_total{code="429"}[24h]))')
    lat = q(PROM, "histogram_quantile(0.99, sum by (le, route) (rate(kong_request_latency_ms_bucket[24h])))")
    d["p99_route"] = {l.get("route", "-"): v for l, v in lat if v == v}
    # --- Internet (Loki) ---
    d["total"] = one(LOKI, f"sum(count_over_time({ACC} [24h]))")
    p = f"{ACC} {PARSE}"
    d["ips"] = one(LOKI, f"count(sum by (ip) (count_over_time({p} [24h])))")
    d["c404"] = one(LOKI, f'sum(count_over_time({p} | status="404" [24h]))')
    d["c2xx"] = one(LOKI, f'sum(count_over_time({p} | status=~"2.." [24h]))')
    d["top_ips"] = sorted(((l["ip"], v) for l, v in
                           q(LOKI, f"topk(10, sum by (ip) (count_over_time({p} [24h])))")), key=lambda x: -x[1])
    ips404 = q(LOKI, f'sum by (ip) (count_over_time({p} | status="404" [24h]))')
    d["ips_umbral"] = sorted(((l["ip"], v) for l, v in ips404 if v >= UMBRAL_404), key=lambda x: -x[1])
    d["top_404"] = sorted(((l["path"], v) for l, v in
                           q(LOKI, f'topk(10, sum by (path) (count_over_time({p} | status="404" [24h])))')),
                          key=lambda x: -x[1])
    d["top_ua"] = sorted(((l["ua"], v) for l, v in
                          q(LOKI, f"topk(8, sum by (ua) (count_over_time({p} [24h])))")), key=lambda x: -x[1])
    d["methods"] = sorted(((l["method"], v) for l, v in
                           q(LOKI, f"sum by (method) (count_over_time({p} [24h]))")), key=lambda x: -x[1])
    return d


# ------------------------------------------------------------------ HTML --
def para(txt):
    return (f'<div style="font-family:{FONT};font-size:13px;line-height:20px;color:{T.C_TEXT};'
            f'padding:0 0 10px 0;">{txt}</div>')


def mono(txt):
    return f'<span style="font-family:Consolas,Menlo,monospace;font-size:12px;">{T.esc(txt) if hasattr(T, "esc") else txt}</span>'


def ranking(cols, rows, empty):
    if not rows:
        return para(f'<span style="color:{T.C_MUTED};">{empty}</span>')
    h = T.table_open(cols)
    for i, r in enumerate(rows):
        h += T.table_row(r, i)
    return h + T.TABLE_CLOSE


def clean(s: str, n=70) -> str:
    s = re.sub(r"[<>&\"]", "", s)
    return s if len(s) <= n else s[: n - 1] + "…"


def build(d: dict, only_body: bool = False) -> tuple[str, str, str]:
    # agrega por servicio/ruta y por consumidor
    api = defaultdict(lambda: defaultdict(float))
    cons = defaultdict(lambda: defaultdict(float))
    for svc, route, c, code, v in d["rows"]:
        if svc == "admin-api":
            continue
        api[(svc, route)][code[0] + "xx"] += v
        if c != "—":
            cons[(c, svc, route)][code[0] + "xx"] += v
    tot_api = sum(sum(x.values()) for x in api.values())
    e5 = sum(x["5xx"] for x in api.values())
    pct5 = (100 * e5 / tot_api) if tot_api else 0.0
    atk = [(ip, v) for ip, v in d["ips_umbral"] if not propia(ip)]
    own = [(ip, v) for ip, v in d["ips_umbral"] if propia(ip)]
    n_atk = len(atk)

    # estado
    if e5 > 0 and pct5 >= 1:
        estado, kind = "ATENCION", "atencion"
    elif n_atk:
        estado, kind = "ACTIVIDAD", "info"
    else:
        estado, kind = "SIN NOVEDAD", "ok"

    cards = T.metric_row([
        T.metric_card("Requests a APIs", T.num(tot_api), T.C_GREEN, "pasaron por una ruta"),
        T.metric_card("Error 5xx", f"{pct5:.1f}%", T.C_CRIT if pct5 >= 1 else T.C_GREEN, f"{T.num(e5)} requests"),
        T.metric_card("p99 latencia", fmt_ms(d["p99"]), T.C_GREEN, "todas las rutas"),
        T.metric_card("Rate limit (429)", T.num(d["rate_limited"]), T.C_HIGH if d["rate_limited"] else T.C_GREEN, "bloqueados"),
    ])
    cards2 = T.metric_row([
        T.metric_card("Requests de Internet", T.num(d["total"]), T.C_GREEN, "con o sin ruta"),
        T.metric_card("IPs distintas", T.num(d["ips"]), T.C_GREEN, "orígenes"),
        T.metric_card("Respuestas 404", T.num(d["c404"]), T.C_HIGH, "rutas inexistentes"),
        T.metric_card("IPs sobre umbral", T.num(n_atk), T.C_CRIT if n_atk else T.C_GREEN, f"≥{UMBRAL_404} 404"),
    ])

    L, R = "left", "right"
    # consumo por API
    rows_api = []
    for (svc, route), c in sorted(api.items(), key=lambda kv: -sum(kv[1].values())):
        t = sum(c.values())
        rows_api.append([(f"<b>{svc}</b><br><span style='color:{T.C_MUTED};'>{route}</span>", L, ""),
                         (T.num(t), R, ""), (T.num(c["2xx"]), R, ""), (T.num(c["4xx"]), R, ""),
                         (T.num(c["5xx"]), R, f"color:{T.C_CRIT};" if c["5xx"] else ""),
                         (fmt_ms(d["p99_route"].get(route, float('nan'))), R, "")])
    s_api = ranking([("API / ruta", None, L), ("Total", 70, R), ("2xx", 60, R), ("4xx", 60, R), ("5xx", 60, R),
                     ("p99", 70, R)], rows_api, "Sin tráfico a las APIs en las últimas 24 horas.")

    rows_c = [[(f"<b>{c}</b>", L, ""), (f"{svc}<br><span style='color:{T.C_MUTED};'>{route}</span>", L, ""),
               (T.num(sum(v.values())), R, ""), (T.num(v["2xx"]), R, ""), (T.num(v["4xx"] + v["5xx"]), R, "")]
              for (c, svc, route), v in sorted(cons.items(), key=lambda kv: -sum(kv[1].values()))[:15]]
    s_cons = ranking([("Consumidor", 150, L), ("Servicio / ruta", None, L), ("Total", 70, R), ("2xx", 60, R),
                      ("Errores", 70, R)], rows_c, "Ningún consumidor autenticado usó las APIs.")

    # ataques
    s_ips = ranking([("IP", None, L), ("Requests", 90, R)],
                    [[(mono(clean(ip, 45)) + (f' <span style="color:{T.C_MUTED};">({propia(ip)})</span>'
                                        if propia(ip) else ""), L, ""), (T.num(v), R, "")]
                     for ip, v in d["top_ips"]],
                    "Sin tráfico registrado.")
    s_umbral = ranking([("IP", None, L), ("404", 90, R)],
                       [[(mono(clean(ip, 45)), L, f"color:{T.C_CRIT};"), (T.num(v), R, "")]
                        for ip, v in atk[:15]],
                       f"Ninguna IP llegó a {UMBRAL_404} respuestas 404.")
    s_404 = ranking([("Ruta buscada", None, L), ("Veces", 80, R)],
                    [[(mono(clean(pth)), L, ""), (T.num(v), R, "")] for pth, v in d["top_404"]],
                    "Sin 404 en el período.")
    s_ua = ranking([("User-agent", None, L), ("Requests", 90, R)],
                   [[(clean(ua, 80) or "(vacío)", L, ""), (T.num(v), R, "")] for ua, v in d["top_ua"]],
                   "Sin datos.")

    # observaciones
    obs = []
    if not tot_api:
        obs.append(("Ninguna API recibió tráfico en las últimas 24 horas.", T.C_HIGH))
    if e5:
        obs.append((f"{T.num(e5)} respuestas 5xx de las APIs ({pct5:.1f}%): revisar el backend.", T.C_CRIT))
    if d["rate_limited"]:
        obs.append((f"{T.num(d['rate_limited'])} requests frenados por rate limit.", T.C_HIGH))
    if n_atk:
        obs.append((f"{n_atk} IP(s) con {UMBRAL_404} o más 404: candidatas a bloqueo (el SIEM las pone en "
                    "cuarentena automáticamente).", T.C_HIGH))
    if own:
        obs.append(("IPs propias con 404 sobre el umbral (no cuentan como ataque): " +
                    ", ".join(f"{ip} ({propia(ip)}, {T.num(v)})" for ip, v in own[:5]) +
                    ". Si el SIEM bloquea por 404, pueden quedar en cuarentena.", T.C_HIGH))
    if d["total"] and not d["c2xx"]:
        obs.append(("Nada del tráfico de Internet fue respondido con 2xx: todo lo que llegó fue rechazado "
                    "o no tenía ruta.", T.C_GREEN))
    if d["kong_up"] < 1:
        obs.append(("Prometheus no ve a Kong arriba.", T.C_CRIT))
    if not obs:
        obs.append(("Sin novedades.", T.C_GREEN))

    parts = [
        T.callout(f"Resumen de las últimas 24 horas del gateway de APIs: {T.num(tot_api)} requests a las APIs "
                  f"y {T.num(d['total'])} de Internet en total, {T.num(d['ips'])} IPs distintas.",
                  "Resumen"), T.spacer(),
        T.section("Qué mirar", "", T.bullet_list(obs)), T.spacer(),
        T.section("Consumo de las APIs", "Requests que pasaron por una ruta de Kong", cards + T.spacer(12) + s_api),
        T.spacer(),
        T.section("Por consumidor", "Quién usó qué (solo requests con key válida)", s_cons), T.spacer(),
        T.section("Tráfico de Internet y ataques", "Todo lo que llegó al gateway, con o sin API detrás",
                  cards2 + T.spacer(12) + para("<b>IPs sobre el umbral de bloqueo</b>") + s_umbral + T.spacer(12)
                  + para("<b>Rutas más buscadas con 404</b>") + s_404 + T.spacer(12)
                  + para("<b>IPs más activas</b>") + s_ips + T.spacer(12)
                  + para("<b>User-agents</b>") + s_ua), T.spacer(),
        T.section("Más detalle", "", para(
            f'Dashboard completo: <a href="{PUBLIC_URL}" style="color:{T.C_GREEN_DK};">{PUBLIC_URL}</a> · '
            f'SIEM: <a href="https://siem.grupoalemana.com" style="color:{T.C_GREEN_DK};">'
            "siem.grupoalemana.com</a>")),
    ]
    fecha = datetime.now().strftime("%d/%m/%Y")
    if only_body:  # sin el resumen inicial ni el pie de links: para embeber en otro correo
        return "".join(parts[2:-2]), "", ""
    body = "".join(parts)
    html = T.document(title="Resumen diario del gateway", subtitle=f"Kong · últimas 24 h · {fecha}",
                      body=body, badge_kind=kind, doc_title=f"Resumen diario Kong {fecha}",
                      preheader=f"{T.num(tot_api)} requests a APIs · {T.num(d['total'])} de Internet · "
                                f"{n_atk} IP(s) sobre umbral",
                      logo_src=T.logo_data_uri() or "")
    plain = ("RESUMEN DIARIO KONG (24 h) - " + fecha + "\n"
             f"APIs: {T.num(tot_api)} req, 5xx {pct5:.1f}%, p99 {fmt_ms(d['p99'])}, 429: {T.num(d['rate_limited'])}\n"
             f"Internet: {T.num(d['total'])} req, {T.num(d['ips'])} IPs, 404: {T.num(d['c404'])}, "
             f"IPs sobre umbral: {n_atk}\n" + "\n".join("- " + o for o, _ in obs) + f"\nDashboard: {PUBLIC_URL}\n")
    subj = T.subject("KONG", estado, "resumen diario", fecha)
    return html, plain, subj


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--email", action="store_true", help="enviar por correo")
    ap.add_argument("--to", action="append", default=[], help="destinatario (repetible)")
    ap.add_argument("--out", default=str(ROOT / "logs/reports/kong_daily.html"))
    a = ap.parse_args()
    html, plain, subj = build(collect())
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(html)
    print(f"HTML: {a.out} ({len(html) // 1024} KB)\nAsunto: {subj}")
    if a.email:
        if not a.to:
            sys.exit("ERROR: --email requiere --to")
        cfg = json.load(open(EMAIL_CONFIG_FILE, encoding="utf-8"))
        ok, info = T.send_report(cfg, html=html, plain=plain, subject=subj, recipients=a.to)
        print("Mail:", "enviado" if ok else "FALLÓ", info)
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
