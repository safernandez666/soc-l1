#!/usr/bin/env python3
"""Prueba de humo del camino real a la API de Ordenes publicada en Kong.

Solo stdlib (corre en Kali, Mac o cualquier equipo con python3). Hace GET/PUT/POST inocuos: el
unico POST va sin credenciales y sin key, asi que Kong lo corta antes del backend. La key
se toma de ORD_APIKEY o se pide sin eco; nunca se imprime ni se escribe en disco.

  python3 probar_kong_ordenes.py                  # --modo auto: elige LAN o WAN segun a donde resuelve gateway
  python3 probar_kong_ordenes.py --modo lan       # directo a Kong https://192.168.38.62:8443 (cert autofirmado)
  python3 probar_kong_ordenes.py --modo wan       # por Internet: https://gateway.grupoalemana.com, TLS verificado

LAN prueba Kong + backend sin pasar por FortiGate; WAN prueba el camino completo Internet -> FortiGate
-> Kong -> IIS (correrlo desde afuera: 4G, Kali). Desde la LAN, gateway resuelve al nginx de Grafana.
Con --base se ignora --modo (control manual; --host-header e --insecure siguen valiendo).

En una terminal pide apikey, usuario ERP y password (sin eco; o ORD_APIKEY / ORD_USER / ORD_PASS),
y agrega la prueba 5: POST /api/token y un GET de lectura con apikey + Bearer. Ojo: el login real
queda en el log del ERP; avisar a Matias/Juan antes. --sin-login lo omite; sin terminal
(cron, pipes) tampoco corre salvo --login u ORD_USER.

Colores: se activan solos en una terminal; --no-color o NO_COLOR los apagan, --color los fuerza.
Sale con codigo 0 si todo coincide con lo esperado, 1 si alguna prueba falla.
"""
import argparse
import getpass
import ipaddress
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

COMBO = "/api/MsGestion/abm/alicuotas/combo"
ZONAS = "/api/MsOrdenTrabajo/abm/zonas/combo"   # lectura de la coleccion Postman de Fase 1
EMPRESA = 8                                      # Cirugia Alemana
ANCHO = 78
GATEWAY = "gateway.grupoalemana.com"
LAN_BASE = "https://192.168.38.62:8443"


class C:
    """Codigos ANSI; todo vacio si no hay colores."""
    on = False

    @classmethod
    def s(cls, txt, *codes):
        return f"\033[{';'.join(codes)}m{txt}\033[0m" if cls.on and codes else str(txt)


def ok(t): return C.s(t, "1", "32")          # verde fuerte
def bad(t): return C.s(t, "1", "31")         # rojo fuerte
def warn(t): return C.s(t, "1", "33")        # amarillo
def dim(t): return C.s(t, "2")               # gris
def hl(t): return C.s(t, "1", "36")          # cian: dato clave
def sec(t): return C.s(t, "1", "34")         # azul: seccion


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def request(base, path, method="GET", headers=None, data=None, ctx=None):
    """-> (status, headers en minusculas, segundos). Los 4xx/5xx no son excepcion."""
    req = urllib.request.Request(base + path, method=method, data=data, headers=headers or {})
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    t0 = time.perf_counter()
    try:
        resp = opener.open(req, timeout=20)
    except urllib.error.HTTPError as e:
        resp = e
    except (urllib.error.URLError, OSError) as e:
        return None, {"error": str(getattr(e, "reason", e))}, time.perf_counter() - t0
    return resp.status if hasattr(resp, "status") else resp.code, \
        {k.lower(): v for k, v in resp.headers.items()}, time.perf_counter() - t0


def color_ms(ms):
    t = f"{ms:>5.0f} ms"
    return ok(t) if ms < 300 else warn(t) if ms < 1000 else bad(t)


def detectar_vpn():
    """(en_vpn, detalle): la red de Grupo Alemana es alcanzable (Kong LAN) y el gateway resuelve a IP privada."""
    host, port = LAN_BASE.split("//")[1].split(":")
    try:
        ip_gw = socket.gethostbyname(GATEWAY)
    except OSError:
        ip_gw = None
    try:
        socket.create_connection((host, int(port)), timeout=3).close()
        lan = True
    except OSError:
        lan = False
    priv = bool(ip_gw) and ipaddress.ip_address(ip_gw).is_private
    detalle = f"{GATEWAY} -> {ip_gw or 'no resuelve'}  ·  Kong LAN {host}:{port} " + ("alcanzable" if lan else "NO alcanzable")
    return lan or priv, detalle


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--modo", choices=("auto", "lan", "wan"), default="auto",
                    help="lan: directo a Kong; wan: por Internet; auto: segun a donde resuelve gateway")
    ap.add_argument("--base", help="URL base manual (anula --modo)")
    ap.add_argument("--host-header", help="Host a enviar (si --base es una IP)")
    ap.add_argument("--insecure", action="store_true", help="no verificar el certificado TLS")
    ap.add_argument("--login", action="store_true", help="forzar la prueba 5 aunque no haya terminal")
    ap.add_argument("--sin-login", action="store_true", help="omitir la prueba 5 (login ERP real)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--no-color", action="store_true", help="sin colores")
    g.add_argument("--color", action="store_true", help="forzar colores aunque no sea una terminal")
    a = ap.parse_args()
    C.on = a.color or (sys.stdout.isatty() and not a.no_color and "NO_COLOR" not in os.environ)

    modo = "manual"
    if not a.base:
        modo = a.modo
        if modo == "auto":
            try:
                modo = "lan" if ipaddress.ip_address(socket.gethostbyname(GATEWAY)).is_private else "wan"
            except OSError:
                modo = "wan"
        if modo == "lan":
            a.base, a.insecure, a.host_header = LAN_BASE, True, a.host_header or GATEWAY
        else:
            a.base = "https://" + GATEWAY

    key = os.environ.get("ORD_APIKEY") or getpass.getpass("apikey (sin eco): ")
    ctx = ssl.create_default_context()
    if a.insecure:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    base = a.base.rstrip("/")
    # El borde (FortiGate) responde 403 al UA por defecto de urllib ("Python-urllib/3.x"): hay que mandar uno propio.
    h = {"User-Agent": "probar-kong-ordenes/1.0"}
    if a.host_header:
        h["Host"] = a.host_header
    hk = {**h, "apikey": key}
    resultados = []  # (ok, que comprueba)

    def check(nombre, que, esperado, res, extra=None):
        """esperado: (status, server-substring). extra: {header: substring} adicionales."""
        st, hd, _ = res
        srv = hd.get("server", "")
        paso = st == esperado[0] and esperado[1].lower() in srv.lower()
        for k, v in (extra or {}).items():
            paso = paso and v.lower() in hd.get(k, "").lower()
        resultados.append((paso, que))
        marca = ok(" OK ") if paso else bad("FAIL")
        if st is None:
            print(f" [{marca}] {nombre}\n         {bad('sin respuesta: ' + hd['error'])}")
            return
        col = ok if paso else bad
        print(f" [{marca}] {C.s(nombre, '1')}")
        det = f"{col(st)}  server={hl(srv) if paso else bad(srv or '-')}"
        for k in (extra or {}):
            det += f"  {dim(k + '=')}{hd.get(k, '-')}"
        print(f"         {det}")
        if not paso:
            print(f"         {warn('esperado:')} {esperado[0]} / server~{esperado[1]}"
                  + "".join(f" / {k}~{v}" for k, v in (extra or {}).items()))

    def seccion(t):
        print(f"\n{sec('━━ ' + t + ' ' + '━' * max(2, ANCHO - len(t) - 4))}")

    print(sec("═" * ANCHO))
    print(C.s("  PRUEBA DEL CAMINO REAL · API de Órdenes en Kong", "1") + f"  [{modo.upper()}]")
    print(f"  {dim('destino')}  {hl(base)}" + (f"  {dim('Host:')} {a.host_header}" if a.host_header else ""))
    print(f"  {dim('origen ')}  {socket.gethostname()}  ·  {datetime.now():%Y-%m-%d %H:%M:%S}")
    en_vpn, det_vpn = detectar_vpn()
    print(f"  {dim('red    ')}  " + (ok("EN LA VPN / red de Grupo Alemana") if en_vpn
                                   else warn("FUERA de la VPN (Internet)")))
    print(f"           {dim(det_vpn)}")
    print(sec("═" * ANCHO))

    st0, hd0, _ = request(base, COMBO, headers=h, ctx=ctx)
    if st0 is None or "kong" not in hd0.get("server", "").lower():
        print(f"\n {warn('⚠ AVISO')} la primera respuesta no es de Kong "
              f"(status={st0}, server={hd0.get('server', hd0.get('error', '-'))}).")
        print(dim("   Si estás en la red interna/VPN, gateway.grupoalemana.com resuelve al nginx de Grafana.\n"
                  "   Probar con --modo lan (directo a Kong) o desde una red externa."))

    seccion("1 · Kong corta ANTES del backend (sin credenciales)")
    check("GET combo sin key", "Llega a Kong y exige API key", (401, "kong"),
          request(base, COMBO, headers=h, ctx=ctx), {"www-authenticate": "Key"})
    check("POST /api/token sin key", "El login no llega al backend sin key", (401, "kong"),
          request(base, "/api/token", "POST", {**h, "Content-Type": "application/json"}, b"{}", ctx),
          {"www-authenticate": "Key"})

    seccion("2 · Con key llega al BACKEND (IIS)")
    check("GET combo con key", "Pasa key-auth y llega al IIS (limite 300/min)", (401, "microsoft-iis"),
          request(base, COMBO, headers=hk, ctx=ctx),
          {"www-authenticate": "Bearer", "x-ratelimit-limit-minute": "300", "via": "kong"})

    seccion("3 · Superficie expuesta (todo esto debe dar 404 de Kong)")
    check("GET /api/otra (ruta inexistente)", "No hay demo ni rutas sobrantes bajo /api", (404, "kong"),
          request(base, "/api/otra", headers=h, ctx=ctx))
    check("PUT con key (ruta de solo lectura)", "No hay camino de escritura hacia el ERP", (404, "kong"),
          request(base, COMBO, "PUT", hk, ctx=ctx))
    check("GET /admin-api/status", "El Admin API de Kong no se expone", (404, "kong"),
          request(base, "/admin-api/status", headers=h, ctx=ctx))

    seccion("4 · Latencia (con key, 3 intentos; el 1ro puede ser arranque en frío del IIS)")
    ts = []
    for i in range(3):
        st, hd, dt = request(base, COMBO, headers=hk, ctx=ctx)
        ts.append(dt * 1000)
        barra = "█" * max(1, min(40, int(dt * 1000 / 25)))
        print(f"   intento {i + 1}  {color_ms(dt * 1000)}  {dim(barra)}  "
              f"{dim('upstream=' + hd.get('x-kong-upstream-latency', '-') + ' ms')}")
    lento = ts[2] > 1000
    resultados.append((not lento, "Latencia normal una vez en caliente (< 1 s)"))
    print(f" [{bad('FAIL') if lento else ok(' OK ')}] {C.s('3er intento < 1000 ms', '1')}")

    if a.login or (not a.sin_login and (sys.stdin.isatty() or os.environ.get("ORD_USER"))):
        seccion("5 · Login ERP real + GET de lectura (apikey + Bearer)")
        user = os.environ.get("ORD_USER") or input("   usuario ERP: ")
        pw = os.environ.get("ORD_PASS") or getpass.getpass("   password (sin eco): ")
        emp = int(os.environ.get("ORD_EMPRESA") or input(f"   EmpresaId [{EMPRESA}]: ") or EMPRESA)
        body = json.dumps({"Usuario": user, "Password": pw, "EmpresaId": emp}).encode()
        del pw
        req = urllib.request.Request(base + "/api/token", method="POST", data=body,
                                     headers={**hk, "Content-Type": "application/json"})
        token, st = None, None
        try:
            r = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx)).open(req, timeout=20)
            st = r.status
            d = json.load(r).get("Datos")
            token = (d.get("Token") if isinstance(d, dict) else d[0].get("Token")) if d else None
        except urllib.error.HTTPError as e:
            st = e.code
        except Exception as e:
            st = type(e).__name__
        del body
        paso = bool(token)
        resultados.append((paso, "Login ERP real devuelve token"))
        print(f" [{ok(' OK ') if paso else bad('FAIL')}] {C.s('POST /api/token con usuario real', '1')}\n"
              f"         status={st}  {dim('token=' + str(len(token)) + ' chars, no se imprime') if paso else ''}")
        if paso:
            hb = {**hk, "Authorization": "Bearer " + token}
            st, hd, dt = request(base, ZONAS, headers=hb, ctx=ctx)
            # lectura con datos: 200, via kong, Datos con filas ZonaID/Descripcion (no se imprimen)
            filas, cols = None, False
            if st == 200:
                try:
                    rq = urllib.request.Request(base + ZONAS, headers=hb)
                    d = json.load(urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx)).open(rq, timeout=20))
                    filas = d.get("Datos") or []
                    cols = bool(filas) and not d.get("HayError") and {"ZonaID", "Descripcion"} <= set(filas[0])
                except Exception:
                    pass
            paso2 = st == 200 and "kong" in hd.get("via", "").lower() and cols
            resultados.append((paso2, "Lectura autenticada con datos (zonas/combo)"))
            print(f" [{ok(' OK ') if paso2 else bad('FAIL')}] {C.s('GET zonas/combo con key + Bearer', '1')}\n"
                  f"         status={st}  filas={filas if filas is not None else '-'}  "
                  f"server={hd.get('server', '-')}  {dim(f'{dt * 1000:.0f} ms')}")
            # recurso inexistente: el backend contesta 404 EndpointIncorrecto (no Kong)
            st, hd, _ = request(base, "/api/MsOrdenTrabajo/abm/no_existe_xyz/combo", headers=hb, ctx=ctx)
            try:
                rq = urllib.request.Request(base + "/api/MsOrdenTrabajo/abm/no_existe_xyz/combo", headers=hb)
                urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx)).open(rq, timeout=20)
                cod = None
            except urllib.error.HTTPError as e:
                try:
                    cod = json.load(e).get("ListaErrores", [{}])[0].get("CodigoError")
                except Exception:
                    cod = None
            except Exception:
                cod = None
            paso3 = st == 404 and cod == "EndpointIncorrecto"
            resultados.append((paso3, "Error de negocio llega intacto (404 EndpointIncorrecto)"))
            print(f" [{ok(' OK ') if paso3 else bad('FAIL')}] {C.s('GET recurso inexistente con Bearer', '1')}\n"
                  f"         status={st}  CodigoError={cod}")
        del token

    seccion("RESUMEN")
    for paso, que in resultados:
        print(f"  {ok('✔') if paso else bad('✘')}  {que if paso else bad(que)}")
    fallas = sum(not p for p, _ in resultados)
    print()
    if fallas:
        print(C.s(f"  ✘ {fallas} DE {len(resultados)} PRUEBAS FALLARON  ", "1", "97", "41"))
    else:
        print(C.s(f"  ✔ TODO OK · {len(resultados)} DE {len(resultados)} PRUEBAS  ", "1", "30", "42"))
    print()
    return 1 if fallas else 0


if __name__ == "__main__":
    sys.exit(main())
