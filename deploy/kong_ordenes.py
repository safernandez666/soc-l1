#!/usr/bin/env python3
"""Publica la API de Ordenes de Trabajo (OT Dynamics, Fase 1) en Kong.

Corre EN EL HOST DE KONG (192.168.38.62), donde el Admin API es alcanzable. Solo stdlib.

  python3 kong_ordenes.py --dry-run     # solo lee: muestra que crearia/cambiaria
  python3 kong_ordenes.py               # aplica (hace backup antes)
  python3 kong_ordenes.py --rollback    # borra TODO lo que creo este script (por tag)

Fase 1 = solo lectura: las rutas aceptan GET, y POST unicamente en /api/token.
/state y /health NO se publican. Para habilitar la Fase 2 (POST/PUT) agregar los
metodos en ROUTES a proposito, no por accidente.
"""
import argparse
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request

TAG = "ordenes-api"
SERVICE = "ordenes-api"
CONSUMER = "ordenes-integracion"


def routes(hosts):
    r = lambda name, paths, methods: {  # noqa: E731
        "name": name, "hosts": list(hosts), "paths": paths, "methods": methods,
        "strip_path": False, "protocols": ["http", "https"], "tags": [TAG]}
    return [
        r("ordenes-token", ["/api/token"], ["POST"]),
        r("ordenes-gestion-f1", ["/api/MsGestion/"], ["GET"]),
        r("ordenes-ot-f1", ["/api/MsOrdenTrabajo/"], ["GET"]),
    ]


# (scope, nombre-del-scope, plugin, config)
PLUGINS = [
    ("services", SERVICE, "key-auth", {"key_names": ["apikey"], "hide_credentials": True}),
    ("services", SERVICE, "rate-limiting",
     {"minute": 300, "policy": "local", "limit_by": "consumer", "fault_tolerant": True}),
    # El login es el blanco de fuerza bruta: tope bajo y cuerpo chico.
    ("routes", "ordenes-token", "rate-limiting",
     {"minute": 10, "hour": 60, "policy": "local", "limit_by": "consumer"}),
    ("routes", "ordenes-token", "request-size-limiting",
     {"allowed_payload_size": 1, "size_unit": "megabytes"}),
]


class Kong:
    def __init__(self, admin):
        self.admin = admin.rstrip("/")

    def call(self, method, path, body=None):
        req = urllib.request.Request(
            self.admin + path, method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, raw.decode(errors="replace")

    def get(self, path):
        code, data = self.call("GET", path)
        if code == 404:
            return None
        if code != 200:
            sys.exit(f"GET {path} -> {code}: {data}")
        return data


def differs(want, have):
    """True si algun campo pedido no coincide con lo existente (subset compare)."""
    for k, v in want.items():
        h = have.get(k)
        if isinstance(v, dict) and isinstance(h, dict):
            if differs(v, h):
                return True
        elif isinstance(v, list) and isinstance(h, list):
            if sorted(map(str, v)) != sorted(map(str, h)):
                return True
        elif h != v:
            return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--admin", default=os.environ.get("KONG_ADMIN_URL", "http://127.0.0.1:8001"))
    ap.add_argument("--host", action="append", help="hostname publico que atiende la ruta; repetible "
                    "(default: ordenes.grupoalemana.com)")
    ap.add_argument("--upstream", default="http://172.16.1.35:8080",
                    help="backend; cambiar a https://...:443 cuando Matias migre")
    ap.add_argument("--preserve-host", action="store_true", help="mandar el Host publico al backend")
    ap.add_argument("--no-key", action="store_true", help="no crear API key (se emite a mano, fuera de este log)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--rollback", action="store_true")
    a = ap.parse_args()
    k = Kong(a.admin)
    dry = a.dry_run

    if k.get("/status") is None:
        sys.exit(f"No llego al Admin API en {a.admin}. Correr en el host de Kong o pasar --admin.")

    if a.rollback:
        return rollback(k, dry)

    proto, rest = a.upstream.split("://", 1)
    uhost, _, uport = rest.partition(":")
    service = {
        "name": SERVICE, "protocol": proto, "host": uhost,
        "port": int(uport or (443 if proto == "https" else 80)),
        "connect_timeout": 5000,
        "read_timeout": 130000,   # /ordentrabajo/agregar (Fase 2) pide >=120 s
        "write_timeout": 130000,
        "retries": 0,             # no reintentar: las escrituras no son idempotentes
        "tags": [TAG],
    }
    if proto == "https":
        service["tls_verify"] = True   # wildcard Sectigo publico; el SNI sale del host del servicio

    if not dry:
        backup(k)

    def ensure(path_collection, name, want):
        have = k.get(f"{path_collection}/{name}")
        if have is None:
            print(f"  + crear   {path_collection}/{name}")
            if not dry:
                code, d = k.call("POST", path_collection, want)
                if code not in (200, 201):
                    sys.exit(f"POST {path_collection} -> {code}: {d}")
        elif differs({k_: v for k_, v in want.items() if k_ != "service"}, have):
            print(f"  ~ cambiar {path_collection}/{name}")
            if not dry:
                code, d = k.call("PATCH", f"{path_collection}/{name}", want)
                if code != 200:
                    sys.exit(f"PATCH {path_collection}/{name} -> {code}: {d}")
        else:
            print(f"  = igual   {path_collection}/{name}")

    print("Servicio")
    ensure("/services", SERVICE, service)
    print("Rutas")
    for rt in routes(a.host or ["ordenes.grupoalemana.com"]):
        rt = dict(rt, preserve_host=a.preserve_host, service={"name": SERVICE})
        ensure("/routes", rt["name"], rt)
    print("Plugins")
    for scope, name, plugin, config in PLUGINS:
        have = k.get(f"/{scope}/{name}/plugins")
        cur = next((p for p in (have or {}).get("data", []) if p["name"] == plugin), None)
        label = f"{scope}/{name}: {plugin}"
        if cur is None:
            print(f"  + crear   {label}")
            if not dry:
                code, d = k.call("POST", f"/{scope}/{name}/plugins",
                                 {"name": plugin, "config": config, "tags": [TAG]})
                if code not in (200, 201):
                    sys.exit(f"POST plugin {label} -> {code}: {d}")
        elif differs({"config": config}, cur):
            print(f"  ~ cambiar {label}")
            if not dry:
                k.call("PATCH", f"/plugins/{cur['id']}", {"config": config})
        else:
            print(f"  = igual   {label}")

    print("Consumer + API key")
    if k.get(f"/consumers/{CONSUMER}") is None:
        print(f"  + crear   consumer {CONSUMER}")
        if not dry:
            k.call("POST", "/consumers", {"username": CONSUMER, "tags": [TAG]})
    keys = (k.get(f"/consumers/{CONSUMER}/key-auth") or {}).get("data", [])
    if keys:
        print("  = igual   ya tiene API key (no se vuelve a mostrar; para rotar: --rollback y reaplicar)")
    elif a.no_key:
        print("  - omitido API key (--no-key)")
    else:
        print("  + crear   API key")
        if not dry:
            key = secrets.token_urlsafe(32)
            code, d = k.call("POST", f"/consumers/{CONSUMER}/key-auth", {"key": key, "tags": [TAG]})
            if code not in (200, 201):
                sys.exit(f"POST key-auth -> {code}: {d}")
            print("\n  API KEY (se muestra UNA vez, guardarla ya en un gestor de secretos):")
            print(f"  {key}\n")

    print("\nDRY-RUN: no se toco nada." if dry else "\nListo. Rollback: --rollback")


def backup(k):
    snap = {c: (k.get(f"/{c}?size=1000") or {}).get("data", [])
            for c in ("services", "routes", "plugins", "consumers")}
    fn = f"kong-backup-{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}.json"
    fd = os.open(fn, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(snap, f, indent=1)
    print(f"Backup: {os.path.abspath(fn)}")


def rollback(k, dry):
    print("Rollback (solo lo taggeado '%s')" % TAG)
    for kind in ("plugins", "routes", "services", "consumers"):
        for e in (k.get(f"/{kind}?tags={TAG}&size=1000") or {}).get("data", []):
            ident = e.get("name") or e.get("username") or e["id"]
            print(f"  - borrar {kind}/{ident}")
            if not dry:
                k.call("DELETE", f"/{kind}/{e['id']}")


if __name__ == "__main__":
    main()
