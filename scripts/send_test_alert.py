#!/usr/bin/env python3
"""Envía una alerta sintética al webhook de soc-l1 con HMAC válido.

Usa el fixture por default (Defender keygen) o cualquier JSON que le pases.

Uso:
  python3 scripts/send_test_alert.py
  python3 scripts/send_test_alert.py path/to/alert.json
  cat my_alert.json | python3 scripts/send_test_alert.py -
  python3 scripts/send_test_alert.py --url http://localhost:8000/webhook/wazuh-alert
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path


def find_env(start: Path) -> Path | None:
    """Busca .env caminando hacia arriba desde start."""
    p = start.resolve()
    while p != p.parent:
        candidate = p / ".env"
        if candidate.exists():
            return candidate
        p = p.parent
    return None


def _read_secret_from(path: Path) -> str | None:
    """Si el .env del path tiene WAZUH_WEBHOOK_SECRET, lo devuelve. Si no, None."""
    if not path.exists():
        return None
    for line in path.read_text().splitlines():
        if line.startswith("WAZUH_WEBHOOK_SECRET="):
            value = line.split("=", 1)[1].strip().strip("\"'")
            if value:
                return value
    return None


def load_secret() -> str:
    """Busca WAZUH_WEBHOOK_SECRET en orden:
      1. .env del directorio del script (soc-l1 root) - el más confiable
      2. .env caminando hacia arriba desde cwd

    Esto evita el bug de tomar ~/.env del usuario (que puede existir por otras
    razones y no tener el secret de soc-l1).
    """
    # 1. Prioridad: .env junto al código de soc-l1
    script_env = Path(__file__).resolve().parent.parent / ".env"
    secret = _read_secret_from(script_env)
    if secret:
        return secret

    # 2. Fallback: walk desde cwd
    cwd_env = find_env(Path.cwd())
    if cwd_env:
        secret = _read_secret_from(cwd_env)
        if secret:
            return secret
        sys.exit(f"WAZUH_WEBHOOK_SECRET no encontrado en {cwd_env}")

    sys.exit(
        f"No encontré .env (probé {script_env} y subiendo desde {Path.cwd()})"
    )


def default_fixture() -> Path:
    """tests/fixtures/defender_keygen.json relativo al root del repo."""
    here = Path(__file__).resolve().parent
    return here.parent / "tests" / "fixtures" / "defender_keygen.json"


def main() -> int:
    ap = argparse.ArgumentParser(description="Send synthetic alert to soc-l1 webhook")
    ap.add_argument(
        "fixture",
        nargs="?",
        default=str(default_fixture()),
        help="Path to JSON file (or - for stdin). Default: defender_keygen.json fixture",
    )
    ap.add_argument(
        "--url",
        default="http://localhost:8000/webhook/wazuh-alert",
        help="Webhook URL (default: localhost:8000)",
    )
    ap.add_argument(
        "--timeout", type=int, default=10, help="HTTP timeout in seconds (default: 10)"
    )
    args = ap.parse_args()

    if args.fixture == "-":
        payload = sys.stdin.buffer.read()
        source_desc = "stdin"
    else:
        path = Path(args.fixture)
        if not path.exists():
            sys.exit(f"FAIL: no existe {path}")
        payload = path.read_bytes()
        source_desc = str(path)

    # Validar que es JSON (sin reformatear - HMAC debe ser sobre bytes exactos)
    try:
        json.loads(payload)
    except json.JSONDecodeError as e:
        sys.exit(f"FAIL: {source_desc} no es JSON válido: {e}")

    secret = load_secret()
    sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    print(f"Source:    {source_desc}")
    print(f"Body:      {len(payload)} bytes")
    print(f"Signature: {sig[:30]}...")
    print(f"POST:      {args.url}")
    print()

    req = urllib.request.Request(
        args.url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Wazuh-Signature": sig,
            "User-Agent": "soc-l1-test/1.0",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as resp:
            code = resp.getcode()
            body = resp.read().decode("utf-8", errors="replace")
            print(f"<- {code}")
            print(f"   {body}")
            return 0 if 200 <= code < 300 else 1
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"<- {e.code} {e.reason}")
        print(f"   {body}")
        return 1
    except urllib.error.URLError as e:
        print(f"<- Error de red: {e.reason}")
        print("  (el servicio uvicorn está corriendo? curl http://localhost:8000/health)")
        return 2


if __name__ == "__main__":
    sys.exit(main())
