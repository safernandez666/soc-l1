#!/usr/bin/env python3
"""Wazuh integrator para soc-l1.

Recibe alertas de Wazuh manager, las firma con HMAC-SHA256 y las postea
al webhook del servicio soc-l1.

Wazuh invoca este script con argv:
  argv[1] = path al archivo JSON de la alerta
  argv[2] = api_key  -> usado como SHARED_SECRET HMAC (matchea WAZUH_WEBHOOK_SECRET del .env)
  argv[3] = hook_url -> URL del webhook (ej. http://localhost:8000/webhook/wazuh-alert)
  argv[4] = (opcional) options-file

Solo stdlib (no requiere instalar nada extra).
"""

import hashlib
import hmac
import json
import os
import sys
import time
from urllib import request as urlrequest
from urllib.error import HTTPError, URLError

LOG_FILE = "/var/ossec/logs/integrations.log"
TIMEOUT_SECS = 10
MAX_RETRIES = 3
RETRY_BACKOFF_SECS = 2
INTEGRATION_NAME = "custom-soc-l1"


def log(msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {INTEGRATION_NAME}: {msg}\n"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        sys.stderr.write(line)


def read_alert(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def sign(secret: str, body: bytes) -> str:
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def post(url: str, body: bytes, signature: str) -> None:
    req = urlrequest.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"wazuh-integrator-{INTEGRATION_NAME}/1.0",
            "X-Wazuh-Signature": signature,
        },
    )
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with urlrequest.urlopen(req, timeout=TIMEOUT_SECS) as resp:
                code = resp.getcode()
                log(f"POST {url} -> {code} (attempt {attempt})")
                if 200 <= code < 300:
                    return
                last_err = f"HTTP {code}"
        except HTTPError as e:
            last_err = f"HTTPError {e.code}: {e.reason}"
            log(f"attempt {attempt} failed: {last_err}")
            if 400 <= e.code < 500 and e.code != 429:
                break  # 4xx no retryable except 429
        except URLError as e:
            last_err = f"URLError: {e.reason}"
            log(f"attempt {attempt} failed: {last_err}")
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
            log(f"attempt {attempt} failed: {last_err}")
        time.sleep(RETRY_BACKOFF_SECS * attempt)
    log(f"giving up after {MAX_RETRIES} attempts: {last_err}")
    sys.exit(2)


def main(argv: list) -> int:
    if len(argv) < 4:
        log(f"usage: {INTEGRATION_NAME}.py <alert_file> <api_key> <hook_url> [options]; got {argv}")
        return 1

    alert_file, api_key, hook_url = argv[1], argv[2], argv[3]

    if not api_key or api_key == "-":
        log("missing api_key (HMAC secret) - configure <api_key> in ossec.conf integration block")
        return 1

    try:
        alert = read_alert(alert_file)
    except (OSError, json.JSONDecodeError) as e:
        log(f"cannot read alert file {alert_file}: {e}")
        return 1

    # IMPORTANTE: usamos separators sin espacios para que el body que firmamos
    # acá sea byte-a-byte idéntico a lo que recibe el verificador del otro lado.
    payload = {"alert": alert, "integration": INTEGRATION_NAME}
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    signature = sign(api_key, body)

    rule = alert.get("rule", {})
    log(
        f"sending alert rule_id={rule.get('id')} level={rule.get('level')} bytes={len(body)}"
    )

    post(hook_url, body, signature)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
