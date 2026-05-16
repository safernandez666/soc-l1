"""Verificación HMAC del webhook Wazuh.

El integrator custom-n8n firma el body con HMAC-SHA256 usando un secret
compartido, en el header X-Wazuh-Signature: sha256=<hex>.
"""
from __future__ import annotations

import hashlib
import hmac


def verify_wazuh_signature(secret: str, body: bytes, signature_header: str | None) -> bool:
    """Devuelve True si la firma HMAC es válida.

    secret: el shared secret (typicalmente del .env WAZUH_WEBHOOK_SECRET)
    body: bytes del raw body del request
    signature_header: valor del header X-Wazuh-Signature (ej: "sha256=abc123...")
    """
    if not secret or not signature_header:
        return False
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    actual = signature_header.removeprefix("sha256=").strip()
    return hmac.compare_digest(expected, actual)
