"""Auth del panel /ui: login por password compartido + cookie de sesión firmada.

Sin dependencias nuevas: la cookie se firma con HMAC-SHA256 (hmac/hashlib stdlib).
Formato de la cookie:  base64url(payload) "." base64url(sig)
  payload = '<exp_epoch_utc>'   (entero, segundos)
  sig     = HMAC(secret, payload)

El panel es solo-lectura, así que la cookie no transporta identidad ni permisos:
solo prueba "este browser pasó el login y la sesión no expiró".
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import time

from src.config import Settings

logger = logging.getLogger("soc-l1")

COOKIE_NAME = "soc_l1_session"

# Rate-limit en memoria para /ui/login (password compartido → blanco de brute-force).
# Ventana deslizante de intentos fallidos por IP. Single-process uvicorn, así que un
# dict en memoria alcanza; no persiste entre restarts (aceptable para un throttle).
_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_WINDOW_SECONDS = 300
_login_attempts: dict[str, list[float]] = {}


def login_rate_limited(ip: str) -> bool:
    """True si la IP superó el máximo de intentos fallidos en la ventana."""
    now = time.time()
    recent = [t for t in _login_attempts.get(ip, []) if now - t < _LOGIN_WINDOW_SECONDS]
    _login_attempts[ip] = recent
    return len(recent) >= _LOGIN_MAX_ATTEMPTS


def record_login_failure(ip: str) -> None:
    _login_attempts.setdefault(ip, []).append(time.time())


def clear_login_attempts(ip: str) -> None:
    _login_attempts.pop(ip, None)


def _secret(settings: Settings) -> bytes:
    """Secreto para firmar. Usa dashboard_session_secret; si está vacío, deriva
    del webhook secret (siempre presente) para no requerir config extra."""
    raw = settings.dashboard_session_secret or ("dash:" + settings.wazuh_webhook_secret)
    return hashlib.sha256(raw.encode("utf-8")).digest()


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def password_ok(settings: Settings, candidate: str) -> bool:
    """Compara el password en tiempo constante. Password vacío en config = deshabilitado."""
    expected = settings.dashboard_password or ""
    if not settings.dashboard_enabled or not expected:
        return False
    return hmac.compare_digest(candidate.encode("utf-8"), expected.encode("utf-8"))


def issue_session(settings: Settings) -> str:
    """Crea el valor de cookie firmado con expiración dashboard_session_hours."""
    exp = int(time.time()) + settings.dashboard_session_hours * 3600
    payload = str(exp).encode("ascii")
    sig = hmac.new(_secret(settings), payload, hashlib.sha256).digest()
    return f"{_b64e(payload)}.{_b64e(sig)}"


def session_valid(settings: Settings, cookie_value: str | None) -> bool:
    """True si la cookie es válida (firma correcta + no expirada)."""
    if not cookie_value or "." not in cookie_value:
        return False
    try:
        payload_b64, sig_b64 = cookie_value.split(".", 1)
        payload = _b64d(payload_b64)
        sig = _b64d(sig_b64)
    except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
        return False
    expected_sig = hmac.new(_secret(settings), payload, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected_sig):
        return False
    try:
        exp = int(payload.decode("ascii"))
    except ValueError:
        return False
    return time.time() < exp


def cookie_max_age(settings: Settings) -> int:
    return settings.dashboard_session_hours * 3600
