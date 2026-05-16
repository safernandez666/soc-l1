"""Tests de LdapConfig - resolución de credenciales en orden de precedencia."""
from __future__ import annotations

import base64
from pathlib import Path

import pytest

from src.config import LdapConfig

# Password con TODOS los chars que rompen .env parsing
NASTY_PASSWORD = "=P,T\"JH57CGE;B+0$Q4@.R8NW0GO'HV~"


def test_explicit_credentials_skip_file_loading() -> None:
    """Si bind_dn y bind_password vienen explícitos, no intenta leer file."""
    cfg = LdapConfig(
        bind_dn="user@example.com",
        bind_password="secret",
        credentials_file="/nonexistent/path",  # no se va a tocar
    )
    assert cfg.bind_dn == "user@example.com"
    assert cfg.bind_password == "secret"


def test_b64_password_is_decoded() -> None:
    """LDAP_BIND_PASSWORD_B64 se decodea correctamente."""
    b64 = base64.b64encode(NASTY_PASSWORD.encode("utf-8")).decode("ascii")
    cfg = LdapConfig(
        bind_dn="user@example.com",
        bind_password_b64=b64,
        credentials_file="/nonexistent/path",
    )
    assert cfg.bind_password == NASTY_PASSWORD


def test_direct_password_takes_precedence_over_b64() -> None:
    """Si ambos están, bind_password directo gana."""
    b64 = base64.b64encode(b"from-b64").decode("ascii")
    cfg = LdapConfig(
        bind_dn="user@example.com",
        bind_password="from-direct",
        bind_password_b64=b64,
        credentials_file="/nonexistent/path",
    )
    assert cfg.bind_password == "from-direct"


def test_invalid_b64_raises_clear_error() -> None:
    """Si LDAP_BIND_PASSWORD_B64 no es base64 válido, error claro."""
    with pytest.raises(ValueError, match="LDAP_BIND_PASSWORD_B64 inválido"):
        LdapConfig(
            bind_dn="user@example.com",
            bind_password_b64="not-base64-!!!",
            credentials_file="/nonexistent/path",
        )


def test_credentials_file_loading(tmp_path: Path) -> None:
    """Si bind_dn/password vacíos pero existe credentials_file, los toma de ahí."""
    creds = tmp_path / "ad_creds"
    creds.write_text(f"AD_USER=svc@example.com\nAD_PASSWORD={NASTY_PASSWORD}\n", encoding="utf-8")
    cfg = LdapConfig(credentials_file=str(creds))
    assert cfg.bind_dn == "svc@example.com"
    assert cfg.bind_password == NASTY_PASSWORD


def test_missing_everything_raises() -> None:
    """Sin ninguna fuente → ValueError claro."""
    with pytest.raises(ValueError, match="bind_dn vacío"):
        LdapConfig(credentials_file="/nonexistent/path")


def test_b64_overrides_credentials_file_password(tmp_path: Path) -> None:
    """Si b64 está seteado, gana sobre lo que diga el credentials_file."""
    creds = tmp_path / "ad_creds"
    creds.write_text("AD_USER=svc@example.com\nAD_PASSWORD=from-file\n", encoding="utf-8")
    b64 = base64.b64encode(b"from-b64").decode("ascii")
    cfg = LdapConfig(bind_password_b64=b64, credentials_file=str(creds))
    assert cfg.bind_dn == "svc@example.com"  # bind_dn vino del file
    assert cfg.bind_password == "from-b64"  # password ganó b64
