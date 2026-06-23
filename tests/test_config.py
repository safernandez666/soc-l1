"""Tests de LdapConfig - resolución de credenciales en orden de precedencia."""
from __future__ import annotations

import base64
from pathlib import Path

import pytest

from src.config import LdapConfig, Settings

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


# ===== DRY_RUN granular por familia (kill-switch duro) =====


def test_dry_run_master_on_forces_all_families() -> None:
    """Kill-switch duro: master=true simula TODO, ignorando overrides por familia."""
    s = Settings(
        openai_api_key="x",
        dry_run_mode=True,
        dry_run_fortigate="false",  # intenta ejecutar, pero el master gana
        dry_run_defender="false",
        dry_run_ad="false",
    )
    assert s.dry_run_for("block_ip") is True
    assert s.dry_run_for("scan_host") is True
    assert s.dry_run_for("disable_user") is True
    assert s.dry_run_state() == {"ad": True, "fortigate": True, "defender": True}


def test_dry_run_master_off_no_overrides_executes_all() -> None:
    """master=false y sin overrides → todo ejecuta (hereda master=false)."""
    s = Settings(openai_api_key="x", dry_run_mode=False)
    assert s.dry_run_for("block_ip") is False
    assert s.dry_run_for("scan_host") is False
    assert s.dry_run_for("force_password_change") is False


def test_dry_run_per_family_overrides_when_master_off() -> None:
    """El caso del cutover: FortiGate ejecuta, Defender simula, AD hereda master."""
    s = Settings(
        openai_api_key="x",
        dry_run_mode=False,
        dry_run_fortigate="false",  # EJECUTA en vivo
        dry_run_defender="true",    # simula
        dry_run_ad="",              # hereda master (false → ejecuta)
    )
    assert s.dry_run_for("block_ip") is False       # fortigate live
    assert s.dry_run_for("scan_host") is True        # defender simula
    assert s.dry_run_for("isolate_host") is True
    assert s.dry_run_for("disable_user") is False     # ad hereda master
    assert s.dry_run_state() == {"ad": False, "fortigate": False, "defender": True}


def test_dry_run_empty_and_invalid_override_inherit_master() -> None:
    """Override vacío o basura → hereda el master (no rompe)."""
    s_true = Settings(openai_api_key="x", dry_run_mode=True, dry_run_fortigate="")
    assert s_true.dry_run_for("block_ip") is True
    s_false = Settings(openai_api_key="x", dry_run_mode=False, dry_run_fortigate="garbage")
    assert s_false.dry_run_for("block_ip") is False


def test_dry_run_override_accepts_common_truthy_tokens() -> None:
    """Tolera 1/yes/on y 0/no/off además de true/false."""
    assert Settings(openai_api_key="x", dry_run_fortigate="yes").dry_run_for("block_ip") is True
    assert Settings(openai_api_key="x", dry_run_fortigate="on").dry_run_for("block_ip") is True
    s = Settings(openai_api_key="x", dry_run_mode=True, dry_run_fortigate="off")
    # master gana igual
    assert s.dry_run_for("block_ip") is True


def test_dry_run_for_action_without_family_uses_master() -> None:
    """notify_only/escalate_l2 no tienen familia → caen al master, sin crash."""
    assert Settings(openai_api_key="x", dry_run_mode=True).dry_run_for("notify_only") is True
    assert Settings(openai_api_key="x", dry_run_mode=False).dry_run_for("escalate_l2") is False
