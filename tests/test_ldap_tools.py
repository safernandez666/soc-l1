"""Tests de tools/ldap.py usando ldap3.MOCK_SYNC — no requiere AD real."""
from __future__ import annotations

from collections.abc import Iterator

import pytest
from ldap3 import MOCK_SYNC, OFFLINE_AD_2012_R2, Connection, Server

from src import tools
from src.config import LdapConfig
from src.tools import ldap as ldap_tools

BASE_DN = "DC=example,DC=local"
ADMIN_DN = "CN=admin,DC=example,DC=local"
ADMIN_PASSWORD = "test-password-OK"


@pytest.fixture
def cfg() -> LdapConfig:
    return LdapConfig(
        host="fake-server",
        port=389,
        base_dn=BASE_DN,
        bind_dn=ADMIN_DN,
        bind_password=ADMIN_PASSWORD,
        use_starttls=False,  # mock no soporta StartTLS
    )


@pytest.fixture
def mock_conn(monkeypatch: pytest.MonkeyPatch) -> Iterator[Connection]:
    """Reemplaza el context manager _connection() con una mock connection
    que tiene 1 admin (para bind) + 1 user de prueba (svc-soar)."""
    server = Server("fake-server", get_info=OFFLINE_AD_2012_R2)
    conn = Connection(server, user=ADMIN_DN, password=ADMIN_PASSWORD, client_strategy=MOCK_SYNC)

    # Admin (para bindear)
    conn.strategy.add_entry(
        ADMIN_DN,
        {
            "objectClass": ["top", "person", "user"],
            "sAMAccountName": "admin",
            "userAccountControl": 512,
            "userPassword": ADMIN_PASSWORD,
        },
    )
    # Usuario target
    test_user_dn = "CN=svc-soar,OU=Services,OU=Tech,OU=Example Corp,DC=example,DC=local"
    conn.strategy.add_entry(
        test_user_dn,
        {
            "objectClass": ["top", "person", "user"],
            "sAMAccountName": "svc-soar",
            "displayName": "Wazuh Service Account",
            "mail": "svc-soar@example.com",
            "department": "IT Security",
            "title": "Service Account",
            "memberOf": [
                "CN=Domain Users,CN=Users,DC=example,DC=local",
                "CN=Servicios,OU=Groups,DC=example,DC=local",
            ],
            "userAccountControl": 512,  # NORMAL_ACCOUNT (enabled)
            "badPwdCount": 0,
            "lockoutTime": 0,
            "pwdLastSet": 133600000000000000,  # algún filetime válido
        },
    )

    conn.bind()

    # Hookear el context manager: nuestras tools van a usar ESTA conn
    from contextlib import contextmanager

    @contextmanager
    def fake_connection(_cfg: LdapConfig):
        yield conn

    monkeypatch.setattr(ldap_tools, "_connection", fake_connection)
    yield conn
    conn.unbind()


def test_search_user_found(cfg: LdapConfig, mock_conn: Connection) -> None:
    user = ldap_tools.search_user(cfg, "svc-soar")
    assert user is not None
    assert user.sam == "svc-soar"
    assert user.display_name == "Wazuh Service Account"
    assert user.mail == "svc-soar@example.com"
    assert user.department == "IT Security"
    assert user.account_enabled is True
    assert user.locked_out is False
    assert user.user_account_control == 512
    assert len(user.member_of) == 2


def test_search_user_not_found(cfg: LdapConfig, mock_conn: Connection) -> None:
    user = ldap_tools.search_user(cfg, "nonexistent-user")
    assert user is None


def test_search_user_escapes_ldap_injection(cfg: LdapConfig, mock_conn: Connection) -> None:
    """Un sam con metacaracteres LDAP no debe alterar el filtro ni matchear a otro.

    Sin escape_filter_chars, 'svc-soar)(objectClass=*' inyectaría una cláusula
    extra y devolvería el usuario real; escapado, queda como literal → None.
    """
    user = ldap_tools.search_user(cfg, "svc-soar)(objectClass=*")
    assert user is None


def test_disable_user_sets_uac_bit(cfg: LdapConfig, mock_conn: Connection) -> None:
    result = ldap_tools.disable_user(cfg, "svc-soar")
    assert result.ok is True
    assert result.action == "disable_user"
    assert result.target_sam == "svc-soar"
    assert result.target_dn is not None and "svc-soar" in result.target_dn

    # Verificá el estado post-disable
    user = ldap_tools.search_user(cfg, "svc-soar")
    assert user is not None
    assert user.account_enabled is False
    assert user.user_account_control & 0x2  # ACCOUNT_DISABLE bit


def test_disable_user_not_found(cfg: LdapConfig, mock_conn: Connection) -> None:
    result = ldap_tools.disable_user(cfg, "ghost")
    assert result.ok is False
    assert result.message == "user not found"


def test_force_password_change_sets_pwdlastset_zero(
    cfg: LdapConfig, mock_conn: Connection
) -> None:
    # Verificá estado previo
    user_before = ldap_tools.search_user(cfg, "svc-soar")
    assert user_before is not None
    assert user_before.pwd_last_set is not None  # tenía un valor

    # Ejecutar acción
    result = ldap_tools.force_password_change(cfg, "svc-soar")
    assert result.ok is True
    assert result.action == "force_password_change"
    assert result.target_dn is not None

    # Verificá post: pwdLastSet=0 → ldap3 lo devuelve como None en nuestro mapper
    user_after = ldap_tools.search_user(cfg, "svc-soar")
    assert user_after is not None
    assert user_after.pwd_last_set is None


def test_force_password_change_not_found(cfg: LdapConfig, mock_conn: Connection) -> None:
    result = ldap_tools.force_password_change(cfg, "ghost")
    assert result.ok is False
    assert result.message == "user not found"
