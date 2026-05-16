"""LDAP/AD tools - search, disable user, force password change.

Estas funciones son las que el Enricher (read) y Operator (write) van a
exponer como tools al LLM. Cada una es sync, simple, tipada.

Para los tests usamos ldap3.MOCK_SYNC en lugar de un AD real.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Iterator

from ldap3 import (
    ALL,
    MODIFY_REPLACE,
    SIMPLE,
    SUBTREE,
    Connection,
    Server,
    Tls,
)
from ldap3.core.exceptions import LDAPException

from src.config import LdapConfig
from src.models import ADUser, LdapActionResult

# AD userAccountControl bit flags relevantes
UAC_ACCOUNT_DISABLE = 0x0002
UAC_LOCKOUT = 0x0010

# Atributos que pedimos al search de usuario
USER_ATTRS = [
    "distinguishedName",
    "sAMAccountName",
    "displayName",
    "mail",
    "department",
    "title",
    "manager",
    "memberOf",
    "userAccountControl",
    "lockoutTime",
    "lastLogonTimestamp",
    "badPwdCount",
    "pwdLastSet",
]


@contextmanager
def _connection(cfg: LdapConfig) -> Iterator[Connection]:
    """Context manager: abre conexión, hace STARTTLS si corresponde, bind, cierra."""
    tls = Tls(validate=0) if cfg.use_starttls else None  # 0 = CERT_NONE
    server = Server(cfg.host, port=cfg.port, use_ssl=False, get_info=ALL, tls=tls, connect_timeout=cfg.timeout)
    conn = Connection(
        server,
        user=cfg.bind_dn,
        password=cfg.bind_password,
        authentication=SIMPLE,
        auto_bind=False,
        receive_timeout=cfg.timeout,
    )
    try:
        conn.open()
        if cfg.use_starttls:
            if not conn.start_tls():
                raise LDAPException(f"STARTTLS failed: {conn.result}")
        if not conn.bind():
            raise LDAPException(f"Bind failed: {conn.result}")
        yield conn
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def _ad_filetime_to_iso(raw_value) -> str | None:
    """AD guarda timestamps como uint64 con epoch 1601-01-01 (100ns ticks).
    Cero / epoch significa "nunca" o "force change at next logon" → devolvemos None.
    """
    if raw_value is None or raw_value == 0:
        return None
    if isinstance(raw_value, datetime):
        # ldap3 deserializa filetime=0 como datetime(1601,1,1) → tratarlo como None
        if raw_value.year == 1601:
            return None
        return raw_value.isoformat()
    try:
        ticks = int(raw_value)
        if ticks == 0:
            return None
        # AD epoch a Unix epoch
        secs = ticks / 10_000_000 - 11644473600
        return datetime.fromtimestamp(secs, tz=timezone.utc).isoformat()
    except (TypeError, ValueError):
        return None


def _entry_to_aduser(entry) -> ADUser:
    """Mapea un entry de ldap3 a ADUser."""
    attrs = entry.entry_attributes_as_dict
    uac = int((attrs.get("userAccountControl") or [0])[0])
    lockout_time = (attrs.get("lockoutTime") or [0])[0]
    locked_out = bool(uac & UAC_LOCKOUT) or (
        isinstance(lockout_time, int) and lockout_time > 0
    )
    member_of = attrs.get("memberOf") or []
    return ADUser(
        dn=entry.entry_dn,
        sam=(attrs.get("sAMAccountName") or [""])[0],
        display_name=(attrs.get("displayName") or [None])[0],
        mail=(attrs.get("mail") or [None])[0],
        department=(attrs.get("department") or [None])[0],
        title=(attrs.get("title") or [None])[0],
        manager=(attrs.get("manager") or [None])[0],
        member_of=list(member_of),
        account_enabled=not bool(uac & UAC_ACCOUNT_DISABLE),
        locked_out=locked_out,
        last_logon=_ad_filetime_to_iso((attrs.get("lastLogonTimestamp") or [None])[0]),
        bad_pwd_count=int((attrs.get("badPwdCount") or [0])[0] or 0),
        pwd_last_set=_ad_filetime_to_iso((attrs.get("pwdLastSet") or [None])[0]),
        user_account_control=uac,
    )


def search_user(cfg: LdapConfig, sam_account_name: str) -> ADUser | None:
    """Busca un usuario por sAMAccountName. Devuelve None si no existe."""
    with _connection(cfg) as conn:
        conn.search(
            search_base=cfg.base_dn,
            search_filter=f"(&(objectClass=user)(sAMAccountName={sam_account_name}))",
            search_scope=SUBTREE,
            attributes=USER_ATTRS,
            size_limit=1,
        )
        if not conn.entries:
            return None
        return _entry_to_aduser(conn.entries[0])


def disable_user(cfg: LdapConfig, sam_account_name: str) -> LdapActionResult:
    """Setea el bit ACCOUNTDISABLE (0x2) en userAccountControl."""
    with _connection(cfg) as conn:
        conn.search(
            search_base=cfg.base_dn,
            search_filter=f"(&(objectClass=user)(sAMAccountName={sam_account_name}))",
            search_scope=SUBTREE,
            attributes=["distinguishedName", "userAccountControl"],
            size_limit=1,
        )
        if not conn.entries:
            return LdapActionResult(
                ok=False,
                action="disable_user",
                target_sam=sam_account_name,
                message="user not found",
            )
        entry = conn.entries[0]
        current_uac = int(entry.entry_attributes_as_dict.get("userAccountControl", [512])[0])
        new_uac = current_uac | UAC_ACCOUNT_DISABLE
        ok = conn.modify(entry.entry_dn, {"userAccountControl": [(MODIFY_REPLACE, [new_uac])]})
        return LdapActionResult(
            ok=ok,
            action="disable_user",
            target_sam=sam_account_name,
            target_dn=entry.entry_dn,
            message=None if ok else str(conn.result),
        )


def force_password_change(cfg: LdapConfig, sam_account_name: str) -> LdapActionResult:
    """Setea pwdLastSet=0 → usuario debe cambiar pw en próximo logon."""
    with _connection(cfg) as conn:
        conn.search(
            search_base=cfg.base_dn,
            search_filter=f"(&(objectClass=user)(sAMAccountName={sam_account_name}))",
            search_scope=SUBTREE,
            attributes=["distinguishedName"],
            size_limit=1,
        )
        if not conn.entries:
            return LdapActionResult(
                ok=False,
                action="force_password_change",
                target_sam=sam_account_name,
                message="user not found",
            )
        dn = conn.entries[0].entry_dn
        ok = conn.modify(dn, {"pwdLastSet": [(MODIFY_REPLACE, [0])]})
        return LdapActionResult(
            ok=ok,
            action="force_password_change",
            target_sam=sam_account_name,
            target_dn=dn,
            message=None if ok else str(conn.result),
        )
