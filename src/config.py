"""Config tipada vía pydantic-settings.

LdapConfig soporta 3 fuentes de credenciales (en orden de precedencia):
  1. Env vars LDAP_BIND_DN / LDAP_BIND_PASSWORD (literal, ojo con escaping)
  2. Env var LDAP_BIND_PASSWORD_B64 (base64-encoded, safe para chars como $, ', ")
  3. credentials_file (AD_USER=... AD_PASSWORD=..., default /root/.ad_wazuh_credentials)

Recomendación: usar opción 2 (b64) para evitar el .env parsing issue cuando el
password tiene chars especiales. La opción 3 es útil si ya tenés sync_ad.py
con esa estructura y querés reusar.
"""
from __future__ import annotations

import base64
import binascii
import os

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _parse_credentials_file(path: str) -> dict[str, str]:
    """Parsea un archivo con líneas KEY=value (formato /root/.ad_wazuh_credentials).

    Tolera comentarios (#) y líneas vacías. No hace stripping de quotes (los acepta literal).
    """
    creds: dict[str, str] = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            creds[key.strip()] = value
    return creds


class LdapConfig(BaseSettings):
    """Conexión a AD on-prem (mismo patrón que sync_ad.py).

    Precedencia de credenciales:
      1. Env vars LDAP_BIND_DN / LDAP_BIND_PASSWORD (si están seteadas)
      2. credentials_file (archivo AD_USER=... AD_PASSWORD=...)

    Default credentials_file: /root/.ad_wazuh_credentials (requiere correr como root).

    Para correr sin root, override:
      LDAP_CREDENTIALS_FILE=/opt/soc-l1/secrets/ad_creds
      o
      LDAP_BIND_DN=... + LDAP_BIND_PASSWORD=...   (en .env, ojo con escaping)
    """

    model_config = SettingsConfigDict(
        env_prefix="LDAP_",
        env_file=".env",
        extra="ignore",
    )

    host: str = Field(default="192.0.2.10")  # RFC 5737 documentation IP
    port: int = Field(default=389)
    base_dn: str = Field(default="DC=example,DC=local")

    credentials_file: str = Field(default="/root/.ad_wazuh_credentials")
    bind_dn: str = Field(default="")
    bind_password: str = Field(default="")
    bind_password_b64: str = Field(default="")

    use_starttls: bool = Field(default=True)
    timeout: int = Field(default=10)

    @model_validator(mode="after")
    def _resolve_credentials(self) -> LdapConfig:
        """Resuelve bind_dn y bind_password desde múltiples fuentes en orden de precedencia."""
        # 1. Si vino LDAP_BIND_PASSWORD_B64 y no hay bind_password directo, decodear
        if self.bind_password_b64 and not self.bind_password:
            try:
                decoded = base64.b64decode(self.bind_password_b64, validate=True)
                self.bind_password = decoded.decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError) as e:
                raise ValueError(
                    f"LDAP_BIND_PASSWORD_B64 inválido (no es base64 válido o no decodea a UTF-8): {e}"
                ) from e

        # 2. Si todavía faltan, intentar credentials_file
        need_dn = not self.bind_dn
        need_pwd = not self.bind_password
        if (need_dn or need_pwd) and self.credentials_file:
            if os.path.exists(self.credentials_file):
                try:
                    creds = _parse_credentials_file(self.credentials_file)
                    if need_dn and "AD_USER" in creds:
                        self.bind_dn = creds["AD_USER"]
                    if need_pwd and "AD_PASSWORD" in creds:
                        self.bind_password = creds["AD_PASSWORD"]
                except PermissionError as e:
                    raise ValueError(
                        f"No permission to read {self.credentials_file}. "
                        f"Corré con sudo, o seteá LDAP_BIND_DN/LDAP_BIND_PASSWORD_B64 en .env. "
                        f"Detalle: {e}"
                    ) from e

        # 3. Validación final
        if not self.bind_dn:
            raise ValueError(
                "bind_dn vacío. Seteá LDAP_BIND_DN en .env o asegurate que el credentials_file existe."
            )
        if not self.bind_password:
            raise ValueError(
                "bind_password vacío. Opciones: "
                "LDAP_BIND_PASSWORD_B64 (recomendado), LDAP_BIND_PASSWORD, o credentials_file."
            )
        return self


class Settings(BaseSettings):
    """Config global del servicio."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    wazuh_webhook_secret: str = Field(default="change-me")
    openai_api_key: str = Field(default="")
    openai_model_light: str = Field(default="gpt-4o-mini")
    openai_model_heavy: str = Field(default="gpt-4o")

    service_host: str = Field(default="0.0.0.0")
    service_port: int = Field(default=8000)
    log_level: str = Field(default="INFO")

    # Allowlist de IPs que pueden POSTear al webhook. Default = localhost only.
    # En deploy típico el integrator de Wazuh corre en el mismo host, así que con localhost
    # alcanza. Si Wazuh está en otro server, agregar la IP de ese server.
    # Comma-separated. Soporta IPs exactas (no CIDR todavía).
    webhook_allowed_ips: str = Field(default="127.0.0.1,::1")

    # Wazuh manager API (usado por el Enricher para get_rule, recent alerts).
    # En el server productivo el manager corre local con cert self-signed → verify_ssl=False.
    wazuh_api_host: str = Field(default="127.0.0.1")
    wazuh_api_port: int = Field(default=55000)
    wazuh_api_user: str = Field(default="wazuh")
    wazuh_api_password: str = Field(default="")
    wazuh_api_verify_ssl: bool = Field(default=False)

    # Threat Intel (Enricher externo: file hashes + IP reputation)
    virustotal_api_key: str = Field(default="")
    abuseipdb_api_key: str = Field(default="")

    # FortiGate (acciones de red: check de sessions + block_ip post-aprobación)
    # Host típicamente "fortigate.example.local:4443" o IP:puerto.
    fortigate_host: str = Field(default="")
    fortigate_token: str = Field(default="")
    fortigate_verify_ssl: bool = Field(default=False)
    # CIDRs que JAMÁS deben bloquearse aunque el Narrator lo recomiende y se apruebe.
    # Comma-separated. Default: redes privadas RFC1918 + loopback (defensa anti-pie en pala).
    protected_networks: str = Field(
        default="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8"
    )

    # SMTP para email approvals (Exchange 2016 con STARTTLS en server cliente)
    smtp_host: str = Field(default="")
    smtp_port: int = Field(default=25)
    smtp_user: str = Field(default="")
    smtp_password: str = Field(default="")
    smtp_from: str = Field(default="soc-l1@example.local")
    smtp_to_approvers: str = Field(
        default="",
        description="Lista de destinatarios separados por coma. Ej: soc@org.com,oncall@org.com",
    )
    smtp_use_starttls: bool = Field(default=True)
    smtp_ssl_verify: bool = Field(default=False)  # self-signed cert del Exchange

    # Approval workflow
    approval_base_url: str = Field(
        default="http://localhost:8000",
        description="URL pública del servicio (la que aparece en los emails). Ej: https://soc-l1.org.com",
    )
    approval_ttl_hours: int = Field(default=24)
    state_db_path: str = Field(default="/var/lib/soc-l1/state.db")

    # Lista de cuentas "intocables" - el executor refusa disable_user/force_password
    # sobre estos sams sin importar si el approval se clickeó. Defensa en profundidad
    # para evitar que un Narrator agresivo + click accidental desactive cuentas críticas.
    # Formato: comma-separated, case-insensitive. Ejemplo: "jdoe,admin,svc-soar"
    protected_users: str = Field(default="")

    # Si true, el executor logea las acciones pero NO ejecuta nada (todas no-op).
    # Útil mientras se valida que el Narrator hace recomendaciones sensatas.
    dry_run_mode: bool = Field(default=False)

    # Feature flags
    enable_triage: bool = Field(default=False)
    enable_enricher: bool = Field(default=False)
    enable_threat_intel: bool = Field(default=False)
    enable_narrator: bool = Field(default=False)

    def protected_users_set(self) -> set[str]:
        """Parsea protected_users a un set lowercase para lookup eficiente."""
        return {
            sam.strip().lower()
            for sam in self.protected_users.split(",")
            if sam.strip()
        }

    def webhook_allowed_ips_set(self) -> set[str]:
        """Parsea webhook_allowed_ips a un set para lookup O(1)."""
        return {ip.strip() for ip in self.webhook_allowed_ips.split(",") if ip.strip()}

    def protected_networks_list(self) -> list[str]:
        """Lista de CIDRs (o IPs) protegidos contra block_ip. Se usa con ipaddress."""
        return [
            cidr.strip() for cidr in self.protected_networks.split(",") if cidr.strip()
        ]
