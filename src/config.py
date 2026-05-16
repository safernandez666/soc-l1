"""Config tipada vía pydantic-settings.

LdapConfig sigue el patrón de sync_ad.py: lee credenciales de un archivo
con formato `AD_USER=...\\nAD_PASSWORD=...` (default: /root/.ad_wazuh_credentials).

Override possible vía env vars LDAP_BIND_DN / LDAP_BIND_PASSWORD.
"""
from __future__ import annotations

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

    use_starttls: bool = Field(default=True)
    timeout: int = Field(default=10)

    @model_validator(mode="after")
    def _load_from_credentials_file(self) -> LdapConfig:
        """Si faltan bind_dn / bind_password, intentar cargarlos del archivo."""
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
                        f"Corré con sudo, o seteá LDAP_BIND_DN/LDAP_BIND_PASSWORD en .env. "
                        f"Detalle: {e}"
                    ) from e

        if not self.bind_dn:
            raise ValueError(
                "bind_dn vacío. Seteá LDAP_BIND_DN en .env o agregá AD_USER al credentials_file."
            )
        if not self.bind_password:
            raise ValueError(
                "bind_password vacío. Seteá LDAP_BIND_PASSWORD en .env o agregá AD_PASSWORD al credentials_file."
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
