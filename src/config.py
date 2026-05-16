"""Config tipada vía pydantic-settings. Lee del .env y de secrets_dir."""
from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class LdapConfig(BaseSettings):
    """Conexión a AD on-prem.

    Para `bind_password`, dos opciones:
      1. Variable LDAP_BIND_PASSWORD en .env (no recomendado si tiene chars especiales)
      2. Archivo en secrets_dir/bind_password (recomendado — sin escaping issues)

    Si ambos están seteados, secrets_dir gana.
    """

    model_config = SettingsConfigDict(
        env_prefix="LDAP_",
        env_file=".env",
        secrets_dir="/opt/soc-l1/secrets",  # ver DEPLOY.md sección "Secrets"
        extra="ignore",
    )

    host: str = Field(default="192.0.2.10")  # RFC 5737 documentation IP
    port: int = Field(default=389)
    base_dn: str = Field(default="DC=example,DC=local")
    bind_dn: str
    bind_password: str = Field(default="")
    use_starttls: bool = Field(default=True)
    timeout: int = Field(default=10)


class Settings(BaseSettings):
    """Config global del servicio."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    wazuh_webhook_secret: str = Field(default="change-me")
    openai_api_key: str = Field(default="")
    openai_model_light: str = Field(default="gpt-4o-mini")
    openai_model_heavy: str = Field(default="gpt-4o")

    # HTTP service
    service_host: str = Field(default="0.0.0.0")
    service_port: int = Field(default=8000)
    log_level: str = Field(default="INFO")
