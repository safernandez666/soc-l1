"""Config tipada vía pydantic-settings. Lee del .env."""
from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class LdapConfig(BaseSettings):
    """Conexión a AD on-prem. Use STARTTLS sobre puerto 389."""

    model_config = SettingsConfigDict(env_prefix="LDAP_", env_file=".env", extra="ignore")

    host: str = Field(default="192.168.32.29")
    port: int = Field(default=389)
    base_dn: str = Field(default="DC=example,DC=dns")
    bind_dn: str
    bind_password: str
    use_starttls: bool = Field(default=True)
    timeout: int = Field(default=10)


class Settings(BaseSettings):
    """Config global del servicio."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    wazuh_webhook_secret: str = Field(default="change-me")
    openai_api_key: str = Field(default="")
    openai_model_light: str = Field(default="gpt-4o-mini")
    openai_model_heavy: str = Field(default="gpt-4o")
