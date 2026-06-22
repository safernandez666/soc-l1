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
import logging
import os
from functools import lru_cache

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

    # Microsoft Defender for Endpoint (acciones de respuesta sobre el endpoint:
    # scan AV + aislamiento de máquina, post-aprobación). Relación hoy unidireccional
    # (solo ingesta vía Wazuh); estos 3 datos los provee un App Registration en Entra ID
    # con permisos de aplicación WindowsDefenderATP (Machine.Scan, Machine.Isolate,
    # Machine.Read.All) y admin consent. Auth: OAuth2 client-credentials.
    defender_tenant_id: str = Field(default="")
    defender_client_id: str = Field(default="")
    defender_client_secret: str = Field(default="")
    defender_verify_ssl: bool = Field(default=True)
    # Hosts "intocables" - el executor refusa scan_host/isolate_host sobre estos nombres
    # sin importar si el approval se clickeó. Pensado para DCs, Exchange, hipervisores, etc.
    # Match contra action.target (hostname o FQDN), case-insensitive, comma-separated.
    protected_hosts: str = Field(default="")

    # InvGate Service Desk (creación de tickets post-Narrator + updates en cada hito).
    # Las env vars usan sufijo _INVGATE (USER_INVGATE, PASS_INVGATE, HOST_INVGATE,
    # CREATOR_ID_INVGATE) por convención del admin → mapeamos con validation_alias.
    # customer_id y category_id son fijos (5 y 59) pero overrideables vía env si hace falta.
    invgate_host: str = Field(default="", validation_alias="HOST_INVGATE")
    invgate_user: str = Field(default="", validation_alias="USER_INVGATE")
    invgate_password: str = Field(default="", validation_alias="PASS_INVGATE")
    invgate_creator_id: int = Field(default=0, validation_alias="CREATOR_ID_INVGATE")
    invgate_customer_id: int = Field(default=5, validation_alias="CUSTOMER_ID_INVGATE")
    invgate_category_id: int = Field(default=59, validation_alias="CATEGORY_ID_INVGATE")
    invgate_verify_ssl: bool = Field(default=True, validation_alias="INVGATE_VERIFY_SSL")

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

    # Notificación de cierre (post-decisión). Teams: hook futuro, vacío = deshabilitado.
    teams_webhook_url: str = Field(
        default="",
        description="Incoming webhook de Teams para notificar el cierre del caso. Vacío = deshabilitado.",
    )

    # Approval workflow
    approval_base_url: str = Field(
        default="http://localhost:8000",
        description="URL pública del servicio (la que aparece en los emails). Ej: https://soc-l1.org.com",
    )
    approval_ttl_hours: int = Field(default=24)
    approval_retention_days: int = Field(
        default=30,
        description="Días que se conservan los approvals terminales antes de purgarlos.",
    )
    state_db_path: str = Field(default="/var/lib/soc-l1/state.db")

    # DB del Wazuh Health Squad (probes de cobertura/capacidad/higiene). Solo-lectura
    # desde el panel /ui para los KPIs de salud de Wazuh. La escribe el daemon aparte.
    wazuh_health_db_path: str = Field(default="/var/lib/wazuh-health/state.db")

    # KPIs de volumen de alertas (panel /ui). El agregador (scripts/aggregate_alert_volume.py)
    # recorre los archivos rotados de Wazuh y deja un JSON con el conteo mensual; el panel
    # lo lee solo-lectura (descomprimir en cada request sería inviable).
    wazuh_alerts_archive_dir: str = Field(default="/var/ossec/logs/alerts")
    alert_volume_cache_path: str = Field(default="/var/lib/soc-l1/alert_volume.json")

    # ===== GUI / Dashboard (ZebraSecurity) =====
    # Panel de revisión solo-lectura sobre state.db, servido en /ui detrás de login.
    # Si dashboard_password queda vacío, el login rechaza todo (dashboard inhabilitado).
    dashboard_enabled: bool = Field(default=True)
    dashboard_password: str = Field(
        default="",
        description="Password compartido para entrar al panel /ui. Vacío = panel inaccesible.",
    )
    # Secreto para firmar la cookie de sesión (HMAC). Si vacío, se deriva del webhook secret.
    dashboard_session_secret: str = Field(default="")
    dashboard_session_hours: int = Field(default=12)

    # Línea base de medición: los contadores del panel y los KPIs solo cuentan casos
    # con created_at >= este timestamp (ISO 8601). Vacío = sin corte (cuenta todo el
    # histórico). Sirve para "arrancar de cero" sin borrar datos: lo viejo queda en la
    # DB pero no se mide. Reversible: vaciar el campo restaura el histórico completo.
    metrics_baseline_at: str = Field(default="")

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

    def protected_hosts_set(self) -> set[str]:
        """Parsea protected_hosts a un set lowercase para lookup eficiente."""
        return {
            host.strip().lower()
            for host in self.protected_hosts.split(",")
            if host.strip()
        }

    def defender_configured(self) -> bool:
        """True si están los 3 datos para hablar con la API de MDE."""
        return bool(
            self.defender_tenant_id
            and self.defender_client_id
            and self.defender_client_secret
        )

    def webhook_allowed_ips_set(self) -> set[str]:
        """Parsea webhook_allowed_ips a un set para lookup O(1)."""
        return {ip.strip() for ip in self.webhook_allowed_ips.split(",") if ip.strip()}

    def protected_networks_list(self) -> list[str]:
        """Lista de CIDRs (o IPs) protegidos contra block_ip. Se usa con ipaddress."""
        return [
            cidr.strip() for cidr in self.protected_networks.split(",") if cidr.strip()
        ]

    @model_validator(mode="after")
    def _check_secrets(self) -> "Settings":
        """Falla el arranque (o avisa) ante secretos en default que abren agujeros.

        El combo realmente explotable: panel /ui accesible (enabled + password) con
        la cookie firmada por un secreto derivado del webhook secret default
        'change-me' → cualquiera forja una sesión válida. Eso hard-failea. El resto
        son WARNINGs para no bloquear entornos de dev.
        """
        log = logging.getLogger("soc-l1")
        panel_reachable = self.dashboard_enabled and bool(self.dashboard_password)
        weak_cookie_secret = (
            not self.dashboard_session_secret and self.wazuh_webhook_secret == "change-me"
        )
        if panel_reachable and weak_cookie_secret:
            raise ValueError(
                "Config insegura: el panel /ui está habilitado pero la cookie de "
                "sesión se firma con el webhook secret default 'change-me' "
                "(forjable). Seteá DASHBOARD_SESSION_SECRET o WAZUH_WEBHOOK_SECRET."
            )
        if self.wazuh_webhook_secret == "change-me":
            log.warning("config: WAZUH_WEBHOOK_SECRET está en el default 'change-me' — cambialo.")
        if self.dashboard_enabled and not self.dashboard_session_secret:
            log.warning(
                "config: DASHBOARD_SESSION_SECRET vacío — la cookie se deriva del "
                "webhook secret. Seteá un secreto dedicado."
            )
        return self


# ===== Singleton de settings (lee .env una sola vez) =====
#
# Único get_settings de toda la app: main.py y src/web/router.py lo importan de
# acá (antes cada uno tenía su propio @lru_cache, y un cambio en uno dejaba al
# otro con valores viejos). reload_settings() limpia el cache para que el próximo
# request/alerta tome el .env reescrito desde la UI de configuración, sin reiniciar.


@lru_cache(maxsize=1)
def get_settings() -> "Settings":
    """Cache singleton de settings (lee .env una sola vez)."""
    return Settings()


def reload_settings() -> "Settings":
    """Invalida el cache y re-lee .env. Usar tras escribir .env desde la UI."""
    get_settings.cache_clear()
    return get_settings()
