"""Configuración editable vía UI (/ui/api/config).

Expone un subconjunto **operativo** de Settings para editar desde el dashboard y
lo persiste en `.env`. Principios:

- **Allowlist:** solo los campos declarados en SECTIONS son editables; un POST con
  cualquier otra clave se rechaza (nunca se toca dry_run_mode, webhook_allowed_ips,
  dashboard_password/session_secret, etc. desde acá).
- **Secretos write-only:** los campos `secret` nunca se devuelven al browser (el GET
  manda solo `set: bool` + hint enmascarado). En el POST, un secreto vacío = "no
  cambiar" (permite guardar el form sin re-tipear las keys).
- **Hot-reload:** tras escribir `.env` se llama reload_settings() (cache_clear del
  único get_settings) → el próximo request/alerta toma los valores nuevos sin
  reiniciar el proceso.
- **Seguro:** escritura atómica (tmp + os.replace) con backup, preserva
  comentarios/orden del `.env`, y si el nuevo `.env` no valida en pydantic se
  restaura el backup y se aborta.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from src.config import Settings, get_settings, reload_settings

logger = logging.getLogger("soc-l1")

# .env vive en la raíz del repo (src/web/config_io.py -> parents[2] == /opt/soc-l1),
# robusto sin depender del cwd (pydantic lo lee relativo al cwd, pero acá lo fijamos).
ENV_PATH = Path(__file__).resolve().parents[2] / ".env"

_ENV_LINE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=")


class ConfigError(ValueError):
    """Update inválido (campo no editable, tipo incorrecto, valor con newline)."""


@dataclass(frozen=True)
class CfgField:
    name: str  # nombre del campo en Settings
    label: str
    kind: str  # "str" | "csv" | "int" | "bool" | "secret"
    help: str = ""
    options: tuple[str, ...] = field(default_factory=tuple)  # para selects (modelos)


@dataclass(frozen=True)
class Section:
    key: str
    title: str
    fields: tuple[CfgField, ...]


_MODELS = ("gpt-4o", "gpt-4o-mini", "gpt-4.1", "gpt-4.1-mini")

SECTIONS: tuple[Section, ...] = (
    Section("llm", "IA / LLM", (
        CfgField("openai_api_key", "OpenAI API Key", "secret", "Key del proveedor LLM."),
        CfgField("openai_model_light", "Modelo liviano", "str", "Triage/Enricher.", _MODELS),
        CfgField("openai_model_heavy", "Modelo pesado", "str", "Narrator.", _MODELS),
    )),
    Section("threat_intel", "Threat Intel", (
        CfgField("virustotal_api_key", "VirusTotal API Key", "secret"),
        CfgField("abuseipdb_api_key", "AbuseIPDB API Key", "secret"),
    )),
    Section("email", "Email / SMTP", (
        CfgField("smtp_host", "Host", "str"),
        CfgField("smtp_port", "Puerto", "int"),
        CfgField("smtp_user", "Usuario", "str"),
        CfgField("smtp_password", "Password", "secret"),
        CfgField("smtp_from", "From", "str"),
        CfgField("smtp_to_approvers", "Aprobadores (coma)", "csv",
                 "Emails que reciben el pedido de aprobación."),
        CfgField("smtp_use_starttls", "STARTTLS", "bool"),
        CfgField("smtp_ssl_verify", "Verificar SSL", "bool"),
    )),
    Section("approvals", "Aprobaciones", (
        CfgField("approval_base_url", "Base URL", "str",
                 "URL pública de los links de aprobación en los emails."),
        CfgField("approval_ttl_hours", "TTL del link (horas)", "int"),
        CfgField("approval_retention_days", "Retención (días)", "int"),
    )),
    Section("pipeline", "Pipeline", (
        CfgField("enable_triage", "Triage", "bool"),
        CfgField("enable_enricher", "Enricher", "bool"),
        CfgField("enable_threat_intel", "Threat Intel", "bool"),
        CfgField("enable_narrator", "Narrator", "bool"),
    )),
    Section("integrations", "Integraciones", (
        CfgField("wazuh_api_host", "Wazuh API host", "str"),
        CfgField("wazuh_api_port", "Wazuh API port", "int"),
        CfgField("wazuh_api_user", "Wazuh API user", "str"),
        CfgField("wazuh_api_password", "Wazuh API password", "secret"),
        CfgField("wazuh_api_verify_ssl", "Wazuh verificar SSL", "bool"),
        CfgField("fortigate_host", "FortiGate host", "str"),
        CfgField("fortigate_token", "FortiGate token", "secret"),
        CfgField("fortigate_verify_ssl", "FortiGate verificar SSL", "bool"),
        CfgField("defender_tenant_id", "Defender tenant ID", "str"),
        CfgField("defender_client_id", "Defender client ID", "str"),
        CfgField("defender_client_secret", "Defender client secret", "secret"),
        CfgField("defender_verify_ssl", "Defender verificar SSL", "bool"),
        CfgField("invgate_host", "InvGate host", "str"),
        CfgField("invgate_user", "InvGate user", "str"),
        CfgField("invgate_password", "InvGate password", "secret"),
        CfgField("invgate_creator_id", "InvGate creator ID", "int"),
        CfgField("invgate_customer_id", "InvGate customer ID", "int"),
        CfgField("invgate_category_id", "InvGate category ID", "int"),
        CfgField("invgate_verify_ssl", "InvGate verificar SSL", "bool"),
    )),
    Section("guardrails", "Guardrails", (
        CfgField("protected_users", "Usuarios protegidos (coma)", "csv",
                 "Nunca se deshabilitan/resetean en AD."),
        CfgField("protected_networks", "Redes protegidas (CIDR, coma)", "csv",
                 "Nunca se bloquean en FortiGate."),
        CfgField("protected_hosts", "Hosts protegidos (coma)", "csv",
                 "Nunca se aíslan en Defender."),
    )),
    # NOTA: el master DRY_RUN_MODE (kill-switch global) NO es editable desde la UI a
    # propósito — es la red de seguridad y se toca solo por .env. Acá solo los overrides
    # por familia, que únicamente aplican cuando el master está apagado.
    Section("ejecucion", "Ejecución (Dry-Run por familia)", (
        CfgField("dry_run_ad", "AD (disable/reset)", "str",
                 "Vacío = heredar master · true = simular · false = ejecutar en vivo.",
                 ("", "true", "false")),
        CfgField("dry_run_fortigate", "FortiGate (block_ip)", "str",
                 "Vacío = heredar master · true = simular · false = ejecutar en vivo.",
                 ("", "true", "false")),
        CfgField("dry_run_defender", "Defender (scan/isolate)", "str",
                 "Vacío = heredar master · true = simular · false = ejecutar en vivo.",
                 ("", "true", "false")),
    )),
)

# field name -> CfgField (allowlist de lo editable)
_EDITABLE: dict[str, CfgField] = {f.name: f for sec in SECTIONS for f in sec.fields}


def env_key_for(name: str) -> str:
    """Nombre de la env-var para un campo de Settings.

    Respeta validation_alias (ej. invgate_host -> HOST_INVGATE); si no hay alias,
    la convención de pydantic-settings es el nombre del campo en mayúsculas.
    """
    info = Settings.model_fields[name]
    alias = info.validation_alias
    return alias if isinstance(alias, str) else name.upper()


def _mask(secret: str) -> str:
    if not secret:
        return ""
    return ("••••" + secret[-4:]) if len(secret) > 4 else "••••"


def public_config() -> dict:
    """Vista para el GET: valores actuales, con secretos enmascarados."""
    s = get_settings()
    out_sections = []
    for sec in SECTIONS:
        fields = []
        for f in sec.fields:
            val = getattr(s, f.name)
            item = {"name": f.name, "label": f.label, "kind": f.kind, "help": f.help}
            if f.options:
                item["options"] = list(f.options)
            if f.kind == "secret":
                sval = str(val or "")
                item["set"] = bool(sval)
                item["hint"] = _mask(sval)
            else:
                item["value"] = val
            fields.append(item)
        out_sections.append({"key": sec.key, "title": sec.title, "fields": fields})
    return {"sections": out_sections}


def _coerce(f: CfgField, raw) -> str | None:
    """Valida y normaliza un valor a su representación en .env. None = no escribir."""
    if f.kind == "secret":
        sval = "" if raw is None else str(raw).strip()
        if sval == "":
            return None  # write-only: vacío = no cambiar
        _no_newline(sval)
        return sval
    if f.kind == "bool":
        if isinstance(raw, bool):
            return "true" if raw else "false"
        token = str(raw).strip().lower()
        if token in ("true", "1", "yes", "on"):
            return "true"
        if token in ("false", "0", "no", "off", ""):
            return "false"
        raise ConfigError(f"{f.name}: valor booleano inválido {raw!r}")
    if f.kind == "int":
        try:
            return str(int(str(raw).strip()))
        except (ValueError, TypeError) as e:
            raise ConfigError(f"{f.name}: se esperaba un entero, llegó {raw!r}") from e
    # str / csv
    sval = "" if raw is None else str(raw)
    _no_newline(sval)
    return sval.strip()


def _no_newline(s: str) -> None:
    if "\n" in s or "\r" in s:
        raise ConfigError("el valor no puede tener saltos de línea")


def apply_updates(updates: dict) -> dict:
    """Valida los updates contra la allowlist, los persiste en .env y recarga.

    Devuelve {"applied": [...]} con los campos efectivamente escritos.
    Lanza ConfigError ante cualquier campo no editable o valor inválido.
    """
    if not isinstance(updates, dict):
        raise ConfigError("body inválido: se esperaba un objeto {campo: valor}")

    env_kv: dict[str, str] = {}
    applied: list[str] = []
    for name, raw in updates.items():
        f = _EDITABLE.get(name)
        if f is None:
            raise ConfigError(f"campo no editable: {name}")
        coerced = _coerce(f, raw)
        if coerced is None:
            continue  # secreto vacío: se deja como está
        env_kv[env_key_for(name)] = coerced
        applied.append(name)

    if not env_kv:
        return {"applied": []}

    backup = _write_env(env_kv)
    try:
        reload_settings()  # re-instancia Settings: si el .env quedó inválido, levanta
    except Exception as e:
        if backup and backup.exists():
            shutil.copy2(backup, ENV_PATH)
            reload_settings()
        logger.exception("config UI: nuevo .env inválido, restaurado backup")
        raise ConfigError(f"el nuevo valor rompió la config, se revirtió: {e}") from e

    return {"applied": applied}


def _ts() -> str:
    return datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S")


def _write_env(env_kv: dict[str, str]) -> Path | None:
    """Update-or-append de claves en .env, atómico y con backup.

    Preserva comentarios, líneas en blanco y orden. Devuelve el path del backup.
    """
    existing = ENV_PATH.read_text().splitlines() if ENV_PATH.exists() else []
    remaining = dict(env_kv)
    out: list[str] = []
    for line in existing:
        m = _ENV_LINE.match(line)
        if m and m.group(1) in remaining:
            key = m.group(1)
            out.append(f"{key}={remaining.pop(key)}")
        else:
            out.append(line)
    for key, val in remaining.items():  # claves nuevas: al final
        out.append(f"{key}={val}")
    content = "\n".join(out) + "\n"

    backup: Path | None = None
    if ENV_PATH.exists():
        backup = ENV_PATH.with_name(f"{ENV_PATH.name}.bak-uiconfig-{_ts()}")
        shutil.copy2(ENV_PATH, backup)

    tmp = ENV_PATH.with_name(f"{ENV_PATH.name}.tmp-uiconfig")
    tmp.write_text(content)
    os.replace(tmp, ENV_PATH)  # atómico en el mismo filesystem
    return backup
