"""HealthConfig: env + YAML merge with Pydantic validation."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

DEFAULT_YAML = Path(__file__).parent / "default.yaml"


class LocalFSConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alerts_path: str = "/var/ossec/logs/alerts/alerts.json"
    rotated_glob: str | None = None
    ossec_conf: str = "/var/ossec/etc/ossec.conf"
    client_keys: str = "/var/ossec/etc/client.keys"


class WazuhAPIConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host: str = ""
    port: int = 55000
    verify_ssl: bool = True


class SourceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    backend: str = "local_fs"
    local_fs: LocalFSConfig = LocalFSConfig()
    wazuh_api: WazuhAPIConfig = WazuhAPIConfig()


class ScheduledJob(BaseModel):
    model_config = ConfigDict(extra="forbid")
    interval_seconds: int


class SchedulerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    jitter_seconds: int = 30
    jobs: dict[str, ScheduledJob] = Field(default_factory=dict)


class ThresholdYAML(BaseModel):
    model_config = ConfigDict(extra="forbid")
    metric: str
    rule: str
    severity: str


class ThresholdsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    capacity: list[ThresholdYAML] = Field(default_factory=list)
    hygiene: list[ThresholdYAML] = Field(default_factory=list)
    coverage: list[ThresholdYAML] = Field(default_factory=list)


class CooldownsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    default_minutes: int = 360
    by_metric: dict[str, int] = Field(default_factory=dict)


class LLMConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    light_model: str = "gpt-4o-mini"
    heavy_model: str = "gpt-4o"
    max_tool_calls_per_turn: int = 6
    input_token_cap: int = 8000
    output_token_cap: int = 2000
    timeout_seconds: int = 60
    daily_cap_per_agent: int = 50


class PrivacyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pseudonymize: bool = True
    pseudonymize_fields: list[str] = Field(
        default_factory=lambda: ["srcip", "dstip", "agent.name", "user"]
    )


class StorageConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    db_path: str = "/var/lib/wazuh-health/state.db"
    report_dir: str = "/var/log/wazuh-health/reports"
    retention_days: int = 30


class SlackNotifyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    webhook_url: str = ""
    severity_floor: str = "warning"


class EmailNotifyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    to: str = ""
    sender: str = "wazuh-health@localhost"
    smtp_host: str = "localhost"
    smtp_port: int = 25
    smtp_user: str = ""
    smtp_password: str = ""
    use_tls: bool = False


class FilesystemNotifyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True


class NotifyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    filesystem: FilesystemNotifyConfig = FilesystemNotifyConfig()
    slack: SlackNotifyConfig = SlackNotifyConfig()
    email: EmailNotifyConfig = EmailNotifyConfig()


class HealthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: SourceConfig = SourceConfig()
    scheduler: SchedulerConfig = SchedulerConfig()
    thresholds: ThresholdsConfig = ThresholdsConfig()
    cooldowns: CooldownsConfig = CooldownsConfig()
    llm: LLMConfig = LLMConfig()
    privacy: PrivacyConfig = PrivacyConfig()
    storage: StorageConfig = StorageConfig()
    notify: NotifyConfig = NotifyConfig()


_ENV_VAR_RE = re.compile(r"\$\{([A-Z0-9_]+)(?::-(.*?))?\}")


def _expand(value: Any) -> Any:
    if isinstance(value, str):
        def repl(m):
            return os.getenv(m.group(1), m.group(2) or "")
        return _ENV_VAR_RE.sub(repl, value)
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config() -> HealthConfig:
    base = yaml.safe_load(DEFAULT_YAML.read_text()) or {}
    yaml_path = os.getenv("WAZUH_HEALTH_CONFIG_PATH")
    if yaml_path and Path(yaml_path).exists():
        user = yaml.safe_load(Path(yaml_path).read_text()) or {}
        base = _deep_merge(base, user)
    expanded = _expand(base)
    return HealthConfig.model_validate(expanded)
