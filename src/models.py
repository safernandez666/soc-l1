"""Pydantic models for normalized SOC alerts.

The normalizer turns raw Wazuh alerts (native or Defender-via-Wazuh) into
this common schema. Agents always work against NormalizedAlert, never raw.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

UserRole = Literal["logged_on", "file_path_owner", "event_user"]
AlertSource = Literal["defender_via_wazuh", "wazuh_native"]
Severity = Literal["informational", "low", "medium", "high", "critical"]


class User(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sam: str
    domain: str | None = None
    role: UserRole


class Device(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hostname: str | None = None
    fqdn: str | None = None
    internal_ip: str | None = None
    external_ip: str | None = None
    os: str | None = None
    mde_id: str | None = None
    entra_id: str | None = None
    domain: str | None = None
    risk_score: str | None = None
    health: str | None = None


class FileEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = None
    sha256: str | None = None
    sha1: str | None = None
    md5: str | None = None
    path: str | None = None
    size: int | None = None
    verdict: str | None = None
    remediation: str | None = None


class Network(BaseModel):
    model_config = ConfigDict(extra="forbid")
    src_ip_internal: str | None = None
    src_ip_external: str | None = None
    dst_ip: str | None = None


class Threat(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: str
    family: str | None = None
    display_name: str | None = None
    provider_actions: str | None = None
    incident_id: str | None = None
    incident_url: str | None = None
    alert_url: str | None = None


class WazuhRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str | None = None
    level: int = 0
    description: str = "Unknown"
    groups: list[str] = Field(default_factory=list)


class NormalizedAlert(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: AlertSource
    alert_id: str
    timestamp: str
    wazuh_rule: WazuhRule
    severity_source: Severity
    title: str
    category: str
    device: Device
    users_involved: list[User] = Field(default_factory=list)
    files: list[FileEvidence] = Field(default_factory=list)
    network: Network
    threat: Threat
    raw: dict[str, Any]


# ===== Active Directory =====


class ADUser(BaseModel):
    """Snapshot de un usuario en AD post-search."""

    model_config = ConfigDict(extra="forbid")
    dn: str
    sam: str
    display_name: str | None = None
    mail: str | None = None
    department: str | None = None
    title: str | None = None
    manager: str | None = None
    member_of: list[str] = Field(default_factory=list)
    account_enabled: bool
    locked_out: bool
    last_logon: str | None = None
    bad_pwd_count: int = 0
    pwd_last_set: str | None = None
    user_account_control: int


class LdapActionResult(BaseModel):
    """Resultado de una operación de modificación en AD."""

    model_config = ConfigDict(extra="forbid")
    ok: bool
    action: str
    target_sam: str
    target_dn: str | None = None
    message: str | None = None


# ===== Wazuh Manager API =====


class WazuhRuleInfo(BaseModel):
    """Detalle de una rule del Wazuh manager (para enriquecer alertas)."""

    model_config = ConfigDict(extra="forbid")
    rule_id: str
    level: int
    description: str
    groups: list[str] = Field(default_factory=list)
    mitre_ids: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    gdpr: list[str] = Field(default_factory=list)
    pci_dss: list[str] = Field(default_factory=list)


class WazuhRecentAlert(BaseModel):
    """Resumen de una alerta histórica para context windowing / outbreak detection."""

    model_config = ConfigDict(extra="forbid")
    timestamp: str
    rule_id: str
    level: int
    description: str
    agent_name: str | None = None
    agent_id: str | None = None
    host: str | None = None
    user: str | None = None
    sha256: str | None = None


# ===== Threat Intel =====


class VtFileReport(BaseModel):
    """Resumen del file report de VirusTotal v3 para el LLM (subset relevante)."""

    model_config = ConfigDict(extra="forbid")
    sha256: str
    malicious_count: int = 0
    suspicious_count: int = 0
    undetected_count: int = 0
    total_engines: int = 0
    family: str | None = None  # popular_threat_classification.suggested_threat_label
    categories: list[str] = Field(default_factory=list)
    first_submission: str | None = None  # ISO de first_submission_date
    last_analysis: str | None = None
    names: list[str] = Field(default_factory=list)
    type_description: str | None = None
    size: int | None = None


class AbuseipdbReport(BaseModel):
    """Resumen del IP report de AbuseIPDB v2 para el LLM."""

    model_config = ConfigDict(extra="forbid")
    ip: str
    abuse_confidence_score: int = 0  # 0-100
    country_code: str | None = None
    isp: str | None = None
    domain: str | None = None
    total_reports: int = 0
    distinct_reporters: int = 0
    last_reported_at: str | None = None
    is_whitelisted: bool = False
    is_tor: bool = False
    usage_type: str | None = None


# ===== FortiGate =====


class FortigateIpContext(BaseModel):
    """Snapshot de una IP en FortiGate: sessions activas + si está ya quarantined."""

    model_config = ConfigDict(extra="forbid")
    ip: str
    active_sessions: int = 0
    already_quarantined: bool = False
    quarantine_expires: str | None = None
    # Cantidad por dirección (útil para distinguir "viene de afuera" vs "sale de adentro")
    sessions_as_source: int = 0
    sessions_as_destination: int = 0


class FortigateActionResult(BaseModel):
    """Resultado de quarantine_ip (o futuras acciones de FortiGate)."""

    model_config = ConfigDict(extra="forbid")
    ok: bool
    ip: str
    action: str  # "quarantine_ip" hoy
    expires_at: str | None = None
    message: str | None = None


# ===== InvGate Service Desk =====


class InvgateTicketResult(BaseModel):
    """Resultado de una operación contra el API de InvGate Service Desk."""

    model_config = ConfigDict(extra="forbid")
    ok: bool
    request_id: int | None = None
    info: str | None = None
    error: str | None = None
