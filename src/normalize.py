"""Normalize raw Wazuh alerts (native or Defender-via-Wazuh) into NormalizedAlert.

Why: agents shouldn't care which source produced the alert. They consume the
common schema and the normalizer handles the shape differences.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from src.models import (
    Device,
    FileEvidence,
    Network,
    NormalizedAlert,
    Threat,
    User,
    WazuhRule,
)

# Regex que extrae el dueño del perfil desde un path windows: c:\users\<user>\...
USER_FROM_PATH = re.compile(r"\\users\\([^\\]+)\\", re.IGNORECASE)


def _severity_from_level(level: int) -> str:
    if level >= 12:
        return "critical"
    if level >= 9:
        return "high"
    if level >= 6:
        return "medium"
    return "low"


_VALID_SEVERITIES = {"informational", "low", "medium", "high", "critical"}


def _normalize_severity(raw: Any, level: int) -> str:
    """Mapea el severity crudo al enum Severity.

    Defender suele mandar 'High'/'Informational' (capitalizado) y podría mandar
    valores inesperados; si no matchea o falta, cae al severity derivado del nivel
    de la rule. Evita que un valor fuera del enum tire ValidationError y se pierda
    la alerta entera.
    """
    if isinstance(raw, str):
        s = raw.strip().lower()
        if s in _VALID_SEVERITIES:
            return s
    return _severity_from_level(level)


def _unwrap(raw: dict[str, Any]) -> dict[str, Any]:
    """Wazuh integrator can deliver _source-wrapped or root-level. Handle both."""
    if "_source" in raw and isinstance(raw["_source"], dict):
        return raw["_source"]
    if "alert" in raw and isinstance(raw["alert"], dict):
        return raw["alert"]
    return raw


def _is_defender(rule_groups: list[str], data: dict[str, Any]) -> bool:
    return (
        "defender" in rule_groups
        or data.get("serviceSource") == "microsoftDefenderForEndpoint"
    )


def _parse_defender(
    data: dict[str, Any],
) -> tuple[Device, list[User], list[FileEvidence], Network, Threat]:
    evidence = data.get("evidence") or []
    device_ev: dict[str, Any] = next(
        (e for e in evidence if "deviceEvidence" in (e.get("@odata.type") or "")),
        {},
    )
    file_evs = [
        e for e in evidence if "fileEvidence" in (e.get("@odata.type") or "")
    ]

    logged_users = [
        User(
            sam=u.get("accountName"),
            domain=u.get("domainName"),
            role="logged_on",
        )
        for u in (device_ev.get("loggedOnUsers") or [])
        if u.get("accountName")
    ]

    # Usuarios extra desde el path: c:\users\<name>\... (suelen no ser el logged_on)
    path_users: set[str] = set()
    for fe in file_evs:
        path = (fe.get("fileDetails") or {}).get("filePath") or ""
        m = USER_FROM_PATH.search(path)
        if m:
            path_users.add(m.group(1).lower())

    logged_sams = {u.sam.lower() for u in logged_users if u.sam}
    extra_users = [
        User(sam=name, domain=None, role="file_path_owner")
        for name in sorted(path_users)
        if name not in logged_sams
    ]
    users = logged_users + extra_users

    device = Device(
        hostname=device_ev.get("hostName"),
        fqdn=device_ev.get("deviceDnsName"),
        internal_ip=device_ev.get("lastIpAddress"),
        external_ip=device_ev.get("lastExternalIpAddress"),
        os=device_ev.get("osPlatform"),
        mde_id=device_ev.get("mdeDeviceId"),
        entra_id=device_ev.get("azureAdDeviceId"),
        domain=device_ev.get("ntDomain") or device_ev.get("dnsDomain"),
        risk_score=device_ev.get("riskScore"),
        health=device_ev.get("healthStatus"),
    )

    files = [
        FileEvidence(
            name=(fe.get("fileDetails") or {}).get("fileName"),
            sha256=(fe.get("fileDetails") or {}).get("sha256"),
            sha1=(fe.get("fileDetails") or {}).get("sha1"),
            md5=(fe.get("fileDetails") or {}).get("md5"),
            path=(fe.get("fileDetails") or {}).get("filePath"),
            size=(fe.get("fileDetails") or {}).get("fileSize"),
            verdict=fe.get("verdict"),
            remediation=fe.get("remediationStatus"),
        )
        for fe in file_evs
    ]

    network = Network(
        src_ip_internal=device.internal_ip,
        src_ip_external=device.external_ip,
        dst_ip=None,
    )

    threat = Threat(
        provider=data.get("productName") or "Microsoft Defender for Endpoint",
        family=data.get("threatFamilyName"),
        display_name=data.get("threatDisplayName"),
        provider_actions=data.get("recommendedActions"),
        incident_id=data.get("incidentId"),
        incident_url=data.get("incidentWebUrl"),
        alert_url=data.get("alertWebUrl"),
    )

    return device, users, files, network, threat


def _parse_wazuh_native(
    data: dict[str, Any], agent: dict[str, Any], src: dict[str, Any]
) -> tuple[Device, list[User], list[FileEvidence], Network, Threat]:
    device = Device(
        hostname=agent.get("name"),
        internal_ip=data.get("srcip"),
    )
    users: list[User] = []
    sam = data.get("srcuser") or data.get("user") or src.get("user")
    if sam:
        users.append(User(sam=sam, domain=None, role="event_user"))
    network = Network(
        src_ip_internal=None,
        src_ip_external=data.get("srcip"),
        dst_ip=data.get("dstip"),
    )
    threat = Threat(provider="Wazuh native")
    return device, users, [], network, threat


def normalize(raw_payload: dict[str, Any]) -> NormalizedAlert:
    """Convert a raw Wazuh alert payload into a NormalizedAlert."""
    src = _unwrap(raw_payload)
    data = src.get("data") or {}
    rule = src.get("rule") or {}
    agent = src.get("agent") or {}

    groups = rule.get("groups") or []
    is_defender = _is_defender(groups, data)

    if is_defender:
        device, users, files, network, threat = _parse_defender(data)
        source = "defender_via_wazuh"
    else:
        device, users, files, network, threat = _parse_wazuh_native(data, agent, src)
        source = "wazuh_native"

    severity_source = _normalize_severity(data.get("severity"), int(rule.get("level") or 0))

    wazuh_rule = WazuhRule(
        id=str(rule["id"]) if rule.get("id") is not None else None,
        level=int(rule.get("level") or 0),
        description=rule.get("description") or data.get("title") or "Unknown",
        groups=list(groups),
    )

    alert_id = (
        str(data.get("id"))
        if data.get("id")
        else str(src.get("id") or int(datetime.now(tz=timezone.utc).timestamp()))
    )
    timestamp = src.get("timestamp") or datetime.now(tz=timezone.utc).isoformat()
    title = data.get("title") or rule.get("description") or "Alert"
    category = data.get("category") or (groups[0] if groups else "unknown")

    return NormalizedAlert(
        source=source,
        alert_id=alert_id,
        timestamp=timestamp,
        wazuh_rule=wazuh_rule,
        severity_source=severity_source,
        title=title,
        category=category,
        device=device,
        users_involved=users,
        files=files,
        network=network,
        threat=threat,
        raw=src,
    )
