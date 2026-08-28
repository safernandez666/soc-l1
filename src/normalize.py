"""Normalize raw Wazuh alerts (native or Defender-via-Wazuh) into NormalizedAlert.

Why: agents shouldn't care which source produced the alert. They consume the
common schema and the normalizer handles the shape differences.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any

from src.models import (
    Device,
    EmailEvidence,
    FileEvidence,
    Network,
    NormalizedAlert,
    Threat,
    User,
    WazuhRule,
)

# Regex que extrae el dueño del perfil desde un path windows: c:\users\<user>\...
USER_FROM_PATH = re.compile(r"\\users\\([^\\]+)\\", re.IGNORECASE)

# Caps para no inundar al Enricher (una LDAP query por usuario) ni al prompt del
# Narrator: una campaña de phishing puede tocar decenas de buzones.
MAX_MAILBOX_USERS = 10
MAX_EMAILS = 10


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


def _clean_null(value: Any) -> str | None:
    """Graph manda el string literal "null" en varios campos (threatFamilyName,
    threatDisplayName, classification). Sin esto el correo mostraba un badge que
    decía "null" como si fuera la familia del malware."""
    if value is None:
        return None
    text = str(value).strip()
    return None if text.lower() in ("null", "none", "") else text


def _is_public_ip(ip: str | None) -> bool:
    """True si es una IP ruteable (sirve para AbuseIPDB).

    Descarta privadas, loopback y los placeholders que mete Defender cuando no
    conoce el origen real (255.255.255.255 aparece seguido en alertas de mail).
    """
    if not ip:
        return False
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_reserved
        or parsed.is_multicast
        or parsed.is_unspecified
    )


def _parse_office365_evidence(
    evidence: list[dict[str, Any]],
) -> tuple[list[User], list[EmailEvidence], str | None]:
    """Evidencia de Defender for Office 365 (alertas de mail).

    O365 no manda deviceEvidence ni fileEvidence: manda mailboxEvidence,
    analyzedMessageEvidence, userEvidence e ipEvidence. Sin esto las alertas de
    phishing llegaban al Narrator con users=[], files=[] y network vacía, y el
    resumen ejecutivo salía diciendo "no hay usuarios ni sistemas afectados"
    aunque el payload traía destinatarios, asunto y la URL maliciosa.

    Devuelve (users, emails, sender_ip).
    """
    users: list[User] = []
    seen_sams: set[str] = set()
    for e in evidence:
        odata = e.get("@odata.type") or ""
        if "mailboxEvidence" not in odata and "userEvidence" not in odata:
            continue
        account = e.get("userAccount") or {}
        sam = account.get("accountName")
        if not sam or sam.lower() in seen_sams:
            continue
        seen_sams.add(sam.lower())
        users.append(
            User(
                sam=sam,
                domain=account.get("domainName"),
                role="mailbox_owner",
            )
        )
        if len(users) >= MAX_MAILBOX_USERS:
            break

    emails: list[EmailEvidence] = []
    seen_msgs: set[str] = set()
    for e in evidence:
        if "analyzedMessageEvidence" not in (e.get("@odata.type") or ""):
            continue
        msg_id = e.get("networkMessageId") or ""
        if msg_id and msg_id in seen_msgs:
            continue
        if msg_id:
            seen_msgs.add(msg_id)
        # El From visible (p2Sender) es el que ve el usuario; p1Sender es el
        # envelope. Para triage vale más el visible, con fallback al envelope.
        p2 = e.get("p2Sender") or {}
        p1 = e.get("p1Sender") or {}
        urls = [u for u in (e.get("urls") or []) if u]
        emails.append(
            EmailEvidence(
                subject=e.get("subject"),
                recipient=e.get("recipientEmailAddress"),
                sender_address=p2.get("emailAddress") or p1.get("emailAddress"),
                sender_ip=e.get("senderIp"),
                urls=urls,
                url_count=int(e.get("urlCount") or len(urls)),
                attachments_count=int(e.get("attachmentsCount") or 0),
                received_at=e.get("receivedDateTime"),
                delivery_action=e.get("deliveryAction"),
                delivery_location=e.get("deliveryLocation"),
                threats=[t for t in (e.get("threats") or []) if t],
                verdict=e.get("verdict"),
                remediation=e.get("remediationStatus"),
                internet_message_id=e.get("internetMessageId"),
                network_message_id=e.get("networkMessageId"),
            )
        )
        if len(emails) >= MAX_EMAILS:
            break

    # urlEvidence suelta: si ningún mensaje trajo URLs, no la perdemos.
    loose_urls = [
        u
        for e in evidence
        if "urlEvidence" in (e.get("@odata.type") or "") and (u := e.get("url"))
    ]
    if loose_urls and emails and not any(m.urls for m in emails):
        emails[0].urls = loose_urls
        emails[0].url_count = emails[0].url_count or len(loose_urls)

    # IP de origen: la del sender del mail, o la ipEvidence. Solo públicas: el
    # ThreatIntel las manda a AbuseIPDB y 255.255.255.255 quema una llamada.
    sender_ip = next((m.sender_ip for m in emails if _is_public_ip(m.sender_ip)), None)
    if not sender_ip:
        sender_ip = next(
            (
                ip
                for e in evidence
                if "ipEvidence" in (e.get("@odata.type") or "")
                and _is_public_ip(ip := e.get("ipAddress"))
            ),
            None,
        )
    return users, emails, sender_ip


def _parse_defender(
    data: dict[str, Any],
) -> tuple[Device, list[User], list[FileEvidence], list[EmailEvidence], Network, Threat]:
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

    # Defender for Office 365 (mail): otra familia de evidencia entera.
    mailbox_users, emails, sender_ip = _parse_office365_evidence(evidence)
    known_sams = {u.sam.lower() for u in users if u.sam}
    users += [u for u in mailbox_users if u.sam.lower() not in known_sams]

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
        src_ip_external=device.external_ip or sender_ip,
        dst_ip=None,
    )

    threat = Threat(
        provider=data.get("productName") or "Microsoft Defender for Endpoint",
        family=_clean_null(data.get("threatFamilyName")),
        display_name=_clean_null(data.get("threatDisplayName")),
        provider_actions=data.get("recommendedActions"),
        incident_id=data.get("incidentId"),
        incident_url=data.get("incidentWebUrl"),
        alert_url=data.get("alertWebUrl"),
        mitre_techniques=[t for t in (data.get("mitreTechniques") or []) if t],
    )

    return device, users, files, emails, network, threat


def _parse_wazuh_native(
    data: dict[str, Any], agent: dict[str, Any], src: dict[str, Any]
) -> tuple[Device, list[User], list[FileEvidence], list[EmailEvidence], Network, Threat]:
    device = Device(
        hostname=agent.get("name"),
        internal_ip=data.get("srcip"),
    )
    users: list[User] = []
    # `dstuser` cubre los logs SSL-VPN de FortiGate, donde el usuario autenticado
    # viene en data.dstuser (no en srcuser/user). Va al final para no pisar el
    # actor real en alertas que sí traen srcuser/user.
    sam = (
        data.get("srcuser") or data.get("user") or data.get("dstuser") or src.get("user")
    )
    if sam:
        users.append(User(sam=sam, domain=None, role="event_user"))
    # `remip` es la IP del cliente en VPN SSL de FortiGate (no hay srcip). Es la IP
    # externa que el ThreatIntel chequea contra AbuseIPDB.
    network = Network(
        src_ip_internal=None,
        src_ip_external=data.get("srcip") or data.get("remip"),
        dst_ip=data.get("dstip"),
    )
    threat = Threat(provider="Wazuh native")
    return device, users, [], [], network, threat


def normalize(raw_payload: dict[str, Any]) -> NormalizedAlert:
    """Convert a raw Wazuh alert payload into a NormalizedAlert."""
    src = _unwrap(raw_payload)
    data = src.get("data") or {}
    rule = src.get("rule") or {}
    agent = src.get("agent") or {}

    groups = rule.get("groups") or []
    is_defender = _is_defender(groups, data)

    if is_defender:
        device, users, files, emails, network, threat = _parse_defender(data)
        source = "defender_via_wazuh"
    else:
        device, users, files, emails, network, threat = _parse_wazuh_native(
            data, agent, src
        )
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
        emails=emails,
        network=network,
        threat=threat,
        raw=src,
    )
