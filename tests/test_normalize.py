"""Tests para el normalizador. Cubre Defender-via-Wazuh y Wazuh nativo."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.normalize import _normalize_severity, normalize

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize(
    "raw,level,expected",
    [
        ("High", 0, "high"),            # Defender capitalizado → enum
        ("INFORMATIONAL", 0, "informational"),
        ("low", 0, "low"),
        ("bogus", 12, "critical"),      # valor inválido → cae al nivel (12 = critical)
        (None, 9, "high"),              # ausente → nivel (9 = high)
        (42, 6, "medium"),              # tipo inesperado → nivel (6 = medium)
    ],
)
def test_normalize_severity_maps_or_falls_back(raw, level, expected) -> None:
    assert _normalize_severity(raw, level) == expected


@pytest.fixture
def defender_keygen() -> dict:
    return json.loads((FIXTURES / "defender_keygen.json").read_text())


def test_defender_keygen_basic_metadata(defender_keygen: dict) -> None:
    """La alerta Defender se detecta correctamente y los campos top-level."""
    a = normalize(defender_keygen)
    assert a.source == "defender_via_wazuh"
    assert a.alert_id == "synthetic-alert-id-001"
    assert a.title == "'Keygen' hacktool was detected"
    assert a.category == "Malware"
    assert a.severity_source == "low"
    assert a.wazuh_rule.id == "200002"
    assert a.wazuh_rule.level == 7
    assert "defender" in a.wazuh_rule.groups


def test_defender_keygen_device(defender_keygen: dict) -> None:
    """Device evidence: hostname, IPs, IDs de Defender y Entra."""
    a = normalize(defender_keygen)
    assert a.device.hostname == "desktop-1234"
    assert a.device.fqdn == "desktop-1234.example.local"
    assert a.device.internal_ip == "10.99.0.42"
    assert a.device.external_ip == "203.0.113.45"
    assert a.device.os == "Windows10"
    assert a.device.mde_id == "0000000000000000000000000000000000000001"
    assert a.device.entra_id == "00000000-0000-0000-0000-000000000001"
    assert a.device.risk_score == "low"
    assert a.device.health == "active"


def test_defender_keygen_users_logged_and_path(defender_keygen: dict) -> None:
    """Caso clásico: usuario logueado distinto del dueño del path del archivo."""
    a = normalize(defender_keygen)
    by_sam = {u.sam: u for u in a.users_involved}
    # jdoe viene de loggedOnUsers
    assert "jdoe" in by_sam
    assert by_sam["jdoe"].role == "logged_on"
    assert by_sam["jdoe"].domain == "EXAMPLE"
    # asmith viene del path c:\users\asmith\...
    assert "asmith" in by_sam
    assert by_sam["asmith"].role == "file_path_owner"
    assert by_sam["asmith"].domain is None


def test_defender_keygen_file_evidence(defender_keygen: dict) -> None:
    """File evidence: hashes completos, verdict, path."""
    a = normalize(defender_keygen)
    assert len(a.files) == 1
    f = a.files[0]
    assert f.name == "synthetic-tool.exe"
    assert f.sha256 == "1111111111111111111111111111111111111111111111111111111111111111"
    assert f.sha1 == "0000000000000000000000000000000000000000"
    assert f.md5 == "22222222222222222222222222222222"
    assert f.size == 871936
    assert f.verdict == "malicious"
    assert "asmith" in (f.path or "")


def test_defender_keygen_threat(defender_keygen: dict) -> None:
    """Threat metadata enriquecida desde Defender."""
    a = normalize(defender_keygen)
    assert a.threat.provider == "Microsoft Defender for Endpoint"
    assert a.threat.family == "Keygen"
    assert a.threat.display_name == "HackTool:Win32/Keygen!pz"
    assert a.threat.incident_id == "999"
    assert "security.microsoft.com" in (a.threat.incident_url or "")
    assert "security.microsoft.com" in (a.threat.alert_url or "")


def test_defender_keygen_network(defender_keygen: dict) -> None:
    """Network: en Defender la IP interna/externa vienen del device."""
    a = normalize(defender_keygen)
    assert a.network.src_ip_internal == "10.99.0.42"
    assert a.network.src_ip_external == "203.0.113.45"
    assert a.network.dst_ip is None


def test_wazuh_native_ssh_brute_force_minimal() -> None:
    """Wazuh nativo (no Defender) - shape distinto, mismo schema de salida."""
    raw = {
        "_source": {
            "agent": {"name": "web-prod-01", "id": "001"},
            "data": {
                "srcip": "203.0.113.45",
                "srcuser": "admin",
            },
            "rule": {
                "id": "5712",
                "level": 10,
                "description": "SSH brute force from external IP",
                "groups": ["authentication_failed", "sshd"],
            },
            "id": "test-native-001",
            "timestamp": "2026-05-15T10:00:00Z",
        }
    }
    a = normalize(raw)
    assert a.source == "wazuh_native"
    assert a.device.hostname == "web-prod-01"
    assert a.network.src_ip_external == "203.0.113.45"
    assert len(a.users_involved) == 1
    assert a.users_involved[0].sam == "admin"
    assert a.users_involved[0].role == "event_user"
    assert a.severity_source == "high"  # level 10 → high
    assert a.threat.provider == "Wazuh native"


@pytest.fixture
def fgt_vpn_offhours() -> dict:
    return json.loads((FIXTURES / "fortigate_vpn_offhours.json").read_text())


def test_fortigate_vpn_offhours_user_from_dstuser(fgt_vpn_offhours: dict) -> None:
    """VPN SSL de FortiGate (rule 196104): el usuario autenticado viene en
    data.dstuser (no srcuser/user) y la IP del cliente en data.remip (no srcip).
    Sin esto el Enricher no resuelve el user en AD y el Narrator no puede proponer
    acción de identidad."""
    a = normalize(fgt_vpn_offhours)
    assert a.source == "wazuh_native"
    assert a.wazuh_rule.id == "196104"
    assert a.wazuh_rule.level == 8
    assert a.severity_source == "medium"  # level 8 → medium
    # usuario monitoreado resuelto desde dstuser
    assert len(a.users_involved) == 1
    assert a.users_involved[0].sam == "mbaez"
    assert a.users_involved[0].role == "event_user"
    # IP del cliente VPN desde remip
    assert a.network.src_ip_external == "186.158.30.106"
    assert "fortigate_vpn_monitored_user" in a.wazuh_rule.groups


def test_unwrap_raw_without_source_envelope() -> None:
    """Si el integrator manda sin _source envelope, también funciona."""
    raw = {
        "agent": {"name": "host-x"},
        "data": {"srcip": "1.2.3.4"},
        "rule": {"id": "100", "level": 5, "description": "test", "groups": ["test"]},
        "id": "raw-no-source",
        "timestamp": "2026-05-15T10:00:00Z",
    }
    a = normalize(raw)
    assert a.source == "wazuh_native"
    assert a.alert_id == "raw-no-source"


# ===== Defender for Office 365 (alertas de correo) =====


@pytest.fixture
def defender_o365() -> dict:
    """Alerta real de O365: "malicious URL removed after delivery", 2 buzones."""
    return json.loads((FIXTURES / "defender_o365_malicious_url.json").read_text())


def test_o365_extracts_mailbox_users(defender_o365: dict) -> None:
    """Los buzones alcanzados salen como users_involved.

    Regresión: el parser solo miraba deviceEvidence/fileEvidence (MDE), así que
    estas alertas llegaban con users_involved=[] y el Narrator escribía
    "no hay usuarios involucrados" con dos destinatarios reales en el payload.
    """
    a = normalize(defender_o365)
    sams = {u.sam for u in a.users_involved}
    assert sams == {"jperez", "mgomez"}
    assert all(u.role == "mailbox_owner" for u in a.users_involved)
    assert all(u.domain == "contoso.dns" for u in a.users_involved)


def test_o365_extracts_email_evidence(defender_o365: dict) -> None:
    """Asunto, remitente, IP y URL maliciosa llegan al modelo normalizado."""
    a = normalize(defender_o365)
    assert len(a.emails) == 2
    m = a.emails[0]
    assert m.subject.startswith("Actualizá tus datos")
    assert m.recipient == "jperez@contoso.com"
    assert m.sender_ip == "200.41.220.50"
    assert m.sender_address.endswith("@4167062.mailer-example.com")
    assert m.urls == ["abre.ai/rw8y"]
    assert m.url_count == 1
    assert m.verdict == "suspicious"


def test_o365_sender_ip_becomes_external_ip(defender_o365: dict) -> None:
    """La IP del sender es el IOC que el ThreatIntel manda a AbuseIPDB."""
    a = normalize(defender_o365)
    assert a.network.src_ip_external == "200.41.220.50"


def test_o365_keeps_vendor_mitre(defender_o365: dict) -> None:
    """T1566.002 viene en el payload de Defender aunque la rule 200001 no mapee."""
    a = normalize(defender_o365)
    assert a.threat.mitre_techniques == ["T1566.002"]
    assert a.threat.incident_id == "29"


def test_o365_null_strings_are_cleaned(defender_o365: dict) -> None:
    """Graph manda el string "null"; no queremos family="null" en el correo."""
    a = normalize(defender_o365)
    assert a.threat.family is None
    assert a.threat.display_name is None


def test_o365_no_device_fields(defender_o365: dict) -> None:
    """No hay endpoint en estas alertas: device queda vacío, no inventado."""
    a = normalize(defender_o365)
    assert a.device.hostname is None
    assert a.files == []


def test_endpoint_alert_has_no_emails(defender_keygen: dict) -> None:
    """Las alertas de endpoint no deben ganar evidencia de correo."""
    a = normalize(defender_keygen)
    assert a.emails == []


@pytest.mark.parametrize(
    "ip,expected",
    [
        ("200.41.220.50", True),
        ("255.255.255.255", False),  # placeholder que mete Defender
        ("192.168.1.10", False),
        ("10.0.0.1", False),
        ("127.0.0.1", False),
        ("no-es-una-ip", False),
        (None, False),
    ],
)
def test_is_public_ip(ip, expected) -> None:
    from src.normalize import _is_public_ip

    assert _is_public_ip(ip) is expected
