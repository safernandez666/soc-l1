"""Resumen de fallos 4776/4625 para alertas de enumeración de cuentas."""
from __future__ import annotations

import json
from pathlib import Path

from src.normalize import normalize
from src.tools.auth_spray import (
    is_account_enumeration,
    summarize_auth_failures,
    window_for,
)


def _alert(**data_extra):
    return normalize({
        "timestamp": "2026-10-26T07:09:31.290-0300",
        "rule": {"id": "200003", "level": 10, "description": "Defender [medium]: enum",
                 "groups": ["azure", "defender"]},
        "data": {
            "id": "ri1_aml", "title": "Suspected account enumeration (Kerberos, NTLM, AD FS)",
            "severity": "medium", "mitreTechniques": ["T1087.002"],
            "firstActivityDateTime": "2026-10-26T09:46:11Z",
            "lastActivityDateTime": "2026-10-26T09:51:44Z",
            "evidence": [], **data_extra,
        },
    })


def _event(ts: str, agent: str, event_id: str, user: str, status: str | None = None, **ed):
    eventdata = {"targetUserName": user, **ed}
    if status is not None:
        eventdata["status"] = status
    return json.dumps({
        "timestamp": ts, "agent": {"name": agent},
        "data": {"win": {"system": {"eventID": event_id}, "eventdata": eventdata}},
    })


def _write(tmp_path: Path, lines: list[str]) -> str:
    p = tmp_path / "alerts.json"
    p.write_text("\n".join(lines) + "\n")
    return str(p)


def test_is_account_enumeration_by_mitre_and_title() -> None:
    assert is_account_enumeration(_alert())
    other = normalize({"rule": {"id": "1", "level": 3, "description": "x", "groups": []},
                       "data": {"title": "Something else"}})
    assert not is_account_enumeration(other)


def test_window_pads_defender_activity() -> None:
    start, end = window_for(_alert())
    assert start.strftime("%H:%M") == "09:31"
    assert end.strftime("%H:%M") == "10:06"


def test_summary_counts_names_codes_and_existing_accounts(tmp_path) -> None:
    path = _write(tmp_path, [
        # fuera de la ventana: no cuenta (alerts.json es cronológico)
        _event("2026-10-26T03:00:00.000-0300", "SRVDC2", "4776", "otro", "0xc000006a"),
        _event("2026-10-26T06:46:18.000-0300", "SRVDC2", "4776", "smtp", "0xc000006a"),
        _event("2026-10-26T06:46:44.000-0300", "SRVEXCHANGE2016", "4776", "test", "0xc0000064"),
        _event("2026-10-26T06:46:44.000-0300", "SRVDC2", "4776", "test", "0xc000006a"),
        _event("2026-10-26T06:47:00.000-0300", "SRVDC2", "4776", "postmaster", "0xc0000064"),
    ])
    s = summarize_auth_failures(_alert(), alerts_path=path)
    assert s.failures == 4
    assert set(s.names) == {"smtp", "test", "postmaster"}
    assert s.existing == {"smtp", "test"}
    assert s.by_agent["SRVDC2"] == 3
    text = s.to_text()
    assert "4 fallos" in text and "postmaster" in text
    assert "clave incorrecta (la cuenta existe)" in text
    assert "campo viene vacío" in text


def test_summary_reports_origin_when_present(tmp_path) -> None:
    path = _write(tmp_path, [
        _event("2026-10-26T06:46:18.000-0300", "SRVDC2", "4776", "admin", "0xc000006a",
               workstation="178-16-53-33"),
        _event("2026-10-26T06:46:19.000-0300", "SRVDC2", "4776", "info", "0xc0000064",
               workstation="-"),
    ])
    s = summarize_auth_failures(_alert(), alerts_path=path)
    assert dict(s.origins) == {"178-16-53-33": 1}


def test_summary_flags_success_for_probed_name(tmp_path) -> None:
    path = _write(tmp_path, [
        _event("2026-10-26T06:46:18.000-0300", "SRVDC2", "4776", "smtp", "0xc000006a"),
        _event("2026-10-26T06:48:00.000-0300", "SRVDC2", "4624", "smtp"),
        _event("2026-10-26T06:48:00.000-0300", "SRVDC2", "4624", "otrousuario"),
    ])
    s = summarize_auth_failures(_alert(), alerts_path=path)
    assert len(s.successes) == 1 and s.successes[0].startswith("smtp 4624")
    assert "EXITOSAS" in s.to_text()


def test_summary_without_events_or_file(tmp_path) -> None:
    empty = summarize_auth_failures(_alert(), alerts_path=_write(tmp_path, []))
    assert "sin eventos" in empty.to_text()
    missing = summarize_auth_failures(_alert(), alerts_path=str(tmp_path / "nope.json"))
    assert missing.failures == 0


def test_window_extends_to_whole_spray_burst(tmp_path) -> None:
    """Defender vio 09:46-09:51Z, pero el spray siguió hasta ~09:58Z: se resume todo."""
    lines = [_event("2026-10-26T06:31:00.000-0300", "SRVDC2", "4776", "ruido", "0xc000006a")]
    for minute in range(40, 59):  # 06:40..06:58 -03 = 09:40..09:58Z
        for i in range(6):
            lines.append(_event(f"2026-10-26T06:{minute}:{i * 5:02d}.000-0300", "SRVDC2",
                                "4776", f"user{minute}_{i}", "0xc0000064"))
    # ruido posterior de un solo nombre: no debe sumarse
    lines.append(_event("2026-10-26T08:30:00.000-0300", "SRVDC2", "4776", "veeam", "0xc0000064"))
    s = summarize_auth_failures(_alert(), alerts_path=_write(tmp_path, lines))
    assert s.failures == 19 * 6
    assert "veeam" not in s.names and "ruido" not in s.names
    assert s.end.strftime("%H:%M") == "09:59"


def test_success_ignores_system_and_machine_accounts_and_dedupes(tmp_path) -> None:
    path = _write(tmp_path, [
        _event("2026-10-26T06:46:00.000-0300", "SRVDC2", "4776", "system", "0xc0000064"),
        _event("2026-10-26T06:46:01.000-0300", "SRVDC2", "4776", "smtp", "0xc000006a"),
        _event("2026-10-26T06:47:00.000-0300", "BKP", "4624", "system"),
        _event("2026-10-26T06:47:10.000-0300", "SRVDC2", "4624", "smtp"),
        _event("2026-10-26T06:47:20.000-0300", "SRVDC2", "4624", "smtp"),
    ])
    s = summarize_auth_failures(_alert(), alerts_path=path)
    assert len(s.successes) == 1 and s.successes[0].startswith("smtp 4624 en SRVDC2")
