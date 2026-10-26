"""Correlación de fallos de autenticación para alertas de enumeración de cuentas.

Defender for Identity avisa "Suspected account enumeration" pero no dice cuántos
intentos hubo, qué nombres probaron ni si alguno entró. Esa evidencia está en los
4776/4625 que los DCs y los servidores (Exchange) mandan a Wazuh: la leemos del
tail de alerts.json, igual que wazuh_alerts, y la resumimos en texto plano para
el Narrator y el ticket. Determinista: no pasa por el LLM.
"""
from __future__ import annotations

import json
import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from src.models import NormalizedAlert
from src.tools.wazuh_alerts import ALERTS_PATH, _parse_timestamp, _reverse_line_reader

logger = logging.getLogger("soc-l1")

# Una jornada de alerts.json pasa de 70k líneas; 300k cubre varios días de tail.
_MAX_SCAN_LINES = 300_000
_WINDOW_PAD = timedelta(minutes=15)
_MAX_NAMES = 40
# Una "ráfaga de spray" son minutos con muchos nombres distintos fallando: el ruido
# normal (un usuario con la clave vieja, un backup) repite 1-3 nombres.
_SPRAY_MIN_NAMES_PER_MINUTE = 5
_SPRAY_MAX_GAP_MINUTES = 5

_FAIL_EVENTS = {"4776", "4625", "4771"}
_SUCCESS_EVENTS = {"4624", "4768"}

# Códigos NTSTATUS de 4776/4625. Con clave incorrecta el DC contesta 0xC000006A
# tanto para cuentas habilitadas como deshabilitadas (valida la clave primero),
# así que 6A prueba que el nombre existe, no que la cuenta esté activa.
_STATUS_MEANING = {
    "0xc0000064": "usuario inexistente",
    "0xc000006a": "clave incorrecta (la cuenta existe)",
    "0xc0000072": "cuenta deshabilitada",
    "0xc0000234": "cuenta bloqueada",
    "0xc000006d": "logon fallido",
    "0xc0000071": "clave vencida",
}
_EXISTS_STATUSES = {"0xc000006a", "0xc0000072", "0xc0000234", "0xc0000071"}
# Logons locales del sistema que coinciden por casualidad con un nombre del diccionario.
_SYSTEM_ACCOUNTS = {"system", "local service", "network service", "anonymous logon", "-"}
_EMPTY_ORIGIN = {"", "-", "null", "none"}


def is_account_enumeration(alert: NormalizedAlert) -> bool:
    techniques = [t.upper() for t in alert.threat.mitre_techniques]
    return (
        any(t.startswith("T1087") for t in techniques)
        or "account enumeration" in alert.title.lower()
    )


_TZ_NO_COLON = re.compile(r"([+-]\d{2})(\d{2})$")


def _iso(value: Any) -> datetime | None:
    """ISO8601 de Wazuh ('...-0300' sin dos puntos, que Python 3.10 no parsea) o de Graph ('...Z')."""
    if not isinstance(value, str):
        return None
    dt = _parse_timestamp(_TZ_NO_COLON.sub(r"\1:\2", value))
    if dt is not None and dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def window_for(alert: NormalizedAlert) -> tuple[datetime, datetime]:
    """Ventana de actividad de Defender ± 15 min (o el timestamp de la alerta ± 30)."""
    data = (alert.raw or {}).get("data") or {}
    first = _iso(data.get("firstActivityDateTime"))
    last = _iso(data.get("lastActivityDateTime"))
    if first and last:
        return first - _WINDOW_PAD, last + _WINDOW_PAD
    ts = _iso(alert.timestamp) or datetime.now(tz=timezone.utc)
    return ts - timedelta(minutes=30), ts + timedelta(minutes=30)


@dataclass
class AuthSpraySummary:
    start: datetime
    end: datetime
    failures: int = 0
    first_seen: str | None = None
    last_seen: str | None = None
    by_agent: Counter = field(default_factory=Counter)
    by_status: Counter = field(default_factory=Counter)
    names: Counter = field(default_factory=Counter)
    existing: set[str] = field(default_factory=set)
    origins: Counter = field(default_factory=Counter)
    successes: list[str] = field(default_factory=list)
    burst_found: bool = False

    def to_text(self) -> str:
        if not self.failures and not self.successes:
            return (
                "Wazuh: sin eventos 4776/4625/4771 en la ventana "
                f"{_fmt(self.start)}–{_fmt(self.end)} UTC."
            )
        lines = [
            f"Wazuh {_fmt(self.start)}–{_fmt(self.end)} UTC: {self.failures} fallos de "
            f"autenticación ({self.first_seen} a {self.last_seen} UTC), "
            f"{len(self.names)} nombres distintos.",
            "Equipos que validaron: "
            + ", ".join(f"{a} ({n})" for a, n in self.by_agent.most_common()),
            "Códigos: "
            + ", ".join(
                f"{s} {_STATUS_MEANING.get(s.lower(), '')}".strip() + f" ×{n}"
                for s, n in self.by_status.most_common()
            ),
            "Nombres probados: "
            + ", ".join(n for n, _ in self.names.most_common(_MAX_NAMES))
            + (" …" if len(self.names) > _MAX_NAMES else ""),
        ]
        if self.existing:
            lines.append("Existen en AD (el DC rechazó la clave): " + ", ".join(sorted(self.existing)))
        if self.origins:
            lines.append(
                "Origen informado: "
                + ", ".join(f"{o} ({n})" for o, n in self.origins.most_common(10))
            )
        else:
            lines.append("Origen informado: ninguno (el campo viene vacío en los eventos).")
        if self.successes:
            lines.append("⚠ Autenticaciones EXITOSAS de esos nombres: " + "; ".join(self.successes[:10]))
        else:
            lines.append(
                "Sin autenticaciones exitosas de esos nombres en Wazuh "
                "(no concluyente: no todos los logons exitosos llegan al SIEM)."
            )
        return "\n".join(lines)


def _fmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%d/%m %H:%M")


def _defender_activity(alert: NormalizedAlert) -> tuple[datetime | None, datetime | None]:
    data = (alert.raw or {}).get("data") or {}
    return _iso(data.get("firstActivityDateTime")), _iso(data.get("lastActivityDateTime"))


def _spray_burst(
    events: list[tuple[datetime, str, str, dict[str, Any]]],
    first: datetime | None,
    last: datetime | None,
) -> tuple[datetime, datetime] | None:
    """Ráfaga de spray (minutos con muchos nombres distintos) que toca la actividad de Defender."""
    names_by_minute: dict[datetime, set[str]] = {}
    for ts, _agent, event_id, ed in events:
        status = str(ed.get("status") or "").lower()
        if event_id in _FAIL_EVENTS and status not in ("", "0x0"):
            minute = ts.astimezone(timezone.utc).replace(second=0, microsecond=0)
            names_by_minute.setdefault(minute, set()).add(str(ed.get("targetUserName") or "").lower())
    hot = sorted(m for m, n in names_by_minute.items() if len(n) >= _SPRAY_MIN_NAMES_PER_MINUTE)
    if not hot:
        return None
    gap = timedelta(minutes=_SPRAY_MAX_GAP_MINUTES)
    chains: list[list[datetime]] = [[hot[0]]]
    for m in hot[1:]:
        if m - chains[-1][-1] <= gap:
            chains[-1].append(m)
        else:
            chains.append([m])
    lo = (first or hot[0]) - gap
    hi = (last or hot[-1]) + gap
    for chain in chains:
        if chain[0] <= hi and chain[-1] >= lo:
            return chain[0], chain[-1] + timedelta(minutes=1)
    return None


def _event_fields(alert: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    win = (alert.get("data") or {}).get("win") or {}
    event_id = str((win.get("system") or {}).get("eventID") or "")
    ed = win.get("eventdata") or {}
    if event_id and ed:
        return event_id, ed
    return None


def summarize_auth_failures(
    alert: NormalizedAlert,
    *,
    alerts_path: str = ALERTS_PATH,
    max_scan_lines: int = _MAX_SCAN_LINES,
) -> AuthSpraySummary:
    start, end = window_for(alert)
    summary = AuthSpraySummary(start=start, end=end)
    path = Path(alerts_path)
    if not path.exists():
        logger.warning("auth_spray: %s no existe", alerts_path)
        return summary

    events: list[tuple[datetime, str, str, dict[str, Any]]] = []
    for line in _reverse_line_reader(path, max_lines=max_scan_lines):
        try:
            raw = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        ts = _iso(raw.get("timestamp"))
        if ts is None:
            continue
        if ts < start:
            break
        parsed = _event_fields(raw)
        if parsed is None or parsed[0] not in (_FAIL_EVENTS | _SUCCESS_EVENTS):
            continue
        events.append((ts, (raw.get("agent") or {}).get("name") or "?", *parsed))

    # Defender solo reporta un tramo; la ráfaga real suele seguir. Se extiende la
    # ventana mientras haya minutos de spray encadenados.
    burst = _spray_burst(events, *_defender_activity(alert))
    if burst is not None:
        summary.start, summary.end = burst
        summary.burst_found = True
        start, end = burst
    events = [e for e in events if start <= e[0] <= end]

    events.sort(key=lambda e: e[0])
    failed_names: set[str] = set()
    for ts, agent, event_id, ed in events:
        name = str(ed.get("targetUserName") or "").strip()
        status = str(ed.get("status") or "").lower()
        if event_id in _FAIL_EVENTS and status not in ("", "0x0"):
            summary.failures += 1
            hhmm = ts.astimezone(timezone.utc).strftime("%H:%M")
            summary.first_seen = summary.first_seen or hhmm
            summary.last_seen = hhmm
            summary.by_agent[agent] += 1
            summary.by_status[status] += 1
            if name:
                summary.names[name.lower()] += 1
                failed_names.add(name.lower())
                if status in _EXISTS_STATUSES:
                    summary.existing.add(name.lower())
            origin = str(ed.get("workstation") or ed.get("workstationName") or ed.get("ipAddress") or "").strip()
            if origin.lower() not in _EMPTY_ORIGIN:
                summary.origins[origin] += 1

    seen_success: set[tuple[str, str, str]] = set()
    for ts, agent, event_id, ed in events:
        name = str(ed.get("targetUserName") or "").strip().lower()
        status = str(ed.get("status") or "").lower()
        if (
            event_id in _SUCCESS_EVENTS
            and name in failed_names
            and status in ("", "0x0")
            and name not in _SYSTEM_ACCOUNTS
            and not name.endswith("$")
            and (name, event_id, agent) not in seen_success
        ):
            seen_success.add((name, event_id, agent))
            summary.successes.append(
                f"{name} {event_id} en {agent} {ts.astimezone(timezone.utc).strftime('%H:%M')} UTC"
            )
    return summary
