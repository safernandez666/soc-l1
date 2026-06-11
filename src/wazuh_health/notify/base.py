"""Notifier Protocol."""
from __future__ import annotations

from pathlib import Path
from typing import Protocol

from src.wazuh_health.contracts import DomainFinding, WazuhHealthReport


class Notifier(Protocol):
    enabled: bool

    def notify_finding(self, finding: DomainFinding) -> None: ...
    def notify_report(self, report: WazuhHealthReport, *, markdown: str) -> Path | None: ...
