"""Filesystem notifier — always writes reports to report_dir."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from src.wazuh_health.contracts import DomainFinding, WazuhHealthReport


class FilesystemNotifier:
    enabled: bool = True

    def __init__(self, *, report_dir: Path) -> None:
        self._report_dir = Path(report_dir)
        self._report_dir.mkdir(parents=True, exist_ok=True)

    def notify_finding(self, finding: DomainFinding) -> None:
        # No per-finding output — filesystem is bulk-only.
        return None

    def notify_report(self, report: WazuhHealthReport, *, markdown: str) -> Path:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d-%H%M")
        out = self._report_dir / f"{ts}.md"
        out.write_text(markdown, encoding="utf-8")
        return out
