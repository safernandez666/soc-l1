"""Slack notifier — webhook-based, severity-floor gated."""
from __future__ import annotations

from pathlib import Path
from typing import Literal

import httpx

from src.wazuh_health.contracts import DomainFinding, WazuhHealthReport

_SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}


class SlackNotifier:
    enabled: bool = True

    def __init__(
        self,
        *,
        webhook_url: str,
        severity_floor: Literal["info", "warning", "critical"] = "warning",
        timeout_s: float = 5.0,
    ) -> None:
        self._url = webhook_url
        self._floor = _SEVERITY_ORDER[severity_floor]
        self._timeout = timeout_s

    def _post(self, payload: dict) -> None:
        with httpx.Client(timeout=self._timeout) as c:
            r = c.post(self._url, json=payload)
            r.raise_for_status()

    def notify_finding(self, finding: DomainFinding) -> None:
        if _SEVERITY_ORDER[finding.severity] < self._floor:
            return
        self._post({
            "text": f"*[{finding.severity.upper()}] {finding.title}*\n{finding.body_md[:1000]}"
        })

    def notify_report(self, report: WazuhHealthReport, *, markdown: str) -> Path | None:
        self._post({"text": f"Wazuh Health Report\n```{markdown[:2500]}```"})
        return None
