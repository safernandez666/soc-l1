"""ReporterAgent invocation: open findings → consolidated WazuhHealthReport."""
from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from src.wazuh_health.agents.runner import AgentInvocation, get_runner
from src.wazuh_health.contracts import WazuhHealthReport
from src.wazuh_health.store.audit_store import AuditStore
from src.wazuh_health.store.findings_store import FindingsStore
from src.wazuh_health.tools.readonly import REPORTER_TOOLS

_PROMPT = (Path(__file__).parent / "prompts" / "reporter.md").read_text()


def invoke_reporter_agent(
    *,
    audit_store: AuditStore,
    findings_store: FindingsStore,
    heavy_model: str,
    window_hours: int,
    now: datetime,
) -> WazuhHealthReport:
    since = (now - timedelta(hours=window_hours)).isoformat()
    open_findings = [f.model_dump() for f in findings_store.list_open(since_iso=since)]
    invocation = AgentInvocation(
        agent_name="ReporterAgent",
        instructions=_PROMPT,
        tools=REPORTER_TOOLS,
        input_payload={"window_hours": window_hours, "findings": open_findings},
        output_type=WazuhHealthReport,
        model=heavy_model,
    )
    report, tokens = get_runner().run(invocation)
    audit_store.record_agent_run(
        agent="ReporterAgent", started_at=now, ended_at=now, status="ok",
        input_tokens=tokens["input"], output_tokens=tokens["output"],
        tool_calls=[], output_hash=None, finding_ids=[],
    )
    return report
