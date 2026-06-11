"""CapacityAgent invocation — same shape as HygieneAgent."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path

from src.wazuh_health.agents.runner import AgentInvocation, get_runner
from src.wazuh_health.agents.sanitizer import SanitizeError, sanitize_finding
from src.wazuh_health.contracts import DomainFinding, ThresholdHit
from src.wazuh_health.store.audit_store import AuditStore
from src.wazuh_health.store.findings_store import FindingsStore, compute_hash_key
from src.wazuh_health.tools.readonly import CAPACITY_TOOLS

_PROMPT = (Path(__file__).parent / "prompts" / "capacity.md").read_text()


def invoke_capacity_agent(
    *, hits, audit_store: AuditStore, findings_store: FindingsStore,
    light_model: str, now: datetime,
) -> list[int]:
    invocation = AgentInvocation(
        agent_name="CapacityAgent", instructions=_PROMPT, tools=CAPACITY_TOOLS,
        input_payload={"hits": [h.model_dump() for h in hits]},
        output_type=list[DomainFinding], model=light_model,
    )
    findings, tokens = get_runner().run(invocation)
    persisted: list[int] = []
    for raw in (findings or []):
        try:
            clean = sanitize_finding(raw)
        except SanitizeError:
            continue
        hk = compute_hash_key("capacity", metric=str(hits[0].metric if hits else ""), evidence=clean.evidence)
        persisted.append(findings_store.upsert(clean, hash_key=hk))
    audit_store.record_agent_run(
        agent="CapacityAgent", started_at=now, ended_at=now, status="ok",
        input_tokens=tokens["input"], output_tokens=tokens["output"],
        tool_calls=[], output_hash=None, finding_ids=persisted,
    )
    return persisted
