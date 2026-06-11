"""HygieneAgent invocation: hits → LLM → sanitized findings → store."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from src.wazuh_health.agents.runner import AgentInvocation, get_runner
from src.wazuh_health.agents.sanitizer import SanitizeError, sanitize_finding
from src.wazuh_health.contracts import DomainFinding, ThresholdHit
from src.wazuh_health.store.audit_store import AuditStore
from src.wazuh_health.store.findings_store import FindingsStore, compute_hash_key
from src.wazuh_health.tools.readonly import HYGIENE_TOOLS

_PROMPT = (Path(__file__).parent / "prompts" / "hygiene.md").read_text()


def invoke_hygiene_agent(
    *,
    hits: list[ThresholdHit],
    audit_store: AuditStore,
    findings_store: FindingsStore,
    light_model: str,
    now: datetime,
) -> list[int]:
    payload = {"hits": [h.model_dump() for h in hits]}
    invocation = AgentInvocation(
        agent_name="HygieneAgent",
        instructions=_PROMPT,
        tools=HYGIENE_TOOLS,
        input_payload=payload,
        output_type=list[DomainFinding],
        model=light_model,
    )
    started = now
    findings, tokens = get_runner().run(invocation)
    persisted_ids: list[int] = []
    for raw in (findings or []):
        try:
            clean = sanitize_finding(raw)
        except SanitizeError:
            continue
        hash_key = compute_hash_key(
            "hygiene",
            metric=str(hits[0].metric if hits else ""),
            evidence=clean.evidence,
        )
        fid = findings_store.upsert(clean, hash_key=hash_key)
        persisted_ids.append(fid)

    audit_store.record_agent_run(
        agent="HygieneAgent", started_at=started, ended_at=now,
        status="ok", input_tokens=tokens["input"], output_tokens=tokens["output"],
        tool_calls=[],
        output_hash=hashlib.sha1(
            json.dumps([f.model_dump() for f in (findings or [])], sort_keys=True, default=str).encode()
        ).hexdigest() if findings else None,
        finding_ids=persisted_ids,
    )
    return persisted_ids
