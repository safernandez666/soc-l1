"""Render Wazuh local_rules.xml snippets safely.

- Use `xml.sax.saxutils.escape` for element content (no quote escape needed there).
- Use `xml.sax.saxutils.quoteattr` for attribute values (handles quotes correctly).
- Reject non-numeric rule_ids to prevent injection through if_sid.
- Always include `<group>cleanswarm,</group>` for auditability.
- Include a metadata comment with bucket hash and count for rollback.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from xml.sax.saxutils import escape, quoteattr

from src.wazuh_health.contracts import NoiseBucket

_NUMERIC_RULE_ID = re.compile(r"^\d+$")


def _condition_xml(condition: dict[str, str]) -> str:
    lines: list[str] = []
    if agent_name := condition.get("agent.name"):
        lines.append(
            f"    <field name={quoteattr('agent.name')}>{escape(f'^{agent_name}$')}</field>"
        )
    if srcip := condition.get("srcip"):
        lines.append(f"    <srcip>{escape(srcip)}</srcip>")
    if user := condition.get("user"):
        lines.append(
            f"    <field name={quoteattr('data.srcuser')}>{escape(f'^{user}$')}</field>"
        )
    return "\n".join(lines)


def render_local_rule(
    bucket: NoiseBucket,
    *,
    local_rule_id: int,
    bucket_hash: str,
    count: int | None = None,
) -> str:
    """Render a single suppression snippet for a bucket.

    `local_rule_id` must come from a registry that picks an unused id in 100000-120000.
    `bucket_hash` is for auditability in the metadata comment.
    """
    rid = str(bucket.rule_id or "")
    if not _NUMERIC_RULE_ID.match(rid):
        raise ValueError(f"rule_id must be numeric for safe XML rendering: {rid!r}")

    condition = {k: v for k, v in bucket.dimensions.items() if k != "rule_id"}
    body = _condition_xml(condition)
    n = count if count is not None else bucket.count
    generated = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    meta = escape(
        f"CleanSwarm candidate for noisy rule {rid}; hash={bucket_hash}; count={n}; generated={generated}; review before enabling"
    )
    description = escape(f"CleanSwarm suppress noisy {rid} conditionally")

    return (
        f"<!-- {meta} -->\n"
        f"<rule id=\"{local_rule_id}\" level=\"0\">\n"
        f"    <if_sid>{rid}</if_sid>\n"
        f"{body}\n"
        f"    <group>cleanswarm,</group>\n"
        f"    <description>{description}</description>\n"
        f"</rule>"
    )
