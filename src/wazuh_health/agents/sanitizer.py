"""Validate and clean LLM-emitted DomainFindings before persisting."""
from __future__ import annotations

import re
from xml.etree import ElementTree as ET

from src.wazuh_health.contracts import DomainFinding

EXTERNAL_URL_RE = re.compile(r"https?://(?!internal\.)\S+", re.IGNORECASE)
SHELL_META_RE = re.compile(r"[$;&|`]|\b(rm|curl|wget|nc|bash|sh)\b", re.IGNORECASE)

MAX_TITLE = 120
MAX_BODY = 4000


class SanitizeError(ValueError):
    pass


def sanitize_finding(
    finding: DomainFinding, *, pseudonymizer=None
) -> DomainFinding:
    title = finding.title[:MAX_TITLE]
    body = finding.body_md[:MAX_BODY]
    body = EXTERNAL_URL_RE.sub("[link redacted]", body)

    if SHELL_META_RE.search(finding.suggested_action):
        raise SanitizeError("suggested_action contains shell metacharacters")

    for k, v in finding.evidence.items():
        if isinstance(v, dict | list):
            raise SanitizeError(f"evidence[{k}] must be a scalar")
        if not isinstance(v, str | int | float):
            raise SanitizeError(f"evidence[{k}] has unsupported type")

    if finding.proposed_artifact:
        try:
            ET.fromstring(finding.proposed_artifact)
        except ET.ParseError as exc:
            raise SanitizeError(f"proposed_artifact is not valid XML: {exc}") from exc

    return DomainFinding(
        domain=finding.domain,
        severity=finding.severity,
        title=title,
        body_md=body,
        evidence=finding.evidence,
        suggested_action=finding.suggested_action,
        proposed_artifact=finding.proposed_artifact,
        hash_key="",
    )
