"""Wazuh alert shape used by hygiene/coverage probes."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CleanAlert(BaseModel):
    """Compact Wazuh alert. `raw` is for internal correlation only — it is
    stripped before any LLM-bound serialization to avoid PII leakage."""

    model_config = ConfigDict(extra="forbid")

    timestamp: str
    rule_id: str
    rule_level: int = 0
    rule_description: str = "Unknown"
    rule_groups: list[str] = Field(default_factory=list)
    agent_id: str | None = None
    agent_name: str | None = None
    srcip: str | None = None
    dstip: str | None = None
    user: str | None = None
    decoder_name: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    def to_llm_safe_dict(self) -> dict[str, Any]:
        data = self.model_dump()
        data.pop("raw", None)
        return data
