"""Replaceable adapter between domain agents and the openai-agents SDK.

The dispatcher calls `get_runner().run(invocation)`. In CI, tests call
`set_runner(FakeAgentRunner(...))` so no real LLM call ever happens.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol

from src.wazuh_health.contracts import DomainFinding, WazuhHealthReport


@dataclass(frozen=True)
class AgentInvocation:
    agent_name: str
    instructions: str
    tools: list[Callable[..., Any]]
    input_payload: dict[str, Any]
    output_type: type = DomainFinding
    model: str | None = None
    timeout_seconds: float = 60.0
    max_tool_calls: int = 6
    output_token_cap: int = 2000


class AgentRunner(Protocol):
    def run(
        self, invocation: AgentInvocation
    ) -> tuple[list[DomainFinding] | WazuhHealthReport, dict[str, int]]: ...


class FakeAgentRunner:
    """Returns pre-canned findings by agent name; counts no tokens."""

    def __init__(self, canned: dict[str, list[DomainFinding] | WazuhHealthReport]) -> None:
        self._canned = canned

    def run(self, invocation: AgentInvocation):
        result = self._canned.get(invocation.agent_name, [])
        return result, {"input": 0, "output": 0}


class _OpenAIAgentsRunner:
    """Real runner backed by the openai-agents SDK. Constructed lazily."""

    def run(self, invocation: AgentInvocation):
        from agents import Agent, Runner  # type: ignore

        agent = Agent(
            name=invocation.agent_name,
            instructions=invocation.instructions,
            tools=invocation.tools,
            output_type=invocation.output_type,
            model=invocation.model,
        )
        result = Runner.run_sync(
            agent,
            input=str(invocation.input_payload),
            max_turns=invocation.max_tool_calls,
        )
        final = result.final_output
        tokens = {
            "input": getattr(result, "input_tokens", 0) or 0,
            "output": getattr(result, "output_tokens", 0) or 0,
        }
        return final, tokens


_RUNNER: AgentRunner | None = None


def set_runner(runner: AgentRunner) -> None:
    global _RUNNER
    _RUNNER = runner


def get_runner() -> AgentRunner:
    global _RUNNER
    if _RUNNER is None:
        _RUNNER = _OpenAIAgentsRunner()
    return _RUNNER


def reset_runner() -> None:
    global _RUNNER
    _RUNNER = None
