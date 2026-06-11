from src.wazuh_health.contracts import DomainFinding
from src.wazuh_health.agents.runner import (
    AgentInvocation, FakeAgentRunner, get_runner, set_runner,
)


def test_fake_runner_returns_canned_findings():
    canned = [
        DomainFinding(
            domain="hygiene", severity="info", title="x", body_md="y",
            evidence={"k": "v"}, suggested_action="review",
        )
    ]
    set_runner(FakeAgentRunner({"HygieneAgent": canned}))
    runner = get_runner()
    findings, tokens = runner.run(AgentInvocation(
        agent_name="HygieneAgent", instructions="i", tools=[], input_payload={}
    ))
    assert findings == canned
    assert tokens["input"] == 0
    assert tokens["output"] == 0
