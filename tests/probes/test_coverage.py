from datetime import datetime, timezone, timedelta

from src.wazuh_health.source.base import AgentInfo, ManagerStats
from src.wazuh_health.probes.coverage import CoverageProbe


class _FakeSource:
    def __init__(self, agents, decoder_errors=0):
        self._agents = agents
        self._dec = decoder_errors

    def list_agents(self):
        return self._agents

    def manager_stats(self):
        return ManagerStats(decoder_errors=self._dec, rule_hits_by_id={"5710": 100, "9999": 0})


def test_coverage_counts_disconnected_and_never_connected():
    now = datetime.now(tz=timezone.utc)
    agents = [
        AgentInfo(agent_id="1", name="a", status="active", last_keep_alive=now),
        AgentInfo(agent_id="2", name="b", status="disconnected",
                  last_keep_alive=now - timedelta(days=2)),
        AgentInfo(agent_id="3", name="c", status="never_connected"),
        AgentInfo(agent_id="4", name="d", status="disconnected",
                  last_keep_alive=now - timedelta(days=10)),
    ]
    result = CoverageProbe(source=_FakeSource(agents, decoder_errors=3)).run()
    m = result.metrics
    assert m["agents.total"] == 4
    assert m["agents.active"] == 1
    assert m["agents.disconnected"] == 2
    assert m["agents.never_connected"] == 1
    assert m["decoders.errors"] == 3
    assert m["rules.zero_hit"] == 1
