# tests/source/test_wazuh_api_source.py
import respx
from httpx import Response

from src.wazuh_health.source.wazuh_api import WazuhAPISource


BASE = "https://192.168.38.60:55000"


def _make_source():
    return WazuhAPISource(
        host="192.168.38.60", port=55000, user="u", password="p", verify_ssl=False
    )


@respx.mock(assert_all_called=False)
def test_login_then_list_agents(respx_mock):
    respx_mock.post(f"{BASE}/security/user/authenticate").mock(
        return_value=Response(200, json={"data": {"token": "TKN"}})
    )
    respx_mock.get(f"{BASE}/agents").mock(
        return_value=Response(200, json={"data": {"affected_items": [
            {"id": "001", "name": "vpn01", "ip": "10.0.5.10",
             "status": "active", "last_keep_alive": "2026-06-11T10:00:00Z"},
            {"id": "002", "name": "win01", "ip": "10.0.5.11",
             "status": "disconnected", "last_keep_alive": "2026-06-10T10:00:00Z"},
        ]}})
    )
    src = _make_source()
    agents = src.list_agents()
    assert {a.agent_id for a in agents} == {"001", "002"}
    assert {a.status for a in agents} == {"active", "disconnected"}


@respx.mock(assert_all_called=False)
def test_indexer_stats_parses_cluster_health(respx_mock):
    respx_mock.post(f"{BASE}/security/user/authenticate").mock(
        return_value=Response(200, json={"data": {"token": "TKN"}})
    )
    respx_mock.get(f"{BASE}/cluster/health").mock(
        return_value=Response(200, json={"data": {
            "heap_pct": 78.3, "red_shards": 0, "yellow_shards": 2, "pending_tasks": 1
        }})
    )
    src = _make_source()
    stats = src.indexer_stats()
    assert stats.heap_pct == 78.3
    assert stats.yellow_shards == 2
