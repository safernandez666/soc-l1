from pathlib import Path

from src.wazuh_health.source.base import (
    AgentInfo, DiskStats, IndexerStats, ManagerStats, WazuhSource,
)
from src.wazuh_health.source.local_fs import LocalFSSource


def test_local_fs_source_implements_protocol(tmp_path):
    src = LocalFSSource(
        alerts_path=tmp_path / "alerts.json",
        rotated_glob=None,
        ossec_conf=tmp_path / "ossec.conf",
        client_keys=tmp_path / "client.keys",
    )
    assert isinstance(src, WazuhSource)


def test_list_agents_parses_client_keys(tmp_path):
    keys = tmp_path / "client.keys"
    keys.write_text(
        "001 vpn01 10.0.5.10 abc...\n"
        "002 win01 any def...\n"
        "# comment line\n"
        "\n"
    )
    src = LocalFSSource(
        alerts_path=tmp_path / "alerts.json",
        rotated_glob=None,
        ossec_conf=tmp_path / "ossec.conf",
        client_keys=keys,
    )
    agents = src.list_agents()
    assert {a.agent_id for a in agents} == {"001", "002"}
    assert {a.name for a in agents} == {"vpn01", "win01"}


def test_disk_stats_returns_two_filesystems(tmp_path, monkeypatch):
    src = LocalFSSource(
        alerts_path=tmp_path / "alerts.json",
        rotated_glob=None,
        ossec_conf=tmp_path / "ossec.conf",
        client_keys=tmp_path / "client.keys",
        var_ossec_path=tmp_path,
        indexer_path=tmp_path,
    )
    stats = src.disk_stats()
    assert "var_ossec" in stats.filesystems
    assert "indexer" in stats.filesystems
    assert 0 <= stats.filesystems["var_ossec"].free_pct <= 100
