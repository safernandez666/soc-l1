from src.wazuh_health.source.base import (
    DiskStats, FilesystemStat, IndexerStats, ManagerStats,
)
from src.wazuh_health.probes.capacity import CapacityProbe


class _FakeSource:
    def __init__(self, free_pct=80.0, heap_pct=60.0, alerts_size=1024):
        self._free_pct = free_pct
        self._heap_pct = heap_pct
        self._size = alerts_size

    def disk_stats(self):
        return DiskStats(
            filesystems={
                "var_ossec": FilesystemStat(
                    path="/var/ossec", total_bytes=100, free_bytes=int(self._free_pct),
                    free_pct=self._free_pct,
                ),
                "indexer": FilesystemStat(
                    path="/var/lib/wazuh-indexer", total_bytes=100, free_bytes=50,
                    free_pct=50.0,
                ),
            },
            alerts_json_size_bytes=self._size,
        )

    def manager_stats(self):
        return ManagerStats(cpu_pct=10.0, mem_pct=40.0)

    def indexer_stats(self):
        return IndexerStats(heap_pct=self._heap_pct, red_shards=0, yellow_shards=1)


def test_capacity_probe_emits_expected_metrics():
    probe = CapacityProbe(source=_FakeSource())
    result = probe.run()
    assert result.probe == "capacity"
    m = result.metrics
    assert m["disk.var_ossec.free_pct"] == 80.0
    assert m["disk.indexer.free_pct"] == 50.0
    assert m["indexer.heap_pct"] == 60.0
    assert m["alerts_json.size_bytes"] == 1024


def test_capacity_probe_computes_growth_when_previous_size_provided():
    probe = CapacityProbe(source=_FakeSource(alerts_size=10_000_000), previous_size=5_000_000, hours_between=1.0)
    m = probe.run().metrics
    # delta is 5 MB in 1 h
    assert m["alerts_json.growth_mb_per_h"] == 5.0
