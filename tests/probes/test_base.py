from datetime import datetime, timezone
from src.wazuh_health.contracts import ProbeResult
from src.wazuh_health.probes.base import Probe


class _DummyProbe(Probe):
    name = "capacity"

    def collect(self):
        return {"metrics": {"x": 1}, "artifacts": {}, "errors": []}


def test_probe_run_wraps_collect_into_proberesult():
    res = _DummyProbe().run()
    assert isinstance(res, ProbeResult)
    assert res.probe == "capacity"
    assert res.metrics == {"x": 1}
    assert res.run_at.tzinfo is timezone.utc
