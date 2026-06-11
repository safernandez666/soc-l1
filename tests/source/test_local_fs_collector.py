import gzip
import json
from pathlib import Path

from src.wazuh_health.source.local_fs import compact_alert, iter_alerts


def _write_ndjson(path: Path, alerts: list[dict]) -> None:
    with path.open("w") as f:
        for a in alerts:
            f.write(json.dumps(a) + "\n")


def _write_gz_ndjson(path: Path, alerts: list[dict]) -> None:
    with gzip.open(path, "wt") as f:
        for a in alerts:
            f.write(json.dumps(a) + "\n")


def _sample_alert(rid="5710"):
    return {
        "timestamp": "2026-06-11T10:00:00Z",
        "rule": {"id": rid, "level": 5, "description": "x", "groups": []},
        "agent": {"id": "001", "name": "vpn01"},
        "data": {"srcip": "10.0.5.20", "srcuser": "scanner"},
        "decoder": {"name": "sshd"},
    }


def test_iter_alerts_skips_malformed_lines(tmp_path):
    p = tmp_path / "alerts.json"
    with p.open("w") as f:
        f.write(json.dumps(_sample_alert()) + "\n")
        f.write("{not json\n")
        f.write("\n")
        f.write(json.dumps(_sample_alert("5712")) + "\n")
    out = list(iter_alerts(p))
    assert [a.rule_id for a in out] == ["5710", "5712"]


def test_iter_alerts_reads_gz(tmp_path):
    p = tmp_path / "alerts.json.gz"
    _write_gz_ndjson(p, [_sample_alert(), _sample_alert("5712")])
    assert len(list(iter_alerts(p))) == 2


def test_iter_alerts_reads_rotated_files(tmp_path):
    main = tmp_path / "alerts.json"
    rot1 = tmp_path / "alerts.json.1"
    rot2 = tmp_path / "alerts.json.2.gz"
    _write_ndjson(main, [_sample_alert("A")])
    _write_ndjson(rot1, [_sample_alert("B")])
    _write_gz_ndjson(rot2, [_sample_alert("C")])
    out = list(iter_alerts(main, rotated_glob=str(tmp_path / "alerts.json.*")))
    rule_ids = sorted(a.rule_id for a in out)
    assert rule_ids == ["A", "B", "C"]


def test_compact_alert_handles_string_win_eventdata():
    raw = {
        "timestamp": "2026-06-11T10:00:00Z",
        "rule": {"id": "5710", "level": 5, "description": "x", "groups": []},
        "agent": {"id": "001", "name": "vpn01"},
        "data": {"win": "not a dict, edge case decoder"},
        "decoder": {"name": "sshd"},
    }
    alert = compact_alert(raw)
    assert alert is not None
    assert alert.user is None


def test_compact_alert_drops_alerts_with_no_rule_id():
    raw = {"timestamp": "x", "rule": {"level": 5}}
    assert compact_alert(raw) is None
