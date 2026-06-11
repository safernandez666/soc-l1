# tests/test_cli.py
from src.wazuh_health.cli import build_parser


def test_subcommands_registered():
    p = build_parser()
    subs = p._subparsers._actions[-1].choices  # type: ignore[attr-defined]
    assert {"serve", "once", "report", "doctor", "migrate"} <= set(subs)


def test_once_runs_with_local_fs(tmp_path, monkeypatch):
    # Smoke: just verify the function returns 0 with an empty alerts file.
    alerts = tmp_path / "alerts.json"
    alerts.write_text("")
    monkeypatch.setenv("WAZUH_HEALTH_SOURCE", "local_fs")
    monkeypatch.setenv("WAZUH_HEALTH_DB_PATH", str(tmp_path / "state.db"))
    monkeypatch.setenv("WAZUH_HEALTH_REPORT_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("OPENAI_MODEL_LIGHT", "gpt-4o-mini")
    monkeypatch.setenv("OPENAI_MODEL_HEAVY", "gpt-4o")
    from src.wazuh_health.cli import main
    assert main(["once", "--alerts-path", str(alerts)]) == 0
