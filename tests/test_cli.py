# tests/test_cli.py
import os

from src.wazuh_health.cli import build_parser, load_env_file


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


def test_explicit_env_file_loads_vars(tmp_path, monkeypatch):
    """--env-file points at an explicit dotenv and vars become available."""
    monkeypatch.delenv("WAZUH_HEALTH_FROM_ENV_TEST", raising=False)
    env_path = tmp_path / "production.env"
    env_path.write_text(
        "WAZUH_HEALTH_FROM_ENV_TEST=hello\n"
        "OPENAI_API_KEY=sk-fake-from-dotenv\n"
    )
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    loaded = load_env_file(env_path)
    assert loaded == env_path
    assert os.getenv("WAZUH_HEALTH_FROM_ENV_TEST") == "hello"
    assert os.getenv("OPENAI_API_KEY") == "sk-fake-from-dotenv"


def test_env_file_does_not_override_existing(monkeypatch, tmp_path):
    """Already-set env vars win — dotenv is only a fallback (override=False)."""
    monkeypatch.setenv("WAZUH_HEALTH_OVERRIDE_TEST", "from_shell")
    env_path = tmp_path / ".env"
    env_path.write_text("WAZUH_HEALTH_OVERRIDE_TEST=from_dotenv\n")
    load_env_file(env_path)
    assert os.getenv("WAZUH_HEALTH_OVERRIDE_TEST") == "from_shell"


def test_env_file_falls_back_to_cwd_dotenv(tmp_path, monkeypatch):
    """When no explicit path is given, ./.env is the fallback."""
    monkeypatch.delenv("WAZUH_HEALTH_ENV_FILE", raising=False)
    monkeypatch.delenv("WAZUH_HEALTH_CWD_DOTENV_TEST", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("WAZUH_HEALTH_CWD_DOTENV_TEST=found\n")
    loaded = load_env_file(None)
    assert loaded == tmp_path / ".env"
    assert os.getenv("WAZUH_HEALTH_CWD_DOTENV_TEST") == "found"


def test_env_file_returns_none_when_no_file_exists(tmp_path, monkeypatch):
    monkeypatch.delenv("WAZUH_HEALTH_ENV_FILE", raising=False)
    monkeypatch.chdir(tmp_path)  # empty dir
    assert load_env_file(None) is None
