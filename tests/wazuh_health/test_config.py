from src.wazuh_health.config.settings import HealthConfig, load_config


def test_loads_defaults_without_user_yaml(monkeypatch, tmp_path):
    monkeypatch.delenv("WAZUH_HEALTH_CONFIG_PATH", raising=False)
    monkeypatch.setenv("OPENAI_MODEL_LIGHT", "gpt-4o-mini")
    monkeypatch.setenv("OPENAI_MODEL_HEAVY", "gpt-4o")
    cfg = load_config()
    assert isinstance(cfg, HealthConfig)
    assert cfg.llm.light_model == "gpt-4o-mini"
    assert cfg.llm.heavy_model == "gpt-4o"
    assert cfg.scheduler.jobs["capacity"].interval_seconds == 300


def test_yaml_override_takes_precedence(monkeypatch, tmp_path):
    yaml_path = tmp_path / "config.yaml"
    yaml_path.write_text(
        "scheduler:\n  jobs:\n    capacity:\n      interval_seconds: 60\n"
    )
    monkeypatch.setenv("WAZUH_HEALTH_CONFIG_PATH", str(yaml_path))
    monkeypatch.setenv("OPENAI_MODEL_LIGHT", "gpt-4o-mini")
    monkeypatch.setenv("OPENAI_MODEL_HEAVY", "gpt-4o")
    cfg = load_config()
    assert cfg.scheduler.jobs["capacity"].interval_seconds == 60
