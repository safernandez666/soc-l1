from src.wazuh_health.contracts.alerts import CleanAlert


def test_llm_safe_dump_strips_raw():
    alert = CleanAlert(
        timestamp="2026-06-11T10:00:00Z",
        rule_id="5710",
        rule_level=5,
        raw={"sensitive": "payload"},
    )
    payload = alert.to_llm_safe_dict()
    assert "raw" not in payload
    assert payload["rule_id"] == "5710"


def test_model_dump_keeps_raw_for_internal_use():
    alert = CleanAlert(
        timestamp="2026-06-11T10:00:00Z",
        rule_id="5710",
        rule_level=5,
        raw={"sensitive": "payload"},
    )
    assert alert.model_dump()["raw"] == {"sensitive": "payload"}
