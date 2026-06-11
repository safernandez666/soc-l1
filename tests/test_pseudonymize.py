from src.wazuh_health.pseudonymize import Pseudonymizer


def test_same_value_same_token_within_session():
    p = Pseudonymizer(salt="s1")
    a = p.encode("ip", "10.0.0.1")
    b = p.encode("ip", "10.0.0.1")
    assert a == b
    assert a.startswith("ip_")


def test_different_categories_distinct_namespaces():
    p = Pseudonymizer(salt="s1")
    assert p.encode("ip", "10.0.0.1") != p.encode("user", "10.0.0.1")


def test_decode_returns_original_in_session():
    p = Pseudonymizer(salt="s1")
    t = p.encode("user", "alice")
    assert p.decode(t) == "alice"


def test_walk_dict_pseudonymizes_known_fields():
    p = Pseudonymizer(salt="s1")
    obj = {"srcip": "10.0.0.1", "user": "alice", "rule_id": "5710", "agent.name": "vpn01"}
    masked = p.mask(obj, fields=["srcip", "user", "agent.name"])
    assert masked["srcip"].startswith("ip_")
    assert masked["user"].startswith("user_")
    assert masked["agent.name"].startswith("agent_name_")
    assert masked["rule_id"] == "5710"
