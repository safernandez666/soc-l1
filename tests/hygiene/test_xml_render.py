from xml.etree import ElementTree as ET

from src.wazuh_health.contracts import NoiseBucket
from src.wazuh_health.hygiene.xml_render import render_local_rule


def _bucket(**kw):
    base = dict(
        key="rule_id=5710|agent.name=vpn01",
        dimensions={"rule_id": "5710", "agent.name": "vpn01"},
        count=10,
        rule_id="5710",
        rule_level=5,
        rule_description="ssh fail",
    )
    base.update(kw)
    return NoiseBucket(**base)


def test_rendered_snippet_is_well_formed_xml():
    snippet = render_local_rule(_bucket(), local_rule_id=110000, bucket_hash="abc123")
    root = ET.fromstring(snippet)
    assert root.tag == "rule"


def test_includes_cleanswarm_group():
    snippet = render_local_rule(_bucket(), local_rule_id=110000, bucket_hash="abc")
    assert "<group>cleanswarm,</group>" in snippet


def test_includes_metadata_comment():
    snippet = render_local_rule(
        _bucket(), local_rule_id=110000, bucket_hash="abc", count=42
    )
    assert "cleanswarm" in snippet.lower()
    assert "abc" in snippet
    assert "42" in snippet


def test_quoting_injection_attempt_is_neutralized():
    b = _bucket(dimensions={
        "rule_id": "5710",
        "agent.name": 'evil"$(rm -rf /)',
    })
    snippet = render_local_rule(b, local_rule_id=110000, bucket_hash="x")
    # Must parse cleanly — quote was escaped, no XML break.
    root = ET.fromstring(snippet)
    # The attribute value should be present but escaped.
    assert root is not None
    assert "$(rm -rf /)" not in snippet or "&" in snippet  # at least escaped


def test_non_numeric_rule_id_is_rejected():
    b = _bucket(rule_id="<inject>")
    import pytest
    with pytest.raises(ValueError):
        render_local_rule(b, local_rule_id=110000, bucket_hash="x")
