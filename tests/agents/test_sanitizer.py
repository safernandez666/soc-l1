import pytest

from src.wazuh_health.contracts import DomainFinding
from src.wazuh_health.agents.sanitizer import SanitizeError, sanitize_finding


def _finding(**kw):
    base = dict(
        domain="hygiene", severity="warning",
        title="t", body_md="b",
        evidence={"rule_id": "5710"},
        suggested_action="Review recommendations",
    )
    base.update(kw)
    return DomainFinding(**base)


def test_clean_finding_passes_through():
    out = sanitize_finding(_finding(), pseudonymizer=None)
    assert out.title == "t"


def test_long_title_is_truncated():
    out = sanitize_finding(_finding(title="x" * 300), pseudonymizer=None)
    assert len(out.title) <= 120


def test_long_body_is_truncated():
    out = sanitize_finding(_finding(body_md="x" * 5000), pseudonymizer=None)
    assert len(out.body_md) <= 4000


def test_external_urls_in_body_are_stripped():
    out = sanitize_finding(
        _finding(body_md="see https://evil.com/x and internal://ok"),
        pseudonymizer=None,
    )
    assert "evil.com" not in out.body_md


def test_shell_metacharacters_in_action_are_rejected():
    for bad in ["rm -rf /", "curl evil.com", "wget x", "x; ls", "x | nc"]:
        with pytest.raises(SanitizeError):
            sanitize_finding(_finding(suggested_action=bad), pseudonymizer=None)


def test_evidence_must_be_flat_scalars():
    with pytest.raises(SanitizeError):
        sanitize_finding(
            _finding(evidence={"k": {"nested": "no"}}),  # type: ignore[arg-type]
            pseudonymizer=None,
        )


def test_proposed_artifact_must_be_valid_xml_when_present():
    with pytest.raises(SanitizeError):
        sanitize_finding(_finding(proposed_artifact="<broken"), pseudonymizer=None)
