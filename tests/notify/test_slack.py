# tests/notify/test_slack.py
import respx
from httpx import Response

from src.wazuh_health.contracts import DomainFinding
from src.wazuh_health.notify.slack import SlackNotifier


@respx.mock
def test_severity_floor_filters_findings(respx_mock):
    route = respx_mock.post("https://hooks.slack.com/services/X/Y/Z").mock(
        return_value=Response(200, text="ok")
    )
    n = SlackNotifier(
        webhook_url="https://hooks.slack.com/services/X/Y/Z",
        severity_floor="warning",
    )
    info = DomainFinding(
        domain="hygiene", severity="info", title="t", body_md="b",
        evidence={"k": "v"}, suggested_action="x",
    )
    n.notify_finding(info)
    assert route.called is False

    warn = DomainFinding(
        domain="hygiene", severity="warning", title="t", body_md="b",
        evidence={"k": "v"}, suggested_action="x",
    )
    n.notify_finding(warn)
    assert route.called is True
