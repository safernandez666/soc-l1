from http.client import HTTPConnection

from src.wazuh_health.daemon import HealthDaemon


def test_healthz_endpoint_returns_ok():
    d = HealthDaemon(port=0)  # port=0 lets OS assign
    with d.serve_in_thread() as server:
        conn = HTTPConnection("127.0.0.1", server.actual_port)
        conn.request("GET", "/healthz")
        resp = conn.getresponse()
        assert resp.status == 200
        body = resp.read().decode()
        assert "ok" in body
