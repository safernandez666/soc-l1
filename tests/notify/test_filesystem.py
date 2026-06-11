from datetime import datetime, timezone

from src.wazuh_health.contracts import WazuhHealthReport
from src.wazuh_health.notify.filesystem import FilesystemNotifier


def test_writes_markdown_report_to_dir(tmp_path):
    n = FilesystemNotifier(report_dir=tmp_path)
    report = WazuhHealthReport(
        generated_at=datetime.now(tz=timezone.utc),
        window_hours=6, summary="ok",
        by_domain={"hygiene": [], "capacity": [], "coverage": []},
        top_priorities=[],
    )
    written = n.notify_report(report, markdown="# Report\n\nbody")
    assert written.exists()
    assert "Report" in written.read_text()
