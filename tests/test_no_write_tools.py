"""Only readonly tools may exist in wazuh_health.tools."""
from __future__ import annotations

import re
from pathlib import Path

TOOLS_ROOT = Path("src/wazuh_health/tools")
FORBIDDEN_NAME_RE = re.compile(
    r"^(apply|set|delete|restart|patch|create|update|write|push)_"
)


def test_only_readonly_subpackage_exists() -> None:
    children = {p.name for p in TOOLS_ROOT.iterdir() if p.is_dir()}
    # readonly is the only allowed tool dir.
    assert children <= {"readonly", "__pycache__"}, children


def test_no_tool_name_suggests_write() -> None:
    readonly = TOOLS_ROOT / "readonly"
    for path in readonly.rglob("*.py"):
        text = path.read_text()
        # Look at top-level `def` and `async def` names.
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(("def ", "async def ")):
                name = stripped.split()[1].split("(")[0]
                assert not FORBIDDEN_NAME_RE.match(name), (
                    f"{path} defines write-shaped tool {name}"
                )
