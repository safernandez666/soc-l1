"""Boundary invariants for the wazuh_health package.

Read-only by construction: no imports of the live SOAR write paths, and
no calls to write HTTP verbs from within the package.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

PKG_ROOT = Path("src/wazuh_health")

FORBIDDEN_IMPORTS = {
    "src.executor",
    "src.webhook",
    "src.approvals",
}

FORBIDDEN_VERB_RE = re.compile(r"\.(post|put|delete|patch)\(")

# JWT login is the one allowed POST; whitelist by file path.
POST_WHITELIST_FILES = {
    "src/wazuh_health/source/wazuh_api.py",
}

FORBIDDEN_ENV_VARS = {"WAZUH_WEBHOOK_SECRET", "ENABLE_TRIAGE"}


def _iter_py_files() -> list[Path]:
    return [p for p in PKG_ROOT.rglob("*.py") if p.is_file()]


def test_no_forbidden_imports() -> None:
    for path in _iter_py_files():
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            mod = None
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name
                    assert mod not in FORBIDDEN_IMPORTS, f"{path} imports {mod}"
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                assert mod not in FORBIDDEN_IMPORTS, f"{path} imports from {mod}"


def test_no_write_http_verbs_outside_whitelist() -> None:
    for path in _iter_py_files():
        text = path.read_text()
        for match in FORBIDDEN_VERB_RE.finditer(text):
            rel = str(path).replace("\\", "/")
            assert rel in POST_WHITELIST_FILES, (
                f"{rel} uses HTTP {match.group(1)} but is not whitelisted"
            )


def test_no_soar_envs_referenced() -> None:
    for path in _iter_py_files():
        text = path.read_text()
        for env in FORBIDDEN_ENV_VARS:
            assert env not in text, f"{path} references forbidden env {env}"
