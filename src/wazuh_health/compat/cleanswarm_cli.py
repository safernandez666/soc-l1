"""Compat entry point — delegates to the original CleanSwarm CLI."""
from __future__ import annotations

from src.cleanswarm.cli import main as _legacy_main


def main(argv: list[str] | None = None) -> int:
    return _legacy_main(argv)
