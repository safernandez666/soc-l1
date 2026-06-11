"""Compat shim — moved to wazuh_health.hygiene.report."""
from src.wazuh_health.hygiene.report import analyze_file, render_markdown

__all__ = ["analyze_file", "render_markdown"]
