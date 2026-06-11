"""Compat shim — moved to wazuh_health.source.local_fs."""
from src.wazuh_health.source.local_fs import (
    compact_alert,
    iter_alerts,
    load_alerts,
    parse_timestamp,
)

__all__ = ["compact_alert", "iter_alerts", "load_alerts", "parse_timestamp"]
