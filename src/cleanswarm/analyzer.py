"""Compat shim — moved to wazuh_health.hygiene.analyzer."""
from src.wazuh_health.hygiene.analyzer import build_noise_buckets, parse_timestamp

__all__ = ["build_noise_buckets", "parse_timestamp"]
