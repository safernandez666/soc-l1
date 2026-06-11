"""Compat shim — moved to wazuh_health.hygiene.recommender."""
from src.wazuh_health.hygiene.recommender import (
    SENSITIVE_RULE_GROUPS,
    recommend_from_buckets,
)

__all__ = ["SENSITIVE_RULE_GROUPS", "recommend_from_buckets"]
