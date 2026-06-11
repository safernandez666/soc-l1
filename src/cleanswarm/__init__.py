"""CleanSwarm: Wazuh noise hygiene and tuning recommendations.

This package is intentionally separate from the live SOC-L1 webhook/executor path.
It reads historical alerts, proposes reversible tuning recommendations, and simulates
impact before any human-approved change is considered.
"""

from src.cleanswarm.models import CleanSwarmReport

__all__ = ["CleanSwarmReport"]
