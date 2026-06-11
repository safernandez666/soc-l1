"""Compat shim — symbols moved to wazuh_health.contracts.hygiene."""
from src.wazuh_health.contracts.alerts import CleanAlert
from src.wazuh_health.contracts.hygiene import (
    CleanSwarmReport,
    NoiseBucket,
    Recommendation,
    RecommendationType,
    RiskLevel,
    SimulationResult,
)

__all__ = [
    "CleanAlert",
    "CleanSwarmReport",
    "NoiseBucket",
    "Recommendation",
    "RecommendationType",
    "RiskLevel",
    "SimulationResult",
]
