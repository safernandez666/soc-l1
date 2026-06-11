"""Typed cross-layer contracts."""
from src.wazuh_health.contracts.alerts import CleanAlert
from src.wazuh_health.contracts.findings import DomainFinding, WazuhHealthReport
from src.wazuh_health.contracts.hygiene import (
    CleanSwarmReport,
    CombinedSimulation,
    NoiseBucket,
    Recommendation,
    RecommendationType,
    RiskLevel,
    SimulationResult,
)
from src.wazuh_health.contracts.probes import ProbeResult, Severity, ThresholdHit

__all__ = [
    "CleanAlert",
    "CleanSwarmReport",
    "CombinedSimulation",
    "DomainFinding",
    "NoiseBucket",
    "ProbeResult",
    "Recommendation",
    "RecommendationType",
    "RiskLevel",
    "Severity",
    "SimulationResult",
    "ThresholdHit",
    "WazuhHealthReport",
]
