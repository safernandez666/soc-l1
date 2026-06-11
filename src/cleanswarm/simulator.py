"""Compat shim — moved to wazuh_health.hygiene.simulator."""
from src.wazuh_health.hygiene.simulator import (
    simulate_combined,
    simulate_recommendation,
    simulate_recommendations,
)

__all__ = ["simulate_combined", "simulate_recommendation", "simulate_recommendations"]
