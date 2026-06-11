"""Domain-scoped tool registries. Each domain agent only imports its own list."""
from src.wazuh_health.tools.readonly import (
    capacity_tools, coverage_tools, hygiene_tools, reporter_tools,
)

HYGIENE_TOOL_NAMES = {"get_top_buckets", "get_recommendations", "simulate",
                      "query_rule_history"}
CAPACITY_TOOL_NAMES = {"get_disk_stats", "get_indexer_stats", "get_manager_stats",
                       "list_recent_alerts"}
COVERAGE_TOOL_NAMES = {"get_agent_list", "get_disconnected_agents",
                       "get_rule_hit_counts", "get_decoder_errors"}
REPORTER_TOOL_NAMES = {"query_findings", "get_metric_trend"}

HYGIENE_TOOLS = [getattr(hygiene_tools, n) for n in HYGIENE_TOOL_NAMES]
CAPACITY_TOOLS = [getattr(capacity_tools, n) for n in CAPACITY_TOOL_NAMES]
COVERAGE_TOOLS = [getattr(coverage_tools, n) for n in COVERAGE_TOOL_NAMES]
REPORTER_TOOLS = [getattr(reporter_tools, n) for n in REPORTER_TOOL_NAMES]

__all__ = [
    "HYGIENE_TOOLS", "CAPACITY_TOOLS", "COVERAGE_TOOLS", "REPORTER_TOOLS",
    "HYGIENE_TOOL_NAMES", "CAPACITY_TOOL_NAMES", "COVERAGE_TOOL_NAMES",
    "REPORTER_TOOL_NAMES",
]
