> **Note:** CleanSwarm is now part of [Wazuh Health Squad](./WAZUH_HEALTH.md).
> The `cleanswarm analyze` CLI continues to work unchanged; its internals now
> live under `wazuh_health/hygiene/`. New checks for capacity and coverage are
> documented in the Wazuh Health doc.

# CleanSwarm

CleanSwarm is a read-only Wazuh hygiene module for SOC-L1. It is intentionally separated from the live webhook, approval, and executor path.

Goal: find repeated Wazuh noise, propose conservative tuning, and simulate historical impact before any human-approved Wazuh change.

## Current MVP

Pipeline:

```text
alerts.json NDJSON
  -> collector
  -> noise analyzer
  -> recommender
  -> simulator
  -> JSON/Markdown report
```

CleanSwarm does **not** modify Wazuh config in this MVP.

## Run

```bash
python -m src.cleanswarm analyze \
  --alerts-path /var/ossec/logs/alerts/alerts.json \
  --days 7 \
  --min-count 50 \
  --format markdown \
  --out cleanswarm-report.md
```

If installed as a package, the console script is also available:

```bash
cleanswarm analyze --alerts-path /var/ossec/logs/alerts/alerts.json --days 7
```

## Output

The report contains:

- top noisy buckets
- specific dimensions: `rule_id`, `agent.name`, `srcip`, `user`
- recommendation type
- expected alert reduction
- risk estimate
- simulation results
- optional Wazuh `local_rules.xml` candidate snippet
- rollback note

## Recommendation types

- `suppress_conditionally`: low/medium severity repeated alerts with specific dimensions.
- `tune_frequency`: noisy global rule where full suppression would be risky.
- `investigate_source`: high-severity noisy alerts that should not be silenced automatically.
- `leave_visible`: reserved for future explicit no-op recommendations.

## Safety model

CleanSwarm is conservative by default:

1. No automatic apply.
2. No global rule disablement.
3. Conditional dimensions preferred over broad suppression.
4. High-severity rules become `investigate_source`, not suppression candidates.
5. Every recommendation includes rollback guidance.
6. Simulator reports max hidden level and high/critical hidden count.

## Next steps

- Add Wazuh indexer/API collector for windows longer than `alerts.json` rotation.
- Add persisted recommendation state and review endpoint.
- Add PR/diff generator for `local_rules.xml` instead of direct apply.
- Add post-change auditor to compare before/after noise.
