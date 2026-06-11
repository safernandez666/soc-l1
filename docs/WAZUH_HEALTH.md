# Wazuh Health Squad

Read-only daemon that monitors Wazuh hygiene, capacity, and coverage. It
absorbs the original CleanSwarm module and adds capacity (disk/indexer
heap/manager) and coverage (agents, decoders, zero-hit rules) checks.

> Read-only by design: no writes to Wazuh, no calls to the SOC-L1 webhook,
> approval, or executor paths. The boundary is enforced by tests.

## Run

```bash
# One-shot
wazuh-health once

# Long-running daemon (used by systemd)
wazuh-health serve --port 8787

# On-demand report
wazuh-health report --since 24h --out /tmp/r.json
```

The legacy CLI still works:

```bash
cleanswarm analyze --alerts-path /var/ossec/logs/alerts/alerts.json
```

## Configuration

Layered: env → `/etc/wazuh-health/config.yaml` → versioned defaults.

Key env vars (see also the design spec):

| Variable | Purpose |
|---|---|
| `OPENAI_API_KEY` | OpenAI key for agents |
| `OPENAI_MODEL_LIGHT` | Model for domain agents (default `gpt-4o-mini`) |
| `OPENAI_MODEL_HEAVY` | Model for the reporter (default `gpt-4o`) |
| `WAZUH_HEALTH_SOURCE` | `local_fs` or `wazuh_api` |
| `WAZUH_HEALTH_DB_PATH` | SQLite state file (default `/var/lib/wazuh-health/state.db`) |
| `WAZUH_HEALTH_REPORT_DIR` | Where Markdown reports land |
| `WAZUH_HEALTH_LLM_DAILY_CAP` | Hard cap on LLM invocations per agent per day |
| `WAZUH_HEALTH_PSEUDONYMIZE` | Mask IPs/users before LLM (default `true`) |
| `WAZUH_API_HOST/PORT/USER/PASSWORD` | Used when `SOURCE=wazuh_api` |

## Architecture

See `docs/superpowers/specs/2026-06-11-wazuh-health-squad-design.md` for the
full design. Short version:

```
probes (Python, every N min) → ThresholdEngine → WakeDispatcher
   → domain agents (LLM, read-only tools)
   → sanitizer → FindingsStore
ReporterAgent (every 6 h or on demand) → notifiers (fs / slack / email)
```

## Safety model

1. No automatic apply — output is reports + notifications only.
2. No global rule disablement — recommendations are always conditional.
3. High-severity rules and sensitive groups (`authentication_failures`,
   `attacks`, `malware`, ...) become `investigate_source`, not suppression.
4. Combined simulation shows union/overlap of impact if multiple recs were
   applied.
5. LLM outputs pass through a sanitizer (URL strip, shell-meta reject, XML
   validation) before persistence.
6. PII (IPs, users, agent names) is pseudonymized to stable tokens before
   any LLM call when `pseudonymize=true`.

## systemd

```bash
sudo install -m 644 deploy/wazuh-health.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-health
```

`ReadOnlyPaths=/var/ossec` enforces read-only at kernel level.
