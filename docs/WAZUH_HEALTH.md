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

### Where env vars are loaded from

The CLI loads a `.env` file at boot. Resolution order (first hit wins, existing
exported vars are NEVER overwritten):

1. `--env-file /path/to/file` — explicit flag
2. `WAZUH_HEALTH_ENV_FILE` env var
3. `./.env` in the current working directory

For systemd, `EnvironmentFile=/etc/wazuh-health/wazuh-health.env` in the unit
loads the vars BEFORE the process starts — no `.env` lookup happens at runtime
in that case (already in the process environment).

**Recommended layout in the Wazuh server:**

```bash
# Copy your existing .env to the canonical location
sudo install -m 600 -o wazuh-health -g wazuh-health \
    /path/to/your/.env /etc/wazuh-health/wazuh-health.env

# Run interactively (picks up ./.env in CWD)
cd /opt/soc-l1 && uv run wazuh-health once

# Run with an explicit file from anywhere
uv run wazuh-health --env-file /etc/wazuh-health/wazuh-health.env once
```

### Key env vars

The CLI honors **the same variables you already have in `.env`** for the
SOC-L1 SOAR — it does not duplicate or shadow them:

| Variable | Purpose |
|---|---|
**Already in your SOC-L1 `.env` — reused:**

| Variable | Purpose |
|---|---|
| `OPENAI_API_KEY` | Used by `_OpenAIAgentsRunner` when a real LLM call is made |
| `OPENAI_MODEL_LIGHT` | Model for HygieneAgent / CapacityAgent / CoverageAgent (e.g. `gpt-4o-mini`) |
| `OPENAI_MODEL_HEAVY` | Model for ReporterAgent (e.g. `gpt-4o`) |
| `WAZUH_API_HOST` | Manager API host (e.g. `192.168.38.60`) |
| `WAZUH_API_PORT` | Manager API port (default `55000`) |
| `WAZUH_API_USER` / `WAZUH_API_PASSWORD` | Used only when `WAZUH_HEALTH_SOURCE=wazuh_api` |

**Not read by `wazuh-health`** (kept exclusive to the live SOAR — enforced by `tests/test_boundaries.py`):
`WAZUH_WEBHOOK_SECRET`, `ENABLE_TRIAGE`.

**New variables specific to `wazuh-health` (all optional, sensible defaults):**

| Variable | Default | Purpose |
|---|---|---|
| `WAZUH_HEALTH_SOURCE` | `local_fs` | `local_fs` or `wazuh_api` |
| `WAZUH_HEALTH_DB_PATH` | `/var/lib/wazuh-health/state.db` | SQLite state file |
| `WAZUH_HEALTH_REPORT_DIR` | `/var/log/wazuh-health/reports` | Markdown reports location |
| `WAZUH_HEALTH_LLM_DAILY_CAP` | `50` | Hard cap on LLM invocations per agent per day |
| `WAZUH_HEALTH_PSEUDONYMIZE` | `true` | Mask IPs/users before LLM |
| `WAZUH_HEALTH_SLACK_WEBHOOK` | _(unset)_ | Slack webhook URL (notifier disabled if empty) |
| `WAZUH_HEALTH_EMAIL_TO` | _(unset)_ | Recipient. **Setting this auto-enables email notifications** |
| `WAZUH_HEALTH_EMAIL_FROM` | `wazuh-health@localhost` | Sender address |
| `WAZUH_HEALTH_SMTP_HOST` | `localhost` | SMTP relay host (e.g. `smtp.gmail.com`) |
| `WAZUH_HEALTH_SMTP_PORT` | `25` | `587` for STARTTLS, `465` for implicit TLS |
| `WAZUH_HEALTH_SMTP_USER` | _(unset)_ | If set, AUTH is performed |
| `WAZUH_HEALTH_SMTP_PASSWORD` | _(unset)_ | App password / SMTP password |
| `WAZUH_HEALTH_SMTP_TLS` | `false` | Set to `true` to issue STARTTLS after connect |
| `WAZUH_HEALTH_CONFIG_PATH` | _(unset)_ | Override YAML config path |
| `WAZUH_HEALTH_ENV_FILE` | _(unset)_ | Override `.env` location |

### Email notifications

Email is **auto-enabled when `WAZUH_HEALTH_EMAIL_TO` is set** (no separate
`enabled=true` flag needed). Two behaviors:

- `wazuh-health once` → after the 3 probes run, sends a **template digest**
  (Markdown, no LLM call, no token spend). Subject summarises the state
  (e.g. `Wazuh Health digest — ⚠ disk 12%, 3 hygiene recs`).
- `wazuh-health report` → after the ReporterAgent runs (heavy LLM model),
  sends the JSON report by email AND prints to stdout / writes `--out`.

Example for Gmail:

```bash
WAZUH_HEALTH_EMAIL_TO=ops@example.com
WAZUH_HEALTH_EMAIL_FROM=wazuh-health@example.com
WAZUH_HEALTH_SMTP_HOST=smtp.gmail.com
WAZUH_HEALTH_SMTP_PORT=587
WAZUH_HEALTH_SMTP_USER=wazuh-health@example.com
WAZUH_HEALTH_SMTP_PASSWORD=<gmail app password>
WAZUH_HEALTH_SMTP_TLS=true
```

For Office 365: same, but `WAZUH_HEALTH_SMTP_HOST=smtp.office365.com` and
`WAZUH_HEALTH_SMTP_PORT=587`. For a relay on `localhost:25`, leave `_USER`
empty and `_TLS=false` (the defaults).

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
