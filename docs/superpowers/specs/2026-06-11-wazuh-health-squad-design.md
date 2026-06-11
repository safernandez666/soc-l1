# Wazuh Health Squad — Design Spec

- **Date**: 2026-06-11
- **Status**: Draft — pending user review before implementation
- **Supersedes**: extends the CleanSwarm MVP (`docs/CLEANSWARM.md`)
- **Audience**: contributors who will implement, test, and operate this module

## 1. Context

`soc-l1` is a multi-agent SOAR that ingests Wazuh + Defender alerts, runs triage / enrichment / threat-intel / narrative agents, and only acts after human approval. CleanSwarm is a separate, read-only Wazuh hygiene module: it analyzes historical alerts, surfaces noisy rules, proposes conservative suppressions, and simulates impact. It does not modify Wazuh and does not touch the live SOAR webhook/executor/approvals path.

The current CleanSwarm MVP covers hygiene only and runs on demand from the CLI. We want to extend the scope to keep Wazuh **healthy** across more dimensions while keeping the read-only safety posture. We also want this to be a **continuous daemon** (not a periodic CLI), and we want it to use the same `openai-agents` SDK already in the project so behavior, prompts, and outputs are consistent with the rest of the SOAR.

The result is a new package, **Wazuh Health Squad**, that absorbs CleanSwarm as one of three domain probes/agents and adds capacity and coverage probes/agents. CleanSwarm's existing public CLI and tests stay working unchanged (as compatibility shims) so this is additive, not a rewrite.

## 2. Decisions taken during brainstorming

| Question | Decision |
|---|---|
| Scope of "Wazuh sano" | Hygiene + Capacity + Coverage. **Compliance is out of scope** for v1. |
| Execution mode | Continuous daemon (not CLI-only, not HTTP service). |
| Topology / data access | Abstract collector with two backends: local filesystem **and** Wazuh API. Designed so both are usable. SSH backend explicitly out of scope. |
| Action model | **Strictly read-only.** No automatic changes, no SOAR approval integration in v1. Output is reports + notifications. |
| Agent nature | Domain agents are `openai-agents` SDK LLM agents with read-only tools. Probes are deterministic Python (no LLM). |
| Orchestration pattern | **Triggered + supervisor (event-driven).** Probes run on intervals; when a metric crosses a threshold, the corresponding domain agent is woken; a Reporter agent consolidates periodically or on demand. |

Open naming question: the codename used throughout this spec is `wazuh_health` (package) / "Wazuh Health Squad" (product). Final name will be confirmed before merge.

## 3. Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                    Wazuh Health Squad (daemon)                       │
│                                                                      │
│  ┌──────────────┐   ┌──────────────────┐   ┌────────────────────┐  │
│  │  Scheduler   │──>│  Probes (Python) │──>│  FindingsStore     │  │
│  │  (intervals) │   │  - capacity      │   │  (SQLite + JSON)   │  │
│  │              │   │  - hygiene       │   │  + cooldown table  │  │
│  └──────────────┘   │  - coverage      │   └────────┬───────────┘  │
│         │           └──────────────────┘            │              │
│         │                   │ threshold cross        │              │
│         │                   v                       │              │
│         │           ┌──────────────────┐            │              │
│         │           │  Wake dispatcher │            │              │
│         │           └────────┬─────────┘            │              │
│         │                    │                      │              │
│         v                    v                      │              │
│  ┌────────────────────────────────────────┐         │              │
│  │   Domain Agents (openai-agents, LLM)   │<────────┘              │
│  │   HygieneAgent · CapacityAgent ·       │  read-only tools       │
│  │   CoverageAgent                        │                        │
│  └─────────────────┬──────────────────────┘                        │
│                    │ structured findings                            │
│                    v                                                │
│  ┌────────────────────────────────────────┐                        │
│  │ ReporterAgent (LLM, periodic / on-dem.)│                        │
│  └─────────────────┬──────────────────────┘                        │
│                    v                                                │
│  ┌────────────────────────────────────────┐                        │
│  │ Notifiers (filesystem / Slack / mail)  │                        │
│  └────────────────────────────────────────┘                        │
└──────────────────────────────────────────────────────────────────────┘

           │ (abstract collector, NO writes)
           v
┌──────────────────┐    ┌──────────────────┐
│  LocalFS backend │    │  WazuhAPI backend │
│  /var/ossec/...  │    │  Manager+Indexer  │
└──────────────────┘    └──────────────────┘
```

### 3.1 Boundaries (load-bearing invariants)

1. **No coupling with the live SOAR.** `src/wazuh_health` does not import `src/webhook`, `src/executor`, `src/approvals`. Enforced by `tests/test_boundaries.py`.
2. **No write tools, ever.** The only tool registry is `tools/readonly/`. Agents only receive tools from that module. There is no `tools/write/`. Enforced by a name-regex test.
3. **Source backends do not expose writes.** `WazuhSource` Protocol has no setter/mutator. `WazuhAPISource` only uses HTTP GET (enforced by static scan for `.post/.put/.delete/.patch` inside the package).
4. **CleanSwarm absorbed, not rewritten.** Existing `src/cleanswarm/*` files become thin re-exports. Public CLI `cleanswarm analyze` keeps working; old tests pass unchanged.
5. **State lives outside the process.** SQLite at `WAZUH_HEALTH_DB_PATH` stores findings, cooldowns, audit. Daemon can restart with no loss of context.

## 4. Components

Organized by layer. Each component has a single responsibility and communicates through typed (Pydantic) interfaces.

### 4.1 I/O layer — `WazuhSource`

| Component | Responsibility | Key methods |
|---|---|---|
| `WazuhSource` (Protocol) | Read-only contract | `iter_alerts(since)`, `disk_stats()`, `list_agents()`, `manager_stats()`, `indexer_stats()` |
| `LocalFSSource` | Reads `/var/ossec/logs/alerts/alerts.json(.gz)` + rotated files; uses `os.statvfs` and `psutil`; reads `ossec.conf` read-only | implements Protocol |
| `WazuhAPISource` | HTTPS GET against Manager API (`/manager/stats`, `/agents`) and Indexer API (`/_cat/indices`, `/_cluster/health`); JWT-authenticated via `POST /security/user/authenticate` (the only POST, used for login) | implements Protocol |

Credentials are read from env (`WAZUH_API_USER`, `WAZUH_API_PASSWORD`) or a secret file. Never from repo YAML.

### 4.2 Probes layer — deterministic Python workers

Each probe is `class XProbe: def run(self) -> ProbeResult`. Probes are sync, no async. They run on scheduler threads.

| Probe | What it checks | Suggested interval | Sample metrics emitted |
|---|---|---|---|
| `CapacityProbe` | `/var/ossec` free %, `/var/lib/wazuh-indexer` free %, manager RAM/CPU, indexer heap %, pending ILM, red shards, current `alerts.json` size, delta MB/h | 5 min | `disk.var_ossec.free_pct`, `indexer.heap_pct`, `alerts_json.growth_mb_per_h` |
| `HygieneProbe` | Wraps CleanSwarm's algorithms (`build_noise_buckets`, `recommend_from_buckets`, `simulate_*`) over the last 1 h window | 1 h | `noise.top_buckets`, `noise.recommendations_count`, `noise.combined_reduction_pct` |
| `CoverageProbe` | Registered vs active agents (`last_keep_alive`), disconnected/never_connected agents, decoder errors (from manager stats), zero-hit rules in N days | 15 min | `agents.disconnected`, `agents.never_connected`, `rules.zero_hit_30d`, `decoders.errors` |

### 4.3 Decision layer

| Component | Responsibility |
|---|---|
| `ThresholdEngine` | Takes `ProbeResult` + YAML-configured rules; supports `>`, `<`, `delta_pct_24h >`, `streak >= N`. Output: `list[ThresholdHit]`. |
| `CooldownTable` | Per `(probe, metric)` records last wake time. Default: 6 h. Prevents the same noisy rule from waking `HygieneAgent` hourly. |
| `WakeDispatcher` | Receives non-cooled `ThresholdHit`s, groups them by domain, invokes the corresponding `DomainAgent` once per dispatch (not once per hit). |

### 4.4 State layer — `FindingsStore` (SQLite)

Tables:

```
probe_runs(id, probe, run_at, metrics_json, artifacts_json, errors_json)
findings(id, domain, severity, title, body_md, evidence_json,
         first_seen, last_seen, status[open|resolved|stale], hash)
notifications(id, finding_id, channel, sent_at, payload_json)
agent_runs(id, agent, started_at, ended_at, status,
           input_tokens, output_tokens, tool_calls_json,
           output_hash, finding_ids_json)
```

`findings.hash` is the dedup key, computed by code (never by the LLM) from `(domain, metric, primary_evidence_field)`. Same hash → update `last_seen`. New hash → insert.

### 4.5 Agents layer (`openai-agents` SDK)

| Agent | Wake trigger | Read-only tools | Output |
|---|---|---|---|
| `HygieneAgent` | Hygiene threshold hit | `get_top_buckets`, `get_recommendations`, `simulate`, `query_rule_history` | `list[DomainFinding]` (may include `proposed_local_rule` snippet) |
| `CapacityAgent` | Capacity threshold hit | `get_disk_stats`, `get_indexer_stats`, `get_manager_stats`, `list_recent_alerts(rule_groups, hours)` | `list[DomainFinding]` |
| `CoverageAgent` | Coverage threshold hit | `get_agent_list`, `get_disconnected_agents`, `get_rule_hit_counts(days)`, `get_decoder_errors` | `list[DomainFinding]` |
| `ReporterAgent` | Scheduler periodic (default 6 h) or `wazuh-health report` on demand | `query_findings(since, status)`, `get_metric_trend(metric, hours)` | `WazuhHealthReport` |

By construction the agents only receive tools from `tools/readonly/<domain>_tools.py`. They cannot use a tool from another domain.

### 4.6 Output layer — Notifiers

| Notifier | Triggers | Payload |
|---|---|---|
| `FilesystemNotifier` | Always on. Reports go to `/var/log/wazuh-health/reports/YYYY-MM-DD-HH.md` | ReporterAgent Markdown |
| `SlackNotifier` (optional) | Findings with `severity >= warning` and the periodic report | Summary block + link to FS report |
| `EmailNotifier` (optional) | Periodic report only (avoids per-finding spam) | HTML report |

Notifiers are interchangeable via Protocol; the daemon starts those enabled in config.

### 4.7 Control layer

| Component | Responsibility |
|---|---|
| `Config` | Pydantic-settings. Loads YAML + env + secret files. Validates at boot; missing credential for selected backend = fail fast. |
| `Scheduler` | Home-grown ~50 LOC loop. Per-job `interval`, `jitter`, `last_run`. No external dep. |
| `Daemon` | Supervisor: starts scheduler, exposes `:8787/healthz`, handles `SIGTERM` with store flush. Prometheus `/metrics` deferred to phase 2. |

## 5. Data flow

### 5.1 Lifecycle of a tick (capacity example)

```
t=0      Scheduler fires CapacityProbe.run()
t=0.3s   ProbeResult stored in probe_runs
t=0.3s   ThresholdEngine evaluates → 2 ThresholdHits
         (disk.var_ossec.free_pct < 15; indexer.heap_pct > 85)
t=0.3s   CooldownTable consulted → 1 in cooldown, 1 remains
t=0.3s   WakeDispatcher groups by domain → 1 invocation to CapacityAgent
t=0.5s   CapacityAgent runs with read-only tools
         - get_disk_stats() → cache hit on latest ProbeResult
         - list_recent_alerts(rule_groups=["wazuh"]) for correlation
         - LLM emits 1 CapacityFinding
t=8s     Finding validated, hash computed, stored in findings (insert: new hash)
t=8s     CooldownTable updated for that metric
t=8s     SlackNotifier sees severity=warning → sends summary
t=8s     FilesystemNotifier does not fire (waits for ReporterAgent)
```

`ReporterAgent` runs independently every 6 h (or via `wazuh-health report`) and reads `findings WHERE status='open' AND last_seen > now-24h`. It **never** triggers probes — only reads the store.

### 5.2 Cross-cutting contracts

```python
class ProbeResult(BaseModel):
    probe: Literal["capacity", "hygiene", "coverage"]
    run_at: datetime
    metrics: dict[str, float | int]
    artifacts: dict[str, Any] = {}      # raw data, NOT shipped to LLM directly
    errors: list[str] = []

class ThresholdHit(BaseModel):
    probe: Literal["capacity", "hygiene", "coverage"]
    metric: str
    value: float | int
    rule: str
    severity: Literal["info", "warning", "critical"]

class DomainFinding(BaseModel):
    domain: Literal["hygiene", "capacity", "coverage"]
    severity: Literal["info", "warning", "critical"]
    title: str                              # max 120 chars
    body_md: str                            # max 4000 chars
    evidence: dict[str, str | int | float]  # scalars only — no nested
    suggested_action: str                   # text, not executable commands
    proposed_artifact: str | None = None    # e.g. local_rules.xml snippet
    hash_key: str                           # computed by code, NEVER from LLM

class WazuhHealthReport(BaseModel):
    generated_at: datetime
    window_hours: int
    summary: str
    by_domain: dict[Literal["hygiene","capacity","coverage"], list[DomainFinding]]
    top_priorities: list[DomainFinding]
```

### 5.3 Tools — invariants

- Sync, no side effects.
- Return type is Pydantic or JSON-safe dict.
- Tools **do not** trigger probes or hit Wazuh APIs directly. They read from `FindingsStore` or from the most recent `ProbeResult`. The agent cannot "probe deeper" between scheduler ticks.
- Each domain exports its tool list (`HYGIENE_TOOLS`, `CAPACITY_TOOLS`, `COVERAGE_TOOLS`, `REPORTER_TOOLS`). Agents receive only their domain's list.

### 5.4 What is explicitly NOT in the data flow

- Agents never write to `FindingsStore` directly — the daemon receives the Pydantic output, computes `hash_key`, sanitizes, and writes.
- Agents never see `CleanAlert.raw`. The `raw` field is dropped before any LLM call.
- Agents never see credentials. Backends are passed in as already-authenticated handles in tool closures.
- Metrics containing PII (internal IPs, usernames) only reach the LLM if they live under `artifacts.llm_safe`, and only after pseudonymization if enabled.

## 6. Guardrails

### 6.1 Read-only enforcement (by construction)

| Mechanism | How |
|---|---|
| No write tools in registry | `tools/readonly/` is the only tool module. Test fails if any other tool module exists. |
| `WazuhSource` Protocol has no write methods | Mypy/pylance enforces. |
| `WazuhAPISource` uses HTTP GET only | Static scan in test fails on `.post(` / `.put(` / `.delete(` / `.patch(` inside the package (except the JWT-login POST, which is whitelisted by location). |
| SSH backend prohibited in v1 | Protocol has no shell exec method. If ever added, requires `WAZUH_HEALTH_ALLOW_SSH=true` and explicit config flag. |
| Import boundary | `tests/test_boundaries.py` fails on imports of `src.executor`, `src.webhook`, `src.approvals` or write APIs from within `src.wazuh_health`. |
| Filesystem | systemd unit mounts `/var/ossec` as `ReadOnlyPaths`. Kernel denies writes even if code is compromised. |

### 6.2 LLM cost & rate control

| Control | Default | Reason |
|---|---|---|
| Per-metric cooldown | 6 h | Same noisy rule does not wake `HygieneAgent` 24×/day |
| Daily cap per agent | 50 invocations | If the daemon loops, the cap protects the OpenAI account. On cap, an `internal_finding` (`severity=warning`) is emitted and the agent stops being woken until next day. |
| Model per agent | Domain = `OPENAI_MODEL_LIGHT` (gpt-4o-mini); Reporter = `OPENAI_MODEL_HEAVY` (gpt-4o) | Domain agents run often and decide little; reporter consolidates and benefits from a stronger model |
| Token caps | input ≤ 8000, output ≤ 2000 | Hard limits on tool inputs and `output_type` |
| Tool calls per turn | max 6 | Prevents tool-call loops |
| Invocation timeout | 60 s | After this, cancel + log + emit `internal_finding` |

### 6.3 LLM output validation (defense in depth)

Each `DomainFinding` passes through a sanitizer before reaching `FindingsStore`:

| Check | Action on failure |
|---|---|
| Pydantic schema (`extra="forbid"`) | Reject — retry once |
| `title` ≤ 120, `body_md` ≤ 4000 | Truncate with log |
| `evidence` is scalars only (no nested) | Reject |
| `body_md` contains external URLs (`https?://(?!internal\.)`) | Strip URLs |
| `suggested_action` contains shell metacharacters `[$;&|]` or `rm`/`curl`/`wget` | Reject — the agent emitted something executable |
| `proposed_artifact` (XML) parses as valid XML and matches a Wazuh-tag allowlist | Reject snippet, keep finding without it |
| `hash_key` comes from the LLM | Override silently — code is always the source of truth |

Reject = the finding is not persisted. The raw output is logged for debugging.

### 6.4 Credentials & sensitive data

| Risk | Mitigation |
|---|---|
| Credentials in logs/reports | Backends keep credentials in constructor only; tools never receive the raw client. Logger filter strips `Authorization` / `token` headers. |
| PII in LLM prompts | Each probe declares `artifacts.llm_safe: dict` (filtered subset). Only that subset is shipped to the LLM. When `privacy.pseudonymize=true` (default), IPs/usernames/hostnames are hashed to stable tokens (`agent_a3f2`) before the LLM call; an inverse map lives in the store for un-masking inside trusted destinations (filesystem report). |
| Slack webhook URL | Env only. Validated at boot. |
| SQLite path | Default `/var/lib/wazuh-health/state.db` at 0600. Fallback to `~/.local/share/wazuh-health/state.db` when not running as a privileged user. |

### 6.5 Error handling & fault tolerance

| Failure | Behavior |
|---|---|
| Probe raises | `ProbeResult` stored with `errors=[...]`, partial metrics. Threshold ignores missing metrics (does not treat absence as zero). |
| `WazuhSource` unreachable | Probe records error; exponential backoff (max 3 retries) then circuit-open for 15 min. Emits `internal_finding severity=warning`. |
| LLM API down / rate-limited | Agent fails → `internal_finding`; raw probe finding is stored without LLM enrichment. **Fail open**: deterministic probes are ground truth; LLM is enrichment. |
| `FindingsStore` corruption | Daemon fails fast at boot. Daily backup of `state.db`. |
| Notifier fails | Retry 3× with backoff; mark `notification_failed`. Never blocks the cycle. |
| `SIGTERM` with active agent | Wait up to 30 s, then cancel and persist what is available. |

### 6.6 Auditability

`agent_runs` provides "why did the system propose X on Tuesday?" post-mortem with full input/output token usage, tool calls, and finding IDs produced.

## 7. Testing strategy

### 7.1 Test pyramid

```
unit (~80%)        : probes, store, sanitizer, threshold, tools, hash, schemas
fakes (~15%)       : agents with LLM fake, scheduler with fake clock, notifiers with respx
integration (~5%)  : daemon boot+shutdown, full tick e2e with fixtures, /healthz
manual (off CI)    : smoke against a real model, eval suite
```

Target: ≥85% line coverage in `src/wazuh_health/`, ~100% on sanitizer/guardrail modules.

### 7.2 Per layer

| Layer | What is tested | Tool |
|---|---|---|
| `WazuhSource` backends | NDJSON parsing (gz, malformed, big-line), mocked `os.statvfs`, mocked API responses | `respx`, fixtures in `tests/fixtures/health/` |
| Probes | Each probe with fake `WazuhSource` injected; happy path + partial-error path | constructor injection |
| `ThresholdEngine` | Rule eval, YAML→rules, severity | `hypothesis` for numeric rules |
| `CooldownTable` | Cooldown respected, expiration, persistence | SQLite `:memory:`, fake clock |
| `FindingsStore` | Insert/update with hash dedup, status transitions, backups | SQLite `:memory:`, snapshots |
| Agents (LLM) | LLM fake (interceptor returning canned `list[DomainFinding]`); verifies tool calls, `output_type`, sanitizer rejection | `agents` SDK fake provider |
| Tools read-only | Each tool isolated, shape correct, no network access | injected `FindingsStore` + `ProbeResult` fixtures |
| Sanitizer | Adversarial input table | param tests |
| `WakeDispatcher` | One invocation per domain per dispatch, cooldown respect, cap counting | fake agent counting invocations |
| Notifiers | `FilesystemNotifier` writes path + perms; `SlackNotifier`/`EmailNotifier` with `respx`/SMTP fake | no real network |
| Scheduler | Tick determinism with fake clock; jitter on/off; no overlapping jobs | clock injected as dependency |
| Daemon | Boot ok / fail-fast on missing creds; `SIGTERM` flush; `/healthz` | subprocess + signals |

### 7.3 Cross-cutting tests

| Test | Importance |
|---|---|
| Import boundary (`tests/test_boundaries.py`) | Fails if `src.wazuh_health` imports `src.executor`, `src.webhook`, `src.approvals` or any write HTTP verb in `httpx` |
| No write tools registered | Iterates `tools/readonly` and fails if a tool name matches `(apply\|set\|delete\|restart\|patch\|create\|update)_*` |
| Deterministic finding hash | Property-based: same evidence → same hash; different → different; key-order independent |
| Pseudonymization round-trip | With `pseudonymize=true`, tokens are session-stable and un-masking recovers the original value |
| No PII in prompts | Captures the `messages` payload sent to the fake model and asserts (regex) no real IPs (when `pseudonymize=true`) |
| Daily cap triggers internal finding | Simulates 51 invocations; the 51st does not call the LLM and emits an internal finding |

### 7.4 What is **not** tested with a real LLM

Cost and non-determinism rule it out for CI.

- **CI: 100% LLM fake.** No `OPENAI_API_KEY` in CI. If the code attempts a real call, it fails on missing env.
- **Manual suite `tests/manual/`**: smoke against a real model under `pytest -m manual`. Expected output checked by shape and guardrails, not exact match.
- **Eval suite (phase 2)**: a small fixtures set of realistic `ProbeResult`s with expected `DomainFinding`s. Metric: precision/recall of finding detection vs false positives. Not required for MVP.

### 7.5 CleanSwarm regression

The current `cleanswarm analyze` keeps working as a compat entrypoint. `tests/test_cleanswarm.py` passes unchanged after the absorption — free regression coverage for `HygieneProbe`. The following gaps from the prior review are added at the same time:

- Rule level ≥ 7 with sensitive `rule_groups` → `investigate_source`.
- Malformed/empty JSON lines do not crash.
- `--days` cutoff: alert with an invalid timestamp is discarded (documented decision).
- `_extract_user` with `data.win` as a string (not dict) does not crash.
- XML escaping: `agent_name = 'evil"$(rm -rf /)'` produces valid, non-injecting snippet.
- Bucket with no extra dimensions → `tune_frequency`.

## 8. Layout + config

### 8.1 Directory layout

```
src/
├── cleanswarm/                  # facade (compat) — re-exports
│   ├── __init__.py
│   ├── __main__.py              # bug-fixed: no SystemExit at import
│   ├── cli.py                   # `cleanswarm analyze` keeps working
│   ├── models.py                # re-export shim → wazuh_health.contracts.*
│   ├── collector.py             # re-export shim → wazuh_health.source.local_fs
│   ├── analyzer.py              # re-export shim → wazuh_health.hygiene.analyzer
│   ├── recommender.py           # re-export shim → wazuh_health.hygiene.recommender
│   ├── simulator.py             # re-export shim → wazuh_health.hygiene.simulator
│   └── report.py                # re-export shim → wazuh_health.hygiene.report
│
└── wazuh_health/                # real code lives here
    ├── __init__.py
    ├── __main__.py              # `python -m wazuh_health`
    ├── cli.py                   # serve | once | report | doctor | migrate
    ├── daemon.py                # supervisor + signals + healthz
    ├── scheduler.py             # home-grown scheduler
    ├── config/
    │   ├── __init__.py
    │   ├── settings.py          # Pydantic Settings (env + YAML merge)
    │   └── default.yaml
    ├── contracts/
    │   ├── alerts.py            # CleanAlert (no raw field shipped to LLM)
    │   ├── probes.py            # ProbeResult, ThresholdHit
    │   ├── findings.py          # DomainFinding, WazuhHealthReport
    │   └── hygiene.py           # NoiseBucket, Recommendation, SimulationResult
    ├── source/
    │   ├── base.py              # WazuhSource Protocol
    │   ├── local_fs.py
    │   └── wazuh_api.py
    ├── probes/
    │   ├── base.py              # Probe ABC
    │   ├── capacity.py
    │   ├── hygiene.py
    │   └── coverage.py
    ├── hygiene/                 # pure algorithms (no LLM) — absorbed from CleanSwarm
    │   ├── analyzer.py          # improved scoring
    │   ├── recommender.py       # calibrated thresholds + rule_groups blacklist
    │   ├── simulator.py         # + combined_simulation
    │   └── xml_render.py        # quoteattr/escape + <group>cleanswarm,</group> + metadata
    ├── decision/
    │   ├── threshold.py
    │   ├── cooldown.py
    │   └── dispatcher.py
    ├── store/
    │   ├── db.py                # SQLite connection + migrations
    │   ├── findings_store.py
    │   └── audit_store.py
    ├── agents/
    │   ├── prompts/             # per-agent .md prompts
    │   │   ├── hygiene.md
    │   │   ├── capacity.md
    │   │   ├── coverage.md
    │   │   └── reporter.md
    │   ├── hygiene.py
    │   ├── capacity.py
    │   ├── coverage.py
    │   ├── reporter.py
    │   └── sanitizer.py
    ├── tools/
    │   └── readonly/
    │       ├── __init__.py      # exports HYGIENE_TOOLS, CAPACITY_TOOLS, ...
    │       ├── hygiene_tools.py
    │       ├── capacity_tools.py
    │       ├── coverage_tools.py
    │       └── reporter_tools.py
    ├── notify/
    │   ├── base.py
    │   ├── filesystem.py
    │   ├── slack.py
    │   └── email.py
    ├── compat/
    │   ├── __init__.py
    │   └── cleanswarm_cli.py     # delegate target for `cleanswarm` console script
    └── pseudonymize.py

tests/
├── fixtures/
│   ├── cleanswarm/              # unchanged
│   └── health/
│       ├── alerts/              # NDJSON variants
│       ├── api/                 # mocked Manager + Indexer JSON
│       └── filesystem/          # fake /var/ossec tree
├── test_boundaries.py
├── test_cleanswarm.py           # unchanged
└── <per-layer subdirs>

docs/
├── CLEANSWARM.md                # kept + "now part of wazuh-health" note
├── WAZUH_HEALTH.md              # new overview
└── superpowers/specs/2026-06-11-wazuh-health-squad-design.md

deploy/
└── wazuh-health.service
```

### 8.2 Configuration layers

Priority (highest first):

1. Env vars (override / secrets) — `.env` or systemd `Environment=`
2. YAML per install — `/etc/wazuh-health/config.yaml`
3. YAML default versioned — `src/wazuh_health/config/default.yaml`

All merged into a single `HealthConfig` Pydantic instance, validated at boot.

#### 8.2.1 Env vars

Reuse the project's existing convention:

```bash
# Reused
OPENAI_API_KEY=...
OPENAI_MODEL_LIGHT=gpt-4o-mini     # → HygieneAgent / CapacityAgent / CoverageAgent
OPENAI_MODEL_HEAVY=gpt-4o          # → ReporterAgent
WAZUH_API_HOST=192.168.38.60
WAZUH_API_PORT=55000
WAZUH_API_USER=...
WAZUH_API_PASSWORD=...

# New
WAZUH_HEALTH_SOURCE=local_fs       # or "wazuh_api"
WAZUH_HEALTH_DB_PATH=/var/lib/wazuh-health/state.db
WAZUH_HEALTH_REPORT_DIR=/var/log/wazuh-health/reports
WAZUH_HEALTH_LLM_DAILY_CAP=50
WAZUH_HEALTH_PSEUDONYMIZE=true
WAZUH_HEALTH_SLACK_WEBHOOK=        # optional
WAZUH_HEALTH_EMAIL_TO=             # optional
WAZUH_HEALTH_CONFIG_PATH=/etc/wazuh-health/config.yaml   # optional override
```

Explicitly **not read** by wazuh-health (reinforces the boundary): `WAZUH_WEBHOOK_SECRET`, `ENABLE_TRIAGE`. A test asserts these are never read by code in `src/wazuh_health/`.

#### 8.2.2 YAML — runtime-editable structure

```yaml
source:
  backend: ${WAZUH_HEALTH_SOURCE:-local_fs}
  local_fs:
    alerts_path: /var/ossec/logs/alerts/alerts.json
    rotated_glob: /var/ossec/logs/alerts/alerts.json.*
    ossec_conf: /var/ossec/etc/ossec.conf
  wazuh_api:
    host: ${WAZUH_API_HOST}
    port: ${WAZUH_API_PORT}
    verify_ssl: true

scheduler:
  jitter_seconds: 30
  jobs:
    capacity: { interval_seconds: 300 }
    coverage: { interval_seconds: 900 }
    hygiene:  { interval_seconds: 3600 }
    reporter: { interval_seconds: 21600 }

thresholds:
  capacity:
    - metric: disk.var_ossec.free_pct
      rule: "value < 15"
      severity: warning
    - metric: disk.var_ossec.free_pct
      rule: "value < 5"
      severity: critical
    - metric: indexer.heap_pct
      rule: "value > 85"
      severity: warning
  hygiene:
    - metric: noise.combined_reduction_pct
      rule: "value > 10"
      severity: info
  coverage:
    - metric: agents.disconnected
      rule: "value >= 3 streak >= 2"
      severity: warning

cooldowns:
  default_minutes: 360
  by_metric:
    indexer.heap_pct: 60

llm:
  light_model: ${OPENAI_MODEL_LIGHT}
  heavy_model: ${OPENAI_MODEL_HEAVY}
  max_tool_calls_per_turn: 6
  input_token_cap: 8000
  output_token_cap: 2000
  timeout_seconds: 60
  daily_cap_per_agent: ${WAZUH_HEALTH_LLM_DAILY_CAP:-50}

privacy:
  pseudonymize: ${WAZUH_HEALTH_PSEUDONYMIZE:-true}
  pseudonymize_fields: [srcip, dstip, agent.name, user]

storage:
  db_path: ${WAZUH_HEALTH_DB_PATH:-/var/lib/wazuh-health/state.db}
  report_dir: ${WAZUH_HEALTH_REPORT_DIR:-/var/log/wazuh-health/reports}
  retention_days: 30

notify:
  filesystem: { enabled: true }
  slack:
    enabled: false
    webhook_url: ${WAZUH_HEALTH_SLACK_WEBHOOK}
    severity_floor: warning
  email:
    enabled: false
    to: ${WAZUH_HEALTH_EMAIL_TO}
    smtp_host: localhost
```

Rule of thumb: **structure** (which thresholds exist, which probes run) lives in YAML (editable). **Evaluation logic** lives in code (versioned).

### 8.3 CLI entrypoints

```bash
wazuh-health serve              # daemon (used by systemd)
wazuh-health once               # run all probes once, then exit
wazuh-health report             # invoke ReporterAgent now, stdout
wazuh-health report --since 24h --out /tmp/r.md
wazuh-health doctor             # boot checks: connectivity, perms, schema
wazuh-health migrate            # SQLite migrations (idempotent)

cleanswarm analyze ...          # kept; now sourced from wazuh_health.hygiene
```

`pyproject.toml`:

```toml
[project.scripts]
cleanswarm = "wazuh_health.compat.cleanswarm_cli:main"
wazuh-health = "wazuh_health.cli:main"

[tool.hatch.build.targets.wheel]
packages = ["src/wazuh_health", "src/cleanswarm"]
```

This also fixes the existing entrypoint bug (`src.cleanswarm.cli:main` was unreachable for a real `pip install`).

### 8.4 systemd unit

```ini
[Unit]
Description=Wazuh Health Squad
After=network-online.target wazuh-manager.service
Wants=network-online.target

[Service]
Type=simple
User=wazuh-health
Group=wazuh-health
EnvironmentFile=/etc/wazuh-health/wazuh-health.env
ExecStart=/usr/local/bin/wazuh-health serve
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10
ReadWritePaths=/var/lib/wazuh-health /var/log/wazuh-health
ReadOnlyPaths=/var/ossec
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

`ReadOnlyPaths=/var/ossec` enforces read-only at the kernel level — even if the code is later compromised, the FS denies writes.

## 9. Migration plan (high level)

1. Create `src/wazuh_health/` skeleton with empty modules and contracts.
2. Move CleanSwarm internals into `wazuh_health/hygiene/` (analyzer, recommender, simulator, xml_render), addressing the prior review (severity calibration, XML correctness, rule_groups blacklist, combined simulation).
3. Replace `src/cleanswarm/*` with re-export shims. Existing tests still pass.
4. Build `WazuhSource` Protocol, `LocalFSSource`, `WazuhAPISource` (read-only + JWT login).
5. Build probes (capacity, hygiene-as-probe, coverage), `FindingsStore`, `ThresholdEngine`, `CooldownTable`, `WakeDispatcher`.
6. Build read-only tool modules and per-domain agents with the SDK fake test harness.
7. Build `ReporterAgent`, notifiers, scheduler, daemon, healthz.
8. Wire boundary + write-tool + PII-leak tests.
9. systemd unit + docs (`WAZUH_HEALTH.md`).
10. Run `cleanswarm` regression suite — must pass unchanged.

Detailed implementation plan lives in the plan doc (next step).

## 10. Out of scope (v1)

- Compliance / SCA / CIS dimension.
- SOAR approval integration; auto-apply.
- SSH backend.
- Prometheus `/metrics`.
- Eval suite with model judges.
- Multi-tenant Wazuh deployments.
- Wazuh agent-side health (this monitors the manager + indexer + alert stream, not endpoints).

## 11. Open questions to confirm before plan

1. **Final package/product name**: keep `wazuh_health` / "Wazuh Health Squad", or adopt another (`wazuh_keeper`, `health_swarm`, etc.)?
2. **CleanSwarm CLI deprecation**: keep silent compat, or print a one-line "moved to wazuh-health" notice?
3. **systemd unit shipped from day 1**, or docs-only with `wazuh-health serve` invocation?
4. **Pseudonymization default**: `true` (recommended for LLM safety) or `false` (no surprise behavior for the operator)?
5. **Where `.env` lives**: project-root `.env` (developer ergonomics) vs `/etc/wazuh-health/wazuh-health.env` (prod) — both supported via `EnvironmentFile`, but which is the primary documented path?
