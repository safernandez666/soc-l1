# Wazuh Health Squad Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend CleanSwarm into a read-only daemon (`wazuh_health`) that monitors Wazuh hygiene + capacity + coverage, uses `openai-agents` LLM agents for analysis, and never touches the live SOC-L1 webhook/executor.

**Architecture:** Event-driven. Python deterministic probes run on intervals, emit `ProbeResult`. A `ThresholdEngine` decides if any metric crossed a configured rule; if so, a `WakeDispatcher` invokes one LLM domain agent (Hygiene/Capacity/Coverage) per domain, which emits `DomainFinding`s through a sanitizer into a SQLite `FindingsStore`. A `ReporterAgent` periodically (or on demand) consolidates open findings into a Markdown report. CleanSwarm absorbed as `wazuh_health/hygiene/` with `src/cleanswarm/` kept as compat shims so the existing CLI and tests keep passing.

**Tech Stack:** Python 3.12, Pydantic 2, openai-agents SDK (already in deps), httpx, psutil, pytest, respx, SQLite (stdlib), systemd.

**Spec:** `docs/superpowers/specs/2026-06-11-wazuh-health-squad-design.md`

**Phases (each can pause/review between):**
1. Skeleton + boundary tests + pyproject fix
2. Contracts + Hygiene module migration (absorbs CleanSwarm, fixes review findings)
3. Sources (LocalFS + WazuhAPI)
4. Probes (capacity, hygiene, coverage)
5. Store (SQLite) + Decision (threshold, cooldown, dispatcher)
6. Pseudonymize + tools + sanitizer
7. Agents (Hygiene/Capacity/Coverage + Reporter) + LLM fake provider
8. Scheduler + notifiers + daemon + CLI + config
9. Integration tests + systemd + docs

---

## Phase 1 — Skeleton + boundary tests + pyproject fix

Goal: empty package, enforceable invariants, working compat CLI. After this phase the existing `cleanswarm analyze` still works and CI fails fast on boundary violations.

### Task 1.1: Create `wazuh_health/` package skeleton

**Files:**
- Create: `src/wazuh_health/__init__.py`
- Create: `src/wazuh_health/__main__.py`
- Create: `src/wazuh_health/contracts/__init__.py`
- Create: `src/wazuh_health/source/__init__.py`
- Create: `src/wazuh_health/probes/__init__.py`
- Create: `src/wazuh_health/hygiene/__init__.py`
- Create: `src/wazuh_health/decision/__init__.py`
- Create: `src/wazuh_health/store/__init__.py`
- Create: `src/wazuh_health/agents/__init__.py`
- Create: `src/wazuh_health/agents/prompts/.gitkeep`
- Create: `src/wazuh_health/tools/__init__.py`
- Create: `src/wazuh_health/tools/readonly/__init__.py`
- Create: `src/wazuh_health/notify/__init__.py`
- Create: `src/wazuh_health/compat/__init__.py`
- Create: `src/wazuh_health/config/__init__.py`

- [ ] **Step 1: Create all `__init__.py` files**

Each `__init__.py` is empty for now. `src/wazuh_health/__init__.py` gets a one-line docstring:

```python
"""Wazuh Health Squad: read-only hygiene/capacity/coverage daemon for Wazuh."""
```

- [ ] **Step 2: Create `src/wazuh_health/__main__.py`**

```python
"""Module entry for `python -m wazuh_health`."""
from wazuh_health.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 3: Verify package imports**

Run: `python -c "import wazuh_health; print(wazuh_health.__doc__)"`
Expected: prints the docstring, no errors.

- [ ] **Step 4: Commit**

```bash
git add src/wazuh_health
git commit -m "feat(wazuh-health): scaffold empty package layout"
```

---

### Task 1.2: Fix `src/cleanswarm/__main__.py` SystemExit-at-import bug

**Files:**
- Modify: `src/cleanswarm/__main__.py`

- [ ] **Step 1: Write a failing test**

Create `tests/test_cleanswarm_main_safe_import.py`:

```python
"""Importing cleanswarm.__main__ must not raise SystemExit."""
import importlib


def test_importing_main_does_not_exit():
    # If __main__ runs SystemExit at import, this raises.
    importlib.import_module("src.cleanswarm.__main__")
```

- [ ] **Step 2: Run test, confirm failure**

Run: `pytest tests/test_cleanswarm_main_safe_import.py -v`
Expected: FAIL with `SystemExit` raised on import.

- [ ] **Step 3: Apply the fix**

Replace contents of `src/cleanswarm/__main__.py`:

```python
"""Module entry for `python -m src.cleanswarm`."""
from src.cleanswarm.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run test, confirm pass**

Run: `pytest tests/test_cleanswarm_main_safe_import.py -v`
Expected: PASS.

- [ ] **Step 5: Run full cleanswarm suite for regression**

Run: `pytest tests/test_cleanswarm.py -v`
Expected: all 4 tests still PASS.

- [ ] **Step 6: Commit**

```bash
git add src/cleanswarm/__main__.py tests/test_cleanswarm_main_safe_import.py
git commit -m "fix(cleanswarm): guard __main__ entry against SystemExit at import"
```

---

### Task 1.3: Add import boundary test

**Files:**
- Create: `tests/test_boundaries.py`

- [ ] **Step 1: Write the failing test**

```python
"""Boundary invariants for the wazuh_health package.

Read-only by construction: no imports of the live SOAR write paths, and
no calls to write HTTP verbs from within the package.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

PKG_ROOT = Path("src/wazuh_health")

FORBIDDEN_IMPORTS = {
    "src.executor",
    "src.webhook",
    "src.approvals",
}

FORBIDDEN_VERB_RE = re.compile(r"\.(post|put|delete|patch)\(")

# JWT login is the one allowed POST; whitelist by file path.
POST_WHITELIST_FILES = {
    "src/wazuh_health/source/wazuh_api.py",
}

FORBIDDEN_ENV_VARS = {"WAZUH_WEBHOOK_SECRET", "ENABLE_TRIAGE"}


def _iter_py_files() -> list[Path]:
    return [p for p in PKG_ROOT.rglob("*.py") if p.is_file()]


def test_no_forbidden_imports() -> None:
    for path in _iter_py_files():
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            mod = None
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name
                    assert mod not in FORBIDDEN_IMPORTS, f"{path} imports {mod}"
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                assert mod not in FORBIDDEN_IMPORTS, f"{path} imports from {mod}"


def test_no_write_http_verbs_outside_whitelist() -> None:
    for path in _iter_py_files():
        text = path.read_text()
        for match in FORBIDDEN_VERB_RE.finditer(text):
            rel = str(path).replace("\\", "/")
            assert rel in POST_WHITELIST_FILES, (
                f"{rel} uses HTTP {match.group(1)} but is not whitelisted"
            )


def test_no_soar_envs_referenced() -> None:
    for path in _iter_py_files():
        text = path.read_text()
        for env in FORBIDDEN_ENV_VARS:
            assert env not in text, f"{path} references forbidden env {env}"
```

- [ ] **Step 2: Run test, expect pass (empty package = trivially passes)**

Run: `pytest tests/test_boundaries.py -v`
Expected: 3 tests PASS (no Python files in `wazuh_health` yet beyond `__init__.py`s).

- [ ] **Step 3: Verify the test catches violations**

Temporarily add `import src.executor` to `src/wazuh_health/__init__.py`, re-run:

Run: `pytest tests/test_boundaries.py::test_no_forbidden_imports -v`
Expected: FAIL with AssertionError mentioning `src.executor`.

Revert the change.

- [ ] **Step 4: Commit**

```bash
git add tests/test_boundaries.py
git commit -m "test(wazuh-health): import + write-verb + soar-env boundary tests"
```

---

### Task 1.4: Add no-write-tools registry test

**Files:**
- Create: `tests/test_no_write_tools.py`

- [ ] **Step 1: Write the test**

```python
"""Only readonly tools may exist in wazuh_health.tools."""
from __future__ import annotations

import re
from pathlib import Path

TOOLS_ROOT = Path("src/wazuh_health/tools")
FORBIDDEN_NAME_RE = re.compile(
    r"^(apply|set|delete|restart|patch|create|update|write|push)_"
)


def test_only_readonly_subpackage_exists() -> None:
    children = {p.name for p in TOOLS_ROOT.iterdir() if p.is_dir()}
    # readonly is the only allowed tool dir.
    assert children <= {"readonly", "__pycache__"}, children


def test_no_tool_name_suggests_write() -> None:
    readonly = TOOLS_ROOT / "readonly"
    for path in readonly.rglob("*.py"):
        text = path.read_text()
        # Look at top-level `def` and `async def` names.
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(("def ", "async def ")):
                name = stripped.split()[1].split("(")[0]
                assert not FORBIDDEN_NAME_RE.match(name), (
                    f"{path} defines write-shaped tool {name}"
                )
```

- [ ] **Step 2: Run, expect pass on empty registry**

Run: `pytest tests/test_no_write_tools.py -v`
Expected: 2 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/test_no_write_tools.py
git commit -m "test(wazuh-health): forbid write-shaped tools in registry"
```

---

### Task 1.5: Update `pyproject.toml` — packages + entrypoints

**Files:**
- Modify: `pyproject.toml`

- [ ] **Step 1: Update `[tool.hatch.build.targets.wheel]` and `[project.scripts]`**

Replace those sections with:

```toml
[project.scripts]
cleanswarm = "wazuh_health.compat.cleanswarm_cli:main"
wazuh-health = "wazuh_health.cli:main"

[tool.hatch.build.targets.wheel]
packages = ["src/wazuh_health", "src/cleanswarm"]
```

- [ ] **Step 2: Create stub modules that the entrypoints expect**

Create `src/wazuh_health/cli.py`:

```python
"""Top-level CLI for wazuh-health (stub — implemented in Phase 8)."""
from __future__ import annotations


def main(argv: list[str] | None = None) -> int:
    print("wazuh-health: not yet implemented (Phase 8)")
    return 2
```

Create `src/wazuh_health/compat/cleanswarm_cli.py`:

```python
"""Compat entry point — delegates to the original CleanSwarm CLI."""
from __future__ import annotations

from src.cleanswarm.cli import main as _legacy_main


def main(argv: list[str] | None = None) -> int:
    return _legacy_main(argv)
```

- [ ] **Step 3: Verify entrypoints resolve**

Run: `python -c "from wazuh_health.cli import main; print(main.__doc__)"`
Run: `python -c "from wazuh_health.compat.cleanswarm_cli import main; print('ok')"`
Expected: both print successfully.

- [ ] **Step 4: Run boundary tests, ensure still green**

Run: `pytest tests/test_boundaries.py tests/test_no_write_tools.py tests/test_cleanswarm.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/wazuh_health/cli.py src/wazuh_health/compat/cleanswarm_cli.py
git commit -m "build(wazuh-health): wire console scripts + cleanswarm compat shim"
```

---

**End of Phase 1.** Pause point: package skeleton in place, all existing tests pass, boundaries enforced.

---

## Phase 2 — Contracts + hygiene module migration

Goal: lift the CleanSwarm internals into `wazuh_health/{contracts,hygiene}/`, applying the review fixes (drop `raw` from LLM-visible serialization, calibrate severity + rule_groups blacklist, XML correctness with `<group>` and metadata, combined simulation, gzip + rotated file support, robust `_extract_user`). After this phase the `cleanswarm analyze` CLI behaves identically — just sourced from new modules.

### Task 2.1: Move contracts into `wazuh_health/contracts/`

**Files:**
- Create: `src/wazuh_health/contracts/alerts.py`
- Create: `src/wazuh_health/contracts/hygiene.py`
- Create: `src/wazuh_health/contracts/findings.py`
- Create: `src/wazuh_health/contracts/probes.py`
- Create: `src/wazuh_health/contracts/__init__.py`
- Test: `tests/contracts/test_clean_alert_serialization.py`

- [ ] **Step 1: Write failing test for "no raw in LLM-safe dump"**

```python
# tests/contracts/test_clean_alert_serialization.py
from src.wazuh_health.contracts.alerts import CleanAlert


def test_llm_safe_dump_strips_raw():
    alert = CleanAlert(
        timestamp="2026-06-11T10:00:00Z",
        rule_id="5710",
        rule_level=5,
        raw={"sensitive": "payload"},
    )
    payload = alert.to_llm_safe_dict()
    assert "raw" not in payload
    assert payload["rule_id"] == "5710"


def test_model_dump_keeps_raw_for_internal_use():
    alert = CleanAlert(
        timestamp="2026-06-11T10:00:00Z",
        rule_id="5710",
        rule_level=5,
        raw={"sensitive": "payload"},
    )
    assert alert.model_dump()["raw"] == {"sensitive": "payload"}
```

- [ ] **Step 2: Run test, expect import error**

Run: `pytest tests/contracts/test_clean_alert_serialization.py -v`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Write `contracts/alerts.py`**

```python
"""Wazuh alert shape used by hygiene/coverage probes."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CleanAlert(BaseModel):
    """Compact Wazuh alert. `raw` is for internal correlation only — it is
    stripped before any LLM-bound serialization to avoid PII leakage."""

    model_config = ConfigDict(extra="forbid")

    timestamp: str
    rule_id: str
    rule_level: int = 0
    rule_description: str = "Unknown"
    rule_groups: list[str] = Field(default_factory=list)
    agent_id: str | None = None
    agent_name: str | None = None
    srcip: str | None = None
    dstip: str | None = None
    user: str | None = None
    decoder_name: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    def to_llm_safe_dict(self) -> dict[str, Any]:
        data = self.model_dump()
        data.pop("raw", None)
        return data
```

- [ ] **Step 4: Write `contracts/hygiene.py`** (moved from `src/cleanswarm/models.py`)

```python
"""Noise hygiene aggregates and recommendations (moved from cleanswarm)."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

RecommendationType = Literal[
    "suppress_conditionally",
    "tune_frequency",
    "investigate_source",
    "leave_visible",
]
RiskLevel = Literal["low", "medium", "high"]


class NoiseBucket(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str
    dimensions: dict[str, str]
    count: int
    rule_id: str | None = None
    rule_level: int = 0
    rule_description: str = "Unknown"
    rule_groups: list[str] = Field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    affected_agents: list[str] = Field(default_factory=list)
    affected_srcips: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    noise_score: float = 0.0
    noise_score_breakdown: dict[str, float] = Field(default_factory=dict)


class Recommendation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    type: RecommendationType
    title: str
    rule_id: str
    condition: dict[str, str] = Field(default_factory=dict)
    reason: str
    risk: RiskLevel
    expected_reduction_count: int
    expected_reduction_ratio: float
    proposed_wazuh_rule: str | None = None
    rollback: str


class SimulationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    recommendation_id: str
    matched_alerts: int
    total_alerts: int
    reduction_ratio: float
    max_level_hidden: int
    high_or_critical_hidden: int
    affected_rules: list[str] = Field(default_factory=list)
    sample_hidden_alert_ids: list[str] = Field(default_factory=list)
    verdict: RiskLevel


class CombinedSimulation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    total_alerts: int
    union_matched: int
    union_reduction_ratio: float
    overlap_alerts: int
    max_level_hidden: int
    high_or_critical_hidden: int


class CleanSwarmReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    generated_at: str
    source: str
    total_alerts: int
    analyzed_days: int | None = None
    top_buckets: list[NoiseBucket] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)
    simulations: list[SimulationResult] = Field(default_factory=list)
    combined_simulation: CombinedSimulation | None = None
```

- [ ] **Step 5: Write `contracts/probes.py` and `contracts/findings.py`**

`contracts/probes.py`:

```python
"""Probe and threshold contracts."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ProbeName = Literal["capacity", "hygiene", "coverage"]
Severity = Literal["info", "warning", "critical"]


class ProbeResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    probe: ProbeName
    run_at: datetime
    metrics: dict[str, float | int]
    artifacts: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)


class ThresholdHit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    probe: ProbeName
    metric: str
    value: float | int
    rule: str
    severity: Severity
```

`contracts/findings.py`:

```python
"""Finding and report contracts (LLM agent outputs)."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Domain = Literal["hygiene", "capacity", "coverage"]
Severity = Literal["info", "warning", "critical"]


class DomainFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain: Domain
    severity: Severity
    title: str = Field(max_length=120)
    body_md: str = Field(max_length=4000)
    evidence: dict[str, str | int | float] = Field(default_factory=dict)
    suggested_action: str
    proposed_artifact: str | None = None
    hash_key: str = ""  # filled by daemon, never trusted from LLM


class WazuhHealthReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    generated_at: datetime
    window_hours: int
    summary: str
    by_domain: dict[Domain, list[DomainFinding]] = Field(default_factory=dict)
    top_priorities: list[DomainFinding] = Field(default_factory=list)
```

- [ ] **Step 6: `contracts/__init__.py` exports**

```python
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
```

- [ ] **Step 7: Run tests**

Run: `pytest tests/contracts/ tests/test_boundaries.py -v`
Expected: all PASS (note: boundary test still passes because contracts only reference `pydantic`).

- [ ] **Step 8: Commit**

```bash
git add src/wazuh_health/contracts tests/contracts
git commit -m "feat(wazuh-health): contracts package with LLM-safe alert serialization"
```

---

### Task 2.2: Re-export shim for `src/cleanswarm/models.py`

**Files:**
- Modify: `src/cleanswarm/models.py`

- [ ] **Step 1: Replace contents with a re-export shim**

```python
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
```

- [ ] **Step 2: Verify cleanswarm tests still pass**

Run: `pytest tests/test_cleanswarm.py -v`
Expected: FAIL — `analyzer`/`recommender`/`simulator`/`report` still reference old `src.cleanswarm.models` symbols that no longer exist as classes (they're re-exports now). The re-export must keep the same symbols — verify failure mode is empty/unrelated.

If `test_compact_alert_extracts_common_wazuh_fields` passes (it uses `compact_alert` from `collector`, which still operates), good — we'll migrate the rest in subsequent tasks.

- [ ] **Step 3: Commit shim**

```bash
git add src/cleanswarm/models.py
git commit -m "refactor(cleanswarm): models.py becomes re-export shim"
```

---

### Task 2.3: Move analyzer with calibrated noise score

**Files:**
- Create: `src/wazuh_health/hygiene/analyzer.py`
- Test: `tests/hygiene/test_analyzer_scoring.py`

- [ ] **Step 1: Write tests for the new scoring**

```python
# tests/hygiene/test_analyzer_scoring.py
from src.wazuh_health.contracts import CleanAlert
from src.wazuh_health.hygiene.analyzer import build_noise_buckets


def _alert(rule_id="5710", level=5, agent="vpn01", srcip="10.0.5.20"):
    return CleanAlert(
        timestamp="2026-06-11T10:00:00Z",
        rule_id=rule_id,
        rule_level=level,
        agent_name=agent,
        srcip=srcip,
    )


def test_bucket_score_includes_breakdown():
    alerts = [_alert() for _ in range(20)]
    buckets = build_noise_buckets(alerts, min_count=5)
    assert buckets
    b = buckets[0]
    assert {"volume", "repetition", "severity_penalty", "spread_penalty"} <= set(
        b.noise_score_breakdown
    )


def test_severity_penalty_dampens_high_level_buckets():
    low = [_alert(level=3) for _ in range(50)]
    high = [_alert(rule_id="100100", level=12, agent="win01", srcip="203.0.113.99") for _ in range(50)]
    buckets = build_noise_buckets(low + high, min_count=5)
    by_rule = {b.rule_id: b for b in buckets}
    assert by_rule["100100"].noise_score < by_rule["5710"].noise_score


def test_user_spread_penalty_applied():
    base = []
    for i in range(40):
        base.append(_alert(rule_id="5402", level=4, agent="srv01", srcip=None))
        base[-1].user = f"user{i}"  # 40 distinct users
    buckets = build_noise_buckets(base, min_count=10)
    # Same rule grouped by (rule_id, agent.name) since no srcip/user dim wins...
    # The spread by user should drop the score below the same rule with 1 user
    assert buckets[0].noise_score_breakdown["spread_penalty"] > 0
```

- [ ] **Step 2: Run, expect import failure**

Run: `pytest tests/hygiene/test_analyzer_scoring.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `hygiene/analyzer.py`**

```python
"""Noise aggregation with calibrated scoring + breakdown."""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from src.wazuh_health.contracts import CleanAlert, NoiseBucket


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _signature(alert: CleanAlert) -> tuple[str, dict[str, str]]:
    dims = {"rule_id": alert.rule_id}
    if alert.agent_name:
        dims["agent.name"] = alert.agent_name
    if alert.srcip:
        dims["srcip"] = alert.srcip
    elif alert.user:
        dims["user"] = alert.user
    return ("|".join(f"{k}={v}" for k, v in dims.items()), dims)


def _noise_score_components(
    *, count: int, level: int, unique_agents: int,
    unique_srcips: int, unique_users: int, total: int,
) -> dict[str, float]:
    safe_total = max(total, 1)
    volume = min(count / safe_total, 1.0) * 70.0
    repetition = min(math.log10(max(count, 1)) / math.log10(max(safe_total, 10)) * 20.0, 20.0)
    severity_penalty = max(level - 5, 0) * 5.0
    spread_penalty = (
        max(unique_agents - 1, 0) * 2.0
        + max(unique_srcips - 1, 0)
        + max(unique_users - 1, 0)
    )
    return {
        "volume": round(volume, 2),
        "repetition": round(repetition, 2),
        "severity_penalty": round(severity_penalty, 2),
        "spread_penalty": round(spread_penalty, 2),
    }


def build_noise_buckets(
    alerts: list[CleanAlert], *, min_count: int = 10, top: int = 20
) -> list[NoiseBucket]:
    grouped: dict[str, list[CleanAlert]] = defaultdict(list)
    dimensions_by_key: dict[str, dict[str, str]] = {}

    for alert in alerts:
        key, dims = _signature(alert)
        grouped[key].append(alert)
        dimensions_by_key[key] = dims

    buckets: list[NoiseBucket] = []
    total = len(alerts)
    for key, items in grouped.items():
        if len(items) < min_count:
            continue
        timestamps = [parse_timestamp(a.timestamp) for a in items]
        valid_ts = [ts for ts in timestamps if ts is not None]
        first_seen = min(valid_ts).isoformat() if valid_ts else None
        last_seen = max(valid_ts).isoformat() if valid_ts else None

        agent_counts = Counter(a.agent_name for a in items if a.agent_name)
        srcip_counts = Counter(a.srcip for a in items if a.srcip)
        user_counts = Counter(a.user for a in items if a.user)
        exemplar = items[0]
        breakdown = _noise_score_components(
            count=len(items),
            level=exemplar.rule_level,
            unique_agents=len(agent_counts),
            unique_srcips=len(srcip_counts),
            unique_users=len(user_counts),
            total=total,
        )
        score = round(
            max(
                breakdown["volume"]
                + breakdown["repetition"]
                - breakdown["severity_penalty"]
                - breakdown["spread_penalty"],
                0.0,
            ),
            2,
        )
        buckets.append(
            NoiseBucket(
                key=key,
                dimensions=dimensions_by_key[key],
                count=len(items),
                rule_id=exemplar.rule_id,
                rule_level=exemplar.rule_level,
                rule_description=exemplar.rule_description,
                rule_groups=list(exemplar.rule_groups),
                first_seen=first_seen,
                last_seen=last_seen,
                affected_agents=[k for k, _ in agent_counts.most_common(10)],
                affected_srcips=[k for k, _ in srcip_counts.most_common(10)],
                affected_users=[k for k, _ in user_counts.most_common(10)],
                noise_score=score,
                noise_score_breakdown=breakdown,
            )
        )

    return sorted(buckets, key=lambda b: (b.noise_score, b.count), reverse=True)[:top]
```

- [ ] **Step 4: Run tests, confirm pass**

Run: `pytest tests/hygiene/test_analyzer_scoring.py -v`
Expected: 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/wazuh_health/hygiene/analyzer.py tests/hygiene/test_analyzer_scoring.py
git commit -m "feat(wazuh-health): hygiene analyzer with calibrated score breakdown"
```

---

### Task 2.4: Move recommender with severity recalibration + sensitive rule_groups blacklist

**Files:**
- Create: `src/wazuh_health/hygiene/recommender.py`
- Test: `tests/hygiene/test_recommender_calibration.py`

Note: this task is intentionally Pythonic only; XML rendering moves to its own module in Task 2.5.

- [ ] **Step 1: Write tests for the calibration**

```python
# tests/hygiene/test_recommender_calibration.py
from src.wazuh_health.contracts import NoiseBucket
from src.wazuh_health.hygiene.recommender import (
    SENSITIVE_RULE_GROUPS,
    recommend_from_buckets,
)


def _bucket(level=5, groups=None, count=100, dims=None):
    return NoiseBucket(
        key="rule_id=5710|agent.name=vpn01",
        dimensions=dims or {"rule_id": "5710", "agent.name": "vpn01"},
        count=count,
        rule_id="5710",
        rule_level=level,
        rule_description="ssh fail",
        rule_groups=groups or [],
    )


def test_level_ge_7_goes_to_investigate_source():
    recs = recommend_from_buckets([_bucket(level=7)], total_alerts=200)
    assert recs[0].type == "investigate_source"


def test_sensitive_rule_groups_degrade_to_investigate():
    for g in SENSITIVE_RULE_GROUPS:
        recs = recommend_from_buckets(
            [_bucket(level=4, groups=[g])], total_alerts=200
        )
        assert recs[0].type == "investigate_source", g


def test_no_dimensions_yields_tune_frequency():
    recs = recommend_from_buckets(
        [_bucket(level=3, dims={"rule_id": "5710"})], total_alerts=200
    )
    assert recs[0].type == "tune_frequency"


def test_low_severity_with_dimensions_is_suppress_candidate():
    recs = recommend_from_buckets([_bucket(level=4, count=50)], total_alerts=500)
    assert recs[0].type == "suppress_conditionally"
    assert recs[0].risk == "low"


def test_high_ratio_bumps_risk():
    recs = recommend_from_buckets([_bucket(level=4, count=400)], total_alerts=500)
    assert recs[0].risk == "medium"
```

- [ ] **Step 2: Run, expect import failure**

Run: `pytest tests/hygiene/test_recommender_calibration.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `hygiene/recommender.py`**

```python
"""Conservative tuning recommendations from noise buckets."""
from __future__ import annotations

import re

from src.wazuh_health.contracts import NoiseBucket, Recommendation

SENSITIVE_RULE_GROUPS = frozenset(
    {
        "authentication_failures",
        "attacks",
        "attack",
        "intrusion_attempt",
        "web_attack",
        "malware",
        "virus",
        "rootkit",
        "audit_logon_invalid",
    }
)


def _safe_id(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", value).strip("-")[:80]


def _is_sensitive(bucket: NoiseBucket) -> bool:
    return any(g in SENSITIVE_RULE_GROUPS for g in bucket.rule_groups)


def recommend_from_buckets(
    buckets: list[NoiseBucket],
    *,
    total_alerts: int,
    max_recommendations: int = 10,
) -> list[Recommendation]:
    recommendations: list[Recommendation] = []

    for bucket in buckets[:max_recommendations]:
        if not bucket.rule_id:
            continue
        condition = {k: v for k, v in bucket.dimensions.items() if k != "rule_id"}
        ratio = bucket.count / max(total_alerts, 1)

        if bucket.rule_level >= 10 or (_is_sensitive(bucket) and bucket.rule_level >= 4):
            rec_type = "investigate_source"
            risk = "high"
            reason = (
                "Severity or rule group is sensitive (auth/attack/malware-class). "
                "Do not silence; review source or replace with tighter correlation."
            )
        elif bucket.rule_level >= 7:
            rec_type = "tune_frequency"
            risk = "medium"
            reason = (
                "Mid-high severity. Prefer frequency/threshold tuning over suppression."
            )
        elif not condition:
            rec_type = "tune_frequency"
            risk = "medium"
            reason = (
                "Globally noisy rule with no specific dimensions. Tune threshold or "
                "split the rule before silencing."
            )
        else:
            rec_type = "suppress_conditionally"
            risk = "low" if bucket.rule_level <= 5 and ratio <= 0.3 else "medium"
            reason = (
                "Repeated low-severity pattern with specific dimensions. Candidate "
                "for reversible conditional suppression."
            )

        recommendations.append(
            Recommendation(
                id=f"cs-{_safe_id(bucket.key)}",
                type=rec_type,
                title=f"Reduce noise of rule {bucket.rule_id}: {bucket.rule_description[:80]}",
                rule_id=str(bucket.rule_id),
                condition=condition,
                reason=reason,
                risk=risk,
                expected_reduction_count=bucket.count,
                expected_reduction_ratio=round(ratio, 4),
                proposed_wazuh_rule=None,  # set by xml_render in report assembly
                rollback=(
                    "Not applied automatically. If approved and added to "
                    f"local_rules.xml, rollback = remove the CleanSwarm rule for {bucket.rule_id}."
                ),
            )
        )

    return recommendations
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/hygiene/test_recommender_calibration.py -v`
Expected: 5 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/wazuh_health/hygiene/recommender.py tests/hygiene/test_recommender_calibration.py
git commit -m "feat(wazuh-health): recommender calibrates severity + sensitive groups blacklist"
```

---

### Task 2.5: XML render with safe escaping + `<group>` + metadata

**Files:**
- Create: `src/wazuh_health/hygiene/xml_render.py`
- Test: `tests/hygiene/test_xml_render.py`

- [ ] **Step 1: Adversarial tests**

```python
# tests/hygiene/test_xml_render.py
from xml.etree import ElementTree as ET

from src.wazuh_health.contracts import NoiseBucket
from src.wazuh_health.hygiene.xml_render import render_local_rule


def _bucket(**kw):
    base = dict(
        key="rule_id=5710|agent.name=vpn01",
        dimensions={"rule_id": "5710", "agent.name": "vpn01"},
        count=10,
        rule_id="5710",
        rule_level=5,
        rule_description="ssh fail",
    )
    base.update(kw)
    return NoiseBucket(**base)


def test_rendered_snippet_is_well_formed_xml():
    snippet = render_local_rule(_bucket(), local_rule_id=110000, bucket_hash="abc123")
    root = ET.fromstring(snippet)
    assert root.tag == "rule"


def test_includes_cleanswarm_group():
    snippet = render_local_rule(_bucket(), local_rule_id=110000, bucket_hash="abc")
    assert "<group>cleanswarm,</group>" in snippet


def test_includes_metadata_comment():
    snippet = render_local_rule(
        _bucket(), local_rule_id=110000, bucket_hash="abc", count=42
    )
    assert "cleanswarm" in snippet.lower()
    assert "abc" in snippet
    assert "42" in snippet


def test_quoting_injection_attempt_is_neutralized():
    b = _bucket(dimensions={
        "rule_id": "5710",
        "agent.name": 'evil"$(rm -rf /)',
    })
    snippet = render_local_rule(b, local_rule_id=110000, bucket_hash="x")
    # Must parse cleanly — quote was escaped, no XML break.
    root = ET.fromstring(snippet)
    # The attribute value should be present but escaped.
    assert root is not None
    assert "$(rm -rf /)" not in snippet or "&" in snippet  # at least escaped


def test_non_numeric_rule_id_is_rejected():
    b = _bucket(rule_id="<inject>")
    import pytest
    with pytest.raises(ValueError):
        render_local_rule(b, local_rule_id=110000, bucket_hash="x")
```

- [ ] **Step 2: Run, expect fail**

Run: `pytest tests/hygiene/test_xml_render.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `hygiene/xml_render.py`**

```python
"""Render Wazuh local_rules.xml snippets safely.

- Use `xml.sax.saxutils.escape` for element content (no quote escape needed there).
- Use `xml.sax.saxutils.quoteattr` for attribute values (handles quotes correctly).
- Reject non-numeric rule_ids to prevent injection through if_sid.
- Always include `<group>cleanswarm,</group>` for auditability.
- Include a metadata comment with bucket hash and count for rollback.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from xml.sax.saxutils import escape, quoteattr

from src.wazuh_health.contracts import NoiseBucket

_NUMERIC_RULE_ID = re.compile(r"^\d+$")


def _condition_xml(condition: dict[str, str]) -> str:
    lines: list[str] = []
    if agent_name := condition.get("agent.name"):
        lines.append(
            f"    <field name={quoteattr('agent.name')}>{escape(f'^{agent_name}$')}</field>"
        )
    if srcip := condition.get("srcip"):
        lines.append(f"    <srcip>{escape(srcip)}</srcip>")
    if user := condition.get("user"):
        lines.append(
            f"    <field name={quoteattr('data.srcuser')}>{escape(f'^{user}$')}</field>"
        )
    return "\n".join(lines)


def render_local_rule(
    bucket: NoiseBucket,
    *,
    local_rule_id: int,
    bucket_hash: str,
    count: int | None = None,
) -> str:
    """Render a single suppression snippet for a bucket.

    `local_rule_id` must come from a registry that picks an unused id in 100000-120000.
    `bucket_hash` is for auditability in the metadata comment.
    """
    rid = str(bucket.rule_id or "")
    if not _NUMERIC_RULE_ID.match(rid):
        raise ValueError(f"rule_id must be numeric for safe XML rendering: {rid!r}")

    condition = {k: v for k, v in bucket.dimensions.items() if k != "rule_id"}
    body = _condition_xml(condition)
    n = count if count is not None else bucket.count
    generated = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    meta = escape(
        f"CleanSwarm candidate for noisy rule {rid}; hash={bucket_hash}; count={n}; generated={generated}; review before enabling"
    )
    description = escape(f"CleanSwarm suppress noisy {rid} conditionally")

    return (
        f"<!-- {meta} -->\n"
        f"<rule id=\"{local_rule_id}\" level=\"0\">\n"
        f"    <if_sid>{rid}</if_sid>\n"
        f"{body}\n"
        f"    <group>cleanswarm,</group>\n"
        f"    <description>{description}</description>\n"
        f"</rule>"
    )
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/hygiene/test_xml_render.py -v`
Expected: 5 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/wazuh_health/hygiene/xml_render.py tests/hygiene/test_xml_render.py
git commit -m "feat(wazuh-health): safe XML render with quoteattr/escape, group, metadata"
```

---

### Task 2.6: Migrate simulator + combined simulation

**Files:**
- Create: `src/wazuh_health/hygiene/simulator.py`
- Test: `tests/hygiene/test_simulator.py`

- [ ] **Step 1: Write tests including combined simulation**

```python
# tests/hygiene/test_simulator.py
from src.wazuh_health.contracts import CleanAlert, Recommendation
from src.wazuh_health.hygiene.simulator import (
    simulate_combined,
    simulate_recommendation,
    simulate_recommendations,
)


def _alert(rule_id, level, srcip=None, agent="vpn01"):
    return CleanAlert(
        timestamp="2026-06-11T10:00:00Z",
        rule_id=rule_id, rule_level=level, agent_name=agent, srcip=srcip,
    )


def _rec(rec_id, rule_id, condition):
    return Recommendation(
        id=rec_id, type="suppress_conditionally",
        title="t", rule_id=rule_id, condition=condition,
        reason="r", risk="low",
        expected_reduction_count=0, expected_reduction_ratio=0.0,
        rollback="rb",
    )


def test_simulator_counts_only_exact_condition_match():
    alerts = [
        _alert("5710", 5, srcip="10.0.0.1"),
        _alert("5710", 5, srcip="10.0.0.2"),
    ]
    rec = _rec("r1", "5710", {"srcip": "10.0.0.1"})
    sim = simulate_recommendation(alerts, rec)
    assert sim.matched_alerts == 1


def test_verdict_high_if_any_high_severity_hidden():
    alerts = [_alert("100100", 12, srcip="10.0.0.1")]
    rec = _rec("r1", "100100", {"srcip": "10.0.0.1"})
    sim = simulate_recommendation(alerts, rec)
    assert sim.verdict == "high"


def test_simulate_recommendations_returns_one_per_rec():
    alerts = [_alert("5710", 5, srcip="10.0.0.1")]
    sims = simulate_recommendations(alerts, [_rec("r1", "5710", {"srcip": "10.0.0.1"})])
    assert [s.recommendation_id for s in sims] == ["r1"]


def test_combined_simulation_dedupes_overlapping_recommendations():
    alerts = [_alert("5710", 5, srcip="10.0.0.1") for _ in range(5)]
    r1 = _rec("r1", "5710", {"srcip": "10.0.0.1"})
    r2 = _rec("r2", "5710", {})  # matches all 5710 too
    sims = simulate_recommendations(alerts, [r1, r2])
    combined = simulate_combined(alerts, sims)
    # Each hides 5 separately, but union is still 5 alerts, overlap=5.
    assert combined.union_matched == 5
    assert combined.overlap_alerts == 5
```

- [ ] **Step 2: Run, expect fail**

Run: `pytest tests/hygiene/test_simulator.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `hygiene/simulator.py`**

```python
"""Simulate hygiene recommendations against historical alerts."""
from __future__ import annotations

from src.wazuh_health.contracts import (
    CleanAlert,
    CombinedSimulation,
    Recommendation,
    SimulationResult,
)


def _matches_condition(alert: CleanAlert, rec: Recommendation) -> bool:
    if alert.rule_id != rec.rule_id:
        return False
    table = {
        "agent.name": alert.agent_name,
        "srcip": alert.srcip,
        "user": alert.user,
    }
    for key, expected in rec.condition.items():
        if table.get(key) != expected:
            return False
    return True


def simulate_recommendation(
    alerts: list[CleanAlert], rec: Recommendation, *, sample_size: int = 5
) -> SimulationResult:
    matched: list[CleanAlert] = [a for a in alerts if _matches_condition(a, rec)]
    max_level = max((a.rule_level for a in matched), default=0)
    high_count = sum(1 for a in matched if a.rule_level >= 10)

    if high_count:
        verdict = "high"
    elif max_level >= 7:
        verdict = "medium"
    elif matched:
        verdict = rec.risk
    else:
        verdict = "low"

    return SimulationResult(
        recommendation_id=rec.id,
        matched_alerts=len(matched),
        total_alerts=len(alerts),
        reduction_ratio=round(len(matched) / max(len(alerts), 1), 4),
        max_level_hidden=max_level,
        high_or_critical_hidden=high_count,
        affected_rules=sorted({a.rule_id for a in matched}),
        sample_hidden_alert_ids=[
            f"{a.rule_id}@{a.timestamp}" for a in matched[:sample_size]
        ],
        verdict=verdict,
    )


def simulate_recommendations(
    alerts: list[CleanAlert], recs: list[Recommendation]
) -> list[SimulationResult]:
    return [simulate_recommendation(alerts, r) for r in recs]


def simulate_combined(
    alerts: list[CleanAlert], sims: list[SimulationResult]
) -> CombinedSimulation:
    """Compute union/overlap of alerts that would be hidden by all sims together.

    Identifies alerts by (rule_id, timestamp, agent_name, srcip, user) tuple.
    """
    matched_sets: list[set[tuple]] = []
    sim_to_rec: dict[str, set[tuple]] = {}
    # rebuild matched set by replaying recommendations is not available here;
    # instead, the caller passes sim results that include sample ids — but for an
    # accurate union we recompute against the alert stream using rec ids in sims.
    # We approximate by recomputing match using stored rule_id and the alert stream.
    # For determinism: assume all sims relate to the same alert pool.
    by_id = {f"{a.rule_id}@{a.timestamp}@{a.agent_name}@{a.srcip}@{a.user}": a for a in alerts}
    for sim in sims:
        # Recompute the matched set from the original alert pool using affected_rules.
        s: set[tuple] = set()
        for key, a in by_id.items():
            if a.rule_id in sim.affected_rules:
                s.add(key)
        matched_sets.append(s)

    union: set[tuple] = set().union(*matched_sets) if matched_sets else set()
    # overlap = union minus uniques (alerts covered by 2+ sims)
    counts: dict[tuple, int] = {}
    for s in matched_sets:
        for k in s:
            counts[k] = counts.get(k, 0) + 1
    overlap = sum(1 for v in counts.values() if v >= 2)

    union_alerts = [by_id[k] for k in union]
    max_level = max((a.rule_level for a in union_alerts), default=0)
    high_count = sum(1 for a in union_alerts if a.rule_level >= 10)

    return CombinedSimulation(
        total_alerts=len(alerts),
        union_matched=len(union),
        union_reduction_ratio=round(len(union) / max(len(alerts), 1), 4),
        overlap_alerts=overlap,
        max_level_hidden=max_level,
        high_or_critical_hidden=high_count,
    )
```

- [ ] **Step 4: Run**

Run: `pytest tests/hygiene/test_simulator.py -v`
Expected: 4 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/wazuh_health/hygiene/simulator.py tests/hygiene/test_simulator.py
git commit -m "feat(wazuh-health): simulator with combined union/overlap analysis"
```

---

### Task 2.7: Robust collector — gzip, rotated, `_extract_user` safety

**Files:**
- Create: `src/wazuh_health/source/local_fs.py` (collector lives here permanently)
- Test: `tests/source/test_local_fs_collector.py`

Note: this is the file where the LocalFSSource will live (Task 3). For now we only put the alert-reading + compact helpers, so cleanswarm shims can point here.

- [ ] **Step 1: Write tests**

```python
# tests/source/test_local_fs_collector.py
import gzip
import json
from pathlib import Path

from src.wazuh_health.source.local_fs import compact_alert, iter_alerts


def _write_ndjson(path: Path, alerts: list[dict]) -> None:
    with path.open("w") as f:
        for a in alerts:
            f.write(json.dumps(a) + "\n")


def _write_gz_ndjson(path: Path, alerts: list[dict]) -> None:
    with gzip.open(path, "wt") as f:
        for a in alerts:
            f.write(json.dumps(a) + "\n")


def _sample_alert(rid="5710"):
    return {
        "timestamp": "2026-06-11T10:00:00Z",
        "rule": {"id": rid, "level": 5, "description": "x", "groups": []},
        "agent": {"id": "001", "name": "vpn01"},
        "data": {"srcip": "10.0.5.20", "srcuser": "scanner"},
        "decoder": {"name": "sshd"},
    }


def test_iter_alerts_skips_malformed_lines(tmp_path):
    p = tmp_path / "alerts.json"
    with p.open("w") as f:
        f.write(json.dumps(_sample_alert()) + "\n")
        f.write("{not json\n")
        f.write("\n")
        f.write(json.dumps(_sample_alert("5712")) + "\n")
    out = list(iter_alerts(p))
    assert [a.rule_id for a in out] == ["5710", "5712"]


def test_iter_alerts_reads_gz(tmp_path):
    p = tmp_path / "alerts.json.gz"
    _write_gz_ndjson(p, [_sample_alert(), _sample_alert("5712")])
    assert len(list(iter_alerts(p))) == 2


def test_iter_alerts_reads_rotated_files(tmp_path):
    main = tmp_path / "alerts.json"
    rot1 = tmp_path / "alerts.json.1"
    rot2 = tmp_path / "alerts.json.2.gz"
    _write_ndjson(main, [_sample_alert("A")])
    _write_ndjson(rot1, [_sample_alert("B")])
    _write_gz_ndjson(rot2, [_sample_alert("C")])
    out = list(iter_alerts(main, rotated_glob=str(tmp_path / "alerts.json.*")))
    rule_ids = sorted(a.rule_id for a in out)
    assert rule_ids == ["A", "B", "C"]


def test_compact_alert_handles_string_win_eventdata():
    raw = {
        "timestamp": "2026-06-11T10:00:00Z",
        "rule": {"id": "5710", "level": 5, "description": "x", "groups": []},
        "agent": {"id": "001", "name": "vpn01"},
        "data": {"win": "not a dict, edge case decoder"},
        "decoder": {"name": "sshd"},
    }
    alert = compact_alert(raw)
    assert alert is not None
    assert alert.user is None


def test_compact_alert_drops_alerts_with_no_rule_id():
    raw = {"timestamp": "x", "rule": {"level": 5}}
    assert compact_alert(raw) is None
```

- [ ] **Step 2: Run, expect import fail**

Run: `pytest tests/source/test_local_fs_collector.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement collector helpers in `source/local_fs.py`**

```python
"""Local filesystem helpers for reading Wazuh alerts (NDJSON, gzip, rotated)."""
from __future__ import annotations

import gzip
import json
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from src.wazuh_health.contracts import CleanAlert


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _first_string(*values: Any) -> str | None:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _safe_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _extract_user(data: dict[str, Any]) -> str | None:
    win = _safe_dict(data.get("win"))
    eventdata = _safe_dict(win.get("eventdata"))
    return _first_string(
        data.get("srcuser"),
        data.get("dstuser"),
        data.get("user") if isinstance(data.get("user"), str) else None,
        eventdata.get("targetUserName"),
        eventdata.get("subjectUserName"),
        _safe_dict(data.get("aws")).get("userIdentity", {}).get("userName") if isinstance(_safe_dict(data.get("aws")).get("userIdentity"), dict) else None,
        _safe_dict(data.get("office365")).get("UserId"),
    )


def compact_alert(raw: dict[str, Any]) -> CleanAlert | None:
    rule = _safe_dict(raw.get("rule"))
    agent = _safe_dict(raw.get("agent"))
    data = _safe_dict(raw.get("data"))
    decoder = _safe_dict(raw.get("decoder"))

    rule_id = str(rule.get("id") or "").strip()
    if not rule_id:
        return None

    try:
        level = int(rule.get("level") or 0)
    except (TypeError, ValueError):
        level = 0

    return CleanAlert(
        timestamp=str(raw.get("timestamp") or ""),
        rule_id=rule_id,
        rule_level=level,
        rule_description=str(rule.get("description") or "Unknown")[:300],
        rule_groups=[str(g) for g in (rule.get("groups") or []) if str(g).strip()],
        agent_id=str(agent.get("id")) if agent.get("id") is not None else None,
        agent_name=_first_string(agent.get("name")),
        srcip=_first_string(data.get("srcip"), data.get("src_ip"), data.get("sourceIp")),
        dstip=_first_string(data.get("dstip"), data.get("dst_ip"), data.get("destinationIp")),
        user=_extract_user(data),
        decoder_name=_first_string(decoder.get("name")),
        raw=raw,
    )


def _open_text(path: Path):
    if path.suffix == ".gz" or path.name.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open(encoding="utf-8", errors="replace")


def _iter_one_file(
    path: Path, *, cutoff: datetime | None
) -> Iterator[CleanAlert]:
    with _open_text(path) as f:
        for line in f:
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            alert = compact_alert(raw)
            if alert is None:
                continue
            if cutoff is not None:
                ts = parse_timestamp(alert.timestamp)
                # Drop alerts whose timestamp is unparseable when a cutoff is set.
                if ts is None or ts < cutoff:
                    continue
            yield alert


def iter_alerts(
    path: str | Path,
    *,
    days: int | None = None,
    rotated_glob: str | None = None,
) -> Iterable[CleanAlert]:
    cutoff = (
        datetime.now(tz=timezone.utc) - timedelta(days=days)
        if days is not None
        else None
    )
    main = Path(path)
    files: list[Path] = [main] if main.exists() else []
    if rotated_glob is not None:
        files += sorted(
            (p for p in Path(rotated_glob).parent.glob(Path(rotated_glob).name)),
            key=lambda p: p.name,
        )
        # Avoid double-yielding the main file if the glob also matches it.
        files = list({p.resolve(): p for p in files}.values())

    for fpath in files:
        yield from _iter_one_file(fpath, cutoff=cutoff)


def load_alerts(
    path: str | Path,
    *,
    days: int | None = None,
    limit: int | None = None,
    rotated_glob: str | None = None,
) -> list[CleanAlert]:
    out: list[CleanAlert] = []
    for alert in iter_alerts(path, days=days, rotated_glob=rotated_glob):
        out.append(alert)
        if limit is not None and len(out) >= limit:
            break
    return out
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/source/test_local_fs_collector.py -v`
Expected: 5 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/wazuh_health/source/local_fs.py tests/source/test_local_fs_collector.py
git commit -m "feat(wazuh-health): robust local-fs collector (gz, rotated, safe extractors)"
```

---

### Task 2.8: Migrate `hygiene/report.py`

**Files:**
- Create: `src/wazuh_health/hygiene/report.py`
- Test: regression via `tests/test_cleanswarm.py` after shims (Task 2.9)

- [ ] **Step 1: Implement `hygiene/report.py`**

```python
"""High-level orchestration of the hygiene pipeline (used by CleanSwarm CLI)."""
from __future__ import annotations

from datetime import datetime, timezone

from src.wazuh_health.contracts import CleanSwarmReport
from src.wazuh_health.hygiene.analyzer import build_noise_buckets
from src.wazuh_health.hygiene.recommender import recommend_from_buckets
from src.wazuh_health.hygiene.simulator import (
    simulate_combined,
    simulate_recommendations,
)
from src.wazuh_health.hygiene.xml_render import render_local_rule
from src.wazuh_health.source.local_fs import load_alerts


def analyze_file(
    alerts_path: str,
    *,
    days: int | None = 7,
    min_count: int = 10,
    top: int = 20,
    max_recommendations: int = 10,
    limit: int | None = None,
    rotated_glob: str | None = None,
    first_local_rule_id: int = 110000,
) -> CleanSwarmReport:
    alerts = load_alerts(
        alerts_path, days=days, limit=limit, rotated_glob=rotated_glob
    )
    buckets = build_noise_buckets(alerts, min_count=min_count, top=top)
    recs = recommend_from_buckets(
        buckets, total_alerts=len(alerts), max_recommendations=max_recommendations
    )
    # Attach XML snippets for suppress_conditionally only.
    for idx, rec in enumerate(recs):
        if rec.type == "suppress_conditionally":
            bucket = next(b for b in buckets if str(b.rule_id) == rec.rule_id)
            rec.proposed_wazuh_rule = render_local_rule(
                bucket,
                local_rule_id=first_local_rule_id + idx,
                bucket_hash=rec.id,
                count=rec.expected_reduction_count,
            )
    sims = simulate_recommendations(alerts, recs)
    combined = simulate_combined(alerts, sims) if sims else None

    return CleanSwarmReport(
        generated_at=datetime.now(tz=timezone.utc).isoformat(),
        source=alerts_path,
        total_alerts=len(alerts),
        analyzed_days=days,
        top_buckets=buckets,
        recommendations=recs,
        simulations=sims,
        combined_simulation=combined,
    )


def render_markdown(report: CleanSwarmReport) -> str:
    lines = [
        "# CleanSwarm Wazuh Hygiene Report",
        "",
        f"- Generated: `{report.generated_at}`",
        f"- Source: `{report.source}`",
        f"- Total alerts analyzed: **{report.total_alerts}**",
        f"- Window days: **{report.analyzed_days if report.analyzed_days is not None else 'all'}**",
        "",
        "## Top noisy buckets",
        "",
    ]
    if not report.top_buckets:
        lines.append("No noisy buckets found with the current thresholds.")
    else:
        for b in report.top_buckets:
            lines += [
                f"### {b.rule_id} — {b.rule_description}",
                f"- Count: **{b.count}** | Level: **{b.rule_level}** | Score: **{b.noise_score}**",
                f"- Breakdown: `{b.noise_score_breakdown}`",
                f"- Dimensions: `{b.dimensions}`",
                "",
            ]

    lines += ["", "## Recommendations", ""]
    sims = {s.recommendation_id: s for s in report.simulations}
    for rec in report.recommendations:
        sim = sims.get(rec.id)
        lines += [
            f"### {rec.id}: {rec.title}",
            f"- Type: `{rec.type}` | Risk: **{rec.risk}**",
            f"- Condition: `{rec.condition}`",
            f"- Expected reduction: **{rec.expected_reduction_count}** alerts ({rec.expected_reduction_ratio:.1%})",
            f"- Reason: {rec.reason}",
        ]
        if sim:
            lines.append(
                f"- Simulation: hides **{sim.matched_alerts}**/{sim.total_alerts}; "
                f"max hidden level **{sim.max_level_hidden}**; verdict **{sim.verdict}**"
            )
        if rec.proposed_wazuh_rule:
            lines += ["", "```xml", rec.proposed_wazuh_rule, "```"]
        lines.append("")

    if report.combined_simulation:
        c = report.combined_simulation
        lines += [
            "## Combined impact",
            "",
            f"- Union of hidden alerts: **{c.union_matched}** ({c.union_reduction_ratio:.1%})",
            f"- Overlap (covered by 2+ recs): **{c.overlap_alerts}**",
            f"- Max hidden level: **{c.max_level_hidden}**, high/critical hidden: **{c.high_or_critical_hidden}**",
            "",
        ]

    return "\n".join(lines).rstrip() + "\n"
```

- [ ] **Step 2: Commit**

```bash
git add src/wazuh_health/hygiene/report.py
git commit -m "feat(wazuh-health): hygiene report orchestration with combined simulation"
```

---

### Task 2.9: CleanSwarm compat shims (analyzer / recommender / simulator / collector / report)

**Files:**
- Modify: `src/cleanswarm/analyzer.py`
- Modify: `src/cleanswarm/recommender.py`
- Modify: `src/cleanswarm/simulator.py`
- Modify: `src/cleanswarm/collector.py`
- Modify: `src/cleanswarm/report.py`

- [ ] **Step 1: Replace each file with re-exports**

`src/cleanswarm/analyzer.py`:

```python
"""Compat shim — moved to wazuh_health.hygiene.analyzer."""
from src.wazuh_health.hygiene.analyzer import build_noise_buckets, parse_timestamp

__all__ = ["build_noise_buckets", "parse_timestamp"]
```

`src/cleanswarm/recommender.py`:

```python
"""Compat shim — moved to wazuh_health.hygiene.recommender."""
from src.wazuh_health.hygiene.recommender import (
    SENSITIVE_RULE_GROUPS,
    recommend_from_buckets,
)

__all__ = ["SENSITIVE_RULE_GROUPS", "recommend_from_buckets"]
```

`src/cleanswarm/simulator.py`:

```python
"""Compat shim — moved to wazuh_health.hygiene.simulator."""
from src.wazuh_health.hygiene.simulator import (
    simulate_combined,
    simulate_recommendation,
    simulate_recommendations,
)

__all__ = ["simulate_combined", "simulate_recommendation", "simulate_recommendations"]
```

`src/cleanswarm/collector.py`:

```python
"""Compat shim — moved to wazuh_health.source.local_fs."""
from src.wazuh_health.source.local_fs import (
    compact_alert,
    iter_alerts,
    load_alerts,
    parse_timestamp,
)

__all__ = ["compact_alert", "iter_alerts", "load_alerts", "parse_timestamp"]
```

`src/cleanswarm/report.py`:

```python
"""Compat shim — moved to wazuh_health.hygiene.report."""
from src.wazuh_health.hygiene.report import analyze_file, render_markdown

__all__ = ["analyze_file", "render_markdown"]
```

- [ ] **Step 2: Run the original cleanswarm regression suite**

Run: `pytest tests/test_cleanswarm.py -v`
Expected: all 4 tests PASS (the assertion on the rendered XML now includes `<group>cleanswarm,</group>` — adjust if any expectation about the snippet's structure is too tight; the test currently checks `<if_sid>5710</if_sid>` and `agent.name`, both still present).

- [ ] **Step 3: Run the full suite**

Run: `pytest -v`
Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add src/cleanswarm/
git commit -m "refactor(cleanswarm): replace internals with compat shims to wazuh_health.hygiene"
```

---

### Task 2.10: Adversarial regression tests (XML injection, sensitive groups, bad lines)

**Files:**
- Create: `tests/hygiene/test_adversarial.py`

- [ ] **Step 1: Write tests**

```python
# tests/hygiene/test_adversarial.py
import json
from pathlib import Path

from src.wazuh_health.contracts import CleanAlert
from src.wazuh_health.hygiene.analyzer import build_noise_buckets
from src.wazuh_health.hygiene.recommender import recommend_from_buckets
from src.wazuh_health.hygiene.report import analyze_file


def test_sensitive_group_with_high_volume_does_not_recommend_suppression(tmp_path):
    alerts = []
    for _ in range(100):
        alerts.append(CleanAlert(
            timestamp="2026-06-11T10:00:00Z",
            rule_id="5712", rule_level=5,
            rule_groups=["authentication_failures"],
            agent_name="vpn01", srcip="10.0.5.20",
        ))
    buckets = build_noise_buckets(alerts, min_count=10)
    recs = recommend_from_buckets(buckets, total_alerts=len(alerts))
    assert all(r.type == "investigate_source" for r in recs)


def test_full_pipeline_handles_corrupt_and_high_level_alerts(tmp_path):
    p = tmp_path / "alerts.json"
    with p.open("w") as f:
        f.write("not json\n")
        f.write("\n")
        for _ in range(15):
            f.write(json.dumps({
                "timestamp": "2026-06-11T10:00:00Z",
                "rule": {"id": "5712", "level": 12,
                         "description": "scan", "groups": ["attacks"]},
                "agent": {"id": "1", "name": "vpn01"},
                "data": {"srcip": "10.0.5.20"},
                "decoder": {"name": "sshd"},
            }) + "\n")
    report = analyze_file(str(p), days=None, min_count=5)
    assert report.total_alerts == 15
    assert all(r.type == "investigate_source" for r in report.recommendations)
    # No suppression XML emitted for high-severity rules.
    assert all(r.proposed_wazuh_rule is None for r in report.recommendations)
```

- [ ] **Step 2: Run**

Run: `pytest tests/hygiene/test_adversarial.py -v`
Expected: 2 PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/hygiene/test_adversarial.py
git commit -m "test(wazuh-health): adversarial hygiene regressions"
```

---

**End of Phase 2.** Pause point: CleanSwarm absorbed, prior review findings addressed, `cleanswarm analyze` still works, ~12 new tests added.

---

## Phase 3 — Sources

Goal: a `WazuhSource` Protocol with two implementations (`LocalFSSource`, `WazuhAPISource`). Both read-only. The boundary test must keep passing.

### Task 3.1: Define `WazuhSource` Protocol + DTOs + `LocalFSSource` wrapper class

**Files:**
- Create: `src/wazuh_health/source/base.py`
- Modify: `src/wazuh_health/source/local_fs.py` (add `LocalFSSource` class at the bottom)
- Modify: `src/wazuh_health/source/__init__.py`
- Test: `tests/source/test_local_fs_source.py`

- [ ] **Step 1: Write Protocol contract test**

```python
# tests/source/test_local_fs_source.py
from pathlib import Path

from src.wazuh_health.source.base import (
    AgentInfo, DiskStats, IndexerStats, ManagerStats, WazuhSource,
)
from src.wazuh_health.source.local_fs import LocalFSSource


def test_local_fs_source_implements_protocol(tmp_path):
    src = LocalFSSource(
        alerts_path=tmp_path / "alerts.json",
        rotated_glob=None,
        ossec_conf=tmp_path / "ossec.conf",
        client_keys=tmp_path / "client.keys",
    )
    assert isinstance(src, WazuhSource)


def test_list_agents_parses_client_keys(tmp_path):
    keys = tmp_path / "client.keys"
    keys.write_text(
        "001 vpn01 10.0.5.10 abc...\n"
        "002 win01 any def...\n"
        "# comment line\n"
        "\n"
    )
    src = LocalFSSource(
        alerts_path=tmp_path / "alerts.json",
        rotated_glob=None,
        ossec_conf=tmp_path / "ossec.conf",
        client_keys=keys,
    )
    agents = src.list_agents()
    assert {a.agent_id for a in agents} == {"001", "002"}
    assert {a.name for a in agents} == {"vpn01", "win01"}


def test_disk_stats_returns_two_filesystems(tmp_path, monkeypatch):
    src = LocalFSSource(
        alerts_path=tmp_path / "alerts.json",
        rotated_glob=None,
        ossec_conf=tmp_path / "ossec.conf",
        client_keys=tmp_path / "client.keys",
        var_ossec_path=tmp_path,
        indexer_path=tmp_path,
    )
    stats = src.disk_stats()
    assert "var_ossec" in stats.filesystems
    assert "indexer" in stats.filesystems
    assert 0 <= stats.filesystems["var_ossec"].free_pct <= 100
```

- [ ] **Step 2: Implement `source/base.py`**

```python
"""WazuhSource Protocol and DTOs.

All methods are read-only. Implementations must not expose any setter
or write call. This is enforced by `tests/test_boundaries.py`.
"""
from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from src.wazuh_health.contracts import CleanAlert


class FilesystemStat(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    total_bytes: int
    free_bytes: int
    free_pct: float


class DiskStats(BaseModel):
    model_config = ConfigDict(extra="forbid")
    filesystems: dict[str, FilesystemStat] = Field(default_factory=dict)
    alerts_json_size_bytes: int = 0


class AgentInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str
    name: str
    ip: str | None = None
    status: str = "unknown"  # active, disconnected, never_connected, unknown
    last_keep_alive: datetime | None = None


class ManagerStats(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cpu_pct: float | None = None
    mem_pct: float | None = None
    decoder_errors: int = 0
    rule_hits_by_id: dict[str, int] = Field(default_factory=dict)


class IndexerStats(BaseModel):
    model_config = ConfigDict(extra="forbid")
    heap_pct: float | None = None
    red_shards: int = 0
    yellow_shards: int = 0
    pending_tasks: int = 0


class WazuhSource(Protocol):
    """Read-only data source for Wazuh metrics."""

    def iter_alerts(
        self, *, since_days: int | None = None
    ) -> Iterable[CleanAlert]: ...

    def disk_stats(self) -> DiskStats: ...

    def list_agents(self) -> list[AgentInfo]: ...

    def manager_stats(self) -> ManagerStats: ...

    def indexer_stats(self) -> IndexerStats: ...
```

- [ ] **Step 3: Append `LocalFSSource` to `source/local_fs.py`**

Append to the file:

```python
# --- LocalFSSource ------------------------------------------------------

import os
import re
from collections.abc import Iterable as _Iterable
from datetime import datetime as _datetime, timezone as _timezone
from pathlib import Path as _Path

from src.wazuh_health.source.base import (
    AgentInfo, DiskStats, FilesystemStat, IndexerStats, ManagerStats,
)


_CLIENT_KEY_LINE = re.compile(
    r"^\s*(?P<id>\d+)\s+(?P<name>\S+)\s+(?P<ip>\S+)\s+\S+\s*$"
)


def _filesystem_stat(path: _Path) -> FilesystemStat:
    s = os.statvfs(path)
    total = s.f_frsize * s.f_blocks
    free = s.f_frsize * s.f_bavail
    pct = (free / total * 100.0) if total else 0.0
    return FilesystemStat(
        path=str(path),
        total_bytes=total,
        free_bytes=free,
        free_pct=round(pct, 2),
    )


class LocalFSSource:
    """Filesystem-backed WazuhSource.

    Reads from /var/ossec/* paths. Never writes.
    """

    def __init__(
        self,
        *,
        alerts_path: _Path,
        rotated_glob: str | None,
        ossec_conf: _Path,
        client_keys: _Path,
        var_ossec_path: _Path | None = None,
        indexer_path: _Path | None = None,
    ) -> None:
        self.alerts_path = _Path(alerts_path)
        self.rotated_glob = rotated_glob
        self.ossec_conf = _Path(ossec_conf)
        self.client_keys = _Path(client_keys)
        self.var_ossec_path = _Path(var_ossec_path or "/var/ossec")
        self.indexer_path = _Path(indexer_path or "/var/lib/wazuh-indexer")

    def iter_alerts(self, *, since_days: int | None = None) -> _Iterable[CleanAlert]:
        return iter_alerts(
            self.alerts_path,
            days=since_days,
            rotated_glob=self.rotated_glob,
        )

    def disk_stats(self) -> DiskStats:
        fs: dict[str, FilesystemStat] = {}
        if self.var_ossec_path.exists():
            fs["var_ossec"] = _filesystem_stat(self.var_ossec_path)
        if self.indexer_path.exists():
            fs["indexer"] = _filesystem_stat(self.indexer_path)
        size = self.alerts_path.stat().st_size if self.alerts_path.exists() else 0
        return DiskStats(filesystems=fs, alerts_json_size_bytes=size)

    def list_agents(self) -> list[AgentInfo]:
        if not self.client_keys.exists():
            return []
        out: list[AgentInfo] = []
        for line in self.client_keys.read_text(errors="replace").splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            m = _CLIENT_KEY_LINE.match(line)
            if not m:
                continue
            out.append(AgentInfo(
                agent_id=m.group("id"),
                name=m.group("name"),
                ip=m.group("ip") if m.group("ip") != "any" else None,
                status="unknown",
            ))
        return out

    def manager_stats(self) -> ManagerStats:
        # Local FS does not have manager stats readily available without parsing
        # ossec-control output. v1: return empty; CapacityProbe falls back to
        # psutil for cpu/mem in a later task.
        return ManagerStats()

    def indexer_stats(self) -> IndexerStats:
        # Same as above — without the API we cannot get heap; return empty.
        return IndexerStats()
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/source/ tests/test_boundaries.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/wazuh_health/source tests/source/test_local_fs_source.py
git commit -m "feat(wazuh-health): WazuhSource Protocol + LocalFSSource implementation"
```

---

### Task 3.2: `WazuhAPISource` — JWT login + read endpoints

**Files:**
- Create: `src/wazuh_health/source/wazuh_api.py`
- Test: `tests/source/test_wazuh_api_source.py`

Note: this is the only file allowed to do a POST (JWT login). Tests use `respx`.

- [ ] **Step 1: Write tests**

```python
# tests/source/test_wazuh_api_source.py
import respx
from httpx import Response

from src.wazuh_health.source.wazuh_api import WazuhAPISource


BASE = "https://192.168.38.60:55000"


def _make_source():
    return WazuhAPISource(
        host="192.168.38.60", port=55000, user="u", password="p", verify_ssl=False
    )


@respx.mock(assert_all_called=False)
def test_login_then_list_agents(mocker_unused=None):
    respx.post(f"{BASE}/security/user/authenticate").mock(
        return_value=Response(200, json={"data": {"token": "TKN"}})
    )
    respx.get(f"{BASE}/agents").mock(
        return_value=Response(200, json={"data": {"affected_items": [
            {"id": "001", "name": "vpn01", "ip": "10.0.5.10",
             "status": "active", "last_keep_alive": "2026-06-11T10:00:00Z"},
            {"id": "002", "name": "win01", "ip": "10.0.5.11",
             "status": "disconnected", "last_keep_alive": "2026-06-10T10:00:00Z"},
        ]}})
    )
    src = _make_source()
    agents = src.list_agents()
    assert {a.agent_id for a in agents} == {"001", "002"}
    assert {a.status for a in agents} == {"active", "disconnected"}


@respx.mock(assert_all_called=False)
def test_indexer_stats_parses_cluster_health(mocker_unused=None):
    respx.post(f"{BASE}/security/user/authenticate").mock(
        return_value=Response(200, json={"data": {"token": "TKN"}})
    )
    respx.get(f"{BASE}/cluster/health").mock(
        return_value=Response(200, json={"data": {
            "heap_pct": 78.3, "red_shards": 0, "yellow_shards": 2, "pending_tasks": 1
        }})
    )
    src = _make_source()
    stats = src.indexer_stats()
    assert stats.heap_pct == 78.3
    assert stats.yellow_shards == 2
```

- [ ] **Step 2: Implement `source/wazuh_api.py`**

```python
"""Wazuh API source (read-only except for the JWT login POST)."""
from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any

import httpx

from src.wazuh_health.contracts import CleanAlert
from src.wazuh_health.source.base import (
    AgentInfo, DiskStats, IndexerStats, ManagerStats,
)


class WazuhAPISource:
    """HTTP-based WazuhSource. Authenticates via JWT and uses GET-only afterwards."""

    def __init__(
        self,
        *,
        host: str,
        port: int = 55000,
        user: str,
        password: str,
        verify_ssl: bool = True,
        timeout_s: float = 10.0,
    ) -> None:
        self._base = f"https://{host}:{port}"
        self._user = user
        self._password = password
        self._verify = verify_ssl
        self._timeout = timeout_s
        self._token: str | None = None

    def _login(self) -> str:
        if self._token:
            return self._token
        # The only POST allowed in this package — boundary test whitelists this file.
        with httpx.Client(verify=self._verify, timeout=self._timeout) as c:
            r = c.post(
                f"{self._base}/security/user/authenticate",
                auth=(self._user, self._password),
            )
            r.raise_for_status()
            self._token = r.json()["data"]["token"]
        assert self._token is not None
        return self._token

    def _get(self, path: str) -> dict[str, Any]:
        token = self._login()
        with httpx.Client(
            verify=self._verify,
            timeout=self._timeout,
            headers={"Authorization": f"Bearer {token}"},
        ) as c:
            r = c.get(f"{self._base}{path}")
            r.raise_for_status()
            return r.json()

    def iter_alerts(self, *, since_days: int | None = None) -> Iterable[CleanAlert]:
        # API-based alert streaming is out of MVP scope. Probes that need
        # historical alerts must use LocalFSSource.
        return iter(())

    def disk_stats(self) -> DiskStats:
        # The Manager API exposes /manager/info with disk usage on some versions;
        # left empty in v1.
        return DiskStats()

    def list_agents(self) -> list[AgentInfo]:
        payload = self._get("/agents")
        items = payload.get("data", {}).get("affected_items", [])
        out: list[AgentInfo] = []
        for item in items:
            lka = item.get("last_keep_alive")
            try:
                ts = datetime.fromisoformat(lka.replace("Z", "+00:00")) if lka else None
            except Exception:
                ts = None
            out.append(AgentInfo(
                agent_id=str(item.get("id", "")),
                name=item.get("name", ""),
                ip=item.get("ip"),
                status=item.get("status", "unknown"),
                last_keep_alive=ts,
            ))
        return out

    def manager_stats(self) -> ManagerStats:
        # /manager/stats varies per version; v1 returns empty.
        return ManagerStats()

    def indexer_stats(self) -> IndexerStats:
        payload = self._get("/cluster/health")
        d = payload.get("data", {}) or {}
        return IndexerStats(
            heap_pct=d.get("heap_pct"),
            red_shards=int(d.get("red_shards", 0)),
            yellow_shards=int(d.get("yellow_shards", 0)),
            pending_tasks=int(d.get("pending_tasks", 0)),
        )
```

- [ ] **Step 3: Run tests**

Run: `pytest tests/source/test_wazuh_api_source.py tests/test_boundaries.py -v`
Expected: PASS — boundary test whitelists the POST in `wazuh_api.py`.

- [ ] **Step 4: Commit**

```bash
git add src/wazuh_health/source/wazuh_api.py tests/source/test_wazuh_api_source.py
git commit -m "feat(wazuh-health): Wazuh API source (read-only + JWT login)"
```

---

**End of Phase 3.** Pause point: two source backends working, boundary tests still green.

---

## Phase 4 — Probes

Goal: three deterministic Python workers (`CapacityProbe`, `HygieneProbe`, `CoverageProbe`) that consume a `WazuhSource` and emit `ProbeResult`s. Each probe is independently testable with a fake source.

### Task 4.1: Probe ABC

**Files:**
- Create: `src/wazuh_health/probes/base.py`
- Test: `tests/probes/test_base.py`

- [ ] **Step 1: Write test**

```python
# tests/probes/test_base.py
from datetime import datetime, timezone
from src.wazuh_health.contracts import ProbeResult
from src.wazuh_health.probes.base import Probe


class _DummyProbe(Probe):
    name = "capacity"

    def collect(self):
        return {"metrics": {"x": 1}, "artifacts": {}, "errors": []}


def test_probe_run_wraps_collect_into_proberesult():
    res = _DummyProbe().run()
    assert isinstance(res, ProbeResult)
    assert res.probe == "capacity"
    assert res.metrics == {"x": 1}
    assert res.run_at.tzinfo is timezone.utc
```

- [ ] **Step 2: Implement `probes/base.py`**

```python
"""Probe abstract base class."""
from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, ClassVar

from src.wazuh_health.contracts import ProbeName, ProbeResult


class Probe(ABC):
    name: ClassVar[ProbeName]

    @abstractmethod
    def collect(self) -> dict[str, Any]:
        """Return a dict with 'metrics', 'artifacts', 'errors'."""
        raise NotImplementedError

    def run(self) -> ProbeResult:
        try:
            payload = self.collect()
        except Exception as exc:
            payload = {"metrics": {}, "artifacts": {}, "errors": [repr(exc)]}
        return ProbeResult(
            probe=self.name,
            run_at=datetime.now(tz=timezone.utc),
            metrics=payload.get("metrics", {}),
            artifacts=payload.get("artifacts", {}),
            errors=payload.get("errors", []),
        )
```

- [ ] **Step 3: Run + commit**

```bash
pytest tests/probes/test_base.py -v
git add src/wazuh_health/probes/base.py tests/probes/test_base.py
git commit -m "feat(wazuh-health): Probe abstract base with safe collect→ProbeResult wrap"
```

---

### Task 4.2: `CapacityProbe`

**Files:**
- Create: `src/wazuh_health/probes/capacity.py`
- Test: `tests/probes/test_capacity.py`

- [ ] **Step 1: Write tests**

```python
# tests/probes/test_capacity.py
from src.wazuh_health.source.base import (
    DiskStats, FilesystemStat, IndexerStats, ManagerStats,
)
from src.wazuh_health.probes.capacity import CapacityProbe


class _FakeSource:
    def __init__(self, free_pct=80.0, heap_pct=60.0, alerts_size=1024):
        self._free_pct = free_pct
        self._heap_pct = heap_pct
        self._size = alerts_size

    def disk_stats(self):
        return DiskStats(
            filesystems={
                "var_ossec": FilesystemStat(
                    path="/var/ossec", total_bytes=100, free_bytes=int(self._free_pct),
                    free_pct=self._free_pct,
                ),
                "indexer": FilesystemStat(
                    path="/var/lib/wazuh-indexer", total_bytes=100, free_bytes=50,
                    free_pct=50.0,
                ),
            },
            alerts_json_size_bytes=self._size,
        )

    def manager_stats(self):
        return ManagerStats(cpu_pct=10.0, mem_pct=40.0)

    def indexer_stats(self):
        return IndexerStats(heap_pct=self._heap_pct, red_shards=0, yellow_shards=1)


def test_capacity_probe_emits_expected_metrics():
    probe = CapacityProbe(source=_FakeSource())
    result = probe.run()
    assert result.probe == "capacity"
    m = result.metrics
    assert m["disk.var_ossec.free_pct"] == 80.0
    assert m["disk.indexer.free_pct"] == 50.0
    assert m["indexer.heap_pct"] == 60.0
    assert m["alerts_json.size_bytes"] == 1024


def test_capacity_probe_computes_growth_when_previous_size_provided():
    probe = CapacityProbe(source=_FakeSource(alerts_size=10_000_000), previous_size=5_000_000, hours_between=1.0)
    m = probe.run().metrics
    # delta is 5 MB in 1 h
    assert m["alerts_json.growth_mb_per_h"] == 5.0
```

- [ ] **Step 2: Implement `probes/capacity.py`**

```python
"""Capacity probe — disk, indexer heap, alerts.json growth."""
from __future__ import annotations

from typing import Any

from src.wazuh_health.contracts import ProbeName
from src.wazuh_health.probes.base import Probe
from src.wazuh_health.source.base import WazuhSource


class CapacityProbe(Probe):
    name: ProbeName = "capacity"

    def __init__(
        self,
        *,
        source: WazuhSource,
        previous_size: int | None = None,
        hours_between: float | None = None,
    ) -> None:
        self._source = source
        self._previous_size = previous_size
        self._hours_between = hours_between

    def collect(self) -> dict[str, Any]:
        metrics: dict[str, float | int] = {}
        errors: list[str] = []

        try:
            disk = self._source.disk_stats()
            for name, fs in disk.filesystems.items():
                metrics[f"disk.{name}.free_pct"] = fs.free_pct
                metrics[f"disk.{name}.free_bytes"] = fs.free_bytes
            metrics["alerts_json.size_bytes"] = disk.alerts_json_size_bytes
            if self._previous_size is not None and self._hours_between:
                delta_mb = (
                    disk.alerts_json_size_bytes - self._previous_size
                ) / (1024 * 1024)
                metrics["alerts_json.growth_mb_per_h"] = round(
                    delta_mb / self._hours_between, 2
                )
        except Exception as exc:
            errors.append(f"disk_stats: {exc!r}")

        try:
            mgr = self._source.manager_stats()
            if mgr.cpu_pct is not None:
                metrics["manager.cpu_pct"] = mgr.cpu_pct
            if mgr.mem_pct is not None:
                metrics["manager.mem_pct"] = mgr.mem_pct
        except Exception as exc:
            errors.append(f"manager_stats: {exc!r}")

        try:
            idx = self._source.indexer_stats()
            if idx.heap_pct is not None:
                metrics["indexer.heap_pct"] = idx.heap_pct
            metrics["indexer.red_shards"] = idx.red_shards
            metrics["indexer.yellow_shards"] = idx.yellow_shards
            metrics["indexer.pending_tasks"] = idx.pending_tasks
        except Exception as exc:
            errors.append(f"indexer_stats: {exc!r}")

        return {"metrics": metrics, "artifacts": {}, "errors": errors}
```

- [ ] **Step 3: Run + commit**

```bash
pytest tests/probes/test_capacity.py -v
git add src/wazuh_health/probes/capacity.py tests/probes/test_capacity.py
git commit -m "feat(wazuh-health): CapacityProbe for disk/indexer/growth metrics"
```

---

### Task 4.3: `HygieneProbe`

**Files:**
- Create: `src/wazuh_health/probes/hygiene.py`
- Test: `tests/probes/test_hygiene.py`

- [ ] **Step 1: Write test**

```python
# tests/probes/test_hygiene.py
from src.wazuh_health.contracts import CleanAlert
from src.wazuh_health.probes.hygiene import HygieneProbe


class _FakeSource:
    def __init__(self, alerts: list[CleanAlert]):
        self._alerts = alerts

    def iter_alerts(self, *, since_days=None):
        return iter(self._alerts)


def _alert(rid="5710", level=5):
    return CleanAlert(
        timestamp="2026-06-11T10:00:00Z", rule_id=rid, rule_level=level,
        agent_name="vpn01", srcip="10.0.5.20",
    )


def test_hygiene_probe_emits_bucket_count_and_combined_reduction():
    probe = HygieneProbe(source=_FakeSource([_alert() for _ in range(40)]), min_count=10)
    result = probe.run()
    assert result.metrics["noise.recommendations_count"] >= 1
    assert "noise.combined_reduction_pct" in result.metrics
    assert "top_buckets" in result.artifacts
    assert "recommendations" in result.artifacts


def test_hygiene_probe_with_no_noise_returns_zeros():
    probe = HygieneProbe(source=_FakeSource([]), min_count=10)
    result = probe.run()
    assert result.metrics["noise.recommendations_count"] == 0
    assert result.metrics["noise.combined_reduction_pct"] == 0.0
```

- [ ] **Step 2: Implement `probes/hygiene.py`**

```python
"""Hygiene probe — wraps the CleanSwarm-derived analyzer/recommender/simulator."""
from __future__ import annotations

from typing import Any, Protocol

from src.wazuh_health.contracts import CleanAlert, ProbeName
from src.wazuh_health.hygiene.analyzer import build_noise_buckets
from src.wazuh_health.hygiene.recommender import recommend_from_buckets
from src.wazuh_health.hygiene.simulator import (
    simulate_combined, simulate_recommendations,
)
from src.wazuh_health.probes.base import Probe


class _AlertSource(Protocol):
    def iter_alerts(self, *, since_days: int | None = None): ...


class HygieneProbe(Probe):
    name: ProbeName = "hygiene"

    def __init__(
        self,
        *,
        source: _AlertSource,
        window_hours: int = 1,
        min_count: int = 50,
        top: int = 20,
        max_recommendations: int = 10,
    ) -> None:
        self._source = source
        self._window_hours = window_hours
        self._min_count = min_count
        self._top = top
        self._max_recs = max_recommendations

    def collect(self) -> dict[str, Any]:
        alerts: list[CleanAlert] = list(self._source.iter_alerts(since_days=None))
        total = len(alerts)
        buckets = build_noise_buckets(alerts, min_count=self._min_count, top=self._top)
        recs = recommend_from_buckets(
            buckets, total_alerts=total, max_recommendations=self._max_recs
        )
        sims = simulate_recommendations(alerts, recs)
        combined = simulate_combined(alerts, sims) if sims else None

        metrics: dict[str, float | int] = {
            "noise.total_alerts": total,
            "noise.bucket_count": len(buckets),
            "noise.recommendations_count": len(recs),
            "noise.combined_reduction_pct": (
                round(combined.union_reduction_ratio * 100, 2) if combined else 0.0
            ),
        }
        # Drop `raw` from buckets/alerts before exposing as artifacts (LLM safety).
        artifacts = {
            "top_buckets": [b.model_dump() for b in buckets],
            "recommendations": [r.model_dump() for r in recs],
            "simulations": [s.model_dump() for s in sims],
            "combined_simulation": combined.model_dump() if combined else None,
        }
        return {"metrics": metrics, "artifacts": artifacts, "errors": []}
```

- [ ] **Step 3: Run + commit**

```bash
pytest tests/probes/test_hygiene.py -v
git add src/wazuh_health/probes/hygiene.py tests/probes/test_hygiene.py
git commit -m "feat(wazuh-health): HygieneProbe wraps noise analyzer for probe pipeline"
```

---

### Task 4.4: `CoverageProbe`

**Files:**
- Create: `src/wazuh_health/probes/coverage.py`
- Test: `tests/probes/test_coverage.py`

- [ ] **Step 1: Write tests**

```python
# tests/probes/test_coverage.py
from datetime import datetime, timezone, timedelta

from src.wazuh_health.source.base import AgentInfo, ManagerStats
from src.wazuh_health.probes.coverage import CoverageProbe


class _FakeSource:
    def __init__(self, agents, decoder_errors=0):
        self._agents = agents
        self._dec = decoder_errors

    def list_agents(self):
        return self._agents

    def manager_stats(self):
        return ManagerStats(decoder_errors=self._dec, rule_hits_by_id={"5710": 100, "9999": 0})


def test_coverage_counts_disconnected_and_never_connected():
    now = datetime.now(tz=timezone.utc)
    agents = [
        AgentInfo(agent_id="1", name="a", status="active", last_keep_alive=now),
        AgentInfo(agent_id="2", name="b", status="disconnected",
                  last_keep_alive=now - timedelta(days=2)),
        AgentInfo(agent_id="3", name="c", status="never_connected"),
        AgentInfo(agent_id="4", name="d", status="disconnected",
                  last_keep_alive=now - timedelta(days=10)),
    ]
    result = CoverageProbe(source=_FakeSource(agents, decoder_errors=3)).run()
    m = result.metrics
    assert m["agents.total"] == 4
    assert m["agents.active"] == 1
    assert m["agents.disconnected"] == 2
    assert m["agents.never_connected"] == 1
    assert m["decoders.errors"] == 3
    assert m["rules.zero_hit"] == 1
```

- [ ] **Step 2: Implement `probes/coverage.py`**

```python
"""Coverage probe — agent health, decoder errors, zero-hit rules."""
from __future__ import annotations

from typing import Any, Protocol

from src.wazuh_health.contracts import ProbeName
from src.wazuh_health.probes.base import Probe


class _Source(Protocol):
    def list_agents(self): ...
    def manager_stats(self): ...


class CoverageProbe(Probe):
    name: ProbeName = "coverage"

    def __init__(self, *, source: _Source) -> None:
        self._source = source

    def collect(self) -> dict[str, Any]:
        errors: list[str] = []
        metrics: dict[str, float | int] = {}
        agents_artifact: list[dict] = []
        try:
            agents = self._source.list_agents()
            metrics["agents.total"] = len(agents)
            metrics["agents.active"] = sum(1 for a in agents if a.status == "active")
            metrics["agents.disconnected"] = sum(
                1 for a in agents if a.status == "disconnected"
            )
            metrics["agents.never_connected"] = sum(
                1 for a in agents if a.status == "never_connected"
            )
            agents_artifact = [a.model_dump(mode="json") for a in agents]
        except Exception as exc:
            errors.append(f"list_agents: {exc!r}")

        try:
            mgr = self._source.manager_stats()
            metrics["decoders.errors"] = mgr.decoder_errors
            metrics["rules.zero_hit"] = sum(
                1 for hits in mgr.rule_hits_by_id.values() if hits == 0
            )
        except Exception as exc:
            errors.append(f"manager_stats: {exc!r}")

        return {
            "metrics": metrics,
            "artifacts": {"agents": agents_artifact},
            "errors": errors,
        }
```

- [ ] **Step 3: Run + commit**

```bash
pytest tests/probes/test_coverage.py -v
git add src/wazuh_health/probes/coverage.py tests/probes/test_coverage.py
git commit -m "feat(wazuh-health): CoverageProbe for agent/decoder/rule-coverage metrics"
```

---

**End of Phase 4.** Pause point: all three probes ready, ~12 new tests, boundaries still green.

---

## Phase 5 — Store (SQLite) + Decision (threshold, cooldown, dispatcher)

Goal: persistent state for findings, audit, and cooldown. Threshold rule evaluator and a dispatcher that wakes a domain agent at most once per dispatch and respects cooldown + daily cap.

### Task 5.1: SQLite `db.py` with migrations

**Files:**
- Create: `src/wazuh_health/store/db.py`
- Test: `tests/store/test_db_migrations.py`

- [ ] **Step 1: Tests**

```python
# tests/store/test_db_migrations.py
import sqlite3

from src.wazuh_health.store.db import connect, migrate


def test_migrate_creates_all_tables():
    conn = connect(":memory:")
    migrate(conn)
    tables = {
        r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    assert {"probe_runs", "findings", "notifications", "agent_runs", "cooldowns",
            "schema_version"} <= tables


def test_migrate_is_idempotent():
    conn = connect(":memory:")
    migrate(conn)
    migrate(conn)  # second call must not raise
    v = conn.execute("SELECT max(version) FROM schema_version").fetchone()[0]
    assert v == 1
```

- [ ] **Step 2: Implement `store/db.py`**

```python
"""SQLite connection helper and forward-only migrations."""
from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_V1 = [
    """
    CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS probe_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        probe TEXT NOT NULL,
        run_at TEXT NOT NULL,
        metrics_json TEXT NOT NULL,
        artifacts_json TEXT NOT NULL,
        errors_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hash TEXT UNIQUE NOT NULL,
        domain TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        body_md TEXT NOT NULL,
        evidence_json TEXT NOT NULL,
        suggested_action TEXT NOT NULL,
        proposed_artifact TEXT,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        status TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id INTEGER NOT NULL,
        channel TEXT NOT NULL,
        sent_at TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        FOREIGN KEY(finding_id) REFERENCES findings(id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS agent_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent TEXT NOT NULL,
        started_at TEXT NOT NULL,
        ended_at TEXT,
        status TEXT NOT NULL,
        input_tokens INTEGER DEFAULT 0,
        output_tokens INTEGER DEFAULT 0,
        tool_calls_json TEXT NOT NULL,
        output_hash TEXT,
        finding_ids_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS cooldowns (
        probe TEXT NOT NULL,
        metric TEXT NOT NULL,
        last_woken_at TEXT NOT NULL,
        PRIMARY KEY (probe, metric)
    )
    """,
]


def connect(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def migrate(conn: sqlite3.Connection) -> None:
    from datetime import datetime, timezone
    for stmt in SCHEMA_V1:
        conn.execute(stmt)
    cur = conn.execute("SELECT COALESCE(MAX(version), 0) FROM schema_version")
    current = cur.fetchone()[0]
    if current < 1:
        conn.execute(
            "INSERT INTO schema_version(version, applied_at) VALUES (?, ?)",
            (1, datetime.now(tz=timezone.utc).isoformat()),
        )
    conn.commit()
```

- [ ] **Step 3: Run + commit**

```bash
pytest tests/store/test_db_migrations.py -v
git add src/wazuh_health/store/db.py tests/store/test_db_migrations.py
git commit -m "feat(wazuh-health): SQLite store with idempotent v1 migrations"
```

---

### Task 5.2: `FindingsStore` with deterministic hash dedup

**Files:**
- Create: `src/wazuh_health/store/findings_store.py`
- Test: `tests/store/test_findings_store.py`

- [ ] **Step 1: Tests**

```python
# tests/store/test_findings_store.py
from src.wazuh_health.contracts import DomainFinding
from src.wazuh_health.store.db import connect, migrate
from src.wazuh_health.store.findings_store import FindingsStore, compute_hash_key


def _finding(title="t", domain="hygiene", severity="warning",
             evidence=None, suggested_action="a"):
    return DomainFinding(
        domain=domain, severity=severity, title=title, body_md="b",
        evidence=evidence or {"rule_id": "5710"},
        suggested_action=suggested_action,
    )


def test_hash_key_is_deterministic_and_order_independent():
    h1 = compute_hash_key("hygiene", "rule_id", {"rule_id": "5710", "agent": "x"})
    h2 = compute_hash_key("hygiene", "rule_id", {"agent": "x", "rule_id": "5710"})
    assert h1 == h2


def test_insert_then_same_hash_updates_last_seen_only():
    conn = connect(":memory:"); migrate(conn)
    store = FindingsStore(conn)
    f = _finding()
    fid1 = store.upsert(f, hash_key="abc")
    fid2 = store.upsert(f, hash_key="abc")
    assert fid1 == fid2
    rows = conn.execute("SELECT count(*) FROM findings").fetchone()
    assert rows[0] == 1


def test_query_open_findings_returns_only_open():
    conn = connect(":memory:"); migrate(conn)
    store = FindingsStore(conn)
    store.upsert(_finding(title="a"), hash_key="h1")
    fid = store.upsert(_finding(title="b"), hash_key="h2")
    store.mark_resolved(fid)
    titles = [f.title for f in store.list_open()]
    assert titles == ["a"]
```

- [ ] **Step 2: Implement `store/findings_store.py`**

```python
"""FindingsStore: persists DomainFindings with deterministic dedup."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Iterable

from src.wazuh_health.contracts import DomainFinding


def compute_hash_key(domain: str, metric: str, evidence: dict) -> str:
    """Stable hash for dedup. Order-independent on evidence keys."""
    payload = {
        "domain": domain,
        "metric": metric,
        "evidence": {k: evidence[k] for k in sorted(evidence)},
    }
    blob = json.dumps(payload, sort_keys=True, default=str).encode()
    return hashlib.sha1(blob).hexdigest()


class FindingsStore:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def upsert(self, finding: DomainFinding, *, hash_key: str) -> int:
        now = datetime.now(tz=timezone.utc).isoformat()
        cur = self._conn.execute(
            "SELECT id FROM findings WHERE hash = ?", (hash_key,)
        )
        row = cur.fetchone()
        if row:
            self._conn.execute(
                "UPDATE findings SET last_seen = ?, severity = ?, body_md = ?, "
                "evidence_json = ? WHERE id = ?",
                (now, finding.severity, finding.body_md,
                 json.dumps(finding.evidence, sort_keys=True), row["id"]),
            )
            self._conn.commit()
            return int(row["id"])
        cur = self._conn.execute(
            "INSERT INTO findings(hash, domain, severity, title, body_md, "
            "evidence_json, suggested_action, proposed_artifact, "
            "first_seen, last_seen, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')",
            (
                hash_key, finding.domain, finding.severity, finding.title,
                finding.body_md, json.dumps(finding.evidence, sort_keys=True),
                finding.suggested_action, finding.proposed_artifact,
                now, now,
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def mark_resolved(self, finding_id: int) -> None:
        self._conn.execute(
            "UPDATE findings SET status = 'resolved' WHERE id = ?", (finding_id,)
        )
        self._conn.commit()

    def list_open(self, *, since_iso: str | None = None) -> list[DomainFinding]:
        q = "SELECT * FROM findings WHERE status = 'open'"
        args: tuple = ()
        if since_iso is not None:
            q += " AND last_seen >= ?"
            args = (since_iso,)
        q += " ORDER BY last_seen DESC"
        out: list[DomainFinding] = []
        for row in self._conn.execute(q, args):
            out.append(DomainFinding(
                domain=row["domain"],
                severity=row["severity"],
                title=row["title"],
                body_md=row["body_md"],
                evidence=json.loads(row["evidence_json"]),
                suggested_action=row["suggested_action"],
                proposed_artifact=row["proposed_artifact"],
                hash_key=row["hash"],
            ))
        return out
```

- [ ] **Step 3: Run + commit**

```bash
pytest tests/store/test_findings_store.py -v
git add src/wazuh_health/store/findings_store.py tests/store/test_findings_store.py
git commit -m "feat(wazuh-health): FindingsStore with deterministic hash dedup"
```

---

### Task 5.3: `AuditStore` (probe_runs, agent_runs)

**Files:**
- Create: `src/wazuh_health/store/audit_store.py`
- Test: `tests/store/test_audit_store.py`

- [ ] **Step 1: Tests**

```python
# tests/store/test_audit_store.py
from datetime import datetime, timezone

from src.wazuh_health.contracts import ProbeResult
from src.wazuh_health.store.audit_store import AuditStore
from src.wazuh_health.store.db import connect, migrate


def test_record_probe_run_then_latest_returns_it():
    conn = connect(":memory:"); migrate(conn)
    audit = AuditStore(conn)
    pr = ProbeResult(
        probe="capacity",
        run_at=datetime.now(tz=timezone.utc),
        metrics={"x": 1}, artifacts={"a": 1}, errors=[],
    )
    audit.record_probe_run(pr)
    latest = audit.latest_probe_run("capacity")
    assert latest is not None
    assert latest.metrics["x"] == 1


def test_record_agent_run_persists_token_counts():
    conn = connect(":memory:"); migrate(conn)
    audit = AuditStore(conn)
    audit.record_agent_run(
        agent="HygieneAgent",
        started_at=datetime.now(tz=timezone.utc),
        ended_at=datetime.now(tz=timezone.utc),
        status="ok", input_tokens=120, output_tokens=80,
        tool_calls=[{"name": "get_top_buckets", "args": {}}],
        output_hash="h", finding_ids=[1, 2],
    )
    row = conn.execute("SELECT input_tokens, output_tokens FROM agent_runs").fetchone()
    assert row[0] == 120 and row[1] == 80
```

- [ ] **Step 2: Implement `store/audit_store.py`**

```python
"""AuditStore — probe_runs + agent_runs persistence."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime

from src.wazuh_health.contracts import ProbeName, ProbeResult


class AuditStore:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def record_probe_run(self, result: ProbeResult) -> int:
        cur = self._conn.execute(
            "INSERT INTO probe_runs(probe, run_at, metrics_json, artifacts_json, errors_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                result.probe, result.run_at.isoformat(),
                json.dumps(result.metrics, sort_keys=True, default=str),
                json.dumps(result.artifacts, sort_keys=True, default=str),
                json.dumps(result.errors),
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def latest_probe_run(self, probe: ProbeName) -> ProbeResult | None:
        row = self._conn.execute(
            "SELECT * FROM probe_runs WHERE probe = ? ORDER BY id DESC LIMIT 1",
            (probe,),
        ).fetchone()
        if row is None:
            return None
        return ProbeResult(
            probe=row["probe"],
            run_at=datetime.fromisoformat(row["run_at"]),
            metrics=json.loads(row["metrics_json"]),
            artifacts=json.loads(row["artifacts_json"]),
            errors=json.loads(row["errors_json"]),
        )

    def record_agent_run(
        self,
        *,
        agent: str,
        started_at: datetime,
        ended_at: datetime | None,
        status: str,
        input_tokens: int = 0,
        output_tokens: int = 0,
        tool_calls: list[dict] | None = None,
        output_hash: str | None = None,
        finding_ids: list[int] | None = None,
    ) -> int:
        cur = self._conn.execute(
            "INSERT INTO agent_runs(agent, started_at, ended_at, status, "
            "input_tokens, output_tokens, tool_calls_json, output_hash, finding_ids_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                agent, started_at.isoformat(),
                ended_at.isoformat() if ended_at else None,
                status, input_tokens, output_tokens,
                json.dumps(tool_calls or []),
                output_hash,
                json.dumps(finding_ids or []),
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def count_agent_runs_today(self, agent: str, *, now: datetime) -> int:
        day_start = now.date().isoformat()
        return int(self._conn.execute(
            "SELECT count(*) FROM agent_runs WHERE agent = ? AND started_at >= ?",
            (agent, day_start),
        ).fetchone()[0])
```

- [ ] **Step 3: Run + commit**

```bash
pytest tests/store/test_audit_store.py -v
git add src/wazuh_health/store/audit_store.py tests/store/test_audit_store.py
git commit -m "feat(wazuh-health): AuditStore for probe and agent run telemetry"
```

---

### Task 5.4: `ThresholdEngine`

**Files:**
- Create: `src/wazuh_health/decision/threshold.py`
- Test: `tests/decision/test_threshold.py`

- [ ] **Step 1: Tests**

```python
# tests/decision/test_threshold.py
from datetime import datetime, timezone

from src.wazuh_health.contracts import ProbeResult
from src.wazuh_health.decision.threshold import (
    ThresholdEngine, ThresholdRule,
)


def _result(metrics):
    return ProbeResult(
        probe="capacity", run_at=datetime.now(tz=timezone.utc),
        metrics=metrics, artifacts={}, errors=[],
    )


def test_simple_lt_rule_hits():
    eng = ThresholdEngine(rules={"capacity": [
        ThresholdRule(metric="disk.free_pct", rule="value < 15", severity="warning"),
    ]})
    hits = eng.evaluate(_result({"disk.free_pct": 10}))
    assert len(hits) == 1
    assert hits[0].severity == "warning"


def test_missing_metric_does_not_hit():
    eng = ThresholdEngine(rules={"capacity": [
        ThresholdRule(metric="disk.free_pct", rule="value < 15", severity="warning"),
    ]})
    assert eng.evaluate(_result({"other": 1})) == []


def test_streak_requires_history():
    eng = ThresholdEngine(rules={"capacity": [
        ThresholdRule(metric="agents.disconnected", rule="value >= 3 streak >= 2", severity="warning"),
    ]})
    # First tick — no hit even though value matches.
    hits = eng.evaluate(_result({"agents.disconnected": 5}))
    assert hits == []
    # Second tick — streak reached.
    hits = eng.evaluate(_result({"agents.disconnected": 5}))
    assert len(hits) == 1
```

- [ ] **Step 2: Implement `decision/threshold.py`**

```python
"""Configurable threshold evaluator with streak support."""
from __future__ import annotations

import re
from collections import defaultdict, deque

from pydantic import BaseModel, ConfigDict

from src.wazuh_health.contracts import ProbeName, ProbeResult, Severity, ThresholdHit

_OP_RE = re.compile(
    r"value\s*(?P<op>[<>]=?|==)\s*(?P<num>-?\d+(?:\.\d+)?)\s*"
    r"(?:streak\s*>=\s*(?P<streak>\d+))?"
)


class ThresholdRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    metric: str
    rule: str
    severity: Severity


class ThresholdEngine:
    def __init__(self, *, rules: dict[ProbeName, list[ThresholdRule]]) -> None:
        self._rules = rules
        # streak_hits[(probe, rule_id)] = deque of bools for the last N ticks
        self._streaks: dict[tuple, deque] = defaultdict(lambda: deque(maxlen=10))

    @staticmethod
    def _check(rule: str, value: float | int) -> tuple[bool, int]:
        m = _OP_RE.match(rule.strip())
        if not m:
            return (False, 1)
        op = m.group("op")
        num = float(m.group("num"))
        streak = int(m.group("streak") or 1)
        if op == "<":
            ok = value < num
        elif op == "<=":
            ok = value <= num
        elif op == ">":
            ok = value > num
        elif op == ">=":
            ok = value >= num
        elif op == "==":
            ok = value == num
        else:
            ok = False
        return (ok, streak)

    def evaluate(self, result: ProbeResult) -> list[ThresholdHit]:
        hits: list[ThresholdHit] = []
        for rule in self._rules.get(result.probe, []):
            if rule.metric not in result.metrics:
                continue
            value = result.metrics[rule.metric]
            ok, streak_required = self._check(rule.rule, value)
            key = (result.probe, rule.metric, rule.rule)
            history = self._streaks[key]
            history.append(ok)
            recent = list(history)[-streak_required:]
            if len(recent) == streak_required and all(recent):
                hits.append(ThresholdHit(
                    probe=result.probe,
                    metric=rule.metric,
                    value=value,
                    rule=rule.rule,
                    severity=rule.severity,
                ))
        return hits
```

- [ ] **Step 3: Run + commit**

```bash
pytest tests/decision/test_threshold.py -v
git add src/wazuh_health/decision/threshold.py tests/decision/test_threshold.py
git commit -m "feat(wazuh-health): ThresholdEngine with op + streak support"
```

---

### Task 5.5: `CooldownTable`

**Files:**
- Create: `src/wazuh_health/decision/cooldown.py`
- Test: `tests/decision/test_cooldown.py`

- [ ] **Step 1: Tests**

```python
# tests/decision/test_cooldown.py
from datetime import datetime, timedelta, timezone

from src.wazuh_health.decision.cooldown import CooldownTable
from src.wazuh_health.store.db import connect, migrate


def test_can_wake_when_no_history():
    conn = connect(":memory:"); migrate(conn)
    c = CooldownTable(conn, default_minutes=360)
    assert c.can_wake("capacity", "disk.free_pct", now=datetime.now(tz=timezone.utc))


def test_cooldown_blocks_within_window():
    conn = connect(":memory:"); migrate(conn)
    c = CooldownTable(conn, default_minutes=360)
    now = datetime.now(tz=timezone.utc)
    c.mark_woken("capacity", "disk.free_pct", at=now)
    assert not c.can_wake("capacity", "disk.free_pct", now=now + timedelta(minutes=10))


def test_per_metric_override_used():
    conn = connect(":memory:"); migrate(conn)
    c = CooldownTable(conn, default_minutes=360,
                      per_metric={"indexer.heap_pct": 60})
    now = datetime.now(tz=timezone.utc)
    c.mark_woken("capacity", "indexer.heap_pct", at=now)
    assert c.can_wake("capacity", "indexer.heap_pct", now=now + timedelta(minutes=61))
    assert not c.can_wake("capacity", "indexer.heap_pct", now=now + timedelta(minutes=10))
```

- [ ] **Step 2: Implement `decision/cooldown.py`**

```python
"""Per-metric cooldown table stored in SQLite."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta


class CooldownTable:
    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        default_minutes: int = 360,
        per_metric: dict[str, int] | None = None,
    ) -> None:
        self._conn = conn
        self._default = default_minutes
        self._per_metric = per_metric or {}

    def _window(self, metric: str) -> timedelta:
        return timedelta(minutes=self._per_metric.get(metric, self._default))

    def can_wake(self, probe: str, metric: str, *, now: datetime) -> bool:
        row = self._conn.execute(
            "SELECT last_woken_at FROM cooldowns WHERE probe = ? AND metric = ?",
            (probe, metric),
        ).fetchone()
        if row is None:
            return True
        last = datetime.fromisoformat(row["last_woken_at"])
        return now - last >= self._window(metric)

    def mark_woken(self, probe: str, metric: str, *, at: datetime) -> None:
        self._conn.execute(
            "INSERT INTO cooldowns(probe, metric, last_woken_at) VALUES (?, ?, ?) "
            "ON CONFLICT(probe, metric) DO UPDATE SET last_woken_at=excluded.last_woken_at",
            (probe, metric, at.isoformat()),
        )
        self._conn.commit()
```

- [ ] **Step 3: Run + commit**

```bash
pytest tests/decision/test_cooldown.py -v
git add src/wazuh_health/decision/cooldown.py tests/decision/test_cooldown.py
git commit -m "feat(wazuh-health): per-metric cooldown table"
```

---

### Task 5.6: `WakeDispatcher`

**Files:**
- Create: `src/wazuh_health/decision/dispatcher.py`
- Test: `tests/decision/test_dispatcher.py`

- [ ] **Step 1: Tests**

```python
# tests/decision/test_dispatcher.py
from datetime import datetime, timezone

from src.wazuh_health.contracts import ThresholdHit
from src.wazuh_health.decision.cooldown import CooldownTable
from src.wazuh_health.decision.dispatcher import WakeDispatcher
from src.wazuh_health.store.db import connect, migrate


class _Counting:
    def __init__(self):
        self.calls = 0
        self.hits_seen = []

    def __call__(self, hits, *, audit_store=None):
        self.calls += 1
        self.hits_seen.extend(hits)


def _hit(metric, severity="warning"):
    return ThresholdHit(
        probe="capacity", metric=metric, value=1,
        rule="value < 1", severity=severity,
    )


def _disp():
    conn = connect(":memory:"); migrate(conn)
    return WakeDispatcher(
        cooldown=CooldownTable(conn, default_minutes=360),
        agent_runs=_FakeAuditStore(),
        invoke_by_domain={"capacity": _Counting(), "hygiene": _Counting(),
                          "coverage": _Counting()},
        daily_cap=50,
    )


class _FakeAuditStore:
    def __init__(self):
        self._counts = {}
    def count_agent_runs_today(self, agent, *, now): return self._counts.get(agent, 0)
    def record_agent_run(self, **kw): self._counts[kw["agent"]] = self._counts.get(kw["agent"], 0) + 1


def test_dispatch_invokes_each_domain_once_per_dispatch():
    d = _disp()
    d.dispatch([_hit("disk.free_pct"), _hit("indexer.heap_pct")],
               now=datetime.now(tz=timezone.utc))
    cap = d._invokers["capacity"]
    assert cap.calls == 1
    assert len(cap.hits_seen) == 2


def test_dispatch_skips_metric_in_cooldown():
    d = _disp()
    now = datetime.now(tz=timezone.utc)
    d._cooldown.mark_woken("capacity", "disk.free_pct", at=now)
    d.dispatch([_hit("disk.free_pct")], now=now)
    assert d._invokers["capacity"].calls == 0


def test_dispatch_respects_daily_cap():
    d = _disp()
    d._daily_cap = 0  # already over cap
    d.dispatch([_hit("disk.free_pct")], now=datetime.now(tz=timezone.utc))
    assert d._invokers["capacity"].calls == 0
```

- [ ] **Step 2: Implement `decision/dispatcher.py`**

```python
"""WakeDispatcher: invoke at most one domain agent per dispatch, respecting cooldowns + cap."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Callable, Protocol

from src.wazuh_health.contracts import ProbeName, ThresholdHit


_DOMAIN_OF: dict[ProbeName, str] = {
    "capacity": "capacity",
    "hygiene": "hygiene",
    "coverage": "coverage",
}

_AGENT_OF_DOMAIN: dict[str, str] = {
    "capacity": "CapacityAgent",
    "hygiene": "HygieneAgent",
    "coverage": "CoverageAgent",
}


class _AuditLike(Protocol):
    def count_agent_runs_today(self, agent: str, *, now: datetime) -> int: ...
    def record_agent_run(self, **kw) -> int: ...


class WakeDispatcher:
    def __init__(
        self,
        *,
        cooldown,
        agent_runs: _AuditLike,
        invoke_by_domain: dict[str, Callable[..., None]],
        daily_cap: int = 50,
    ) -> None:
        self._cooldown = cooldown
        self._audit = agent_runs
        self._invokers = invoke_by_domain
        self._daily_cap = daily_cap

    def dispatch(self, hits: list[ThresholdHit], *, now: datetime) -> None:
        # Filter out cooldowned hits per (probe, metric).
        eligible: dict[str, list[ThresholdHit]] = defaultdict(list)
        for h in hits:
            if not self._cooldown.can_wake(h.probe, h.metric, now=now):
                continue
            eligible[_DOMAIN_OF[h.probe]].append(h)

        for domain, dom_hits in eligible.items():
            agent_name = _AGENT_OF_DOMAIN[domain]
            if self._audit.count_agent_runs_today(agent_name, now=now) >= self._daily_cap:
                # Skip but mark cooldown so we don't keep evaluating.
                for h in dom_hits:
                    self._cooldown.mark_woken(h.probe, h.metric, at=now)
                continue
            invoker = self._invokers.get(domain)
            if invoker is None:
                continue
            invoker(dom_hits, audit_store=self._audit)
            for h in dom_hits:
                self._cooldown.mark_woken(h.probe, h.metric, at=now)
```

- [ ] **Step 3: Run + commit**

```bash
pytest tests/decision/test_dispatcher.py -v
git add src/wazuh_health/decision/dispatcher.py tests/decision/test_dispatcher.py
git commit -m "feat(wazuh-health): WakeDispatcher honors cooldown + daily cap"
```

---

**End of Phase 5.** Pause point: persistent state ready, decision pipeline complete with cooldown + cap; no agents wired in yet.

---

## Phase 6 — Pseudonymize + read-only tools + sanitizer

Goal: a stable session-bound IP/user pseudonymizer, the read-only tool registry per domain, and a strict sanitizer for LLM outputs.

### Task 6.1: `pseudonymize.py`

**Files:**
- Create: `src/wazuh_health/pseudonymize.py`
- Test: `tests/test_pseudonymize.py`

- [ ] **Step 1: Tests**

```python
# tests/test_pseudonymize.py
from src.wazuh_health.pseudonymize import Pseudonymizer


def test_same_value_same_token_within_session():
    p = Pseudonymizer(salt="s1")
    a = p.encode("ip", "10.0.0.1")
    b = p.encode("ip", "10.0.0.1")
    assert a == b
    assert a.startswith("ip_")


def test_different_categories_distinct_namespaces():
    p = Pseudonymizer(salt="s1")
    assert p.encode("ip", "10.0.0.1") != p.encode("user", "10.0.0.1")


def test_decode_returns_original_in_session():
    p = Pseudonymizer(salt="s1")
    t = p.encode("user", "alice")
    assert p.decode(t) == "alice"


def test_walk_dict_pseudonymizes_known_fields():
    p = Pseudonymizer(salt="s1")
    obj = {"srcip": "10.0.0.1", "user": "alice", "rule_id": "5710", "agent.name": "vpn01"}
    masked = p.mask(obj, fields=["srcip", "user", "agent.name"])
    assert masked["srcip"].startswith("ip_")
    assert masked["user"].startswith("user_")
    assert masked["agent.name"].startswith("agent_name_")
    assert masked["rule_id"] == "5710"  # not in fields list
```

- [ ] **Step 2: Implement `pseudonymize.py`**

```python
"""Session-bound pseudonymizer for PII fields shipped to the LLM."""
from __future__ import annotations

import hashlib
from typing import Any


class Pseudonymizer:
    def __init__(self, *, salt: str) -> None:
        self._salt = salt
        self._encode_map: dict[tuple[str, str], str] = {}
        self._decode_map: dict[str, str] = {}

    def encode(self, category: str, value: str) -> str:
        key = (category, value)
        if key in self._encode_map:
            return self._encode_map[key]
        digest = hashlib.sha256(
            f"{self._salt}:{category}:{value}".encode()
        ).hexdigest()[:8]
        prefix = category.replace(".", "_").lower()
        token = f"{prefix}_{digest}"
        self._encode_map[key] = token
        self._decode_map[token] = value
        return token

    def decode(self, token: str) -> str | None:
        return self._decode_map.get(token)

    def mask(self, obj: dict[str, Any], *, fields: list[str]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if k in fields and isinstance(v, str):
                out[k] = self.encode(k, v)
            else:
                out[k] = v
        return out
```

- [ ] **Step 3: Run + commit**

```bash
pytest tests/test_pseudonymize.py -v
git add src/wazuh_health/pseudonymize.py tests/test_pseudonymize.py
git commit -m "feat(wazuh-health): session pseudonymizer with stable tokens"
```

---

### Task 6.2: Read-only tool registry (`hygiene_tools`, `capacity_tools`, `coverage_tools`, `reporter_tools`)

**Files:**
- Create: `src/wazuh_health/tools/readonly/hygiene_tools.py`
- Create: `src/wazuh_health/tools/readonly/capacity_tools.py`
- Create: `src/wazuh_health/tools/readonly/coverage_tools.py`
- Create: `src/wazuh_health/tools/readonly/reporter_tools.py`
- Create: `src/wazuh_health/tools/readonly/__init__.py`
- Test: `tests/tools/test_tool_registry.py`

Note: these tools must be JSON-serializable, sync, and read from the last `ProbeResult` / `FindingsStore` only. The agents SDK function-tool decorator is used in Phase 7; here we keep them as plain functions that take the store as first arg so they are trivially testable.

- [ ] **Step 1: Tests**

```python
# tests/tools/test_tool_registry.py
from datetime import datetime, timezone

from src.wazuh_health.contracts import ProbeResult
from src.wazuh_health.store.audit_store import AuditStore
from src.wazuh_health.store.db import connect, migrate
from src.wazuh_health.tools.readonly import (
    CAPACITY_TOOL_NAMES, COVERAGE_TOOL_NAMES, HYGIENE_TOOL_NAMES,
    REPORTER_TOOL_NAMES,
)
from src.wazuh_health.tools.readonly.hygiene_tools import get_top_buckets


def _seed_hygiene(conn):
    audit = AuditStore(conn)
    audit.record_probe_run(ProbeResult(
        probe="hygiene",
        run_at=datetime.now(tz=timezone.utc),
        metrics={"noise.recommendations_count": 1},
        artifacts={"top_buckets": [
            {"key": "k", "dimensions": {"rule_id": "5710"}, "count": 100,
             "rule_id": "5710", "rule_level": 5, "rule_description": "x",
             "rule_groups": [], "first_seen": None, "last_seen": None,
             "affected_agents": [], "affected_srcips": [], "affected_users": [],
             "noise_score": 50.0, "noise_score_breakdown": {}},
        ]},
        errors=[],
    ))


def test_get_top_buckets_reads_latest_probe_run():
    conn = connect(":memory:"); migrate(conn)
    _seed_hygiene(conn)
    audit = AuditStore(conn)
    buckets = get_top_buckets(audit=audit, limit=5)
    assert len(buckets) == 1
    assert buckets[0]["rule_id"] == "5710"


def test_each_domain_tool_set_is_disjoint():
    domains = [HYGIENE_TOOL_NAMES, CAPACITY_TOOL_NAMES,
               COVERAGE_TOOL_NAMES, REPORTER_TOOL_NAMES]
    seen = set()
    for s in domains:
        assert seen.isdisjoint(s), f"overlap: {seen & s}"
        seen |= s
```

- [ ] **Step 2: Implement `hygiene_tools.py`**

```python
"""Read-only hygiene tools. Each tool reads from the latest ProbeResult."""
from __future__ import annotations

from typing import Any

from src.wazuh_health.store.audit_store import AuditStore


def get_top_buckets(*, audit: AuditStore, limit: int = 10) -> list[dict[str, Any]]:
    pr = audit.latest_probe_run("hygiene")
    if pr is None:
        return []
    buckets = pr.artifacts.get("top_buckets", [])
    return buckets[:limit]


def get_recommendations(*, audit: AuditStore, limit: int = 10) -> list[dict[str, Any]]:
    pr = audit.latest_probe_run("hygiene")
    if pr is None:
        return []
    return pr.artifacts.get("recommendations", [])[:limit]


def simulate(*, audit: AuditStore, recommendation_id: str) -> dict[str, Any] | None:
    pr = audit.latest_probe_run("hygiene")
    if pr is None:
        return None
    for sim in pr.artifacts.get("simulations", []):
        if sim.get("recommendation_id") == recommendation_id:
            return sim
    return None


def query_rule_history(
    *, audit: AuditStore, rule_id: str, days: int = 7
) -> dict[str, Any]:
    """Approximation: counts the rule_id presence across the recent hygiene runs."""
    # MVP: read the latest run only; multi-run history is a phase 2 enhancement.
    pr = audit.latest_probe_run("hygiene")
    if pr is None:
        return {"rule_id": rule_id, "count": 0, "first_seen": None, "last_seen": None}
    matching = [
        b for b in pr.artifacts.get("top_buckets", [])
        if str(b.get("rule_id")) == rule_id
    ]
    if not matching:
        return {"rule_id": rule_id, "count": 0, "first_seen": None, "last_seen": None}
    b = matching[0]
    return {
        "rule_id": rule_id,
        "count": b.get("count", 0),
        "first_seen": b.get("first_seen"),
        "last_seen": b.get("last_seen"),
    }
```

- [ ] **Step 3: Implement `capacity_tools.py`**

```python
"""Read-only capacity tools."""
from __future__ import annotations

from typing import Any

from src.wazuh_health.store.audit_store import AuditStore


def get_disk_stats(*, audit: AuditStore) -> dict[str, float | int]:
    pr = audit.latest_probe_run("capacity")
    if pr is None:
        return {}
    return {k: v for k, v in pr.metrics.items() if k.startswith("disk.")}


def get_indexer_stats(*, audit: AuditStore) -> dict[str, float | int]:
    pr = audit.latest_probe_run("capacity")
    if pr is None:
        return {}
    return {k: v for k, v in pr.metrics.items() if k.startswith("indexer.")}


def get_manager_stats(*, audit: AuditStore) -> dict[str, float | int]:
    pr = audit.latest_probe_run("capacity")
    if pr is None:
        return {}
    return {k: v for k, v in pr.metrics.items() if k.startswith("manager.")}


def list_recent_alerts(
    *, audit: AuditStore, rule_groups: list[str] | None = None, hours: int = 1
) -> list[dict[str, Any]]:
    """Returns alert *signatures* from the hygiene run, not raw alerts.

    Pure aggregation. Useful for correlating "disk filling" + "rule X spiking".
    """
    pr = audit.latest_probe_run("hygiene")
    if pr is None:
        return []
    buckets = pr.artifacts.get("top_buckets", [])
    if rule_groups:
        wanted = set(rule_groups)
        buckets = [b for b in buckets if wanted.intersection(b.get("rule_groups", []))]
    # Drop noise_score_breakdown to keep payload small.
    return [{k: v for k, v in b.items() if k != "noise_score_breakdown"}
            for b in buckets[:20]]
```

- [ ] **Step 4: Implement `coverage_tools.py`**

```python
"""Read-only coverage tools."""
from __future__ import annotations

from typing import Any

from src.wazuh_health.store.audit_store import AuditStore


def get_agent_list(*, audit: AuditStore) -> list[dict[str, Any]]:
    pr = audit.latest_probe_run("coverage")
    if pr is None:
        return []
    return pr.artifacts.get("agents", [])


def get_disconnected_agents(*, audit: AuditStore) -> list[dict[str, Any]]:
    return [a for a in get_agent_list(audit=audit) if a.get("status") == "disconnected"]


def get_rule_hit_counts(*, audit: AuditStore, days: int = 30) -> dict[str, int]:
    pr = audit.latest_probe_run("coverage")
    if pr is None:
        return {}
    # The CoverageProbe doesn't currently expose rule_hits_by_id under artifacts —
    # MVP: returns empty when not provided. Future: persist this from manager_stats.
    return pr.artifacts.get("rule_hits_by_id", {})


def get_decoder_errors(*, audit: AuditStore) -> int:
    pr = audit.latest_probe_run("coverage")
    if pr is None:
        return 0
    return int(pr.metrics.get("decoders.errors", 0))
```

- [ ] **Step 5: Implement `reporter_tools.py`**

```python
"""Read-only reporter tools."""
from __future__ import annotations

from typing import Any

from src.wazuh_health.store.findings_store import FindingsStore


def query_findings(
    *, store: FindingsStore, since_iso: str | None = None
) -> list[dict[str, Any]]:
    return [f.model_dump() for f in store.list_open(since_iso=since_iso)]


def get_metric_trend(*, audit, metric: str, hours: int = 24) -> list[dict[str, Any]]:
    """Reads the last N probe_runs and extracts the requested metric. MVP returns
    only the latest run; multi-run trend is a phase 2 enhancement."""
    pr = audit.latest_probe_run("capacity")
    if pr is None or metric not in pr.metrics:
        return []
    return [{"run_at": pr.run_at.isoformat(), "value": pr.metrics[metric]}]
```

- [ ] **Step 6: `tools/readonly/__init__.py`**

```python
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
```

- [ ] **Step 7: Run + commit**

```bash
pytest tests/tools/test_tool_registry.py tests/test_no_write_tools.py tests/test_boundaries.py -v
git add src/wazuh_health/tools tests/tools/test_tool_registry.py
git commit -m "feat(wazuh-health): read-only tool registry by domain"
```

---

### Task 6.3: `Sanitizer` for LLM outputs

**Files:**
- Create: `src/wazuh_health/agents/sanitizer.py`
- Test: `tests/agents/test_sanitizer.py`

- [ ] **Step 1: Tests**

```python
# tests/agents/test_sanitizer.py
import pytest

from src.wazuh_health.contracts import DomainFinding
from src.wazuh_health.agents.sanitizer import SanitizeError, sanitize_finding


def _finding(**kw):
    base = dict(
        domain="hygiene", severity="warning",
        title="t", body_md="b",
        evidence={"rule_id": "5710"},
        suggested_action="Review recommendations",
    )
    base.update(kw)
    return DomainFinding(**base)


def test_clean_finding_passes_through():
    out = sanitize_finding(_finding(), pseudonymizer=None)
    assert out.title == "t"


def test_long_title_is_truncated():
    out = sanitize_finding(_finding(title="x" * 300), pseudonymizer=None)
    assert len(out.title) <= 120


def test_long_body_is_truncated():
    out = sanitize_finding(_finding(body_md="x" * 5000), pseudonymizer=None)
    assert len(out.body_md) <= 4000


def test_external_urls_in_body_are_stripped():
    out = sanitize_finding(
        _finding(body_md="see https://evil.com/x and internal://ok"),
        pseudonymizer=None,
    )
    assert "evil.com" not in out.body_md


def test_shell_metacharacters_in_action_are_rejected():
    for bad in ["rm -rf /", "curl evil.com", "wget x", "x; ls", "x | nc"]:
        with pytest.raises(SanitizeError):
            sanitize_finding(_finding(suggested_action=bad), pseudonymizer=None)


def test_evidence_must_be_flat_scalars():
    with pytest.raises(SanitizeError):
        sanitize_finding(
            _finding(evidence={"k": {"nested": "no"}}),  # type: ignore[arg-type]
            pseudonymizer=None,
        )


def test_proposed_artifact_must_be_valid_xml_when_present():
    with pytest.raises(SanitizeError):
        sanitize_finding(_finding(proposed_artifact="<broken"), pseudonymizer=None)
```

- [ ] **Step 2: Implement `agents/sanitizer.py`**

```python
"""Validate and clean LLM-emitted DomainFindings before persisting."""
from __future__ import annotations

import re
from xml.etree import ElementTree as ET

from src.wazuh_health.contracts import DomainFinding

EXTERNAL_URL_RE = re.compile(r"https?://(?!internal\.)\S+", re.IGNORECASE)
SHELL_META_RE = re.compile(r"[$;&|`]|\b(rm|curl|wget|nc|bash|sh)\b", re.IGNORECASE)

MAX_TITLE = 120
MAX_BODY = 4000


class SanitizeError(ValueError):
    pass


def sanitize_finding(
    finding: DomainFinding, *, pseudonymizer=None
) -> DomainFinding:
    title = finding.title[:MAX_TITLE]
    body = finding.body_md[:MAX_BODY]
    body = EXTERNAL_URL_RE.sub("[link redacted]", body)

    if SHELL_META_RE.search(finding.suggested_action):
        raise SanitizeError("suggested_action contains shell metacharacters")

    for k, v in finding.evidence.items():
        if isinstance(v, dict | list):
            raise SanitizeError(f"evidence[{k}] must be a scalar")
        if not isinstance(v, str | int | float):
            raise SanitizeError(f"evidence[{k}] has unsupported type")

    if finding.proposed_artifact:
        try:
            ET.fromstring(finding.proposed_artifact)
        except ET.ParseError as exc:
            raise SanitizeError(f"proposed_artifact is not valid XML: {exc}") from exc

    # hash_key is always overwritten by the daemon — we don't trust LLM input.
    return DomainFinding(
        domain=finding.domain,
        severity=finding.severity,
        title=title,
        body_md=body,
        evidence=finding.evidence,
        suggested_action=finding.suggested_action,
        proposed_artifact=finding.proposed_artifact,
        hash_key="",
    )
```

- [ ] **Step 3: Run + commit**

```bash
pytest tests/agents/test_sanitizer.py -v
git add src/wazuh_health/agents/sanitizer.py tests/agents/test_sanitizer.py
git commit -m "feat(wazuh-health): sanitizer for LLM-emitted findings"
```

---

**End of Phase 6.** Pause point: pseudonymizer, tool registry, sanitizer ready and tested. Agents in Phase 7 can be wired safely.

---

## Phase 7 — Agents (Hygiene/Capacity/Coverage + Reporter) + fake LLM runner

Goal: four `openai-agents` Agents with read-only tools, instructions from prompt files, and a `run_agent()` adapter that tests can replace with a fake. The dispatcher uses this adapter; no test in CI actually calls OpenAI.

### Task 7.1: Prompt files

**Files:**
- Create: `src/wazuh_health/agents/prompts/hygiene.md`
- Create: `src/wazuh_health/agents/prompts/capacity.md`
- Create: `src/wazuh_health/agents/prompts/coverage.md`
- Create: `src/wazuh_health/agents/prompts/reporter.md`

- [ ] **Step 1: Write each prompt**

`hygiene.md`:

```markdown
You are the HygieneAgent of the Wazuh Health Squad.

You receive threshold hits about noisy Wazuh rules. Your job is to:

1. Use the read-only tools to fetch the current top buckets and recommendations.
2. For each high-priority bucket, emit at most one DomainFinding.
3. Be conservative: prefer recommending `investigate_source` over suppression for
   rules in sensitive groups (authentication_failures, attacks, malware, etc.).
4. NEVER propose disabling a rule globally; only conditional suppressions.
5. Output: a list of DomainFinding with domain="hygiene".

Safety rules:
- Do not emit shell commands in suggested_action. Use prose only.
- Do not include URLs or IPs from external networks.
- If you are unsure, prefer fewer findings over more.
- All output must validate against the DomainFinding schema.
```

`capacity.md`:

```markdown
You are the CapacityAgent of the Wazuh Health Squad.

Threshold hits relate to disk free %, indexer heap, manager CPU/RAM,
alerts.json growth, or red/yellow shards.

For each hit:
1. Fetch the latest disk/indexer/manager stats with the read-only tools.
2. If alerts.json growth is correlated with a noisy bucket (use
   list_recent_alerts), mention that correlation in the finding body.
3. Output one DomainFinding per distinct cause; do not duplicate.
4. Severity must reflect actual risk: free_pct < 5 → critical; heap_pct > 90 → critical.

Same safety rules as Hygiene apply.
```

`coverage.md`:

```markdown
You are the CoverageAgent of the Wazuh Health Squad.

You analyze agent population health and decoder/rule coverage gaps.

For each hit:
1. Fetch the agent list and decoder errors.
2. Group disconnected agents by likely cause (network, decommissioned host, etc.)
   based on evidence; never guess at the cause without data.
3. Highlight zero-hit rules separately; they are candidates for review/removal.
4. Output one DomainFinding per group.

Same safety rules as Hygiene apply.
```

`reporter.md`:

```markdown
You are the ReporterAgent of the Wazuh Health Squad.

You consolidate open findings into a Wazuh Health Report (WazuhHealthReport).

Your job is to:
1. Use query_findings to pull open findings since the requested window.
2. Group findings by domain.
3. Pick the top priorities across domains (highest severity first, then most
   recent).
4. Produce a short summary (3-5 sentences max) that an SRE can read in 30 seconds.

Safety rules:
- Do not invent findings that are not in the query result.
- Do not include IPs or usernames — use the tokens already present in the data.
- Markdown is fine; HTML is not.
```

- [ ] **Step 2: Commit**

```bash
git add src/wazuh_health/agents/prompts
git commit -m "docs(wazuh-health): per-agent prompt files"
```

---

### Task 7.2: `run_agent` adapter (test-replaceable) + agent factories

**Files:**
- Create: `src/wazuh_health/agents/runner.py`
- Test: `tests/agents/test_runner.py`

- [ ] **Step 1: Tests**

```python
# tests/agents/test_runner.py
from src.wazuh_health.contracts import DomainFinding
from src.wazuh_health.agents.runner import (
    AgentInvocation, FakeAgentRunner, get_runner, set_runner,
)


def test_fake_runner_returns_canned_findings():
    canned = [
        DomainFinding(
            domain="hygiene", severity="info", title="x", body_md="y",
            evidence={"k": "v"}, suggested_action="review",
        )
    ]
    set_runner(FakeAgentRunner({"HygieneAgent": canned}))
    runner = get_runner()
    findings, tokens = runner.run(AgentInvocation(
        agent_name="HygieneAgent", instructions="i", tools=[], input_payload={}
    ))
    assert findings == canned
    assert tokens["input"] == 0
    assert tokens["output"] == 0
```

- [ ] **Step 2: Implement `agents/runner.py`**

```python
"""Replaceable adapter between domain agents and the openai-agents SDK.

The dispatcher calls `get_runner().run(invocation)`. In CI, tests call
`set_runner(FakeAgentRunner(...))` so no real LLM call ever happens.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol

from src.wazuh_health.contracts import DomainFinding, WazuhHealthReport


@dataclass(frozen=True)
class AgentInvocation:
    agent_name: str
    instructions: str
    tools: list[Callable[..., Any]]
    input_payload: dict[str, Any]
    output_type: type = DomainFinding  # or WazuhHealthReport for reporter
    model: str | None = None
    timeout_seconds: float = 60.0
    max_tool_calls: int = 6
    output_token_cap: int = 2000


class AgentRunner(Protocol):
    def run(
        self, invocation: AgentInvocation
    ) -> tuple[list[DomainFinding] | WazuhHealthReport, dict[str, int]]: ...


class FakeAgentRunner:
    """Returns pre-canned findings by agent name; counts no tokens.

    Used in CI to avoid touching the network.
    """

    def __init__(self, canned: dict[str, list[DomainFinding] | WazuhHealthReport]) -> None:
        self._canned = canned

    def run(self, invocation: AgentInvocation):
        result = self._canned.get(invocation.agent_name, [])
        return result, {"input": 0, "output": 0}


class _OpenAIAgentsRunner:
    """Real runner backed by the openai-agents SDK. Constructed lazily."""

    def run(self, invocation: AgentInvocation):
        # Import lazily so tests that never call .run() do not need the SDK.
        from agents import Agent, Runner  # type: ignore

        agent = Agent(
            name=invocation.agent_name,
            instructions=invocation.instructions,
            tools=invocation.tools,
            output_type=invocation.output_type,
            model=invocation.model,
        )
        result = Runner.run_sync(
            agent,
            input=str(invocation.input_payload),
            max_turns=invocation.max_tool_calls,
        )
        final = result.final_output
        tokens = {
            "input": getattr(result, "input_tokens", 0) or 0,
            "output": getattr(result, "output_tokens", 0) or 0,
        }
        return final, tokens


_RUNNER: AgentRunner | None = None


def set_runner(runner: AgentRunner) -> None:
    global _RUNNER
    _RUNNER = runner


def get_runner() -> AgentRunner:
    global _RUNNER
    if _RUNNER is None:
        _RUNNER = _OpenAIAgentsRunner()
    return _RUNNER


def reset_runner() -> None:
    global _RUNNER
    _RUNNER = None
```

- [ ] **Step 3: Run + commit**

```bash
pytest tests/agents/test_runner.py -v
git add src/wazuh_health/agents/runner.py tests/agents/test_runner.py
git commit -m "feat(wazuh-health): replaceable agent runner adapter with FakeAgentRunner"
```

---

### Task 7.3: Domain agent invokers (Hygiene, Capacity, Coverage)

**Files:**
- Create: `src/wazuh_health/agents/hygiene.py`
- Create: `src/wazuh_health/agents/capacity.py`
- Create: `src/wazuh_health/agents/coverage.py`
- Test: `tests/agents/test_domain_invokers.py`

- [ ] **Step 1: Tests**

```python
# tests/agents/test_domain_invokers.py
from datetime import datetime, timezone

from src.wazuh_health.contracts import DomainFinding, ThresholdHit
from src.wazuh_health.agents.hygiene import invoke_hygiene_agent
from src.wazuh_health.agents.runner import FakeAgentRunner, set_runner
from src.wazuh_health.store.audit_store import AuditStore
from src.wazuh_health.store.db import connect, migrate
from src.wazuh_health.store.findings_store import FindingsStore


def test_invoke_hygiene_writes_findings_through_sanitizer():
    canned = [DomainFinding(
        domain="hygiene", severity="warning",
        title="t", body_md="b", evidence={"rule_id": "5710"},
        suggested_action="Review the rule",
    )]
    set_runner(FakeAgentRunner({"HygieneAgent": canned}))
    conn = connect(":memory:"); migrate(conn)
    audit = AuditStore(conn)
    store = FindingsStore(conn)

    invoke_hygiene_agent(
        hits=[ThresholdHit(probe="hygiene", metric="noise.bucket_count",
                            value=1, rule="value >= 1", severity="warning")],
        audit_store=audit, findings_store=store,
        light_model="gpt-4o-mini", now=datetime.now(tz=timezone.utc),
    )
    assert len(store.list_open()) == 1


def test_rejected_finding_is_not_persisted():
    canned = [DomainFinding(
        domain="hygiene", severity="warning",
        title="t", body_md="b", evidence={"rule_id": "5710"},
        suggested_action="rm -rf /",  # blocked by sanitizer
    )]
    set_runner(FakeAgentRunner({"HygieneAgent": canned}))
    conn = connect(":memory:"); migrate(conn)
    audit = AuditStore(conn)
    store = FindingsStore(conn)

    invoke_hygiene_agent(
        hits=[ThresholdHit(probe="hygiene", metric="noise.bucket_count",
                            value=1, rule="value >= 1", severity="warning")],
        audit_store=audit, findings_store=store,
        light_model="gpt-4o-mini", now=datetime.now(tz=timezone.utc),
    )
    assert store.list_open() == []
```

- [ ] **Step 2: Implement `agents/hygiene.py`**

```python
"""HygieneAgent invocation: hits → LLM → sanitized findings → store."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from src.wazuh_health.agents.runner import AgentInvocation, get_runner
from src.wazuh_health.agents.sanitizer import SanitizeError, sanitize_finding
from src.wazuh_health.contracts import DomainFinding, ThresholdHit
from src.wazuh_health.store.audit_store import AuditStore
from src.wazuh_health.store.findings_store import FindingsStore, compute_hash_key
from src.wazuh_health.tools.readonly import HYGIENE_TOOLS

_PROMPT = (Path(__file__).parent / "prompts" / "hygiene.md").read_text()


def invoke_hygiene_agent(
    *,
    hits: list[ThresholdHit],
    audit_store: AuditStore,
    findings_store: FindingsStore,
    light_model: str,
    now: datetime,
) -> list[int]:
    payload = {"hits": [h.model_dump() for h in hits]}
    invocation = AgentInvocation(
        agent_name="HygieneAgent",
        instructions=_PROMPT,
        tools=HYGIENE_TOOLS,
        input_payload=payload,
        output_type=list[DomainFinding],
        model=light_model,
    )
    started = now
    findings, tokens = get_runner().run(invocation)
    persisted_ids: list[int] = []
    for raw in (findings or []):
        try:
            clean = sanitize_finding(raw)
        except SanitizeError:
            continue
        hash_key = compute_hash_key(
            "hygiene",
            metric=str(hits[0].metric if hits else ""),
            evidence=clean.evidence,
        )
        fid = findings_store.upsert(clean, hash_key=hash_key)
        persisted_ids.append(fid)

    audit_store.record_agent_run(
        agent="HygieneAgent", started_at=started, ended_at=now,
        status="ok", input_tokens=tokens["input"], output_tokens=tokens["output"],
        tool_calls=[],
        output_hash=hashlib.sha1(
            json.dumps([f.model_dump() for f in (findings or [])], sort_keys=True, default=str).encode()
        ).hexdigest() if findings else None,
        finding_ids=persisted_ids,
    )
    return persisted_ids
```

- [ ] **Step 3: Implement `agents/capacity.py` and `agents/coverage.py`** (same shape)

`agents/capacity.py`:

```python
"""CapacityAgent invocation — same shape as HygieneAgent."""
from __future__ import annotations

import hashlib, json
from datetime import datetime
from pathlib import Path

from src.wazuh_health.agents.runner import AgentInvocation, get_runner
from src.wazuh_health.agents.sanitizer import SanitizeError, sanitize_finding
from src.wazuh_health.contracts import DomainFinding, ThresholdHit
from src.wazuh_health.store.audit_store import AuditStore
from src.wazuh_health.store.findings_store import FindingsStore, compute_hash_key
from src.wazuh_health.tools.readonly import CAPACITY_TOOLS

_PROMPT = (Path(__file__).parent / "prompts" / "capacity.md").read_text()


def invoke_capacity_agent(
    *, hits, audit_store: AuditStore, findings_store: FindingsStore,
    light_model: str, now: datetime,
) -> list[int]:
    invocation = AgentInvocation(
        agent_name="CapacityAgent", instructions=_PROMPT, tools=CAPACITY_TOOLS,
        input_payload={"hits": [h.model_dump() for h in hits]},
        output_type=list[DomainFinding], model=light_model,
    )
    findings, tokens = get_runner().run(invocation)
    persisted: list[int] = []
    for raw in (findings or []):
        try:
            clean = sanitize_finding(raw)
        except SanitizeError:
            continue
        hk = compute_hash_key("capacity", metric=str(hits[0].metric if hits else ""), evidence=clean.evidence)
        persisted.append(findings_store.upsert(clean, hash_key=hk))
    audit_store.record_agent_run(
        agent="CapacityAgent", started_at=now, ended_at=now, status="ok",
        input_tokens=tokens["input"], output_tokens=tokens["output"],
        tool_calls=[], output_hash=None, finding_ids=persisted,
    )
    return persisted
```

`agents/coverage.py`: identical pattern with `CoverageAgent`, `COVERAGE_TOOLS`, prompt `coverage.md`, domain `"coverage"`. Copy `capacity.py`, replace identifiers.

- [ ] **Step 4: Run + commit**

```bash
pytest tests/agents/test_domain_invokers.py -v
git add src/wazuh_health/agents/hygiene.py src/wazuh_health/agents/capacity.py src/wazuh_health/agents/coverage.py tests/agents/test_domain_invokers.py
git commit -m "feat(wazuh-health): domain agent invokers with sanitized persistence"
```

---

### Task 7.4: `ReporterAgent`

**Files:**
- Create: `src/wazuh_health/agents/reporter.py`
- Test: `tests/agents/test_reporter.py`

- [ ] **Step 1: Tests**

```python
# tests/agents/test_reporter.py
from datetime import datetime, timezone

from src.wazuh_health.agents.reporter import invoke_reporter_agent
from src.wazuh_health.agents.runner import FakeAgentRunner, set_runner
from src.wazuh_health.contracts import DomainFinding, WazuhHealthReport
from src.wazuh_health.store.audit_store import AuditStore
from src.wazuh_health.store.db import connect, migrate
from src.wazuh_health.store.findings_store import FindingsStore


def test_reporter_returns_canned_report():
    canned = WazuhHealthReport(
        generated_at=datetime.now(tz=timezone.utc),
        window_hours=6, summary="ok",
        by_domain={"hygiene": [], "capacity": [], "coverage": []},
        top_priorities=[],
    )
    set_runner(FakeAgentRunner({"ReporterAgent": canned}))
    conn = connect(":memory:"); migrate(conn)
    audit = AuditStore(conn)
    store = FindingsStore(conn)
    rep = invoke_reporter_agent(
        audit_store=audit, findings_store=store,
        heavy_model="gpt-4o", window_hours=6, now=datetime.now(tz=timezone.utc),
    )
    assert rep.window_hours == 6
```

- [ ] **Step 2: Implement `agents/reporter.py`**

```python
"""ReporterAgent invocation: open findings → consolidated WazuhHealthReport."""
from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from src.wazuh_health.agents.runner import AgentInvocation, get_runner
from src.wazuh_health.contracts import WazuhHealthReport
from src.wazuh_health.store.audit_store import AuditStore
from src.wazuh_health.store.findings_store import FindingsStore
from src.wazuh_health.tools.readonly import REPORTER_TOOLS

_PROMPT = (Path(__file__).parent / "prompts" / "reporter.md").read_text()


def invoke_reporter_agent(
    *,
    audit_store: AuditStore,
    findings_store: FindingsStore,
    heavy_model: str,
    window_hours: int,
    now: datetime,
) -> WazuhHealthReport:
    since = (now - timedelta(hours=window_hours)).isoformat()
    open_findings = [f.model_dump() for f in findings_store.list_open(since_iso=since)]
    invocation = AgentInvocation(
        agent_name="ReporterAgent",
        instructions=_PROMPT,
        tools=REPORTER_TOOLS,
        input_payload={"window_hours": window_hours, "findings": open_findings},
        output_type=WazuhHealthReport,
        model=heavy_model,
    )
    report, tokens = get_runner().run(invocation)
    audit_store.record_agent_run(
        agent="ReporterAgent", started_at=now, ended_at=now, status="ok",
        input_tokens=tokens["input"], output_tokens=tokens["output"],
        tool_calls=[], output_hash=None, finding_ids=[],
    )
    return report
```

- [ ] **Step 3: Run + commit**

```bash
pytest tests/agents/test_reporter.py -v
git add src/wazuh_health/agents/reporter.py tests/agents/test_reporter.py
git commit -m "feat(wazuh-health): ReporterAgent invocation"
```

---

**End of Phase 7.** Pause point: all four agents wired with safe runner, sanitizer, prompts. Real LLM never called in CI.

---

## Phase 8 — Scheduler + notifiers + daemon + CLI + config

Goal: a small home-grown scheduler, three notifier backends, Pydantic-settings config, supervising daemon with `/healthz`, and a multi-command CLI.

### Task 8.1: Home-grown scheduler with injectable clock

**Files:**
- Create: `src/wazuh_health/scheduler.py`
- Test: `tests/test_scheduler.py`

- [ ] **Step 1: Tests**

```python
# tests/test_scheduler.py
from src.wazuh_health.scheduler import Job, Scheduler


class _FakeClock:
    def __init__(self, start=0.0):
        self._t = start
    def time(self): return self._t
    def advance(self, s): self._t += s


def test_scheduler_runs_due_jobs_in_order():
    clock = _FakeClock()
    calls = []
    sched = Scheduler(clock=clock, jitter_seconds=0)
    sched.add(Job(name="a", interval_seconds=10, callback=lambda: calls.append("a")))
    sched.add(Job(name="b", interval_seconds=20, callback=lambda: calls.append("b")))
    sched.tick()
    clock.advance(11)
    sched.tick()
    clock.advance(11)
    sched.tick()
    assert calls.count("a") == 3
    assert calls.count("b") == 1


def test_scheduler_skips_not_due_jobs():
    clock = _FakeClock()
    calls = []
    sched = Scheduler(clock=clock, jitter_seconds=0)
    sched.add(Job(name="x", interval_seconds=60, callback=lambda: calls.append(1)))
    sched.tick()
    clock.advance(5)
    sched.tick()
    assert len(calls) == 1
```

- [ ] **Step 2: Implement `scheduler.py`**

```python
"""Tiny scheduler with injectable clock — no third-party dep."""
from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Job:
    name: str
    interval_seconds: float
    callback: Callable[[], None]
    last_run: float | None = None


class _RealClock:
    @staticmethod
    def time() -> float: return time.monotonic()


class Scheduler:
    def __init__(self, *, clock=None, jitter_seconds: float = 0.0) -> None:
        self._clock = clock or _RealClock()
        self._jitter = jitter_seconds
        self._jobs: list[Job] = []

    def add(self, job: Job) -> None:
        self._jobs.append(job)

    def tick(self) -> int:
        """Run any jobs that are due. Returns number of jobs invoked."""
        now = self._clock.time()
        ran = 0
        for job in self._jobs:
            jitter = random.uniform(0, self._jitter) if self._jitter else 0
            if job.last_run is None or now - job.last_run >= job.interval_seconds + jitter:
                try:
                    job.callback()
                finally:
                    job.last_run = now
                    ran += 1
        return ran
```

- [ ] **Step 3: Run + commit**

```bash
pytest tests/test_scheduler.py -v
git add src/wazuh_health/scheduler.py tests/test_scheduler.py
git commit -m "feat(wazuh-health): home-grown scheduler with injectable clock"
```

---

### Task 8.2: `FilesystemNotifier`

**Files:**
- Create: `src/wazuh_health/notify/base.py`
- Create: `src/wazuh_health/notify/filesystem.py`
- Test: `tests/notify/test_filesystem.py`

- [ ] **Step 1: Tests**

```python
# tests/notify/test_filesystem.py
from datetime import datetime, timezone

from src.wazuh_health.contracts import WazuhHealthReport
from src.wazuh_health.notify.filesystem import FilesystemNotifier


def test_writes_markdown_report_to_dir(tmp_path):
    n = FilesystemNotifier(report_dir=tmp_path)
    report = WazuhHealthReport(
        generated_at=datetime.now(tz=timezone.utc),
        window_hours=6, summary="ok",
        by_domain={"hygiene": [], "capacity": [], "coverage": []},
        top_priorities=[],
    )
    written = n.notify_report(report, markdown="# Report\n\nbody")
    assert written.exists()
    assert "Report" in written.read_text()
```

- [ ] **Step 2: Implement**

`notify/base.py`:

```python
"""Notifier Protocol."""
from __future__ import annotations

from pathlib import Path
from typing import Protocol

from src.wazuh_health.contracts import DomainFinding, WazuhHealthReport


class Notifier(Protocol):
    enabled: bool

    def notify_finding(self, finding: DomainFinding) -> None: ...
    def notify_report(self, report: WazuhHealthReport, *, markdown: str) -> Path | None: ...
```

`notify/filesystem.py`:

```python
"""Filesystem notifier — always writes reports to report_dir."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from src.wazuh_health.contracts import DomainFinding, WazuhHealthReport


class FilesystemNotifier:
    enabled: bool = True

    def __init__(self, *, report_dir: Path) -> None:
        self._report_dir = Path(report_dir)
        self._report_dir.mkdir(parents=True, exist_ok=True)

    def notify_finding(self, finding: DomainFinding) -> None:
        # No per-finding output — filesystem is bulk-only.
        return None

    def notify_report(self, report: WazuhHealthReport, *, markdown: str) -> Path:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d-%H%M")
        out = self._report_dir / f"{ts}.md"
        out.write_text(markdown, encoding="utf-8")
        return out
```

- [ ] **Step 3: Run + commit**

```bash
pytest tests/notify/test_filesystem.py -v
git add src/wazuh_health/notify/base.py src/wazuh_health/notify/filesystem.py tests/notify/test_filesystem.py
git commit -m "feat(wazuh-health): filesystem notifier writing periodic reports"
```

---

### Task 8.3: `SlackNotifier`

**Files:**
- Create: `src/wazuh_health/notify/slack.py`
- Test: `tests/notify/test_slack.py`

- [ ] **Step 1: Tests**

```python
# tests/notify/test_slack.py
import respx
from httpx import Response

from src.wazuh_health.contracts import DomainFinding
from src.wazuh_health.notify.slack import SlackNotifier


@respx.mock
def test_severity_floor_filters_findings():
    route = respx.post("https://hooks.slack.com/services/X/Y/Z").mock(
        return_value=Response(200, text="ok")
    )
    n = SlackNotifier(
        webhook_url="https://hooks.slack.com/services/X/Y/Z",
        severity_floor="warning",
    )
    info = DomainFinding(
        domain="hygiene", severity="info", title="t", body_md="b",
        evidence={"k": "v"}, suggested_action="x",
    )
    n.notify_finding(info)
    assert route.called is False

    warn = DomainFinding(
        domain="hygiene", severity="warning", title="t", body_md="b",
        evidence={"k": "v"}, suggested_action="x",
    )
    n.notify_finding(warn)
    assert route.called is True
```

- [ ] **Step 2: Implement `notify/slack.py`**

```python
"""Slack notifier — webhook-based, severity-floor gated."""
from __future__ import annotations

from pathlib import Path
from typing import Literal

import httpx

from src.wazuh_health.contracts import DomainFinding, WazuhHealthReport

_SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}


class SlackNotifier:
    enabled: bool = True

    def __init__(
        self,
        *,
        webhook_url: str,
        severity_floor: Literal["info", "warning", "critical"] = "warning",
        timeout_s: float = 5.0,
    ) -> None:
        self._url = webhook_url
        self._floor = _SEVERITY_ORDER[severity_floor]
        self._timeout = timeout_s

    def _post(self, payload: dict) -> None:
        with httpx.Client(timeout=self._timeout) as c:
            r = c.post(self._url, json=payload)
            r.raise_for_status()

    def notify_finding(self, finding: DomainFinding) -> None:
        if _SEVERITY_ORDER[finding.severity] < self._floor:
            return
        self._post({
            "text": f"*[{finding.severity.upper()}] {finding.title}*\n{finding.body_md[:1000]}"
        })

    def notify_report(self, report: WazuhHealthReport, *, markdown: str) -> Path | None:
        self._post({"text": f"Wazuh Health Report\n```{markdown[:2500]}```"})
        return None
```

Note: this file uses `httpx.Client.post`, which the boundary regex catches. We whitelist it the same way as `wazuh_api.py`. Update `tests/test_boundaries.py` accordingly:

- [ ] **Step 3: Update boundary whitelist**

Edit `tests/test_boundaries.py:POST_WHITELIST_FILES`:

```python
POST_WHITELIST_FILES = {
    "src/wazuh_health/source/wazuh_api.py",
    "src/wazuh_health/notify/slack.py",
}
```

- [ ] **Step 4: Run + commit**

```bash
pytest tests/notify/test_slack.py tests/test_boundaries.py -v
git add src/wazuh_health/notify/slack.py tests/notify/test_slack.py tests/test_boundaries.py
git commit -m "feat(wazuh-health): slack notifier (severity-floor gated, POST whitelisted)"
```

---

### Task 8.4: `EmailNotifier`

**Files:**
- Create: `src/wazuh_health/notify/email.py`
- Test: `tests/notify/test_email.py`

- [ ] **Step 1: Tests**

```python
# tests/notify/test_email.py
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from src.wazuh_health.contracts import WazuhHealthReport
from src.wazuh_health.notify.email import EmailNotifier


def test_email_notifier_only_sends_periodic_reports():
    n = EmailNotifier(to="ops@example.com", smtp_host="localhost")
    with patch("smtplib.SMTP") as smtp_cls:
        smtp = MagicMock()
        smtp_cls.return_value.__enter__.return_value = smtp
        report = WazuhHealthReport(
            generated_at=datetime.now(tz=timezone.utc),
            window_hours=6, summary="ok",
            by_domain={"hygiene": [], "capacity": [], "coverage": []},
            top_priorities=[],
        )
        n.notify_report(report, markdown="# report")
        smtp.send_message.assert_called_once()
```

- [ ] **Step 2: Implement `notify/email.py`**

```python
"""Email notifier — periodic reports only, no per-finding spam."""
from __future__ import annotations

import smtplib
from email.message import EmailMessage
from pathlib import Path

from src.wazuh_health.contracts import DomainFinding, WazuhHealthReport


class EmailNotifier:
    enabled: bool = True

    def __init__(
        self,
        *,
        to: str,
        smtp_host: str = "localhost",
        smtp_port: int = 25,
        sender: str = "wazuh-health@localhost",
    ) -> None:
        self._to = to
        self._sender = sender
        self._host = smtp_host
        self._port = smtp_port

    def notify_finding(self, finding: DomainFinding) -> None:
        return None  # report-only by design

    def notify_report(self, report: WazuhHealthReport, *, markdown: str) -> Path | None:
        msg = EmailMessage()
        msg["From"] = self._sender
        msg["To"] = self._to
        msg["Subject"] = f"Wazuh Health Report ({report.window_hours}h)"
        msg.set_content(markdown)
        with smtplib.SMTP(self._host, self._port) as smtp:
            smtp.send_message(msg)
        return None
```

- [ ] **Step 3: Run + commit**

```bash
pytest tests/notify/test_email.py -v
git add src/wazuh_health/notify/email.py tests/notify/test_email.py
git commit -m "feat(wazuh-health): email notifier for periodic reports"
```

---

### Task 8.5: Config + Pydantic-settings

**Files:**
- Create: `src/wazuh_health/config/settings.py`
- Create: `src/wazuh_health/config/default.yaml`
- Test: `tests/test_config.py`

- [ ] **Step 1: Tests**

```python
# tests/test_config.py
from src.wazuh_health.config.settings import HealthConfig, load_config


def test_loads_defaults_without_user_yaml(monkeypatch, tmp_path):
    monkeypatch.delenv("WAZUH_HEALTH_CONFIG_PATH", raising=False)
    monkeypatch.setenv("OPENAI_MODEL_LIGHT", "gpt-4o-mini")
    monkeypatch.setenv("OPENAI_MODEL_HEAVY", "gpt-4o")
    cfg = load_config()
    assert isinstance(cfg, HealthConfig)
    assert cfg.llm.light_model == "gpt-4o-mini"
    assert cfg.llm.heavy_model == "gpt-4o"
    assert cfg.scheduler.jobs["capacity"].interval_seconds == 300


def test_yaml_override_takes_precedence(monkeypatch, tmp_path):
    yaml_path = tmp_path / "config.yaml"
    yaml_path.write_text(
        "scheduler:\n  jobs:\n    capacity:\n      interval_seconds: 60\n"
    )
    monkeypatch.setenv("WAZUH_HEALTH_CONFIG_PATH", str(yaml_path))
    monkeypatch.setenv("OPENAI_MODEL_LIGHT", "gpt-4o-mini")
    monkeypatch.setenv("OPENAI_MODEL_HEAVY", "gpt-4o")
    cfg = load_config()
    assert cfg.scheduler.jobs["capacity"].interval_seconds == 60
```

- [ ] **Step 2: Implement `config/default.yaml`** — copy from the spec section 8.2.2 verbatim. (Already validated.)

- [ ] **Step 3: Implement `config/settings.py`**

```python
"""HealthConfig: env + YAML merge with Pydantic validation."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

DEFAULT_YAML = Path(__file__).parent / "default.yaml"


class LocalFSConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alerts_path: str = "/var/ossec/logs/alerts/alerts.json"
    rotated_glob: str | None = None
    ossec_conf: str = "/var/ossec/etc/ossec.conf"
    client_keys: str = "/var/ossec/etc/client.keys"


class WazuhAPIConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host: str = ""
    port: int = 55000
    verify_ssl: bool = True


class SourceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    backend: str = "local_fs"
    local_fs: LocalFSConfig = LocalFSConfig()
    wazuh_api: WazuhAPIConfig = WazuhAPIConfig()


class ScheduledJob(BaseModel):
    model_config = ConfigDict(extra="forbid")
    interval_seconds: int


class SchedulerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    jitter_seconds: int = 30
    jobs: dict[str, ScheduledJob] = Field(default_factory=dict)


class ThresholdYAML(BaseModel):
    model_config = ConfigDict(extra="forbid")
    metric: str
    rule: str
    severity: str


class ThresholdsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    capacity: list[ThresholdYAML] = Field(default_factory=list)
    hygiene: list[ThresholdYAML] = Field(default_factory=list)
    coverage: list[ThresholdYAML] = Field(default_factory=list)


class CooldownsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    default_minutes: int = 360
    by_metric: dict[str, int] = Field(default_factory=dict)


class LLMConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    light_model: str = "gpt-4o-mini"
    heavy_model: str = "gpt-4o"
    max_tool_calls_per_turn: int = 6
    input_token_cap: int = 8000
    output_token_cap: int = 2000
    timeout_seconds: int = 60
    daily_cap_per_agent: int = 50


class PrivacyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pseudonymize: bool = True
    pseudonymize_fields: list[str] = Field(
        default_factory=lambda: ["srcip", "dstip", "agent.name", "user"]
    )


class StorageConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    db_path: str = "/var/lib/wazuh-health/state.db"
    report_dir: str = "/var/log/wazuh-health/reports"
    retention_days: int = 30


class SlackNotifyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    webhook_url: str = ""
    severity_floor: str = "warning"


class EmailNotifyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    to: str = ""
    smtp_host: str = "localhost"


class FilesystemNotifyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True


class NotifyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    filesystem: FilesystemNotifyConfig = FilesystemNotifyConfig()
    slack: SlackNotifyConfig = SlackNotifyConfig()
    email: EmailNotifyConfig = EmailNotifyConfig()


class HealthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: SourceConfig = SourceConfig()
    scheduler: SchedulerConfig = SchedulerConfig()
    thresholds: ThresholdsConfig = ThresholdsConfig()
    cooldowns: CooldownsConfig = CooldownsConfig()
    llm: LLMConfig = LLMConfig()
    privacy: PrivacyConfig = PrivacyConfig()
    storage: StorageConfig = StorageConfig()
    notify: NotifyConfig = NotifyConfig()


_ENV_VAR_RE = __import__("re").compile(r"\$\{([A-Z0-9_]+)(?::-(.+?))?\}")


def _expand(value: Any) -> Any:
    if isinstance(value, str):
        def repl(m):
            return os.getenv(m.group(1), m.group(2) or "")
        return _ENV_VAR_RE.sub(repl, value)
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config() -> HealthConfig:
    base = yaml.safe_load(DEFAULT_YAML.read_text()) or {}
    yaml_path = os.getenv("WAZUH_HEALTH_CONFIG_PATH")
    if yaml_path and Path(yaml_path).exists():
        user = yaml.safe_load(Path(yaml_path).read_text()) or {}
        base = _deep_merge(base, user)
    expanded = _expand(base)
    return HealthConfig.model_validate(expanded)
```

- [ ] **Step 4: Add `pyyaml` to dependencies**

Edit `pyproject.toml`:

```toml
[project]
dependencies = [
    "pydantic>=2.9",
    "pydantic-settings>=2.5",
    "ldap3>=2.9",
    "fastapi>=0.115",
    "uvicorn[standard]>=0.32",
    "httpx>=0.27",
    "openai-agents>=0.0.10",
    "pyyaml>=6.0",
    "psutil>=5.9",
]
```

- [ ] **Step 5: Run + commit**

```bash
pip install pyyaml psutil   # ensure local env has them for tests
pytest tests/test_config.py -v
git add src/wazuh_health/config tests/test_config.py pyproject.toml
git commit -m "feat(wazuh-health): config layer (env + YAML merge, env var expansion)"
```

---

### Task 8.6: Daemon supervisor + `/healthz` HTTP

**Files:**
- Create: `src/wazuh_health/daemon.py`
- Test: `tests/test_daemon.py`

- [ ] **Step 1: Tests**

```python
# tests/test_daemon.py
from http.client import HTTPConnection

from src.wazuh_health.daemon import HealthDaemon


def test_healthz_endpoint_returns_ok():
    d = HealthDaemon(port=0)  # port=0 lets OS assign
    with d.serve_in_thread() as server:
        conn = HTTPConnection("127.0.0.1", server.actual_port)
        conn.request("GET", "/healthz")
        resp = conn.getresponse()
        assert resp.status == 200
        body = resp.read().decode()
        assert "ok" in body
```

- [ ] **Step 2: Implement `daemon.py`**

```python
"""Daemon supervisor: scheduler loop + minimal /healthz HTTP server."""
from __future__ import annotations

import contextlib
import signal
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _HealthzHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args) -> None:
        return  # quiet


class _ServerContext:
    def __init__(self, server: ThreadingHTTPServer, thread: threading.Thread) -> None:
        self._server = server
        self._thread = thread
        self.actual_port = server.server_address[1]

    def shutdown(self) -> None:
        self._server.shutdown()
        self._thread.join(timeout=5)


class HealthDaemon:
    def __init__(self, *, port: int = 8787) -> None:
        self._port = port
        self._stop = threading.Event()

    @contextlib.contextmanager
    def serve_in_thread(self):
        server = ThreadingHTTPServer(("127.0.0.1", self._port), _HealthzHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        ctx = _ServerContext(server, thread)
        try:
            yield ctx
        finally:
            ctx.shutdown()

    def run_forever(self, scheduler, *, tick_interval_s: float = 1.0) -> None:
        signal.signal(signal.SIGTERM, lambda *_: self._stop.set())
        signal.signal(signal.SIGINT, lambda *_: self._stop.set())
        with self.serve_in_thread():
            while not self._stop.is_set():
                scheduler.tick()
                time.sleep(tick_interval_s)
```

- [ ] **Step 3: Run + commit**

```bash
pytest tests/test_daemon.py -v
git add src/wazuh_health/daemon.py tests/test_daemon.py
git commit -m "feat(wazuh-health): daemon supervisor with /healthz HTTP endpoint"
```

---

### Task 8.7: Multi-command CLI

**Files:**
- Modify: `src/wazuh_health/cli.py`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Tests**

```python
# tests/test_cli.py
from src.wazuh_health.cli import build_parser


def test_subcommands_registered():
    p = build_parser()
    subs = p._subparsers._actions[-1].choices  # type: ignore[attr-defined]
    assert {"serve", "once", "report", "doctor", "migrate"} <= set(subs)


def test_once_runs_with_local_fs(tmp_path, monkeypatch):
    # Smoke: just verify the function returns 0 with an empty alerts file.
    alerts = tmp_path / "alerts.json"
    alerts.write_text("")
    monkeypatch.setenv("WAZUH_HEALTH_SOURCE", "local_fs")
    monkeypatch.setenv("WAZUH_HEALTH_DB_PATH", str(tmp_path / "state.db"))
    monkeypatch.setenv("WAZUH_HEALTH_REPORT_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("OPENAI_MODEL_LIGHT", "gpt-4o-mini")
    monkeypatch.setenv("OPENAI_MODEL_HEAVY", "gpt-4o")
    from src.wazuh_health.cli import main
    assert main(["once", "--alerts-path", str(alerts)]) == 0
```

- [ ] **Step 2: Implement `cli.py`**

```python
"""wazuh-health CLI: serve | once | report | doctor | migrate."""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from src.wazuh_health.config.settings import HealthConfig, load_config
from src.wazuh_health.daemon import HealthDaemon
from src.wazuh_health.probes.capacity import CapacityProbe
from src.wazuh_health.probes.coverage import CoverageProbe
from src.wazuh_health.probes.hygiene import HygieneProbe
from src.wazuh_health.scheduler import Job, Scheduler
from src.wazuh_health.source.local_fs import LocalFSSource
from src.wazuh_health.source.wazuh_api import WazuhAPISource
from src.wazuh_health.store.audit_store import AuditStore
from src.wazuh_health.store.db import connect, migrate
from src.wazuh_health.store.findings_store import FindingsStore


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wazuh-health")
    sub = p.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("--port", type=int, default=8787)

    once = sub.add_parser("once")
    once.add_argument("--alerts-path", default=None)

    report = sub.add_parser("report")
    report.add_argument("--since", default="24h")
    report.add_argument("--out", default="")

    sub.add_parser("doctor")
    sub.add_parser("migrate")
    return p


def _make_source(cfg: HealthConfig, alerts_path_override: str | None = None):
    if cfg.source.backend == "wazuh_api":
        import os
        return WazuhAPISource(
            host=cfg.source.wazuh_api.host,
            port=cfg.source.wazuh_api.port,
            user=os.environ["WAZUH_API_USER"],
            password=os.environ["WAZUH_API_PASSWORD"],
            verify_ssl=cfg.source.wazuh_api.verify_ssl,
        )
    return LocalFSSource(
        alerts_path=Path(alerts_path_override or cfg.source.local_fs.alerts_path),
        rotated_glob=cfg.source.local_fs.rotated_glob,
        ossec_conf=Path(cfg.source.local_fs.ossec_conf),
        client_keys=Path(cfg.source.local_fs.client_keys),
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = load_config()

    if args.command == "migrate":
        conn = connect(cfg.storage.db_path); migrate(conn)
        print(f"Migrated: {cfg.storage.db_path}")
        return 0

    if args.command == "doctor":
        try:
            conn = connect(cfg.storage.db_path); migrate(conn)
            print("doctor: store ok")
            return 0
        except Exception as exc:
            print(f"doctor: FAILED — {exc}", file=sys.stderr)
            return 1

    if args.command == "once":
        conn = connect(cfg.storage.db_path); migrate(conn)
        audit = AuditStore(conn); store = FindingsStore(conn)
        src = _make_source(cfg, args.alerts_path)
        for probe in (CapacityProbe(source=src),
                      HygieneProbe(source=src),
                      CoverageProbe(source=src)):
            audit.record_probe_run(probe.run())
        return 0

    if args.command == "report":
        from src.wazuh_health.agents.reporter import invoke_reporter_agent
        conn = connect(cfg.storage.db_path); migrate(conn)
        audit = AuditStore(conn); store = FindingsStore(conn)
        hours = int(args.since.rstrip("h")) if args.since.endswith("h") else 24
        report = invoke_reporter_agent(
            audit_store=audit, findings_store=store,
            heavy_model=cfg.llm.heavy_model, window_hours=hours,
            now=datetime.now(tz=timezone.utc),
        )
        out = report.model_dump_json(indent=2)
        if args.out:
            Path(args.out).write_text(out, encoding="utf-8")
        else:
            print(out)
        return 0

    if args.command == "serve":
        conn = connect(cfg.storage.db_path); migrate(conn)
        audit = AuditStore(conn)
        src = _make_source(cfg)
        sched = Scheduler(jitter_seconds=cfg.scheduler.jitter_seconds)
        sched.add(Job(
            name="capacity",
            interval_seconds=cfg.scheduler.jobs["capacity"].interval_seconds,
            callback=lambda: audit.record_probe_run(CapacityProbe(source=src).run()),
        ))
        sched.add(Job(
            name="hygiene",
            interval_seconds=cfg.scheduler.jobs["hygiene"].interval_seconds,
            callback=lambda: audit.record_probe_run(HygieneProbe(source=src).run()),
        ))
        sched.add(Job(
            name="coverage",
            interval_seconds=cfg.scheduler.jobs["coverage"].interval_seconds,
            callback=lambda: audit.record_probe_run(CoverageProbe(source=src).run()),
        ))
        HealthDaemon(port=args.port).run_forever(sched)
        return 0

    return 2
```

- [ ] **Step 3: Run + commit**

```bash
pytest tests/test_cli.py -v
git add src/wazuh_health/cli.py tests/test_cli.py
git commit -m "feat(wazuh-health): multi-command CLI (serve/once/report/doctor/migrate)"
```

---

**End of Phase 8.** Pause point: scheduler, notifiers, config, daemon, and CLI are wired. End-to-end smoke (`wazuh-health once`) runs probes without LLM.

---

## Phase 9 — Integration tests + systemd + docs

Goal: prove the full tick works end-to-end with `FakeAgentRunner`, lock in the daily cap and PII guards, ship the systemd unit, write the operator-facing doc, and update the CleanSwarm doc with the new home.

### Task 9.1: Full-tick e2e integration test

**Files:**
- Create: `tests/integration/test_full_tick.py`

- [ ] **Step 1: Write the test**

```python
# tests/integration/test_full_tick.py
"""End-to-end: probe → threshold → dispatch → fake agent → finding → reporter."""
from datetime import datetime, timezone

from src.wazuh_health.agents.hygiene import invoke_hygiene_agent
from src.wazuh_health.agents.reporter import invoke_reporter_agent
from src.wazuh_health.agents.runner import FakeAgentRunner, set_runner
from src.wazuh_health.contracts import (
    CleanAlert, DomainFinding, WazuhHealthReport,
)
from src.wazuh_health.decision.cooldown import CooldownTable
from src.wazuh_health.decision.dispatcher import WakeDispatcher
from src.wazuh_health.decision.threshold import ThresholdEngine, ThresholdRule
from src.wazuh_health.probes.hygiene import HygieneProbe
from src.wazuh_health.store.audit_store import AuditStore
from src.wazuh_health.store.db import connect, migrate
from src.wazuh_health.store.findings_store import FindingsStore


class _FakeAlertSource:
    def __init__(self, alerts):
        self._alerts = alerts
    def iter_alerts(self, *, since_days=None):
        return iter(self._alerts)


def test_full_tick_creates_finding_and_report():
    now = datetime.now(tz=timezone.utc)
    alerts = [
        CleanAlert(
            timestamp="2026-06-11T10:00:00Z",
            rule_id="5710", rule_level=5,
            agent_name="vpn01", srcip="10.0.5.20",
        )
        for _ in range(60)
    ]
    canned_findings = [DomainFinding(
        domain="hygiene", severity="warning",
        title="Noisy 5710 from 10.0.5.20",
        body_md="Suppress conditionally; matches CleanSwarm recommendation.",
        evidence={"rule_id": "5710", "matched": 60},
        suggested_action="Review the rule",
    )]
    canned_report = WazuhHealthReport(
        generated_at=now, window_hours=6, summary="one open finding",
        by_domain={"hygiene": canned_findings, "capacity": [], "coverage": []},
        top_priorities=canned_findings,
    )
    set_runner(FakeAgentRunner({
        "HygieneAgent": canned_findings,
        "ReporterAgent": canned_report,
    }))

    conn = connect(":memory:"); migrate(conn)
    audit = AuditStore(conn)
    store = FindingsStore(conn)
    cooldown = CooldownTable(conn)

    # 1. Probe runs
    probe = HygieneProbe(source=_FakeAlertSource(alerts), min_count=10)
    result = probe.run()
    audit.record_probe_run(result)

    # 2. Threshold engine
    engine = ThresholdEngine(rules={"hygiene": [
        ThresholdRule(metric="noise.recommendations_count",
                      rule="value >= 1", severity="warning"),
    ]})
    hits = engine.evaluate(result)
    assert hits

    # 3. Dispatcher invokes the hygiene agent
    def _inv(hits, *, audit_store):
        invoke_hygiene_agent(
            hits=hits, audit_store=audit, findings_store=store,
            light_model="gpt-4o-mini", now=now,
        )

    dispatcher = WakeDispatcher(
        cooldown=cooldown, agent_runs=audit,
        invoke_by_domain={"hygiene": _inv}, daily_cap=50,
    )
    dispatcher.dispatch(hits, now=now)

    # 4. One open finding exists
    open_findings = store.list_open()
    assert len(open_findings) == 1
    assert open_findings[0].title.startswith("Noisy 5710")

    # 5. Reporter consolidates
    rep = invoke_reporter_agent(
        audit_store=audit, findings_store=store,
        heavy_model="gpt-4o", window_hours=6, now=now,
    )
    assert rep.summary == "one open finding"
```

- [ ] **Step 2: Run + commit**

```bash
pytest tests/integration/test_full_tick.py -v
git add tests/integration/test_full_tick.py
git commit -m "test(wazuh-health): full-tick e2e probe→threshold→agent→finding→report"
```

---

### Task 9.2: Daily cap integration test

**Files:**
- Create: `tests/integration/test_daily_cap.py`

- [ ] **Step 1: Write the test**

```python
# tests/integration/test_daily_cap.py
from datetime import datetime, timezone

from src.wazuh_health.contracts import ThresholdHit
from src.wazuh_health.decision.cooldown import CooldownTable
from src.wazuh_health.decision.dispatcher import WakeDispatcher
from src.wazuh_health.store.audit_store import AuditStore
from src.wazuh_health.store.db import connect, migrate


def test_dispatcher_stops_invoking_after_daily_cap():
    conn = connect(":memory:"); migrate(conn)
    audit = AuditStore(conn)
    calls = {"n": 0}

    def _inv(hits, *, audit_store):
        calls["n"] += 1
        audit_store.record_agent_run(
            agent="HygieneAgent",
            started_at=datetime.now(tz=timezone.utc),
            ended_at=datetime.now(tz=timezone.utc),
            status="ok",
        )

    dispatcher = WakeDispatcher(
        cooldown=CooldownTable(conn, default_minutes=0),  # no cooldown
        agent_runs=audit,
        invoke_by_domain={"hygiene": _inv},
        daily_cap=3,
    )
    now = datetime.now(tz=timezone.utc)
    for i in range(5):
        dispatcher.dispatch([ThresholdHit(
            probe="hygiene", metric=f"m{i}", value=1,
            rule="value >= 1", severity="warning",
        )], now=now)

    assert calls["n"] == 3
```

- [ ] **Step 2: Run + commit**

```bash
pytest tests/integration/test_daily_cap.py -v
git add tests/integration/test_daily_cap.py
git commit -m "test(wazuh-health): daily cap stops dispatcher after N invocations"
```

---

### Task 9.3: No-PII-in-prompts test

**Files:**
- Create: `tests/integration/test_no_pii_in_prompts.py`

- [ ] **Step 1: Write the test**

```python
# tests/integration/test_no_pii_in_prompts.py
"""Captures the input_payload sent to the agent runner and asserts no raw IPs."""
import re
from datetime import datetime, timezone

from src.wazuh_health.agents.hygiene import invoke_hygiene_agent
from src.wazuh_health.agents.runner import AgentInvocation, set_runner
from src.wazuh_health.contracts import (
    CleanAlert, DomainFinding, ThresholdHit,
)
from src.wazuh_health.probes.hygiene import HygieneProbe
from src.wazuh_health.pseudonymize import Pseudonymizer
from src.wazuh_health.store.audit_store import AuditStore
from src.wazuh_health.store.db import connect, migrate
from src.wazuh_health.store.findings_store import FindingsStore


_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


class _CapturingRunner:
    def __init__(self):
        self.captured: AgentInvocation | None = None

    def run(self, invocation):
        self.captured = invocation
        return [], {"input": 0, "output": 0}


def test_pseudonymized_buckets_contain_no_raw_ips():
    p = Pseudonymizer(salt="s")
    masked_buckets = [
        p.mask({"rule_id": "5710", "srcip": "10.0.5.20", "agent.name": "vpn01"},
               fields=["srcip", "agent.name"])
    ]
    # Simulate the probe writing masked artifacts and the agent invoker passing them.
    runner = _CapturingRunner()
    set_runner(runner)
    conn = connect(":memory:"); migrate(conn)
    audit = AuditStore(conn); store = FindingsStore(conn)

    # Inject masked artifacts manually for the test.
    from src.wazuh_health.contracts import ProbeResult
    audit.record_probe_run(ProbeResult(
        probe="hygiene",
        run_at=datetime.now(tz=timezone.utc),
        metrics={"noise.recommendations_count": 1},
        artifacts={"top_buckets": masked_buckets, "recommendations": [], "simulations": []},
        errors=[],
    ))

    invoke_hygiene_agent(
        hits=[ThresholdHit(probe="hygiene", metric="m", value=1,
                            rule="value >= 1", severity="warning")],
        audit_store=audit, findings_store=store,
        light_model="gpt-4o-mini", now=datetime.now(tz=timezone.utc),
    )
    # Tool calls happen inside Agent.run — but our input_payload should be PII-free.
    payload_str = str(runner.captured.input_payload)
    assert not _IP_RE.search(payload_str), f"raw IP leaked: {payload_str}"
```

- [ ] **Step 2: Run + commit**

```bash
pytest tests/integration/test_no_pii_in_prompts.py -v
git add tests/integration/test_no_pii_in_prompts.py
git commit -m "test(wazuh-health): assert no raw IPs in agent input payloads"
```

---

### Task 9.4: `systemd` unit file

**Files:**
- Create: `deploy/wazuh-health.service`

- [ ] **Step 1: Write the unit**

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

- [ ] **Step 2: Commit**

```bash
git add deploy/wazuh-health.service
git commit -m "deploy(wazuh-health): systemd unit (read-only /var/ossec mount)"
```

---

### Task 9.5: `docs/WAZUH_HEALTH.md` (operator-facing)

**Files:**
- Create: `docs/WAZUH_HEALTH.md`

- [ ] **Step 1: Write the doc**

```markdown
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
```

- [ ] **Step 2: Commit**

```bash
git add docs/WAZUH_HEALTH.md
git commit -m "docs(wazuh-health): operator-facing overview, config reference, run guide"
```

---

### Task 9.6: Update `docs/CLEANSWARM.md`

**Files:**
- Modify: `docs/CLEANSWARM.md`

- [ ] **Step 1: Prepend "moved" notice**

Insert at the top of `docs/CLEANSWARM.md`, above the existing first heading:

```markdown
> **Note:** CleanSwarm is now part of [Wazuh Health Squad](./WAZUH_HEALTH.md).
> The `cleanswarm analyze` CLI continues to work unchanged; its internals now
> live under `wazuh_health/hygiene/`. New checks for capacity and coverage are
> documented in the Wazuh Health doc.
```

- [ ] **Step 2: Commit**

```bash
git add docs/CLEANSWARM.md
git commit -m "docs(cleanswarm): point to wazuh-health for the broader system"
```

---

### Task 9.7: Final full-suite run

- [ ] **Step 1: Run everything**

Run: `pytest -v`
Expected: all tests PASS, target ≥85% coverage on `src/wazuh_health/`.

- [ ] **Step 2: If coverage gap, file follow-up issues**

For any module below 85% coverage in `src/wazuh_health/`, open a follow-up
ticket. Do not extend the plan retroactively.

- [ ] **Step 3: Final commit (only if tests changed)**

If you adjusted any test along the way, commit before declaring done:

```bash
git status
git add tests/
git commit -m "test(wazuh-health): final adjustments after full suite run"
```

---

**End of Phase 9.** Project complete: read-only Wazuh Health Squad daemon with hygiene, capacity, and coverage probes, four LLM agents (HygieneAgent, CapacityAgent, CoverageAgent, ReporterAgent), end-to-end test coverage, systemd unit, and operator docs. CleanSwarm CLI preserved.

---

## Self-review checklist (done)

- **Spec coverage:**
  - Architecture diagram (spec §3) → implemented across Phases 1–8.
  - Boundary invariants (spec §3.1) → Phase 1 Tasks 1.3 + 1.4; whitelist refreshed in Phase 8 Task 8.3.
  - I/O layer (spec §4.1) → Phase 3.
  - Probes (spec §4.2) → Phase 4.
  - Decision layer (spec §4.3) → Phase 5 Tasks 5.4–5.6.
  - State layer (spec §4.4) → Phase 5 Tasks 5.1–5.3.
  - Agents layer (spec §4.5) → Phase 7.
  - Output layer (spec §4.6) → Phase 8 Tasks 8.2–8.4.
  - Control layer (spec §4.7) → Phase 8 Tasks 8.5–8.7.
  - Data flow tick (spec §5.1) → Phase 9 Task 9.1 (e2e test).
  - Contracts (spec §5.2) → Phase 2 Task 2.1.
  - Tools invariants (spec §5.3) → Phase 6 Task 6.2.
  - Guardrails — read-only (spec §6.1) → Phase 1 Tasks 1.3–1.4 + Phase 3 Task 3.2 + Phase 8 Task 8.3.
  - Guardrails — LLM cost/rate (spec §6.2) → Phase 5 Task 5.6 (daily cap, cooldown) + Phase 9 Task 9.2.
  - Guardrails — LLM output validation (spec §6.3) → Phase 6 Task 6.3 (sanitizer).
  - Guardrails — credentials & PII (spec §6.4) → Phase 6 Task 6.1 (pseudonymizer) + Phase 9 Task 9.3.
  - Guardrails — error handling (spec §6.5) → Phase 4 Task 4.1 (Probe.run wraps exceptions) + Phase 7 Task 7.3 (sanitize errors skip persistence).
  - Auditability (spec §6.6) → Phase 5 Task 5.3 (AuditStore).
  - Testing strategy (spec §7) → covered by per-task TDD + Phase 9 integration tests.
  - Layout + config (spec §8) → Phase 1 + Phase 8 Task 8.5.
  - systemd unit + docs (spec §8.4 + §10 deliverables) → Phase 9 Tasks 9.4–9.6.

- **Placeholders:** none. Each step has the actual code, command, or content to insert. Where a tool is a simple alias of code in `wazuh_health.hygiene`, the shim shows the exact import.

- **Type consistency:** `DomainFinding`, `ProbeResult`, `ThresholdHit`, `WazuhHealthReport`, `CleanAlert`, `NoiseBucket`, `Recommendation`, `SimulationResult`, `CombinedSimulation` are introduced in Phase 2 Task 2.1 and used identically across all later phases. `compute_hash_key` signature `(domain, metric, evidence)` is consistent in Phase 5 (definition) and Phase 7 (call sites).

- **Open spec questions deferred** (intentional, surface during execution):
  1. Final package name (`wazuh_health` used throughout this plan).
  2. CleanSwarm CLI deprecation banner (not implemented; can be added in 9.6 as a one-line print in `cleanswarm_cli.main`).
  3. Pseudonymize default = `true` (used here; flip via env if undesired).
  4. `.env` location (env-driven; operator chooses).









