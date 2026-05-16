# SOC L1 - Multi-agent SOAR

SOC Level 1 agent system for Wazuh + Defender alerts. Python + OpenAI Agents SDK.

## Status: en construcción

Hoy: normalizer + tests.
Próximo: agentes (triage, enricher, threat intel, narrator, operator), FastAPI service, email approval flow.

## Setup local

```bash
# uv (fast Python package manager, recommended)
brew install uv

# Crear venv e instalar dependencias
cd /path/to/soc-l1
uv venv --python 3.12
source .venv/bin/activate
uv pip install -e ".[dev]"

# Correr tests
pytest -v
```

## Arquitectura objetivo

```
Wazuh integrator → POST /webhook/wazuh-alert
                   ↓
              normalize + HMAC verify
                   ↓
              triage agent (gpt-4o-mini)
                   ↓
        ┌─ auto_close → audit + notify, end
        └─ analyze:
              enricher agent (gpt-4o-mini) + tools (Graph, FortiGate, Wazuh)
                   ↓
              threat_intel agent (gpt-4o-mini) + tools (VT, AbuseIPDB)
                   ↓
              narrator agent (gpt-4o, structured output)
                → plan JSON
                   ↓
              persist state (SQLite) + send email con link único
              return 202 a Wazuh
                   ↓
              GET /approve/{token}?decision=approve_full
                   ↓
        ┌─ approve → operator agent (gpt-4o) + tools (Graph disable/revoke)
        ├─ escalate → notify L2
        ├─ false_positive → log para tuning
        └─ reject → audit
                   ↓
              audit + notify team
```
