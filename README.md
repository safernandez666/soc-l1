# SOC L1 — Multi-agent SOAR para Wazuh + Microsoft Defender

Servicio Python que automatiza el triage inicial de alertas de Wazuh (nativas o forwardeadas
desde Microsoft Defender for Endpoint) usando un pipeline de agentes LLM y un flujo de
aprobación humana por email antes de ejecutar acciones en Active Directory.

```
┌─────────┐  HMAC   ┌──────────┐    ┌────────┐    ┌──────────┐  ┌────────────┐    ┌──────────┐
│ Wazuh   │ ──────► │ Webhook  │ ─► │ Triage │ ─► │ Enricher │  │ ThreatIntel│ ─► │ Narrator │
│manager  │         │ /alert   │    │(LLM)   │    │ (LLM+AD+ │  │ (LLM+VT+   │    │ (LLM,    │
└─────────┘         └──────────┘    └────────┘    │  Wazuh)  │  │  AbuseIPDB)│    │  plan)   │
                         ▲          ┌────┴────┐   └────┬─────┘  └─────┬──────┘    └─────┬────┘
                         │          │ auto_   │        │              │                 │
                         │          │ close   │        └──────┬───────┘                 │
                         │          └─────────┘             paralelo                    ▼
                         │                                                       ┌────────────┐
                         └────────────── 202 Accepted ◄──── HTTP response        │ SQLite +   │
                                                                                 │ SMTP email │
                                                                                 │ (approve   │
                                                                                 │  /reject)  │
                                                                                 └──────┬─────┘
                                                                                        │ click
                                                                                        ▼
                                                                                 ┌────────────┐
                                                                                 │ Executor   │
                                                                                 │ (LDAP +    │
                                                                                 │  guardrails)│
                                                                                 └────────────┘
```

**No-LLM-en-el-path-de-ejecución**: las acciones reales sobre AD (`disable_user`,
`force_password_change`) las ejecuta un dispatcher determinístico DESPUÉS de la aprobación
humana, nunca el LLM. Defensa contra prompt injection con efecto side-effect.

---

## Tabla de contenidos

- [Estado actual](#estado-actual)
- [Pipeline](#pipeline)
- [Quickstart](#quickstart)
- [Configuración (`.env`)](#configuración-env)
- [Comandos comunes](#comandos-comunes)
- [Arquitectura](#arquitectura)
- [Modelo de seguridad](#modelo-de-seguridad)
- [Desarrollo](#desarrollo)
- [Roadmap](#roadmap)

---

## Estado actual

| Componente | Estado | Descripción |
|---|---|---|
| Normalizer | ✅ | Convierte alerta Wazuh nativa o Defender-via-Wazuh a `NormalizedAlert` |
| Webhook HMAC | ✅ | `POST /webhook/wazuh-alert` con verificación HMAC-SHA256 |
| **Webhook IP allowlist** | ✅ | `WEBHOOK_ALLOWED_IPS` defensa en profundidad al HMAC (default: localhost only) |
| Triage agent | ✅ | gpt-4o-mini; decide `auto_close_benign` / `analyze` / `fast_track_critical` |
| Enricher agent | ✅ | gpt-4o; consulta AD (LDAP STARTTLS) + Wazuh manager API |
| ThreatIntel agent | ✅ | gpt-4o; consulta VirusTotal + AbuseIPDB + **FortiGate** (sessions + quarantine status) |
| **FortiGate integration** | ✅ | Tool `fortigate_check_ip` + acción `block_ip` (quarantine via REST API) |
| Narrator agent | ✅ | gpt-4o; produce plan estructurado con `ProposedAction[]` (incluye `block_ip`) |
| Email approval | ✅ | SMTP (Exchange 2016 STARTTLS), branded HTML matching Wazuh look |
| Approval endpoints | ✅ | `/approve/{token}` y `/reject/{token}`, single-use, TTL 24h (backwards compat) |
| **Granular approval** | ✅ | `/review/{token}` con checkboxes per-action + `/decide/{token}` POST handler |
| Executor | ✅ | Dispatcher determinístico con guardrails (PROTECTED_USERS, **PROTECTED_NETWORKS**, DRY_RUN_MODE) |
| State (SQLite) | ✅ | Pending approvals con audit trail (IP, UA, timestamps, **selected_actions**) |
| **Dashboard `/approvals`** | ✅ | HTML table + JSON API con filtros por status + paginación |
| systemd service | ✅ | `deploy/soc-l1.service` + `scripts/install-systemd.sh` |
| **Backup automático** | ✅ | systemd timer diario (02:00) con SQLite online backup + retención 30 días |
| Observability | ✅ | Logs estructurados por agente y por tool call |
| Tests | ✅ | 166 tests (respx para HTTP, mock LDAP, FortiGate, e2e approval flow) |

---

## Pipeline

```
1. Wazuh integrator (custom-soc-l1) firma con HMAC y POSTea a /webhook/wazuh-alert
       ↓
2. normalize.py: maneja ambos formatos (Wazuh nativo + Defender via Wazuh)
       ↓
3. Triage (gpt-4o-mini, ~2s):
   ├─ auto_close_benign  → log AUDIT, fin
   ├─ analyze            → siguiente paso, priority=normal
   └─ fast_track_critical→ siguiente paso, priority=critical
       ↓
4. EN PARALELO (asyncio.gather, ~5s):
   ├─ Enricher (gpt-4o):
   │    - ldap_search_user(sam) por cada usuario involucrado
   │    - wazuh_get_rule(rule_id) para detalle de la rule
   │    → EnrichmentResult con users + rule + flags
   └─ ThreatIntel (gpt-4o):
        - vt_lookup_hash(sha256) por cada file con SHA256
        - abuseipdb_check(ip) por cada IP pública (skip RFC1918)
        - fortigate_check_ip(ip) por cada IP pública (sessions + quarantine status)
        → ThreatIntelResult con file_reports + ip_reports + fortigate_contexts + flags
       ↓
5. Narrator (gpt-4o, ~3s) recibe: alert + triage + enrichment + threat_intel
       → NarratorPlan con executive_summary + risk_level + actions[] + rationale
       ↓
6. Persistir plan en SQLite (token único single-use, TTL 24h)
       ↓
7. Enviar email HTML al approver con UN solo botón "Revisar y decidir":
       /review/{token}  → página con checkboxes per-action + 2 botones de submit
       ↓
8. Humano elige acciones + click → POST /decide/{token}:
       decision=approve + action_idx=[N,M,...] → solo esas acciones
       decision=reject                          → ninguna acción
       ↓
9. Executor (deterministic, NO LLM) corre las acciones seleccionadas:
   ├─ Guardrail PROTECTED_USERS: refuse si target en whitelist
   ├─ Guardrail PROTECTED_NETWORKS: refuse block_ip si IP en CIDR protegido
   ├─ Guardrail DRY_RUN_MODE: si true, log pero no ejecuta
   ├─ disable_user → tools/ldap.py.disable_user (UAC bit ACCOUNTDISABLE)
   ├─ force_password_change → pwdLastSet=0
   ├─ block_ip → tools/fortigate.py.quarantine_ip (POST /monitor/user/banned/add_users)
   ├─ escalate_l2 → log only (futuro: ticket/Slack)
   └─ notify_only → noop
   → mark_executed en SQLite con resultados
       ↓
10. Audit trail visible en GET /approvals (HTML dashboard) o GET /approvals?format=json
```

**Tiempo total típico end-to-end**: ~10-20 segundos desde webhook hasta email enviado.

---

## Quickstart

### Pre-requisitos

- Python 3.12 + [uv](https://docs.astral.sh/uv/) (manager de paquetes)
- Wazuh manager 4.4+ con un integrator custom (ver `examples/wazuh-integrator/`)
- LDAP/AD con bind credentials (con STARTTLS recomendado)
- OpenAI API key con acceso a gpt-4o + gpt-4o-mini
- SMTP server para emails de aprobación (Exchange 2016 STARTTLS compatible)
- (Opcional) VirusTotal API key — free tier 500/día
- (Opcional) AbuseIPDB API key — free tier 1000/día

### Instalación local (dev)

```bash
git clone https://github.com/safernandez666/soc-l1.git
cd soc-l1
uv venv --python 3.12
source .venv/bin/activate
uv sync
cp .env.example .env  # editá con tus values

# Tests
uv run pytest                                  # 166 tests
uv run python3 scripts/test_ti_apis.py         # smoke test de VT + AbuseIPDB
```

### Deploy en servidor de producción

```bash
# 1. Clonar a /opt/soc-l1 como un user dedicado (ej. jdoe)
sudo mkdir -p /opt/soc-l1
sudo chown $USER:$USER /opt/soc-l1
git clone https://github.com/safernandez666/soc-l1.git /opt/soc-l1
cd /opt/soc-l1

# 2. uv sync + .env
uv venv --python 3.12
uv sync
cp .env.example .env && chmod 600 .env  # seteá todos los values
vim .env

# 3. Instalar como systemd unit (sobrevive reboots, restart on-failure)
sudo /opt/soc-l1/scripts/install-systemd.sh

# 4. Instalar backup automático de state.db (diario 02:00, retención 30 días)
sudo /opt/soc-l1/scripts/install-backup.sh

# 5. Verificar
sudo systemctl status soc-l1
sudo systemctl list-timers soc-l1-backup.timer
curl http://localhost:8000/health

# 6. Configurar el integrator de Wazuh
sudo cp examples/wazuh-integrator/custom-soc-l1.py /var/ossec/integrations/
sudo chmod +x /var/ossec/integrations/custom-soc-l1.py
# Editar /var/ossec/etc/ossec.conf para apuntar al webhook, restart wazuh-manager

# 7. Dashboard de approvals (abrir en browser de la red corporativa)
# http://<host>:8000/approvals
```

### Testear el pipeline (alerta sintética)

```bash
# Fixture con usuarios ficticios:
cd /opt/soc-l1 && python3 scripts/send_test_alert.py

# Fixture con un user real (ej. jdoe - protegido por PROTECTED_USERS):
python3 scripts/send_test_alert.py tests/fixtures/defender_keygen_real_user.json

# Ver logs en vivo
journalctl -u soc-l1 -f
# o
./scripts/restart.sh logs
```

---

## Configuración (`.env`)

Variables principales — ver [`.env.example`](.env.example) para template completo.

### Wazuh

```bash
WAZUH_WEBHOOK_SECRET=...                # HMAC shared secret con el integrator
WAZUH_API_HOST=127.0.0.1                # Para que el Enricher consulte rules
WAZUH_API_PORT=55000
WAZUH_API_USER=wazuh
WAZUH_API_PASSWORD=...
WAZUH_API_VERIFY_SSL=false              # self-signed cert del manager
```

### AD / LDAP

```bash
LDAP_HOST=dc.example.local
LDAP_PORT=389
LDAP_BASE_DN=DC=example,DC=local
LDAP_BIND_DN=svc-soar@example.local
LDAP_USE_STARTTLS=true
LDAP_TIMEOUT=10

# Password tiene 3 opciones (en orden de precedencia):
LDAP_BIND_PASSWORD=...                  # 1. Literal (cuidado con chars especiales en .env)
LDAP_BIND_PASSWORD_B64=...              # 2. Base64 (recomendado para passwords con $, ', ", etc.)
LDAP_CREDENTIALS_FILE=/path/to/file     # 3. Archivo con AD_USER=... AD_PASSWORD=...
```

### OpenAI

```bash
OPENAI_API_KEY=sk-...
OPENAI_MODEL_LIGHT=gpt-4o-mini          # Triage (decisión simple, sin tools)
OPENAI_MODEL_HEAVY=gpt-4o               # Enricher, ThreatIntel, Narrator
```

> Por qué `gpt-4o` para Enricher: en pruebas, `gpt-4o-mini` ignoraba las instrucciones
> anti-loop y machacaba la misma tool 18+ veces hasta agotar `max_turns`. El modelo full
> sigue instrucciones correctamente. Costo: ~$0.005 vs $0.0004 por alerta — irrelevante.

### Threat Intel (opcional, recomendado)

```bash
VIRUSTOTAL_API_KEY=...                  # signup en virustotal.com (500/día free)
ABUSEIPDB_API_KEY=...                   # signup en abuseipdb.com (1000/día free)
```

### FortiGate (opcional - habilita acción `block_ip`)

```bash
# Host típicamente "fortigate.example.local:4443" o IP:puerto. Si no traés scheme,
# asumimos https. Token desde System → Administrators → REST API Admin en FortiOS.
FORTIGATE_HOST=
FORTIGATE_TOKEN=
FORTIGATE_VERIFY_SSL=false

# CIDRs/IPs que JAMÁS deben bloquearse en FortiGate aunque se aprueben.
# Default: RFC1918 + loopback (no bloquear redes propias).
PROTECTED_NETWORKS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8
```

> Scopes que necesita el FortiGate API token (FortiOS Admin → REST API Admin):
> `monitor.firewall.session` (lectura, para conteo de sessions activas) +
> `monitor.user.banned` (lectura+escritura, para quarantine).

### Email approval

```bash
SMTP_HOST=mail.example.local
SMTP_PORT=587
SMTP_USER=svc-soar
SMTP_PASSWORD=...
SMTP_FROM=soc-l1@example.local
SMTP_TO_APPROVERS=soc@example.com,oncall@example.com
SMTP_USE_STARTTLS=true
SMTP_SSL_VERIFY=false                   # self-signed Exchange certs

APPROVAL_BASE_URL=http://192.168.x.x:8000   # URL que aparece en los links del email
APPROVAL_TTL_HOURS=24
STATE_DB_PATH=/opt/soc-l1/state.db
```

### Guardrails de ejecución (CRÍTICO)

```bash
# Cuentas que el executor REFUSA tocar, sin importar approval clickeado.
# Comma-separated, case-insensitive.
PROTECTED_USERS=admin,svc-soar,jdoe,wazuhseg

# Si true, las acciones AD/FortiGate no se ejecutan - solo se loggean.
# Recomendado true mientras se valida que el Narrator hace recomendaciones sensatas.
DRY_RUN_MODE=true
```

### Webhook security (defensa en profundidad al HMAC)

```bash
# IPs autorizadas a POSTear al webhook (además de la verificación HMAC).
# Default: solo localhost. Si Wazuh manager corre en otro server, agregá su IP.
WEBHOOK_ALLOWED_IPS=127.0.0.1,::1
```

### Feature flags

```bash
ENABLE_TRIAGE=true
ENABLE_ENRICHER=true
ENABLE_THREAT_INTEL=true
ENABLE_NARRATOR=true
```

---

## Comandos comunes

```bash
# systemd (modo deploy)
sudo systemctl status soc-l1
sudo systemctl restart soc-l1
sudo systemctl stop soc-l1
journalctl -u soc-l1 -f
journalctl -u soc-l1 --since "10 min ago"

# Script unificado (auto-detecta systemd vs manual)
./scripts/restart.sh                    # restart + tail logs
./scripts/restart.sh status
./scripts/restart.sh logs
./scripts/restart.sh logs -n 100        # last 100, no follow

# Testing
uv run pytest                           # full suite (138 tests)
uv run pytest tests/test_enricher.py    # un archivo
uv run python3 scripts/test_ti_apis.py  # smoke test contra VT + AbuseIPDB reales

# Enviar alerta sintética
python3 scripts/send_test_alert.py                                       # fixture default
python3 scripts/send_test_alert.py tests/fixtures/defender_keygen_real_user.json
```

---

## Arquitectura

### Componentes

```
src/
├── main.py              # FastAPI service + endpoints + pipeline orchestration
├── config.py            # Settings (pydantic-settings, lee .env)
├── models.py            # NormalizedAlert, ADUser, VtFileReport, FortigateIpContext, etc.
├── normalize.py         # Wazuh native + Defender-via-Wazuh → NormalizedAlert
├── security.py          # verify_wazuh_signature (HMAC-SHA256 constant-time)
├── state.py             # SQLite pending_approvals + list_approvals (paginated)
├── mailer.py            # smtplib + STARTTLS, HTML branded matching Wazuh
├── executor.py          # Dispatcher post-approval (PROTECTED_USERS + PROTECTED_NETWORKS + DRY_RUN)
├── tools/
│   ├── ldap.py          # search_user, disable_user, force_password_change (ldap3)
│   ├── wazuh_api.py     # JWT-cached client (httpx async)
│   ├── threatintel.py   # VirusTotalClient + AbuseipdbClient (httpx async)
│   └── fortigate.py     # FortigateClient (sessions + quarantine_ip)
└── agents/
    ├── triage.py        # Decisión rápida sin tools
    ├── enricher.py      # AD + Wazuh rule lookup (cache anti-loop)
    ├── threatintel.py   # VT + AbuseIPDB + FortiGate lookup (cache anti-loop)
    └── narrator.py      # Síntesis final + ProposedAction[] (incluye block_ip)
```

### Convenciones de diseño

- **Sin LLM en el path de ejecución**: post-approval el executor es determinístico.
- **Cache anti-loop por agent context**: tras 2 hits sobre la misma (tool, args), devuelve
  error structure `MAX_RETRIES_EXCEEDED` para forzar al LLM a salir.
- **Logs por tool call**: cada `🔎 TOOL name(args)` + `↳ result` es trazable.
- **structured output** en todos los agents via `output_type=PydanticModel`.
- **Enricher + ThreatIntel en paralelo** (`asyncio.gather`) — independientes, ahorra ~5s.
- **`extra="forbid"`** en todos los Pydantic models — schema drift falla loud, no silent.

### Modelos de datos clave

- `NormalizedAlert` — schema interno común. Los agents nunca ven raw Wazuh.
- `EnrichmentResult` — `{users[], rule, summary, flags[]}` con users encontrados en AD
- `ThreatIntelResult` — `{file_reports[], ip_reports[], fortigate_contexts[], summary, flags[]}`
- `NarratorPlan` — `{executive_summary, risk_level, actions[], rationale}` que el humano aprueba
- `ProposedAction` — `{type, target, justification}`. Types soportados:
  - `disable_user` → setea ACCOUNT_DISABLE bit en AD via LDAP
  - `force_password_change` → setea `pwdLastSet=0` (force change at next logon)
  - `block_ip` → quarantine en FortiGate via REST API (TTL 1h por default)
  - `escalate_l2` → log only (futuro: ticket/Slack)
  - `notify_only` → noop, solo audit

---

## Modelo de seguridad

### Defensa en profundidad

1. **HMAC on webhook**: `/webhook/wazuh-alert` requiere header `X-Wazuh-Signature` válido
   (HMAC-SHA256 con secret compartido). Constant-time compare via `hmac.compare_digest`.
2. **Approval tokens**: `secrets.token_urlsafe(32)` (~256 bits entropy). Single-use, TTL 24h.
   CAS-safe DB update — primer click decide, segundo da `already_decided`.
3. **PROTECTED_USERS**: lista de sams que el executor refuse. Aunque el LLM lo recomiende
   y el humano clickee Aprobar, ciertas cuentas (admins, service accounts) nunca se tocan.
4. **DRY_RUN_MODE**: flag global que convierte acciones AD en no-op. Útil mientras se valida.
5. **NO LLM en post-approval**: el executor es código deterministic; el LLM no decide qué
   ejecutar después de la aprobación.
6. **`extra="forbid"`** en input schemas: si el LLM intenta meter un field no documentado
   (prompt injection), Pydantic falla.
7. **systemd `User=non-root`**: el servicio corre como user normal, no root.
   `NoNewPrivileges=true`, `MemoryMax=1G`.

### Surface attack

| Endpoint | Defensa actual | Notas |
|---|---|---|
| `POST /webhook/wazuh-alert` | HMAC | Debería bindearse a localhost (Wazuh corre local) |
| `GET /approve/{token}` | Token entropía + TTL + single-use | Pública en LAN, idealmente HTTPS+rate-limit (ver Roadmap) |
| `GET /reject/{token}` | Idem | Idem |
| `GET /health` | Ninguna | No expone datos sensibles |

### Datos sensibles

- `.env` debe ser `chmod 600` y nunca commiteado (`.gitignore` cubre `.env`, `*.db`)
- LDAP password en `.env` puede ser literal, base64 (recomendado), o leer de archivo
- OpenAI key, SMTP password, API keys: solo en `.env`

---

## Desarrollo

### Setup local

```bash
git clone https://github.com/safernandez666/soc-l1.git
cd soc-l1
uv venv --python 3.12 && source .venv/bin/activate && uv sync
cp .env.example .env  # editá values mínimos: OPENAI_API_KEY
uv run pytest          # 166 tests passing
```

### Estructura de tests

```
tests/
├── fixtures/
│   ├── defender_keygen.json              # alerta synthetic con users ficticios
│   └── defender_keygen_real_user.json    # con jdoe (testea AD real)
├── test_config.py                        # 3-tier credential resolution
├── test_normalize.py                     # Wazuh native + Defender-via-Wazuh
├── test_security.py                      # HMAC verify
├── test_webhook.py                       # FastAPI endpoint + IP allowlist
├── test_routing.py                       # Triage verdict → handler dispatch
├── test_triage.py                        # Triage agent (build, schema, no LLM)
├── test_enricher.py                      # Enricher agent + tools + cache + hard-stop
├── test_threatintel.py                   # VT + AbuseIPDB clients (respx)
├── test_threatintel_agent.py             # ThreatIntel agent + tools (VT/AbuseIPDB/FortiGate)
├── test_fortigate.py                     # FortiGate client (sessions + quarantine)
├── test_narrator.py                      # Narrator agent (build, schema, bundle)
├── test_ldap_tools.py                    # LDAP operations (ldap3 MOCK_SYNC)
├── test_state.py                         # SQLite CRUD + idempotent decide + selected_actions
├── test_mailer.py                        # SMTP message build + HTML escape
├── test_executor.py                      # Dispatcher + PROTECTED_USERS + PROTECTED_NETWORKS + DRY_RUN + block_ip
└── test_approval_endpoints.py            # E2E approve/reject + /review + /decide + /approvals
```

### Convenciones de código

- Type hints en TODO (Python 3.12 syntax: `str | None`, no `Optional[str]`)
- `extra="forbid"` en Pydantic models (catch schema drift)
- Tests con `respx` para HTTP mocking (NO live API calls en tests)
- LDAP tests con `ldap3.MOCK_SYNC` (NO conexión real)
- Logs estructurados con prefijos visuales: `🤖 AGENT X.run`, `🔎 TOOL Y(args)`,
  `↳ result`, `✅ STAGE`, `🛡️ guardrail`, `🛑 hard-stop`
- Spanish para comentarios en código, English para identifiers

### Agregar un nuevo tool a un agent

1. Implementar el cliente en `src/tools/X.py` (httpx async, Pydantic response model)
2. Tests con respx en `tests/test_X.py`
3. Agregar `@function_tool` wrapper en el agent (`src/agents/Y.py`)
4. Cache + hard-stop usando el patrón existente
5. Update system prompt con criterio de uso
6. Tests del wrapper en `tests/test_Y.py`

---

## Roadmap

### ✅ Completado en versiones recientes

- **Webhook IP allowlist** (`WEBHOOK_ALLOWED_IPS`) — defensa adicional al HMAC, default localhost
- **FortiGate integration** — tool `fortigate_check_ip` en ThreatIntel + acción `block_ip` en executor con guardrail `PROTECTED_NETWORKS`
- **Approval granular** — `/review/{token}` con checkboxes per-action + `POST /decide/{token}` que filtra acciones a ejecutar
- **`GET /approvals` dashboard** — HTML + JSON con filtros por status y paginación
- **Backup automático** de `state.db` — systemd timer diario con retención 30 días

### 🟡 Corto plazo (pendientes)

#### Reverse proxy + HTTPS

Hoy los endpoints `/review`, `/decide`, `/approve`, `/reject` y `/approvals` van por HTTP
plano. En LAN corporativa es OK pero los tokens viajan sin cifrar. Propuesta:

1. **nginx o caddy** en frente del puerto 8000 con TLS (self-signed o Let's Encrypt)
2. **Rate limit por IP** (max N requests/min) en `/decide`
3. **IP allowlist** opcional en `/approvals` (solo IPs corporativas / VPN)
4. **Opcional: SSO challenge** antes de mostrar la página de aprobación

#### Daily digest email

Background task que arma cada mañana un email-resumen con:
- Cuántas alertas se recibieron ayer (por verdict de triage)
- Cuántos planes se aprobaron / rechazaron
- Costo OpenAI estimado
- Top 5 tipos de incidentes más frecuentes

#### Re-send si approval pending > N horas

Background task que re-envía el email a las 4h si sigue `pending`. Útil para alertas
nocturnas que se pierden.

#### Monitoring de uptime

systemd `OnFailure=` apuntando a un script que mande email/Slack cuando el servicio crashea.
Hoy si soc-l1 muere por algo no-recuperable (DB corrupta, OOM), nadie se entera.

### 🔵 Mediano plazo

- **Pylint/ruff CI** en GitHub Actions
- **Métricas Prometheus** — `/metrics` con counters por agent, latencias, error rate por tool
- **OTX + URLhaus** como TI sources adicionales (cuando los falsos positivos lo justifiquen)
- **GreyNoise** cuando salga un tier free decente (hoy solo enterprise pago)

### 🟣 Largo plazo

- **Operator agent (LLM)** opcional: post-approval, decide micro-detalles (ej. duración del
  block, mensaje al user via email). Hoy esto está hardcoded.
- **Playbooks** por categoría de alerta (ransomware vs phishing vs lateral movement) con
  prompts específicos del Narrator
- **Conversational mode**: si el Narrator no está seguro, mandar email con preguntas al
  analista en vez de un plan binario
- **Multi-tenant**: que un soc-l1 pueda servir a varios clientes con configs aisladas

---

## Troubleshooting

### `Permission denied` al arrancar uvicorn vía systemd

Usualmente las directivas `ProtectSystem=strict` o `ProtectHome=true` del unit interfieren
con la ejecución cuando el binario está en `/opt` y el user es AD/LDAP. El unit actual no
las incluye. Si las activás manualmente y rompe, sacalas.

### Triage o Narrator devuelve `MaxTurnsExceeded`

El LLM se atascó llamando la misma tool. Verificá:
1. Que `OPENAI_MODEL_HEAVY=gpt-4o` (no mini) — el Enricher/ThreatIntel necesitan modelo full
2. El cache anti-loop debería capturar esto y devolver hard-stop tras 2 hits
3. Si pasa con frecuencia, abrir issue con el alert_id y los logs

### LDAP `data 52e`

User/password incorrectos. Si tu password tiene chars especiales (`$`, `'`, `"`, etc.),
usá `LDAP_BIND_PASSWORD_B64=$(echo -n 'mi-password' | base64)` en `.env`.

### Email no llega

```bash
# Smoke test del SMTP (no expone password)
journalctl -u soc-l1 | grep "mailer:"

# Verificar que SMTP_TO_APPROVERS está seteado (default es vacío)
grep SMTP_TO_APPROVERS /opt/soc-l1/.env
```

### Tracing errors (429 del Agents SDK)

Resueltos en main desde commit 1840afa (tracing del SDK deshabilitado con
`set_tracing_disabled(True)`). Si volvés a ver `[non-fatal] Tracing client error 429`,
verificá que `from agents import set_tracing_disabled` está siendo llamado en lifespan.

---

## Licencia / créditos

Proyecto interno Example Corp. Stack:

- [OpenAI Agents SDK](https://github.com/openai/openai-agents-python) (Python)
- [FastAPI](https://fastapi.tiangolo.com/)
- [Pydantic v2](https://docs.pydantic.dev/)
- [httpx](https://www.python-httpx.org/) + [respx](https://lundberg.github.io/respx/)
- [ldap3](https://ldap3.readthedocs.io/)
- [uv](https://docs.astral.sh/uv/) (package manager)
- Wazuh + Microsoft Defender for Endpoint
- VirusTotal + AbuseIPDB
