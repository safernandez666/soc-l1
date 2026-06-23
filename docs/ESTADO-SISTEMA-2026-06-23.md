# Estado del sistema SOC-L1 — 2026-06-23 (para revisión)

> Resumen autocontenido del estado operativo tras el cutover a Fase 1 del auto-block de FortiGate.
> Generado para revisión externa (Kimi). Host: `seg-vs85-prod01`.

## 1. Qué es SOC-L1

SOAR multi-agente para alertas de Wazuh. Recibe alertas por **webhook** (`POST /webhook/wazuh-alert`,
HMAC-SHA256 + allowlist de IPs), las normaliza, y según el tipo: enriquece + decide (LLM "Narrator")
con flujo de aprobación humana, o aplica respuesta automática. Tiene dashboard React en `/ui`.

## 2. Estado operativo ACTUAL (verificado)

| Ítem | Valor |
|---|---|
| Servicio | `soc-l1.service` — **systemd `active` + `enabled`** (MainPID 514119) |
| Puerto / health | `0.0.0.0:8000` — `GET /health` = **200** |
| Branch desplegada | `feat/dryrun-toggles-fgt-fase1` @ `631c3ac` (NO es `main`; PR #13 abierto) |
| Reboot del server | **pendiente** (`*** System restart required ***`) — seguro: systemd lo levanta solo |

### Estado del auto-block FortiGate (Fase 1 LIVE)

| Flag / parámetro | Valor |
|---|---|
| `FORTIGATE_AUTOBLOCK_ENABLED` | **true** (enforce real) |
| `DRY_RUN_MODE` (master kill-switch) | **false** |
| `block_ip` (FortiGate) | **EJECUTA EN VIVO** |
| `scan_host`, `isolate_host` (Defender) | SIMULA |
| `disable_user`, `force_password_change` (AD) | SIMULA |
| Reglas de enforce | **24** (las del script viejo; SIN `196205` "Attack BLOCKED") |
| Mecanismo de bloqueo | `quarantine_ip` → `user/banned` con **TTL 1h** (no addrgrp permanente) |
| `fortigate_host` | `192.168.32.1:4343` (write-path validado con IP TEST-NET: ban+unban OK) |
| `PROTECTED_NETWORKS` (guardrail) | `10/8, 172.16/12, 192.168/16, 127/8` |
| Blocker viejo (`custom-email-unified`) | **`fortigate.enabled=false`** → APAGADO (sin doble bloqueo) |

## 3. Flujo de datos (cadena completa)

```
Atacante → FortiGate (IPS dropea inline) → syslog → Wazuh manager
  → regla custom 1962xx (custom-fortigate-ips.xml)
  → integration `custom-soc-l1` (2 bloques en ossec.conf: group=defender + rule_id de las IPS)
  → POST /webhook/wazuh-alert (HMAC) → SOC-L1
  → normalize → fortigate_autoblock.enforce()
       ├─ evaluate(): ¿regla en allowlist (24)? ¿srcip? ¿PROTECTED_NETWORKS?
       ├─ dedup por IP dentro de la ventana TTL (no re-bloquea ráfagas)
       ├─ quarantine_ip(ip, ttl=1h) en FortiGate (si block_ip no es dry-run)
       └─ email de bloqueo + registro en fgt_observations.jsonl
```

- **FortiGate IPS inline sigue dropeando** independientemente (defensa de base). SOC-L1 agrega el
  ban a nivel firewall (TTL) + contexto/notificación.
- La regla `196205` ("Attack BLOCKED") se EXCLUYÓ del enforce: el FortiGate ya bloqueó esas IPs
  inline, re-banearlas sería redundante (el script viejo tampoco las tocaba).

## 4. Kill-switch por familia (`src/config.py`)

`dry_run_for(action_type)`: si `DRY_RUN_MODE` (master) está ON → todo simula. Si OFF → mira el
override por familia (`DRY_RUN_AD` / `DRY_RUN_FORTIGATE` / `DRY_RUN_DEFENDER`); vacío hereda master.
Mapeo `_ACTION_FAMILY`: `disable_user|force_password_change→ad`, `block_ip→fortigate`,
`scan_host|isolate_host→defender`. El executor gatea con `dry_run_for(action.type)`.

**Trampa controlada:** apagar el master pondría AD+Defender en vivo si sus overrides estuvieran
vacíos. Se fijó `DRY_RUN_AD=true` y `DRY_RUN_DEFENDER=true` explícitos ANTES de apagar el master.

## 5. Cambios aplicados hoy (cutover)

1. **Fix dedup por IP** en `observe()`/`enforce()` (commit `9a75628`): evita filas duplicadas en UI
   y doble-quarantine en ráfagas. +2 tests. **Suite: 238 passing.**
2. **Tooling parity** (commit `631c3ac`): `scripts/fgt_parity.py`.
3. **Cutover Fase 1** (`.env`): master off, autoblock on, AD/Defender fijados a simular, 24 reglas.
4. **systemd**: SOC-L1 migrado de nohup a `soc-l1.service`.
5. **Blocker viejo apagado** (`scripts/disable_old_fgt_blocker.py`, con sudo).

## 6. Archivos clave

- `src/fortigate_autoblock.py` — evaluate / observe / enforce / dedup.
- `src/config.py` — Settings, `dry_run_for`, `_ACTION_FAMILY`.
- `src/main.py` — webhook, short-circuit Fase 1, gating de email.
- `src/tools/fortigate.py` — `quarantine_ip` (add_users), `list_banned`.
- `src/executor.py` — ejecuta acciones por tipo, gate dry-run.
- `.env` — flags (DRY_RUN_*, FORTIGATE_*). `fgt_observations.jsonl` — registro (gitignored).
- `/var/ossec/etc/ossec.conf` — integrations. `/var/ossec/etc/email-config.json` — blocker viejo (off).
- `/var/ossec/etc/rules/custom-fortigate-ips.xml` — reglas 1962xx.

## 7. Pendientes / riesgos a revisar

- **Datos de validación escasos:** Fase 0 corrió ~1 día; el cutover se hizo con pocas muestras
  (decisión del operador). Todo el tráfico real observado fue `196205` (scanners ya bloqueados),
  que justamente se excluyó del enforce → habrá que ver volumen real de bloqueos de SOC-L1.
- **Bloqueos permanentes legacy:** las IPs que el script viejo metió en el addrgrp `WAZUH-BLOCKED`
  siguen ahí (permanentes, no se auto-limpian). Falta migrarlas/limpiarlas.
- **No hay unban programático** en `FortigateClient` (solo `clear_users` por API directa). Los bans
  de SOC-L1 expiran por TTL (1h); para unban manual hay que pegarle a la API.
- **PR #13** (branch→main) sin mergear; prod corre la branch, no main.
- **Concurrencia del dedup:** el dedup por IP es best-effort (estado en `fgt_notified.json`); dos
  alertas casi-simultáneas podrían pasar el chequeo antes de marcar (race raro, no crítico).

## 8. Puntos sugeridos para que Kimi revise

1. ¿La lista de 24 reglas de enforce es la correcta? ¿Faltan reglas de "attack DETECTED but NOT
   blocked" (las que el FortiGate NO dropeó y son las que más necesitan respuesta)?
2. ¿El TTL de 1h es adecuado, o conviene más largo para atacantes persistentes?
3. ¿`PROTECTED_NETWORKS` cubre todo lo que no se debe bloquear nunca (saltos, VPN, partners)?
4. Revisar `enforce()` en `src/fortigate_autoblock.py`: manejo de errores, que nunca rompa el ingest.
5. Riesgo de falsos positivos al bloquear en vivo sin aprobación humana (es auto-block directo).
