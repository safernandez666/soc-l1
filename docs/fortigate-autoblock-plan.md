# Plan: migrar el auto-block de FortiGate a SOC-L1

**Estado:** propuesta aprobada en decisiones clave (2026-06-22). Sin implementar.
**Objetivo:** mover el bloqueo automático de IPs de FortiGate desde el integration de Wazuh
(`custom-email-unified`) hacia SOC-L1, sumándole contexto, auditoría y reversibilidad sin perder
la velocidad del bloqueo automático.

---

## 1. Cómo funciona hoy ("corre derecho")

El bloqueo **no** es un active-response de Wazuh ni un script independiente: vive **dentro del
integration `custom-email-unified`** (el mismo que envía los mails), en la clase `FortiGateBlocker`.

Flujo actual:

1. FortiGate emite un evento IPS → Wazuh lo matchea con `custom-fortigate-ips.xml` (grupo `fortigate_ips`).
2. El integration `custom-email-unified` se dispara y `FortiGateBlocker`:
   - `should_block(rule_id)`: ¿la regla está en `auto_block_rules`? (24 reglas:
     `196201–196230`, `196100/101/112` → critical/high/SQLi/RCE/buffer overflow/etc.)
   - Si matchea y hay `data.srcip` → **bloquea inmediatamente**: crea un objeto
     `firewall/address` `WAZUH-<ip>` y lo agrega al address group **`WAZUH-BLOCKED`** vía
     **CMDB API** (`/api/v2/cmdb`), en FortiGate `192.168.32.1`.
   - **Permanente** (sin TTL), **sin humano en el loop**; luego envía el mail
     "🚨 IP BLOQUEADA AUTOMÁTICAMENTE EN FORTIGATE".
3. Config en `/var/ossec/etc/email-config.json` (`fortigate.{enabled, host, api_token,
   blocked_group, auto_block_rules}`).

**Limitaciones del flujo actual:**
- No respeta una allowlist de redes propias/partner (puede bloquear una IP interna).
- Bloqueo permanente sin limpieza automática.
- Sin enriquecimiento, sin ticket, sin trazabilidad como caso, sin dedup.

## 2. Lo que SOC-L1 ya tiene

- `src/tools/fortigate.py` (`FortigateClient`) **ya habla la API de FortiGate**.
- ThreatIntel ya enriquece con `fortigate_check_ip` (contexto de sesiones + estado de quarantine).
- El executor ya tiene la acción `block_ip` → `quarantine_ip`.
- `list_banned()` ya existe (sirve para listar bloqueos activos).
- El puente Wazuh→SOC-L1 (`custom-soc-l1` integration → `http://localhost:8000/webhook/wazuh-alert`)
  hoy rutea **solo** `<group>defender</group>`.

**Diferencia de mecanismo de bloqueo:**

| | Script actual (`custom-email-unified`) | SOC-L1 (`fortigate.py`) |
|---|---|---|
| Método | CMDB `firewall/addrgrp` (`WAZUH-BLOCKED`) | Monitor `user/banned/add_users` |
| Duración | Permanente | **TTL / auto-expiry** (default 1h) |

→ Casi no hay que "sumar API": ya está. La decisión es elegir el primitivo de bloqueo.

## 3. Decisiones (2026-06-22)

- **Modelo: auto-block + contexto.** Las 24 reglas de alta confianza siguen bloqueando
  **automático** (sin aprobación), pero ahora con enrichment + ticket InvGate + auditoría
  (caso con timeline) + mail con análisis de IA. Las reglas `fortigate_ips` de menor confianza
  van al flujo de **aprobación humana** existente (`/approvals`).
- **Mecanismo: banned/TTL.** Reusar `quarantine_ip` (auto-expiry). Cambia la semántica actual
  (hoy es permanente vía addrgrp) — se gana auto-limpieza.

## 4. Riesgos del cutover

1. **Latencia / disponibilidad.** Hoy el bloqueo es inline y síncrono. En SOC-L1 **no debe
   colgar del LLM**: el block sale en el *ingest* (fast-path); enrichment / IA / mail van después.
2. **`DRY_RUN_MODE=true`.** Hoy SOC-L1 simula las acciones. Hay que sacar dry-run para este path
   (o un override por-acción), si no los bloqueos dejan de ocurrir en silencio.
3. **Doble-bloqueo.** Apagar el `FortiGateBlocker` en `custom-email-unified`
   (`email-config.json` → `fortigate.enabled=false`) exactamente cuando SOC-L1 toma la posta.
4. **Guardrail.** Aplicar `PROTECTED_NETWORKS` (ya existe en SOC-L1) — el script actual no lo tiene.

## 5. Plan por fases

### Fase 0 — Observar (cero cambio de comportamiento)
- Agregar un 2º `<integration>` en `ossec.conf` con `<group>fortigate_ips</group>` → webhook SOC-L1.
- Normalizar las alertas IPS en SOC-L1 (`srcip`, `dstip`, `rule.id`, `attack`, severity).
- Pipeline en dry-run: registra el caso y **qué bloquearía**; comparar contra lo que hace el script.
- El script sigue bloqueando: sin riesgo, solo observación y validación de reglas / falsos positivos.

### Fase 1 — Cutover del auto-block
- Fast-path en el ingest para las 24 reglas → `quarantine_ip` (TTL), con **dedup** +
  **`PROTECTED_NETWORKS`**.
- Apagar `FortiGateBlocker` en `custom-email-unified`.
- Sacar dry-run para este path (o override por-acción).
- Sumar enrichment + ticket InvGate + mail con análisis de IA.
- Config nueva en `config.py` (`auto_block_rules`, `ttl`, `enabled`), editable en `/ui/config`.

### Fase 2 — Tiering + operación
- Reglas `fortigate_ips` de menor confianza → aprobación humana (`/approvals`).
- Acción `unblock` + vista de **bloqueos activos** en `/ui` (reusando `list_banned`).
- Tuning del TTL.

## 6. Referencias

- Trigger: `/var/ossec/etc/rules/custom-fortigate-ips.xml` (grupo `fortigate_ips`).
- Bloqueo actual: `/var/ossec/integrations/custom-email-unified` (clase `FortiGateBlocker`).
- Config actual: `/var/ossec/etc/email-config.json` (sección `fortigate`).
- Puente: `custom-soc-l1` integration en `ossec.conf`.
- SOC-L1: `src/tools/fortigate.py`, `src/executor.py` (`block_ip`), `src/agents/threatintel.py`.
