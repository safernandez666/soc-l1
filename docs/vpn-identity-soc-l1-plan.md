# Tratamientos de VPN en SOC-L1 — plan e implementación

Trae las alertas **VPN de FortiGate** (SSL-VPN) al pipeline de SOC-L1 para:
- **notificar** (email de aprobación + cierre con timeline), y
- habilitar **respuesta sobre identidad** con aprobación humana (AD: `force_password_change` / `disable_user`).

NO es autoblock de IP — es el pipeline humano-en-el-loop normal. Espejo del modelo Fase 0 / Fase 1 del [autoblock de FortiGate](fortigate-autoblock-plan.md).

## Taxonomía de reglas (Wazuh `custom-fortigate-vpn.xml`)

| rule_id | nivel | grupo / detección | tratamiento en SOC-L1 |
|---|---|---|---|
| 196104 | 8 | `fortigate_vpn_monitored_user` — usuario monitoreado fuera de horario | señal débil → `notify_only` (escala si hay otra señal) |
| 196105 | 7 | usuario monitoreado fin de semana | `notify_only` |
| 196107 | 11 | `fortigate_vpn_multiple_ips` — mismo user, varias IPs | `force_password_change` |
| 196109 | 13 | `fortigate_vpn_multiple_countries` — impossible travel | `disable_user` + `escalate_l2` |
| 196113 | 12 | admin fuera de horario | `escalate_l2` (+ `force_password_change` si otra señal) |

NO se reenvían `196102/196103` (nivel 5, **todos** los usuarios) → ruido.
`196100/196101/196112` (brute-force / China) ya están en el **autoblock** de SOC-L1 (bloqueo de IP) — quedan como están; respuesta de identidad sobre esas es una fase 2 dual-track.

## Cambios en SOC-L1 (este repo) — HECHOS

- **normalize** (`src/normalize.py`): lee el SAM de `data.dstuser` (los SSL-VPN de FortiGate no traen `srcuser`/`user`) y la IP del cliente de `data.remip`. Sin esto el Enricher no resuelve el user en AD.
- **Triage** (`src/agents/triage.py`): las reglas `fortigate_vpn_*` / MITRE `T1078` van siempre a `analyze`, nunca `auto_close_benign` (no tienen file evidence ni categoría crítica → se auto-cerrarían).
- **Narrator** (`src/agents/narrator.py`): sección VPN/identidad con el mapeo conservador de la tabla. Ante la duda fuera-de-horario sin otra señal → `notify_only`.
- **Tests/fixture**: `tests/fixtures/fortigate_vpn_offhours.json` (alert 196104 real) + tests de normalize y guard-tests de prompt.
- **PROTECTED_USERS** (`.env`): se agregaron `veeambackup,tareaprogramada,migra365,fgarcia-adm,lmata-adm` — cuentas de servicio/admin que corren de noche/finde a propósito y NO deben ser deshabilitadas por el SOC. Requiere restart del servicio antes de Fase 1.

## Cambios en Wazuh (`/var/ossec/etc/ossec.conf`) — PENDIENTE (lo aplica el equipo Wazuh)

### 1. Agregar integración (reenvía las VPN de identidad al webhook de SOC-L1)

```xml
  <!-- soc-l1: alertas VPN/identidad de FortiGate (notif + respuesta AD con aprobación) -->
  <integration>
    <name>custom-soc-l1</name>
    <hook_url>http://localhost:8000/webhook/wazuh-alert</hook_url>
    <api_key>34ca6e272f91bf6684352b512ca86e76b7ebbd4e7bc933af283604bec5ce18e5</api_key>
    <alert_format>json</alert_format>
    <rule_id>196104,196105,196107,196109,196113</rule_id>
  </integration>
```

(El `api_key` es el mismo HMAC que ya usan los otros bloques `custom-soc-l1`.)

### 2. Cutover del email legacy — SOLO en Fase 1 (no en Fase 0)

En Fase 0 dejamos el `custom-email-unified` legacy en paralelo (no perdemos visibilidad mientras validamos). Al pasar a Fase 1, para evitar doble-notificación, quitar estas reglas del legacy:

- Bloque `<group>fortigate_vpn_monitored_user</group>` (level 8) → cubre 196104/196105: **eliminar** el `<integration>`.
- Bloque `<rule_id>196100,196101,196107,196109,196112,196113</rule_id>` (level 11) → **quitar** `196107,196109,196113`, dejando `196100,196101,196112`.

### 3. Aplicar

```bash
# validar config ANTES de reiniciar (un conf malformado tira el manager)
/var/ossec/bin/wazuh-logtest -t   # o verify-agent-conf según versión
systemctl restart wazuh-manager
```

## Rollout

- **Fase 0 — observe/notify** (`DRY_RUN_AD=true`, ya seteado): se reenvían las VPN, corre el pipeline, salen los mails de aprobación, las acciones de AD aprobadas se **simulan**. Validar decisiones del Narrator y calidad de emails ~1 semana. Riesgo cero sobre identidad. Legacy email queda en paralelo.
- **Fase 1 — identidad en vivo** (`DRY_RUN_AD=false`): las acciones aprobadas se ejecutan de verdad. Gates previos:
  1. Restart de `soc-l1.service` para tomar el nuevo `PROTECTED_USERS`.
  2. Confirmar que el bind `wazuhseg@grupoalemana.com` tiene permiso de escritura en AD (`userAccountControl`, `pwdLastSet`).
  3. Cutover del email legacy (sección 2).

## Pendientes / decisiones abiertas

- **Q3**: cuentas de servicio (`veeambackup`, `tareaprogramada`, `migra365`, `*-adm`) — ¿sacarlas del regex en `custom-fortigate-vpn.xml` (ni notifican) o dejarlas notificando pero protegidas en SOC-L1 (ya protegidas)? Define el ruido de Fase 0.
- **B2 opcional**: flag de fuera-de-horario / impossible-travel en el Enricher para más contexto al Narrator (hoy nos apoyamos en la señal del rule de Wazuh, que alcanza).
- **Deuda de tests**: 9 fallas de aislamiento/orden en el run completo (`test_config`/`test_executor`/`test_webhook`; pasan en aislado) — objetivo de la branch `fix/test-isolation-prod-safety`.
