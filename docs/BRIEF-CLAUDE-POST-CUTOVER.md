# Brief para Claude — Tareas post-cutover SOC-L1

> Fecha: 2026-06-23  
> Proyecto: `/opt/soc-l1`  
> Host: `seg-vs85-prod01`  
> Estado: Cutover Fase 1 completado. SOC-L1 es el único blocker de FortiGate en vivo.

---

## 1. Contexto (lo mínimo que necesitás saber)

- SOC-L1 es un SOAR multi-agente que recibe alertas de Wazuh por webhook y aplica acciones automáticas.
- En Fase 1, solo `block_ip` (FortiGate) está en **enforce real** (vivo). Las demás familias están en simulación:
  - `scan_host`, `isolate_host` (Defender) → SIMULA
  - `disable_user`, `force_password_change` (AD) → SIMULA
- El mecanismo de bloqueo usa `quarantine_ip` en FortiGate con TTL de 1h (`user/banned`), NO el addrgrp permanente `WAZUH-BLOCKED` del script viejo.
- El script viejo (`custom-email-unified`) está apagado (`fortigate.enabled=false`).
- El servicio corre bajo systemd (`soc-l1.service`), activo y enabled.
- Health en `http://0.0.0.0:8000/health` responde 200.
- Prod corre el branch `feat/dryrun-toggles-fgt-fase1` @ `631c3ac`. PR #13 aún no mergeado.

---

## 2. Tareas a ejecutar (en este orden)

### Tarea A1 — Mergear PR #13 a `main` y redeployar desde `main`

**Objetivo:** Dejar de correr prod desde un feature branch.

**Pasos sugeridos:**
1. Revisar PR #13 en el repo (diff, tests, conflictos con `main`).
2. Hacer merge a `main` (squash o merge commit, según convención del proyecto).
3. En `seg-vs85-prod01`:
   ```bash
   cd /opt/soc-l1
   git fetch origin
   git checkout main
   git pull origin main
   git log --oneline -1   # debe mostrar el merge de PR #13
   ```
4. Recargar/reiniciar el servicio:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl restart soc-l1
   sudo systemctl status soc-l1 --no-pager
   ```
5. Verificar health:
   ```bash
   curl -s http://127.0.0.1:8000/health | jq .
   ```

**Criterio de éxito:**
- `git branch` en prod muestra `main`.
- `git log --oneline -1` coincide con el merge de PR #13.
- `systemctl is-active soc-l1` = `active`.
- `GET /health` = 200.

**Qué NO hacer:**
- No borrar el branch `feat/dryrun-toggles-fgt-fase1` hasta que `main` esté verificado en prod.
- No reiniciar el servidor todavía (es la Tarea A2).

---

### Tarea A2 — Reinicio controlado del servidor

**Objetivo:** Verificar que systemd levanta SOC-L1 solo después de un reboot.

**Pasos sugeridos:**
1. Avisar al operador humano antes del reboot.
2. En ventana controlada:
   ```bash
   sudo reboot
   ```
3. Esperar que el servidor vuelva.
4. Verificar:
   ```bash
   sudo systemctl is-active soc-l1
   sudo systemctl is-enabled soc-l1
   curl -s http://127.0.0.1:8000/health | jq .
   ```
5. Revisar logs recientes:
   ```bash
   sudo journalctl -u soc-l1 -n 50 --no-pager
   ```

**Criterio de éxito:**
- `systemctl is-active soc-l1` = `active`.
- `systemctl is-enabled soc-l1` = `enabled`.
- Health 200.
- No errores críticos en los últimos 50 líneas de log.

**Qué NO hacer:**
- No reiniciar sin avisar al operador.
- No ejecutar otros cambios durante el mismo mantenimiento.

---

### Tarea A3 — Validar bloqueos reales de SOC-L1 durante 24–48h

**Objetivo:** Confirmar que el auto-block real funciona con tráfico de producción y no genera falsos positivos.

**Pasos sugeridos:**
1. Monitorear el registro de bloqueos:
   ```bash
   tail -f /opt/soc-l1/fgt_observations.jsonl
   ```
   (o `cat` / `jq` si no está en tiempo real).
2. Buscar eventos con acción real (no simulada):
   ```bash
   jq 'select(.action == "quarantine_ip" and .dry_run != true)' /opt/soc-l1/fgt_observations.jsonl
   ```
3. Para cada bloqueo real observado, verificar:
   - La IP no pertenece a `PROTECTED_NETWORKS` (`10/8`, `172.16/12`, `192.168/16`, `127/8`).
   - La IP es efectivamente un atacante externo (no infraestructura propia, VPN, partner, etc.).
   - El TTL es de 1h.
4. Verificar en FortiGate que la IP aparece en `user/banned`:
   ```bash
   # usando el script existente o la API directa
   python3 /opt/soc-l1/scripts/fgt_parity.py
   ```
5. Documentar hallazgos (falsos positivos, volumen, IPs sospechosas).

**Criterio de éxito:**
- Al menos 1 bloqueo real confirmado correcto (IP atacante, no protegida, TTL 1h).
- Cero falsos positivos graves (IP propia o protegida bloqueada).
- `fgt_parity.py` o consulta a FortiGate muestra la IP baneada.

**Qué NO hacer:**
- No modificar reglas de enforce durante esta ventana.
- No tocar la lista `WAZUH-BLOCKED` legacy.

---

### Tarea A4 — Escribir runbook de emergencia para apagar auto-block

**Objetivo:** Tener un procedimiento claro y rápido para desactivar el bloqueo en vivo en caso de incidente.

**Pasos sugeridos:**
1. Crear o actualizar `docs/runbook-emergencia-fortigate.md`.
2. Incluir al menos:
   - Cómo apagar rápido:
     ```bash
     cd /opt/soc-l1
     # Opción A: apagar solo FortiGate auto-block
     sed -i 's/^FORTIGATE_AUTOBLOCK_ENABLED=.*/FORTIGATE_AUTOBLOCK_ENABLED=false/' .env
     # Opción B: master kill-switch (simula TODO, incluido FortiGate)
     sed -i 's/^DRY_RUN_MODE=.*/DRY_RUN_MODE=true/' .env
     sudo systemctl restart soc-l1
     sudo systemctl status soc-l1 --no-pager
     curl -s http://127.0.0.1:8000/health | jq .
     ```
   - Cómo verificar que apagó:
     - Revisar logs: ningún `quarantine_ip` real tras el cambio.
     - Enviar alerta de prueba y confirmar que se simula.
   - Cómo volver a encender (revertir).
   - Quién debe ejecutarlo y cómo documentar la acción.
   - Números/contactos de escalación (dejar placeholders si no se conocen).
3. Hacer un test real del apagado en modo seguro:
   - Cambiar `FORTIGATE_AUTOBLOCK_ENABLED=false`, reiniciar, enviar alerta de prueba, confirmar simulación.
   - Volver a `true` y reiniciar.

**Criterio de éxito:**
- Archivo `docs/runbook-emergencia-fortigate.md` existe y es claro.
- Test de apagado/encendido funciona sin afectar el servicio.
- Health 200 durante todo el proceso.

**Qué NO hacer:**
- No dejar `FORTIGATE_AUTOBLOCK_ENABLED=false` sin avisar al operador.
- No cambiar `DRY_RUN_AD` o `DRY_RUN_DEFENDER` durante el test.

---

## 3. Archivos y rutas clave

| Ruta | Para qué sirve |
|---|---|
| `/opt/soc-l1/.env` | Flags `DRY_RUN_MODE`, `FORTIGATE_AUTOBLOCK_ENABLED`, `DRY_RUN_AD`, `DRY_RUN_DEFENDER`, etc. |
| `/opt/soc-l1/src/config.py` | Lógica de `dry_run_for()`, `_ACTION_FAMILY`, `PROTECTED_NETWORKS`. |
| `/opt/soc-l1/src/fortigate_autoblock.py` | `evaluate()`, `observe()`, `enforce()`, dedup por IP. |
| `/opt/soc-l1/src/tools/fortigate.py` | `quarantine_ip()`, `list_banned()`. |
| `/opt/soc-l1/src/executor.py` | Ejecuta acciones según familia y dry-run. |
| `/opt/soc-l1/fgt_observations.jsonl` | Registro de bloqueos (gitignored). |
| `/opt/soc-l1/scripts/fgt_parity.py` | Verifica parity entre SOC-L1 y FortiGate. |
| `/opt/soc-l1/docs/ESTADO-SISTEMA-2026-06-23.md` | Estado actual detallado. |
| `/etc/systemd/system/soc-l1.service` | Definición del servicio. |
| `/var/ossec/etc/ossec.conf` | Integración de Wazuh con SOC-L1. |
| `/var/ossec/etc/email-config.json` | Config del blocker viejo (apagado). |

---

## 4. Comandos de verificación recurrentes

```bash
# Estado del servicio
sudo systemctl status soc-l1 --no-pager
sudo systemctl is-active soc-l1
sudo systemctl is-enabled soc-l1

# Health
curl -s http://127.0.0.1:8000/health | jq .

# Logs
sudo journalctl -u soc-l1 -n 100 -f

# Bloqueos recientes
jq -c 'select(.action == "quarantine_ip")' /opt/soc-l1/fgt_observations.jsonl | tail -20

# Parity FortiGate
python3 /opt/soc-l1/scripts/fgt_parity.py

# Branch actual
cd /opt/soc-l1 && git branch --show-current && git log --oneline -1
```

---

## 5. Límites claros: qué NO tocar sin consultar al operador

- **NO encender AD ni Defender en vivo.** Quedan en `DRY_RUN_AD=true` y `DRY_RUN_DEFENDER=true`.
- **NO modificar `PROTECTED_NETWORKS`** sin confirmar con el equipo de red.
- **NO limpiar ni modificar el addrgrp `WAZUH-BLOCKED`** legacy en FortiGate.
- **NO agregar ni quitar reglas de enforce** sin validación.
- **NO modificar `/var/ossec/etc/ossec.conf`** sin backup.
- **NO hacer `git push --force`, `git reset`, `git rebase` ni git mutations.**

---

## 6. Criterio de cierre de este brief

Se considera completo cuando:

1. PR #13 está mergeado y prod corre desde `main`.
2. El servidor se reinició y SOC-L1 volvió solo por systemd.
3. Se validó al menos un bloqueo real correcto de SOC-L1 en 24–48h.
4. Existe `docs/runbook-emergencia-fortigate.md` y fue probado.
5. El operador humano fue informado de cualquier hallazgo o desviación.

---

## 7. Notas para Claude

- Trabajá en `/opt/soc-l1`. Todos los paths son relativos a ese directorio salvo que diga lo contrario.
- Si vas a editar `.env`, hacé backup primero (`cp .env .env.bak-claude-YYYYMMDD-HHMMSS`).
- Si vas a reiniciar el servicio, avisá en el chat y confirmá health después.
- Si encontrás errores, detenete y consultá antes de aplicar fixes grandes.
- Mantené los cambios mínimos. El objetivo es estabilizar, no refactorizar.
