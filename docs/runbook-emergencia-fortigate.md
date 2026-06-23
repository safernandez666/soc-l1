# Runbook de emergencia — apagar el auto-block FortiGate de SOC-L1

> Objetivo: desactivar **rápido** el bloqueo automático en vivo ante un incidente
> (falso positivo grave, bloqueo de IP propia/partner, comportamiento anómalo).
> Host: `seg-vs85-prod01` · Servicio: `soc-l1.service` · Dir: `/opt/soc-l1`
> Última actualización: 2026-06-23 (post-cutover Fase 1).

---

## TL;DR — apagar YA

```bash
cd /opt/soc-l1
cp .env .env.bak-emergencia-$(date +%Y%m%d-%H%M%S)
# Opción A (recomendada): apaga SOLO el auto-block de FortiGate
sed -i 's/^FORTIGATE_AUTOBLOCK_ENABLED=.*/FORTIGATE_AUTOBLOCK_ENABLED=false/' .env
sudo systemctl restart soc-l1
```
Verificar (debe decir SIMULA o no ejecutar):
```bash
curl -s -o /dev/null -w "health %{http_code}\n" http://127.0.0.1:8000/health
/opt/soc-l1/.venv/bin/python -c "from src.config import Settings; s=Settings(); print('autoblock_enabled=', s.fortigate_autoblock_enabled, '| block_ip dry_run=', s.dry_run_for('block_ip'))"
```
Resultado esperado: `autoblock_enabled= False`. Con eso SOC-L1 deja de quarantinar (vuelve a solo observar). **El FortiGate IPS inline sigue dropeando igual** — no quedás sin defensa.

---

## Opciones de apagado

### Opción A — apagar solo FortiGate (quirúrgica, RECOMENDADA)
`FORTIGATE_AUTOBLOCK_ENABLED=false` → SOC-L1 vuelve a Fase 0 (observa, no ejecuta). AD/Defender no se tocan.

### Opción B — master kill-switch (apaga TODO)
```bash
cd /opt/soc-l1
cp .env .env.bak-emergencia-$(date +%Y%m%d-%H%M%S)
sed -i 's/^DRY_RUN_MODE=.*/DRY_RUN_MODE=true/' .env
sudo systemctl restart soc-l1
```
Pone en simulación **todas** las familias (FortiGate + AD + Defender), ignorando overrides. Usar si hay dudas generalizadas, no solo de FortiGate.

> Ambas requieren `sudo systemctl restart soc-l1` para tomar efecto (la config se lee al iniciar).

---

## Verificar que realmente apagó

1. **Config efectiva:**
   ```bash
   /opt/soc-l1/.venv/bin/python -c "from src.config import Settings; s=Settings(); \
   print({a: ('SIMULA' if s.dry_run_for(a) else 'EJECUTA') for a in ['block_ip','scan_host','isolate_host','disable_user']})"
   ```
   `block_ip` debe decir `SIMULA` (Opción B) o, con Opción A, `autoblock_enabled=False` (el enforce no corre aunque block_ip figure live).

2. **Sin bloqueos reales nuevos en el registro** (campo correcto = `executed`, NO `action`):
   ```bash
   jq -c 'select(.executed==true)' /opt/soc-l1/fgt_observations.jsonl | tail -5
   ```
   No deben aparecer entradas nuevas con `"executed": true` después del apagado.

3. **Logs del servicio:**
   ```bash
   sudo journalctl -u soc-l1 -n 50 --no-pager | grep -E "FGT-AUTOBLOCK|quarantine"
   ```
   En Fase 0 verás `OBSERVE | WOULD quarantine ... (no ejecutado)`; NO debe haber `ENFORCE | quarantine OK`.

---

## Levantar una IP mal bloqueada (unban inmediato)

No hay unban en la UI. Los bans de SOC-L1 expiran solos por TTL (1h), pero para sacar una YA:
```bash
/opt/soc-l1/.venv/bin/python - <<'PY'
import asyncio
from src.config import Settings
from src.tools.fortigate import FortigateClient
IP = "X.X.X.X"   # <-- IP a desbloquear
async def m():
    async with FortigateClient(Settings()) as fg:
        await fg._post('/api/v2/monitor/user/banned/clear_users', json={'ip_addresses':[IP]})
        print('unban OK', IP, '| baneadas restantes:', len(await fg.list_banned()))
asyncio.run(m())
PY
```
Ver qué hay baneado: `list_banned()` (mismo patrón, `await fg.list_banned()`).

> Nota: esto limpia el ban de SOC-L1 (`user/banned`). El addrgrp legacy `WAZUH-BLOCKED` del script viejo es OTRA cosa (permanente, no se toca acá).

---

## Volver a encender (revertir)

```bash
cd /opt/soc-l1
# revertir al .env previo:
cp .env.bak-emergencia-<TIMESTAMP> .env     # o editar a mano
# o reactivar puntual:
sed -i 's/^FORTIGATE_AUTOBLOCK_ENABLED=.*/FORTIGATE_AUTOBLOCK_ENABLED=true/' .env   # Opción A
sed -i 's/^DRY_RUN_MODE=.*/DRY_RUN_MODE=false/' .env                                # Opción B
sudo systemctl restart soc-l1
```
Verificar que `block_ip` vuelva a `EJECUTA` y `autoblock_enabled=True`.

---

## Quién / cuándo / cómo documentar

- **Quién:** operador con sudo en `seg-vs85-prod01` (hoy: el equipo de seguridad / Santiago).
- **Cuándo:** falso positivo grave (IP propia/partner/VPN bloqueada), comportamiento anómalo del auto-block, o pedido de red/negocio.
- **Documentar:** anotar en el canal del equipo: hora, IP/regla afectada, opción usada (A/B), y abrir seguimiento para la causa raíz antes de re-encender.
- **Escalación:** _(placeholders)_ Seguridad: ____ · Redes/FortiGate: ____ · Dueño SOC-L1: ____

---

## Guardrails que siguen activos (contexto)

- `PROTECTED_NETWORKS` (`10/8, 172.16/12, 192.168/16, 127/8`): esas IPs nunca se bloquean.
- Dedup por IP (ventana TTL 1h): no re-banea ráfagas de la misma IP.
- AD y Defender quedan en simulación (`DRY_RUN_AD=true`, `DRY_RUN_DEFENDER=true`) — **no** encenderlos sin coordinar.
- El FortiGate IPS inline dropea ataques independientemente de SOC-L1 (defensa de base siempre presente).
