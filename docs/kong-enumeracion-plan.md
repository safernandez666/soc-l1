# Enumeración de endpoints en Kong (100207) → SOC-L1

**Fecha:** 2026-09-21 · **Estado:** ✅ en producción desde el 2026-09-21 13:56. Falta el rate-limit en Kong.

## El disparador

El reporte IA diario avisó:

> 🔴 Kong: Multiple 404 errors from 213.209.159.154 – posible enumeración de endpoints
> (seg-vs85-prod01). Investigar origen y considerar bloqueo de la IP en perímetro.

Pregunta razonable: *¿no debería bloquear esa IP solo?* No podía, por dos motivos
independientes.

### 1. Ese aviso no sale de SOC-L1

Sale de `~/scripts/ia/wazuh_ia.py`, el cron del reporte diario, que **no está en este
repo** y es de solo lectura: consulta OpenSearch, resume con un LLM y manda el mail.
Recomienda, nunca actúa. La línea está en `wazuh_ia_daily.log:10306`.

### 2. SOC-L1 nunca veía la alerta

Los cuatro bloques `<integration>` de `custom-soc-l1` en `/var/ossec/etc/ossec.conf`
rutean IPS de FortiGate (`1962xx`), VPN/identidad y cambios de cuenta de AD. La regla
de Kong **100207** no estaba en ninguno → el webhook jamás se disparaba. Y aunque
hubiese llegado, `FORTIGATE_AUTO_BLOCK_RULES` solo tiene firmas IPS, así que
`evaluate()` la habría descartado con `no_rule_match`.

## Qué se hizo

### a) Modo sombra por regla (código)

Se agregó `FORTIGATE_OBSERVE_ONLY_RULES`: reglas que el auto-block trata como
**candidatas** —las evalúa, aplica `PROTECTED_NETWORKS`, deduplica por IP dentro del
TTL, las registra en `fgt_observations.jsonl` y avisa por mail + Teams "bloquearía X"—
pero que **nunca** llaman a la API del FortiGate, aunque `FORTIGATE_AUTOBLOCK_ENABLED=true`.

Existía ya un modo observación, pero era **global** (`fortigate_autoblock_enabled=False`,
la Fase 0 del cutover): usarlo habría apagado el bloqueo en vivo de las 26 reglas IPS.
Por eso el modo sombra es por-regla.

| Archivo | Cambio |
|---|---|
| `src/config.py` | `fortigate_observe_only_rules` + `fortigate_observe_only_rules_set()`. Si un ID está en las dos listas, `fortigate_auto_block_rules_set()` lo resta: gana lo seguro. |
| `src/fortigate_autoblock.py` | `AutoBlockDecision.observe_only`; `evaluate()` lo marca; `enforce()` delega en `observe()` y sale sin tocar el firewall. |
| `src/main.py` | Rama nueva en el fast-path del webhook, antes del short-circuit de "bloqueado". Responde `202 {"status":"observed_fgt_autoblock","mode":"observe_only"}`. El aviso mail+Teams se extrajo a `_spawn_fgt_observation_notices()`, compartido con la Fase 0. |
| `tests/test_fortigate_autoblock.py` | 8 tests nuevos, incluida la regresión de que tener reglas en sombra **no** le saca el gatillo a las IPS. |

**No** se crea ticket InvGate en modo sombra: el closed-loop de auditoría documenta un
bloqueo, y acá no hubo bloqueo que auditar. El ticket vuelve solo si se promueve la regla.

### b) Ruteo en Wazuh

`deploy/route-kong-enumeration-rule.py` agrega el bloque `<integration>` que falta.
Mismo patrón que `route-ad-privileged-rules.py`: backup con sello, validación XML antes
de escribir, restart opt-in, rollback impreso. Idempotente. La `api_key` se lee del
bloque `custom-soc-l1` vivo en vez de hardcodearse.

Se rutea **solo 100207**. No se rutea:

- **100206** (404 suelto, nivel 4, 23.157 hits / 1.667 IPs en 30d): es el sustrato de
  100207 vía `if_matched_sid`. Rutearla sería ruido puro.
- **100241** (alta tasa, nivel 7): sus 226 hits salieron 226/226 del bridge de Docker.

### c) Por qué sombra y no bloqueo directo

Las 26 reglas que hoy bloquean solas son firmas IPS de exploit (nivel 13-14): "esto es
un ataque, punto". 100207 es correlación de N×404 **nivel 8** contra
`gateway.grupoalemana.com`, que está publicado desde el 24/08. Mirando los orígenes
reales de los últimos 30 días (2.041 alertas, 71 IPs distintas, 1-9 por día):

```
80.94.95.211    397     213.209.159.154 238     213.209.159.175 175
35.201.245.139  114  ←  34.125.90.143   109  ←  35.189.146.167  104  ←  GCP
136.85.86.79    107     34.87.12.223     99  ←  23.94.252.178    97
```

Las marcadas son rangos de Google Cloud. Pueden ser escáneres, pero también un cliente
o un monitor legítimo corriendo en GCP: un ban de 1h contra esa IP es una caída de la
integración, no una contención. Eso es exactamente lo que el modo sombra deja medir
antes de decidir.

Dato tranquilizador: **0 alertas desde redes privadas en 30 días**. Eso es el tuning
`zz-kong-tuning.xml` haciendo su trabajo: se desplegó el 26/08 (está en
`/var/ossec/etc/rules/`, mismo tamaño que la copia del repo — no pude hacerle `md5sum`
sin root) y su regla hija 100307 suprime a nivel 0 lo que venga del bridge de Docker.
Doble red: aunque ese tuning se cayera, `172.18.0.1` está dentro de `172.16.0.0/12` →
`PROTECTED_NETWORKS` lo frena igual. Hay un test que fija ese segundo cinturón.

## ✅ Aplicado en producción — 2026-09-21

Con `/tmp/implementar-kong-socl1.sh`. Backup del `ossec.conf` en
`/var/ossec/etc/ossec.conf.bak-pre-kong-20260921-135252`.

- `wazuh-analysisd` reiniciado **13:53:32** → 100207 se rutea a SOC-L1.
- `soc-l1.service` reiniciado **13:56:45**, arranque limpio, `/health` 200.

### Lección: el orden de los reinicios

El script reiniciaba **wazuh primero y soc-l1 después**, y eso abrió una ventana de
**3m13s** (13:53:32 → 13:56:45) en la que wazuh ya ruteaba 100207 pero SOC-L1 corría
código viejo, sin modo sombra. Una alerta en ese hueco habría caído al pipeline completo
—Narrator, enriquecimiento, ticket InvGate y mail de aprobación—, justo lo que el modo
sombra evita. No entró ninguna (las últimas 100207 del día fueron 01:55 y 06:03), pero
fue suerte, no diseño.

**Regla general: primero el consumidor, después el productor.** Desplegar el código
nuevo con el ruteo viejo es inocuo (la alerta simplemente no llega); al revés, no.
El script ya está corregido, y ahora además verifica que el proceso nuevo trate 100207
como sombra **antes** de abrirle el grifo a wazuh.

### Rate-limit en Kong — el fix de fondo (sigue pendiente)

Banear escáneres con TTL de 1h es tapar el sol con la mano: vuelven con otra IP (71 en
30 días ya lo muestran). Lo que corta la enumeración de raíz es limitar la tasa en el
propio gateway.

**No pude hacerlo**: el Admin API de Kong (`192.168.38.62:8001`) no es alcanzable desde
`seg-vs85-prod01` —está bindeado a localhost a propósito— y no hay SSH a ese host desde
esta cuenta (`Permission denied (publickey,password)`). Necesita alguien con acceso al
box.

Desde el host de Kong, plugin global, empezando permisivo para no romper nada:

```bash
curl -s -X POST http://localhost:8001/plugins \
  --data name=rate-limiting \
  --data config.minute=300 \
  --data config.hour=5000 \
  --data config.policy=local \
  --data config.limit_by=ip \
  --data config.fault_tolerant=true
```

`fault_tolerant=true` es importante: si el backend del contador falla, Kong deja pasar
en vez de cortar. Y conviene mirar primero el percentil real de tráfico legítimo
(`config.minute=300` es una conjetura, no una medición) antes de fijar el número.

Si la POC corre en modo declarativo (`KONG_DECLARATIVE_CONFIG`), esto va en el `kong.yml`
bajo `plugins:` y se recarga con `kong reload`, no por el Admin API.

## Cómo verificar que quedó andando

```bash
journalctl -u soc-l1.service -f | grep FGT-AUTOBLOCK
tail -f /opt/soc-l1/fgt_observations.jsonl
```

En la próxima 100207 se espera una línea `🔭 FGT-AUTOBLOCK OBSERVE | WOULD quarantine
ip=<x> rule=100207 ... (modo sombra: no ejecutado)` y un registro con
`"would_block": true, "executed": null`. El `banned` del FortiGate tiene que seguir sin
esa IP:

```bash
.venv/bin/python -c "import asyncio;from src.config import Settings;from src.tools.fortigate import FortigateClient
async def m():
    async with FortigateClient(Settings()) as c: print(await c.list_banned())
asyncio.run(m())"
```

## Si se decide promover la regla a bloqueo real

Después de un par de semanas de sombra, revisar `fgt_observations.jsonl` y confirmar que
no hay ninguna IP que sea un cliente legítimo. Entonces:

1. Mover `100207` de `FORTIGATE_OBSERVE_ONLY_RULES` a `FORTIGATE_AUTO_BLOCK_RULES`.
2. `sudo systemctl restart soc-l1.service`.
3. **Probar que el ban efectivamente corta.** La `banned` list del FortiGate se aplica a
   tráfico que atraviesa el firewall, pero Kong se publica por VIP/access-proxy: no está
   verificado que el ban intercepte ese camino. Probarlo desde fuera (4G, no desde el box
   — el hairpin da falsos negativos, ver el cutover de `socl1.grupoalemana.com`) baneando
   a mano la IP propia y confirmando que el gateway deja de responder.

No tiene sentido promover la regla antes de tener ese punto 3 verificado: bloquearía
creyendo que contiene, sin contener.
