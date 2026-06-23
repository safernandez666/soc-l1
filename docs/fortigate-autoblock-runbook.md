# Runbook: auto-block FortiGate (apply / observar / cutover / rollback)

Operación del plan en `docs/fortigate-autoblock-plan.md`. Todo lo que toca el lado Wazuh
necesita `sudo` (lo aplica el operador). SOC-L1 corre hoy en `:8000` por `nohup` (no systemd).

## 0. Backups (hacer ANTES de tocar nada)

Backup de los archivos del cutover (lado Wazuh + estado SOC-L1), con checksums, fuera del repo:

```bash
TS=$(date +%Y%m%d-%H%M%S); BK=~/backups/fgt-autoblock-$TS
mkdir -p "$BK/wazuh" "$BK/soc-l1"; chmod 700 ~/backups "$BK"
cp -a /var/ossec/etc/ossec.conf /var/ossec/integrations/custom-email-unified \
      /var/ossec/etc/email-config.json "$BK/wazuh/"
cp -a /opt/soc-l1/.env /opt/soc-l1/state.db "$BK/soc-l1/"
( cd "$BK" && find . -type f ! -name MANIFEST.txt -exec sha256sum {} \; > MANIFEST.txt )
chmod -R go-rwx "$BK"   # adentro hay secretos
```

Un backup base ya quedó hecho en `~/backups/fgt-autoblock-20260622-153841/`.

## 1. Fase 0 — Observar (cero cambio de comportamiento)

SOC-L1 corre con `FORTIGATE_AUTOBLOCK_ENABLED=false` (default) → **solo observa y corta**, no
bloquea ni dispara pipeline. El `custom-email-unified` sigue bloqueando como hoy.

**Apply:** agregar en `/var/ossec/etc/ossec.conf`, junto al `<integration>custom-soc-l1</integration>`
existente (antes de `</ossec_config>`):

```xml
<!-- Fase 0 auto-block FortiGate: observar las 24 reglas IPS de alta confianza en SOC-L1 -->
<integration>
  <name>custom-soc-l1</name>
  <hook_url>http://localhost:8000/webhook/wazuh-alert</hook_url>
  <api_key>34ca6e272f91bf6684352b512ca86e76b7ebbd4e7bc933af283604bec5ce18e5</api_key>
  <alert_format>json</alert_format>
  <rule_id>196201,196202,196203,196204,196207,196208,196210,196212,196213,196214,196215,196217,196218,196220,196221,196222,196223,196226,196227,196228,196230,196100,196101,196112</rule_id>
</integration>
```

```bash
sudo systemctl restart wazuh-manager
```

**Observar:**

```bash
tail -f /tmp/soc-l1-uvicorn.log | grep FGT-AUTOBLOCK          # en vivo
/opt/soc-l1/.venv/bin/python -m src.fortigate_autoblock        # resumen acumulado
```

**Qué mirar (1–2 semanas):** volumen de `would_block`/día (¿el TTL tiene sentido?), `ips_protegidas_evitadas`
(bugs latentes del script actual que bloquea redes propias), reglas que disparan sobre tráfico benigno
(candidatas a bajar a aprobación humana en Fase 2).

## 2. Fase 1 — Cutover (SOC-L1 toma el bloqueo)

Solo cuando los datos de Fase 0 estén OK. Es un flip + apagar el blocker viejo:

1. **SOC-L1 bloquea:** en `/opt/soc-l1/.env` → `FORTIGATE_AUTOBLOCK_ENABLED=true`.
   (Revisar TTL: `FORTIGATE_BLOCK_TTL_HOURS`. Hoy era permanente → considerar 8–24h al inicio.)
   Verificar que `DRY_RUN_MODE` no simule este path (override por-acción o cutover de dry-run).
2. **Apagar el blocker viejo:** en `/var/ossec/etc/email-config.json` → `fortigate.enabled=false`
   (el `custom-email-unified` deja de bloquear; puede seguir mandando su mail o se migra al de SOC-L1).
3. Reiniciar: SOC-L1 (`nohup`) y `sudo systemctl restart wazuh-manager`.
4. Validar: una alerta de prueba bloquea vía SOC-L1, queda como caso con timeline + ticket, y el
   `custom-email-unified` NO bloqueó (sin doble-block).

> ⚠️ Coreografía: el paso 1 y 2 van juntos. Si solo hacés 1 → doble bloqueo. Si solo hacés 2 → cero bloqueo.

## 3. Rollback

- **Fase 0:** quitar el `<integration>` agregado de `ossec.conf` y `sudo systemctl restart wazuh-manager`.
  SOC-L1 deja de recibir las IPS (no afecta nada, ya estaba en observación).
- **Fase 1:** `FORTIGATE_AUTOBLOCK_ENABLED=false` en `.env` (SOC-L1 vuelve a observar) **y**
  `fortigate.enabled=true` en `email-config.json` (vuelve a bloquear el script viejo). Reiniciar ambos.
- **Restore desde backup:** copiar de vuelta los archivos de `~/backups/fgt-autoblock-<TS>/` (verificar
  contra `MANIFEST.txt`) y reiniciar los servicios.
```bash
sha256sum -c ~/backups/fgt-autoblock-<TS>/MANIFEST.txt   # (corriendo desde ese dir)
```
