# Deploy de tuning de reglas de Wazuh

Hay dos tunings en este directorio. El script es el mismo; se elige con `TUNING_FILE`:

| Archivo | Qué silencia | Estado |
|---|---|---|
| `zz-custom-ad-tuning.xml` (default) | 100123 DCSync y 100126 audit policy | staged, sin deploy |
| `zz-kong-tuning.xml` | 100241 y 100207 cuando el origen es el bridge de Docker | staged, sin deploy |

```bash
sudo TUNING_FILE=zz-kong-tuning.xml ./deploy.sh --dry-run
sudo TUNING_FILE=zz-kong-tuning.xml ./deploy.sh
sudo TUNING_FILE=zz-kong-tuning.xml ./deploy.sh --rollback
```

Sin `TUNING_FILE` se despliega el de AD, como estaba documentado.

## Tuning de reglas AD (100123 / 100126)

**Qué hace:** suprime el ruido de falsos positivos de `rule 100123` (DCSync) y
`rule 100126` (audit policy changed), manteniendo la detección real. Ver cabecera de
`custom-ad-tuning.xml` para el detalle y los datos (90 días).

**Estado:** archivo staged y validado (XML bien formado). **Falta deploy** — requiere
root (copiar a la ruleset + restart del manager). No se aplicó todavía.

`ossec.conf` tiene `<rule_dir>etc/rules</rule_dir>`, así que **todo `.xml` en
`/var/ossec/etc/rules/` se carga automáticamente en el restart** — no hace falta tocar
`custom-ad.xml`.

## Pasos (como root en `seg-vs85-prod01`)

```bash
# 1) Copiar el archivo a la ruleset con owner/permisos correctos
sudo install -o root -g wazuh -m 0660 \
  /opt/soc-l1/wazuh_tuning/custom-ad-tuning.xml \
  /var/ossec/etc/rules/custom-ad-tuning.xml

# 2) TEST antes de reiniciar — verificar que las reglas cargan sin error
#    (si hay error de sintaxis, lo muestra acá y NO reiniciás)
sudo /var/ossec/bin/wazuh-logtest -t
```

### Test funcional con `wazuh-logtest` (opcional pero recomendado)
Pegá un evento real de DCSync y confirmá el ruteo:

- **MSOL / DC (debe quedar level 0 = suprimido):** buscá en el dashboard un evento
  `rule.id:100123` con `subjectUserName:MSOL_*` o `SRVDC1$`, copiá su `full_log`,
  pegalo en `sudo /var/ossec/bin/wazuh-logtest` → debe matchear **rule 100223/100224,
  level 0**.
- **Cuenta de usuario (debe seguir alertando):** evento `100123` de `mbaez-adm`
  (hay 4 en los últimos 90d) → debe seguir matcheando **rule 100123, level 12**.

```bash
# 3) Aplicar
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager
```

## Verificación post-deploy (a las 24-48 h)
El volumen de 100123/100126 debería desplomarse. Chequeo rápido (read-only) contra el
indexer:

```
rule.id:100123 last 24h  → debería quedar solo lo NO-whitelisteado (cuentas de usuario)
rule.id:100126 last 24h  → debería quedar solo cambios por cuentas de usuario (sin $)
```

## Revertir
```bash
sudo rm /var/ossec/etc/rules/custom-ad-tuning.xml
sudo systemctl restart wazuh-manager
```

## Nota de seguridad (revisar aparte)
- Los **4 eventos de `mbaez-adm` en 100123** (DCSync desde una cuenta de usuario admin)
  quedan alertando — vale revisar si fueron legítimos (¿corrió alguna herramienta de
  replicación/migración?) o ameritan investigación.
- **Fix de fondo de 100126:** el churn de event 4719 (audit policy changed) en todos los
  servers es anómalo (~55/día por host). Idealmente resolver en la GPO/audit policy en vez
  de sólo suprimir a nivel regla.
