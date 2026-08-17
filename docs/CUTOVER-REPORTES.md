# Cutover de los reportes por correo

Estado al 2026-08-17: los reportes nuevos están **activos en el crontab del usuario
`sfernandez-ext`**, pero enviando **solo al analista** (`sfernandez@ironbox.com.ar`),
porque los reportes viejos siguen corriendo y el cliente recibiría todo duplicado.

El paso que falta requiere root.

## Qué corre hoy

| Reporte | Nuevo (activo, solo al analista) | Viejo (activo, va al cliente) |
|---|---|---|
| Vulnerabilidades + parches | `scripts/vuln_priority.py` — lunes 09:15 | `/opt/wazuh-scripts/weekly_comparison.py` — lunes 09:00 |
| Bloqueos FortiGate | `scripts/fgt_blocks_report.py` — lunes 09:20 | `/var/ossec/bin/weekly-blocks-report.sh` — lunes 09:00 |
| Cobertura de agentes | `scripts/agent_coverage_alert.py` — cada 6 h | no existía |

Schedule: `crontab -l` como `sfernandez-ext`.
Credenciales y destinatarios: `/opt/soc-l1/.env.reports` (chmod 600).
Logs: `/opt/soc-l1/logs/reports/{vuln,blocks,coverage}.log`.

## Pasos del cutover (requieren root)

1. **Ubicar el schedule viejo.** No está en el crontab del usuario ni en `/etc/cron.d`,
   así que casi seguro está en el crontab de root:

   ```bash
   sudo crontab -l | grep -E 'weekly_comparison|weekly-blocks-report'
   ```

2. **Apagar los dos reportes viejos** comentando esas líneas:

   ```bash
   sudo crontab -e
   ```

3. **Apuntar los nuevos al cliente.** Editar `/opt/soc-l1/.env.reports` y reemplazar:

   ```
   REPORT_TO=alertas_wazuh@grupoalemana.com,mbaez@grupoalemana.com,azarember@grupoalemana.com,sfernandez@ironbox.com.ar
   ```

   Los destinatarios que usaba el reporte viejo de vulnerabilidades estaban hardcodeados
   en `weekly_comparison.py` (`HARDCODED_RECIPIENTS`): sfernandez@ironbox.com.ar,
   mbaez@grupoalemana.com y azarember@grupoalemana.com.

4. **Verificar** con una corrida manual antes del lunes:

   ```bash
   /opt/soc-l1/scripts/cron/run_report.sh vuln
   /opt/soc-l1/scripts/cron/run_report.sh blocks
   ```

## Opcional pero recomendado

- **Password del indexer en claro.** `weekly_comparison.py` la tiene hardcodeada y el
  archivo está `644` (world-readable). Los scripts nuevos la toman de `.env.reports`
  (chmod 600). Conviene sacarla del script viejo aunque se lo vaya a apagar, porque queda
  en el repo y en los backups.

- **Deliverability de los correos que quedan.** `weekly_comparison.py` y
  `/var/ossec/integrations/custom-email-unified` arman los mensajes sin `Date`,
  sin `Message-ID` y con el HTML en base64: las tres señales que mandaban los reportes
  a No Deseado. En SOC-L1 ya está resuelto de forma central (`src/mailer.py::_stamp_headers`
  y `src/report_theme.py`). Ver `reference_email-deliverability-exchange` en la memoria.

## El detector de vulnerabilidades no re-evalúa 8 de 28 agentes (requiere root)

Diagnóstico del 2026-08-17. Son dos síntomas del mismo problema:

**Inventario desfasado (4 hosts, 2.694 hallazgos = 21% del reporte).** El índice conserva
un build de SO anterior al que el agente reporta hoy, así que cuenta vulnerabilidades ya
parcheadas:

| Host | Build indexado | Build real | Hallazgos |
|---|---|---|---|
| SRVDC2 | 10.0.17763.7009 | 10.0.17763.9020 | 706 |
| SRVDCFICO1 | 10.0.17763.7009 | 10.0.17763.8880 | 706 |
| SRVLEXMARK2 | 10.0.17763.8027 | 10.0.17763.8755 | 684 |
| SRVSOPORTE | 10.0.17763.7314 | 10.0.17763.9020 | 598 |

**Sin hallazgos (4 hosts):** SRVWSUS, SRVIIS, SRVDCVELEZ01, SRVFILE2401.
Otros 4 tienen hallazgos de aplicaciones pero ninguno de SO: SRVEXCHANGE2016, SRVTS,
SRVTS2, TECO-PRD-BKP-01.

**No es falta de datos de entrada.** Se verificó por API que los agentes afectados
reportan todo lo necesario: SRVWSUS tiene 59 paquetes y 46 hotfixes, SRVIIS 13 paquetes
y 137 hotfixes, y todos informan su build de SO. La configuración
(`<vulnerability-detection><enabled>yes`, feed cada 60m) está activa. El que no produce
estado es el detector.

Remediación sugerida (root):

```bash
# 1. Ver si el módulo reporta errores (hoy el log está en DEBUG y es ilegible)
sudo grep -iE 'vulnerability|vulnerability-detector' /var/ossec/logs/ossec.log | grep -viE 'dbsync|wdb_parse'

# 2. Forzar re-evaluación reiniciando el módulo
sudo systemctl restart wazuh-manager

# 3. Si persiste, limpiar el estado del detector para forzar un scan completo
sudo systemctl stop wazuh-manager
sudo rm -rf /var/ossec/queue/vd/state_track/*
sudo systemctl start wazuh-manager
```

Verificación después: `scripts/agent_coverage_alert.py --dry-run` debería bajar de 5
hallazgos a 1 (solo TECO-PRD-AD-01, que está genuinamente desconectado), y el reporte
de vulnerabilidades dejar de mostrar el aviso de calidad de datos.

**Nota aparte:** el logging de `ossec.log` está en DEBUG y genera un volumen enorme de
líneas `wdb_parse`, lo que hace impracticable diagnosticar cualquier cosa. Conviene
volverlo a INFO en `/var/ossec/etc/internal_options.conf` (`wazuh_database.debug=0`).

## Hallazgo abierto que no depende del cutover

La alarma de cobertura detectó **4 agentes activos que no generan ningún hallazgo de
vulnerabilidades** (SRVWSUS, SRVIIS, SRVDCVELEZ01, SRVFILE2401). No es que los agentes
estén caídos: syscollector inventaría paquetes con normalidad (SRVWSUS reporta 59), pero
el detector de vulnerabilidades no produce nada para esos hosts. Esos equipos vienen
desapareciendo del reporte semanal como si estuvieran limpios. Vale revisar la
configuración de `vulnerability-detection` para ellos.
