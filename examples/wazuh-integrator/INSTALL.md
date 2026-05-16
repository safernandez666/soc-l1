# Wazuh integrator custom-soc-l1 — Instalación

## 1. Copiar archivos al manager

```bash
# Desde /opt/soc-l1 en el server:
sudo cp examples/wazuh-integrator/custom-soc-l1 /var/ossec/integrations/
sudo cp examples/wazuh-integrator/custom-soc-l1.py /var/ossec/integrations/

sudo chown root:wazuh /var/ossec/integrations/custom-soc-l1 /var/ossec/integrations/custom-soc-l1.py
sudo chmod 750 /var/ossec/integrations/custom-soc-l1
sudo chmod 750 /var/ossec/integrations/custom-soc-l1.py
```

> El wrapper sin extensión (`custom-soc-l1`) es el que Wazuh invoca. El `.py` es el script real. Esta es la convención de los integrators built-in (slack, virustotal, pagerduty, etc.).

## 2. Configurar en `/var/ossec/etc/ossec.conf`

Dentro del bloque `<ossec_config>`, agregar:

```xml
<integration>
  <name>custom-soc-l1</name>
  <hook_url>http://localhost:8000/webhook/wazuh-alert</hook_url>
  <api_key>EL_VALOR_DE_WAZUH_WEBHOOK_SECRET_DEL_DOTENV</api_key>
  <level>5</level>
  <alert_format>json</alert_format>
</integration>
```

Filtros opcionales (combinables con `<level>`):

```xml
<rule_id>5712,5715,200002</rule_id>           <!-- whitelist rule_ids -->
<group>authentication_failed,sshd,defender</group>  <!-- whitelist groups -->
<event_location>web-prod-01</event_location>  <!-- whitelist agent name -->
```

El `<api_key>` debe coincidir EXACTAMENTE con `WAZUH_WEBHOOK_SECRET` del `/opt/soc-l1/.env`. Para sincronizar:

```bash
SECRET=$(grep '^WAZUH_WEBHOOK_SECRET=' /opt/soc-l1/.env | cut -d= -f2-)
echo "Pegá este valor en el <api_key>: $SECRET"
# (longitud típica: 64 chars hex)
```

## 3. Reiniciar Wazuh manager

```bash
sudo systemctl restart wazuh-manager
sleep 10
sudo systemctl status wazuh-manager | head -10
```

## 4. Verificar

Logs del integrator:
```bash
sudo tail -f /var/ossec/logs/integrations.log
```

Disparar una alerta de prueba (SSH fail):
```bash
echo "$(date '+%b %d %H:%M:%S') $(hostname) sshd[1234]: Failed password for invalid user test from 203.0.113.99 port 12345 ssh2" | sudo tee -a /var/log/auth.log
```

Deberías ver:
```
custom-soc-l1: sending alert rule_id=XXXX level=5 bytes=YYY
custom-soc-l1: POST http://localhost:8000/webhook/wazuh-alert -> 202 (attempt 1)
```

En el uvicorn del servicio:
```
INFO: alert accepted | id=XXX source=wazuh_native severity=low host=... users=1 files=0
```

## 5. Troubleshooting

| Síntoma | Causa | Fix |
|---|---|---|
| `POST ... -> 404` | hook_url path mal | Verificar `http://localhost:8000/webhook/wazuh-alert` |
| `POST ... -> 401` con "invalid signature" del servicio | api_key del ossec.conf no matchea WAZUH_WEBHOOK_SECRET | Sincronizar ambos valores |
| `URLError: Connection refused` | uvicorn no corriendo o puerto bloqueado | Verificar servicio escuchando en 0.0.0.0:8000 |
| No aparece nada en integrations.log al disparar alerta | Wazuh no fueguea el integrator (filtros mal, level alto) | Bajar `<level>` temporalmente a 3, o agregar rule_id whitelist |
| `wazuh-manager` no arranca tras restart | Sintaxis XML mal en ossec.conf | Restaurar backup, validar XML antes de restart |
