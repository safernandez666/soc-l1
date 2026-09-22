# Grafana — Kong Alemana

Dashboard operativo de Kong en la POC (`192.168.38.62:3000`, datasource Prometheus).

- `build_kong_dashboard.py` — genera y sube el dashboard. El JSON es un artefacto,
  la fuente de verdad es el script.
- `kong-alemana.json` — salida generada.
- `original/` — export del dashboard previo al rearmado, para volver atrás.
- `logs/` — Loki + Alloy que alimentan la sección de logs de acceso (ver abajo).

```bash
python3 build_kong_dashboard.py                              # solo genera el JSON
GRAFANA_PASS=... python3 build_kong_dashboard.py --push      # genera y sube
```

Para volver al anterior: importar `original/kong-alemana-pre-rearmado-*.json`
(el objeto `dashboard` de adentro) con `overwrite: true` sobre el uid `kong-alemana`.

## Por qué se rearmó

Eran 43 paneles: el dashboard oficial de Kong importado tal cual, más una fila
"POC - Métricas clave" pegada encima que repetía lo mismo — 15 queries de RPS,
30 de percentiles de latencia, 5 de bandwidth. Para responder "¿está sano?" había
que mirar en dos lugares y decidir a cuál creerle.

Quedó en 30, ordenados por las preguntas que hace un administrador y en el orden
en que las hace: ¿está vivo? → ¿está sano? → ¿está rápido? → ¿quién lo usa? →
¿va a aguantar? → ¿y los upstreams?

## El límite que hay que conocer

**El plugin de Prometheus no está viendo el tráfico de Internet.** Verificado el
2026-09-21: 49 requests en 30 días, todos de `httpbin-service` y `admin-api`, y
**cero 404 históricos**. En el mismo período Wazuh registró 2.041 alertas de
enumeración (regla 100207) y 23.157 de 404, desde 71 IPs distintas.

Hasta habilitar el plugin de forma global, este dashboard describe la POC, no
`gateway.grupoalemana.com`. Hay un panel de notas al pie que lo dice.

Retención de Prometheus: **15 días**. Por eso el selector de tiempo no ofrece más
de 7d — ofrecer 30d solo produce paneles vacíos.

## Logs de acceso (Loki) — la vista del tráfico real

Desde el 2026-09-22 el dashboard tiene una sección **"¿Qué le está pegando?"** que sale
de los **logs de acceso de Kong**, no de Prometheus: requests de Internet, IPs
distintas, 404, % 2xx, requests por código, top IPs, rutas buscadas con 404,
user-agents y el log en vivo. Una variable **IP (o prefijo)** arriba filtra toda la
sección; sirve para pegar la IP de un correo de bloqueo de SOC-L1 y ver qué hizo.

Cómo llegan: Kong loguea con el driver `syslog` de Docker hacia Wazuh (UDP 514), y
Docker igual guarda una copia local (*dual logging*). **Alloy** lee esa copia por la API
de Docker y la manda a **Loki**. No hubo que tocar ni reiniciar Kong, y Wazuh sigue
recibiendo lo mismo.

```bash
# en 192.168.38.62, usuario apimanager
cd ~/kong-setup/logs && docker compose -f docker-compose.logs.yml up -d
```

- Loki no publica puerto: solo Grafana lo consulta, por la red `kong-setup_poc-network`.
- Retención 15 días, igual que Prometheus. Datasource en Grafana: uid `loki`.
- Labels mínimos (`job`, `container`, `kind` = acceso|interno|error, `status_class`).
  IP, ruta y user-agent se parsean al consultar con `| regexp`: como labels harían
  explotar el índice.
- `kind="interno"` es el tráfico 172.x de la red Docker (Konga, curl al Admin API);
  la sección lo excluye.
