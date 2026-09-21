# Grafana — Kong Alemana

Dashboard operativo de Kong en la POC (`192.168.38.62:3000`, datasource Prometheus).

- `build_kong_dashboard.py` — genera y sube el dashboard. El JSON es un artefacto,
  la fuente de verdad es el script.
- `kong-alemana.json` — salida generada.
- `original/` — export del dashboard previo al rearmado, para volver atrás.

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
