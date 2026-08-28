#!/bin/bash
# Wrapper de cron para los reportes por correo de SOC-L1.
#
# Uso:  run_report.sh <vuln|blocks|coverage>
#
# Carga el entorno desde /opt/soc-l1/.env.reports (chmod 600), toma un lock por
# reporte para que dos corridas no se pisen, y deja log en logs/reports/.
set -uo pipefail

REPORT="${1:-}"
BASE="/opt/soc-l1"
PY="$BASE/.venv/bin/python"
ENV_FILE="$BASE/.env.reports"
LOG_DIR="$BASE/logs/reports"

if [ -z "$REPORT" ]; then
  echo "uso: $0 <vuln|blocks|coverage>" >&2
  exit 2
fi

# Pararse en $BASE antes de cualquier cosa: src/config.py declara env_file=".env",
# que es RELATIVO al directorio de trabajo. Desde cron el CWD es $HOME, así que
# Settings() no encontraba /opt/soc-l1/.env y se quedaba sin WAZUH_API_PASSWORD.
# Efecto observado: agent_coverage_alert.py moría con rc=1 (KeyError: 'data') en
# cada corrida, y el aviso de calidad del dato del reporte de vulnerabilidades
# fallaba en silencio con un 401 contra la API del manager. Las corridas manuales
# desde /opt/soc-l1 funcionaban, que es por qué no se había notado.
cd "$BASE" || { echo "$(date -Is) ERROR: no se puede entrar a $BASE" >&2; exit 1; }

mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/$REPORT.log"

if [ ! -r "$ENV_FILE" ]; then
  echo "$(date -Is) ERROR: no se puede leer $ENV_FILE" >> "$LOG"
  exit 1
fi
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

# Destinatario por reporte, con fallback a REPORT_TO. Se pasa como --to repetido
# para que cada dirección viaje como destinatario propio.
case "$REPORT" in
  vuln)     TO="${REPORT_TO_VULN:-${REPORT_TO:-}}" ;;
  blocks)   TO="${REPORT_TO_BLOCKS:-${REPORT_TO:-}}" ;;
  coverage) TO="${REPORT_TO_COVERAGE:-${REPORT_TO:-}}" ;;
  *)        TO="${REPORT_TO:-}" ;;
esac
if [ -z "$TO" ]; then
  echo "$(date -Is) ERROR: no hay destinatarios para '$REPORT'" >> "$LOG"
  exit 1
fi
TO_ARGS=()
IFS=',' read -ra _dests <<< "$TO"
for d in "${_dests[@]}"; do
  d="$(echo "$d" | xargs)"
  [ -n "$d" ] && TO_ARGS+=(--to "$d")
done

# Un lock por reporte. Si la corrida anterior sigue viva, esta se saltea en vez
# de encimarse (el de vulnerabilidades tarda ~1 min por los lotes de EPSS).
LOCK="/tmp/soc-l1-report-$REPORT.lock"
exec 9>"$LOCK"
if ! flock -n 9; then
  echo "$(date -Is) SKIP: ya hay una corrida de '$REPORT' en curso" >> "$LOG"
  exit 0
fi

echo "$(date -Is) === inicio $REPORT ===" >> "$LOG"

case "$REPORT" in
  vuln)
    "$PY" "$BASE/scripts/vuln_priority.py" \
      --email "${TO_ARGS[@]}" \
      --subject "Reporte de Vulnerabilidades y Cumplimiento de Parches - ${VULN_ORG_NAME:-Grupo Alemana}" \
      --top 15 >> "$LOG" 2>&1
    ;;
  blocks)
    "$PY" "$BASE/scripts/fgt_blocks_report.py" \
      --email "${TO_ARGS[@]}" \
      --subject "Reporte Semanal de Bloqueos Automáticos - ${VULN_ORG_NAME:-Grupo Alemana}" \
      >> "$LOG" 2>&1
    ;;
  coverage)
    # Solo notifica si hay novedades (estado en SQLite), así que puede correr seguido.
    "$PY" "$BASE/scripts/agent_coverage_alert.py" \
      --email --teams "${TO_ARGS[@]}" >> "$LOG" 2>&1
    ;;
  *)
    echo "$(date -Is) ERROR: reporte desconocido '$REPORT'" >> "$LOG"
    exit 2
    ;;
esac

RC=$?
echo "$(date -Is) === fin $REPORT (rc=$RC) ===" >> "$LOG"

# Log acotado: nos quedamos con las últimas 5000 líneas.
if [ "$(wc -l < "$LOG")" -gt 5000 ]; then
  tail -5000 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
fi

exit $RC
