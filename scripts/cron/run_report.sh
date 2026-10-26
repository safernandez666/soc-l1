#!/bin/bash
# Wrapper de cron para los reportes por correo de SOC-L1.
#
# Uso:  run_report.sh <vuln|vuln-ingest|blocks|coverage>
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
  echo "uso: $0 <vuln|vuln-ingest|blocks|coverage>" >&2
  exit 2
fi

# Pararse en $BASE antes de cualquier cosa: src/config.py declara env_file=".env",
# que es RELATIVO al directorio de trabajo. Desde cron el CWD es $HOME, así que
# Settings() no encontraba /opt/soc-l1/.env y se quedaba sin WAZUH_API_PASSWORD.
# Efecto observado: el aviso de calidad del dato del reporte de vulnerabilidades
# venía fallando en silencio (401 contra la API del manager) en toda corrida por
# cron, mientras que las manuales desde /opt/soc-l1 funcionaban.
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

# vuln-ingest solo actualiza el ciclo de vida en SQLite; no manda correo, así que
# no necesita destinatarios y se saltea toda la resolución de abajo.
NEEDS_RECIPIENTS=1
[ "$REPORT" = "vuln-ingest" ] && NEEDS_RECIPIENTS=0

# Destinatario por reporte, con fallback a REPORT_TO. Se pasa como --to repetido
# para que cada dirección viaje como destinatario propio.
case "$REPORT" in
  vuln)     TO="${REPORT_TO_VULN:-${REPORT_TO:-}}" ;;
  blocks)   TO="${REPORT_TO_BLOCKS:-${REPORT_TO:-}}" ;;
  coverage) TO="${REPORT_TO_COVERAGE:-${REPORT_TO:-}}" ;;
  *)        TO="${REPORT_TO:-}" ;;
esac
TO_ARGS=()
if [ "$NEEDS_RECIPIENTS" = "1" ]; then
  if [ -z "$TO" ]; then
    echo "$(date -Is) ERROR: no hay destinatarios para '$REPORT'" >> "$LOG"
    exit 1
  fi
  IFS=',' read -ra _dests <<< "$TO"
  for d in "${_dests[@]}"; do
    d="$(echo "$d" | xargs)"
    [ -n "$d" ] && TO_ARGS+=(--to "$d")
  done
fi

# Un lock por reporte. Si la corrida anterior sigue viva, esta se saltea en vez
# de encimarse (el de vulnerabilidades tarda ~1 min por los lotes de EPSS).
LOCK_KEY="$REPORT"
[ "$REPORT" = "vuln-ingest" ] && LOCK_KEY="vuln"
LOCK="/tmp/soc-l1-report-$LOCK_KEY.lock"
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
  vuln-ingest)
    # Ingesta diaria: refresca el ciclo de vida (nuevas / persistentes / resueltas /
    # reabiertas) sin mandar correo. Sin esto el ciclo de vida solo se actualiza los
    # lunes, y como Wazuh borra el hallazgo apenas se parchea el paquete, un cierre
    # que pasa entre dos corridas no queda registrado en ningún lado.
    #
    # --no-snapshot es OBLIGATORIO acá: load_previous_snapshot() compara contra el
    # snapshot más reciente que no sea de hoy. Si la corrida diaria escribiera uno,
    # el reporte del lunes compararía contra el domingo en vez de contra el lunes
    # anterior y los deltas de cumplimiento se aplanarían sin ningún aviso.
    "$PY" "$BASE/scripts/vuln_priority.py" --no-snapshot >> "$LOG" 2>&1
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
