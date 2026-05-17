#!/usr/bin/env bash
#
# Backup diario de state.db (SQLite). Usa SQLite online backup API (safe con
# escrituras concurrentes - no necesita parar el servicio).
#
# Genera: $BACKUP_DIR/state-YYYYMMDD-HHMMSS.db.gz
# Retención: borra backups más viejos que $RETAIN_DAYS días.
#
# Diseñado para correr vía systemd timer (deploy/soc-l1-backup.timer)
# o cron: 0 2 * * * /opt/soc-l1/scripts/backup-state.sh
#
# Override vía env vars:
#   DB=/path/to/state.db
#   BACKUP_DIR=/var/backups/soc-l1
#   RETAIN_DAYS=30

set -euo pipefail

DB="${DB:-/opt/soc-l1/state.db}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/soc-l1}"
RETAIN_DAYS="${RETAIN_DAYS:-30}"

# Colores solo si es tty (no en cron)
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
else
    GREEN='' YELLOW='' RED='' NC=''
fi
ok()   { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}!${NC} $*"; }
err()  { echo -e "${RED}✗${NC} $*" >&2; }

# Logging dual: stdout para tty/journald, syslog para discoverabilidad
_log() {
    echo "$*"
    if command -v logger &>/dev/null; then
        logger -t soc-l1-backup "$*"
    fi
}

# Sanity
if [[ ! -f "$DB" ]]; then
    err "DB no encontrada: $DB"
    _log "FAIL: DB no encontrada: $DB"
    exit 1
fi

if ! command -v sqlite3 &>/dev/null; then
    err "sqlite3 no instalado (apt install sqlite3)"
    exit 1
fi

# Crear backup dir si falta
mkdir -p "$BACKUP_DIR"

TS=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="$BACKUP_DIR/state-$TS.db"

# SQLite online backup (no bloquea writes en la DB original)
# Si esto falla, no creamos archivo basura ni borramos backups viejos
if ! sqlite3 "$DB" ".backup '$BACKUP_FILE'"; then
    err "sqlite3 .backup falló"
    _log "FAIL: sqlite3 .backup failed for $DB"
    rm -f "$BACKUP_FILE"  # cleanup parcial
    exit 1
fi

# Comprimir (state.db chico pero crece con audit history)
if ! gzip "$BACKUP_FILE"; then
    err "gzip falló"
    _log "FAIL: gzip $BACKUP_FILE"
    rm -f "$BACKUP_FILE" "$BACKUP_FILE.gz"
    exit 1
fi

SIZE=$(stat -c%s "$BACKUP_FILE.gz" 2>/dev/null || stat -f%z "$BACKUP_FILE.gz" 2>/dev/null || echo "?")
ok "Backup creado: $BACKUP_FILE.gz ($SIZE bytes)"
_log "OK: $BACKUP_FILE.gz ($SIZE bytes)"

# Cleanup de viejos
DELETED=$(find "$BACKUP_DIR" -name "state-*.db.gz" -mtime +"$RETAIN_DAYS" -print -delete | wc -l)
if [[ "$DELETED" -gt 0 ]]; then
    ok "Eliminados $DELETED backups con más de $RETAIN_DAYS días"
    _log "Cleanup: borrados $DELETED backups antiguos"
fi

# Info final
TOTAL=$(find "$BACKUP_DIR" -name "state-*.db.gz" | wc -l)
DISK=$(du -sh "$BACKUP_DIR" 2>/dev/null | awk '{print $1}')
ok "Total backups: $TOTAL (usando $DISK en $BACKUP_DIR)"
