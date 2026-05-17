#!/usr/bin/env bash
#
# Instala el backup automático de state.db como systemd timer (diario 02:00).
#
# Uso:
#   sudo ./scripts/install-backup.sh
#   sudo ./scripts/install-backup.sh --backup-dir /custom/path
#   sudo ./scripts/install-backup.sh --retain-days 60
#
# Después de instalar, el backup corre diariamente a las 02:00. Para forzar
# uno ahora: sudo systemctl start soc-l1-backup.service

set -euo pipefail

SOC_DIR="${SOC_DIR:-/opt/soc-l1}"
BACKUP_DIR=""
RETAIN_DAYS=""
SOC_USER=""
SOC_GROUP=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --backup-dir)  BACKUP_DIR="$2"; shift 2 ;;
        --retain-days) RETAIN_DAYS="$2"; shift 2 ;;
        --user)        SOC_USER="$2"; shift 2 ;;
        --group)       SOC_GROUP="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# *//'
            exit 0
            ;;
        *) echo "Argumento desconocido: $1" >&2; exit 1 ;;
    esac
done

if [[ -t 1 ]]; then
    GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
else
    GREEN='' YELLOW='' RED='' BLUE='' NC=''
fi
log()  { echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $*"; }
ok()   { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}!${NC} $*"; }
err()  { echo -e "${RED}✗${NC} $*" >&2; }

if [[ $EUID -ne 0 ]]; then
    err "Requiere sudo (escribe /etc/systemd y crea /var/backups/soc-l1)"
    exit 1
fi

UNIT_SOURCE_SERVICE="${SOC_DIR}/deploy/soc-l1-backup.service"
UNIT_SOURCE_TIMER="${SOC_DIR}/deploy/soc-l1-backup.timer"

if [[ ! -f "$UNIT_SOURCE_SERVICE" || ! -f "$UNIT_SOURCE_TIMER" ]]; then
    err "Falta deploy/soc-l1-backup.{service,timer} en ${SOC_DIR}"
    err "Hacé git pull primero"
    exit 1
fi

if [[ ! -x "${SOC_DIR}/scripts/backup-state.sh" ]]; then
    err "Falta o no es ejecutable: ${SOC_DIR}/scripts/backup-state.sh"
    exit 1
fi

# Autodetect user/group si no vinieron
if [[ -z "$SOC_USER" ]]; then
    SOC_USER="$(stat -c '%U' "$SOC_DIR")"
    log "Autodetect User=${SOC_USER}"
fi
if [[ -z "$SOC_GROUP" ]]; then
    SOC_GROUP="$(stat -c '%G' "$SOC_DIR")"
    log "Autodetect Group=${SOC_GROUP}"
fi

# Crear backup dir y darle permisos al user del servicio
DEFAULT_BACKUP_DIR="/var/backups/soc-l1"
mkdir -p "$DEFAULT_BACKUP_DIR"
chown -R "${SOC_USER}:${SOC_GROUP}" "$DEFAULT_BACKUP_DIR"
chmod 750 "$DEFAULT_BACKUP_DIR"
ok "Backup dir ${DEFAULT_BACKUP_DIR} (chown ${SOC_USER}:${SOC_GROUP}, mode 750)"

# Generar service unit con sustituciones
UNIT_TARGET_SERVICE="/etc/systemd/system/soc-l1-backup.service"
UNIT_TARGET_TIMER="/etc/systemd/system/soc-l1-backup.timer"

sed \
    -e "s|__SOC_USER__|${SOC_USER}|g" \
    -e "s|__SOC_GROUP__|${SOC_GROUP}|g" \
    "$UNIT_SOURCE_SERVICE" > "$UNIT_TARGET_SERVICE"
chmod 644 "$UNIT_TARGET_SERVICE"

cp "$UNIT_SOURCE_TIMER" "$UNIT_TARGET_TIMER"
chmod 644 "$UNIT_TARGET_TIMER"
ok "Service + timer instalados"

# Override de BACKUP_DIR / RETAIN_DAYS si vinieron por argumento
if [[ -n "$BACKUP_DIR" ]]; then
    sed -i "s|Environment=BACKUP_DIR=.*|Environment=BACKUP_DIR=${BACKUP_DIR}|" "$UNIT_TARGET_SERVICE"
    log "Override BACKUP_DIR=${BACKUP_DIR}"
fi
if [[ -n "$RETAIN_DAYS" ]]; then
    sed -i "s|Environment=RETAIN_DAYS=.*|Environment=RETAIN_DAYS=${RETAIN_DAYS}|" "$UNIT_TARGET_SERVICE"
    log "Override RETAIN_DAYS=${RETAIN_DAYS}"
fi

# Reload + enable timer
systemctl daemon-reload
systemctl enable soc-l1-backup.timer
systemctl start soc-l1-backup.timer

# Test: forzar un backup ahora para verificar que funciona
log "Disparando backup manual de prueba..."
if systemctl start soc-l1-backup.service; then
    sleep 2
    if systemctl is-failed --quiet soc-l1-backup.service; then
        err "Backup test FALLÓ. Ver:"
        journalctl -u soc-l1-backup.service -n 20 --no-pager
        exit 1
    fi
    ok "Backup test ejecutado"
fi

# Mostrar resultados
echo
log "Estado del timer:"
systemctl list-timers soc-l1-backup.timer --no-pager
echo
log "Backups actuales:"
ls -lah "${BACKUP_DIR:-$DEFAULT_BACKUP_DIR}" 2>/dev/null | head -10
echo
ok "Backup automático INSTALADO"
echo
echo "Comandos útiles:"
echo "  sudo systemctl list-timers soc-l1-backup.timer       # ver próximo disparo"
echo "  sudo systemctl start soc-l1-backup.service           # forzar backup ahora"
echo "  journalctl -u soc-l1-backup.service -f               # logs del backup"
echo "  ls -lah ${BACKUP_DIR:-$DEFAULT_BACKUP_DIR}           # ver backups"
echo "  zcat ${BACKUP_DIR:-$DEFAULT_BACKUP_DIR}/state-*.db.gz > restored.db  # restaurar"
