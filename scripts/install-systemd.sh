#!/usr/bin/env bash
#
# Instala el unit de systemd para soc-l1 (servicio que sobrevive reboots).
#
# Uso:
#   sudo ./scripts/install-systemd.sh
#   sudo ./scripts/install-systemd.sh --user otro-user --group otro-group
#
# Lo que hace:
#   1. Detiene cualquier uvicorn corriendo a mano (nohup) si lo encuentra
#   2. Genera /etc/systemd/system/soc-l1.service desde deploy/soc-l1.service
#      reemplazando User/Group con valores reales
#   3. systemctl daemon-reload + enable + start
#   4. Verifica que arrancó OK
#
# Default: User=el dueño de /opt/soc-l1 (autodetect). Override con --user.
#
# Después de instalar, podés usar:
#   sudo systemctl status soc-l1
#   sudo systemctl restart soc-l1
#   sudo systemctl stop soc-l1
#   journalctl -u soc-l1 -f
# O seguir usando ./scripts/restart.sh (auto-detecta systemd).

set -euo pipefail

SOC_DIR="${SOC_DIR:-/opt/soc-l1}"
UNIT_NAME="soc-l1.service"
UNIT_SOURCE="${SOC_DIR}/deploy/soc-l1.service"
UNIT_TARGET="/etc/systemd/system/${UNIT_NAME}"

# Parseo de args
SOC_USER=""
SOC_GROUP=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --user)  SOC_USER="$2"; shift 2 ;;
        --group) SOC_GROUP="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# *//'
            exit 0
            ;;
        *)
            echo "Argumento desconocido: $1" >&2
            exit 1
            ;;
    esac
done

# Colores
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
else
    GREEN='' YELLOW='' RED='' BLUE='' NC=''
fi
log()  { echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $*"; }
ok()   { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}!${NC} $*"; }
err()  { echo -e "${RED}✗${NC} $*" >&2; }

# Sanity checks
if [[ $EUID -ne 0 ]]; then
    err "Este script necesita sudo (escribe en /etc/systemd/system y corre systemctl)"
    err "Reintentar con: sudo $0"
    exit 1
fi

if [[ ! -d "$SOC_DIR" ]]; then
    err "No encuentro ${SOC_DIR} - ¿el código está en otro path?"
    exit 1
fi

if [[ ! -f "$UNIT_SOURCE" ]]; then
    err "No encuentro el template del unit: ${UNIT_SOURCE}"
    err "¿Hiciste git pull para traer deploy/soc-l1.service?"
    exit 1
fi

if [[ ! -x "${SOC_DIR}/.venv/bin/uvicorn" ]]; then
    err "No encuentro uvicorn en ${SOC_DIR}/.venv/bin/"
    err "Corré 'uv sync' como dueño de ${SOC_DIR} primero"
    exit 1
fi

if [[ ! -f "${SOC_DIR}/.env" ]]; then
    err "No encuentro ${SOC_DIR}/.env (config del servicio)"
    exit 1
fi

# Autodetect user/group si no vinieron
if [[ -z "$SOC_USER" ]]; then
    SOC_USER="$(stat -c '%U' "$SOC_DIR")"
    log "Autodetect User=${SOC_USER} (dueño de ${SOC_DIR})"
fi
if [[ -z "$SOC_GROUP" ]]; then
    SOC_GROUP="$(stat -c '%G' "$SOC_DIR")"
    log "Autodetect Group=${SOC_GROUP} (grupo de ${SOC_DIR})"
fi

# Validar que el user existe
if ! id "$SOC_USER" &>/dev/null; then
    err "User '${SOC_USER}' no existe en el sistema"
    exit 1
fi

# Paso 1: matar cualquier uvicorn manual previo
log "Buscando uvicorn corriendo a mano (no-systemd)..."
existing_pid="$(pgrep -f 'uvicorn src.main:app' || true)"
if [[ -n "$existing_pid" ]]; then
    warn "Encontré uvicorn manual PID ${existing_pid}, lo mato antes de instalar systemd"
    kill "$existing_pid" 2>/dev/null || true
    sleep 2
    if kill -0 "$existing_pid" 2>/dev/null; then
        warn "PID ${existing_pid} sigue vivo, SIGKILL"
        kill -9 "$existing_pid" 2>/dev/null || true
        sleep 1
    fi
    ok "uvicorn manual detenido"
fi

# Paso 2: generar unit con valores reales
log "Generando ${UNIT_TARGET} con User=${SOC_USER} Group=${SOC_GROUP}"
sed \
    -e "s|__SOC_USER__|${SOC_USER}|g" \
    -e "s|__SOC_GROUP__|${SOC_GROUP}|g" \
    "$UNIT_SOURCE" > "$UNIT_TARGET"
chmod 644 "$UNIT_TARGET"
ok "Unit instalado en ${UNIT_TARGET}"

# Paso 3: reload + enable + start
log "systemctl daemon-reload"
systemctl daemon-reload

log "Habilitando para arrancar en boot (systemctl enable)"
systemctl enable "$UNIT_NAME"

log "Arrancando el servicio (systemctl start)"
systemctl start "$UNIT_NAME"

# Paso 4: verificar
sleep 3
if systemctl is-active --quiet "$UNIT_NAME"; then
    ok "Servicio soc-l1 ACTIVO"
    echo
    systemctl status "$UNIT_NAME" --no-pager -l | head -15
    echo
    log "Health check..."
    if curl -fsS http://localhost:8000/health 2>/dev/null; then
        echo
        ok "Health endpoint respondiendo"
    else
        warn "Health no respondió aún (puede tardar 1-2s más)"
    fi
    echo
    echo "Comandos útiles:"
    echo "  sudo systemctl status soc-l1     # ver estado"
    echo "  sudo systemctl restart soc-l1    # reiniciar"
    echo "  sudo systemctl stop soc-l1       # parar"
    echo "  journalctl -u soc-l1 -f          # logs en vivo (Ctrl-C sale)"
    echo "  ./scripts/restart.sh             # también funciona (auto-detecta systemd)"
else
    err "Servicio NO arrancó. Logs:"
    journalctl -u "$UNIT_NAME" -n 30 --no-pager
    exit 1
fi
