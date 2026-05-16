#!/usr/bin/env bash
#
# Stop + restart del servicio soc-l1 (uvicorn en foreground con nohup).
#
# Uso:
#   ./scripts/restart.sh           # stop + start
#   ./scripts/restart.sh stop      # solo stop
#   ./scripts/restart.sh start     # solo start (falla si ya hay uno corriendo)
#   ./scripts/restart.sh status    # ver estado actual
#
# Asume cwd = /opt/soc-l1 (o donde esté el .venv y src/).
# Logs van a /tmp/uvicorn.log.
#
# Cuando armemos el systemd unit, este script queda obsoleto y se reemplaza
# por `sudo systemctl restart soc-l1`.

set -euo pipefail

SOC_DIR="${SOC_DIR:-/opt/soc-l1}"
LOG_FILE="${LOG_FILE:-/tmp/uvicorn.log}"
PORT="${PORT:-8000}"
HOST="${HOST:-0.0.0.0}"
UVICORN_BIN="${SOC_DIR}/.venv/bin/uvicorn"

# Colores para output (solo si es terminal)
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    RED='\033[0;31m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    GREEN='' YELLOW='' RED='' BLUE='' NC=''
fi

log()  { echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $*"; }
ok()   { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}!${NC} $*"; }
err()  { echo -e "${RED}✗${NC} $*" >&2; }

find_pid() {
    # Solo el proceso uvicorn de soc-l1 (no el tail -f, no otros uvicorn)
    pgrep -f "uvicorn src.main:app" 2>/dev/null | head -1
}

wait_port_free() {
    local tries=15
    while (( tries > 0 )); do
        if ! ss -lnt 2>/dev/null | grep -q ":${PORT}\b"; then
            return 0
        fi
        sleep 1
        ((tries--))
    done
    return 1
}

wait_port_listening() {
    local tries=20
    while (( tries > 0 )); do
        if ss -lnt 2>/dev/null | grep -q ":${PORT}\b"; then
            return 0
        fi
        sleep 1
        ((tries--))
    done
    return 1
}

cmd_status() {
    local pid
    pid="$(find_pid || true)"
    if [[ -n "$pid" ]]; then
        ok "Servicio corriendo: PID ${pid}"
        ss -lntp 2>/dev/null | grep ":${PORT}\b" || true
        if command -v curl &>/dev/null; then
            local health
            health=$(curl -fsS "http://localhost:${PORT}/health" 2>/dev/null || echo "")
            if [[ -n "$health" ]]; then
                ok "Health: ${health}"
            else
                warn "Health endpoint no respondió"
            fi
        fi
        return 0
    else
        warn "No hay uvicorn corriendo"
        return 1
    fi
}

cmd_stop() {
    local pid
    pid="$(find_pid || true)"
    if [[ -z "$pid" ]]; then
        warn "No hay uvicorn corriendo, nada que parar"
        return 0
    fi

    log "Parando uvicorn PID ${pid} (SIGTERM)..."
    kill "$pid" 2>/dev/null || sudo kill "$pid"

    # Esperar a que el proceso muera (hasta 10s)
    local tries=10
    while (( tries > 0 )) && kill -0 "$pid" 2>/dev/null; do
        sleep 1
        ((tries--))
    done

    if kill -0 "$pid" 2>/dev/null; then
        warn "PID ${pid} sigue vivo tras 10s, mando SIGKILL"
        kill -9 "$pid" 2>/dev/null || sudo kill -9 "$pid"
        sleep 1
    fi

    if ! wait_port_free; then
        err "Puerto ${PORT} sigue ocupado tras stop"
        return 1
    fi
    ok "Servicio parado, puerto ${PORT} libre"
}

cmd_start() {
    if [[ -n "$(find_pid || true)" ]]; then
        err "Ya hay un uvicorn corriendo (PID $(find_pid)). Usá 'restart' o 'stop' primero."
        return 1
    fi

    if [[ ! -x "$UVICORN_BIN" ]]; then
        err "No encuentro uvicorn en ${UVICORN_BIN}"
        err "Verificá que el .venv esté armado (cd ${SOC_DIR} && uv sync)"
        return 1
    fi

    if [[ ! -d "${SOC_DIR}/src" ]]; then
        err "No encuentro ${SOC_DIR}/src - SOC_DIR está mal o falta el código"
        return 1
    fi

    log "Arrancando uvicorn (${HOST}:${PORT})..."
    cd "$SOC_DIR"
    nohup "$UVICORN_BIN" src.main:app \
        --host "$HOST" \
        --port "$PORT" \
        --log-level info \
        > "$LOG_FILE" 2>&1 &
    disown

    if ! wait_port_listening; then
        err "uvicorn no levantó el puerto ${PORT} en 20s"
        err "Últimas líneas del log:"
        tail -20 "$LOG_FILE" >&2
        return 1
    fi

    sleep 1
    local pid
    pid="$(find_pid || true)"
    if [[ -z "$pid" ]]; then
        err "uvicorn no quedó corriendo (port up pero sin proceso?)"
        return 1
    fi
    ok "uvicorn arrancó: PID ${pid}"
    ok "Log: ${LOG_FILE}"

    # Health check rápido
    if command -v curl &>/dev/null; then
        sleep 1
        local health
        health=$(curl -fsS "http://localhost:${PORT}/health" 2>/dev/null || echo "FAIL")
        if [[ "$health" != "FAIL" ]]; then
            ok "Health: ${health}"
        else
            warn "Health check falló (puede tardar 1-2s más en estar listo)"
        fi
    fi

    echo
    log "Últimas líneas del log:"
    tail -10 "$LOG_FILE"
}

cmd_restart() {
    cmd_stop || true
    sleep 1
    cmd_start
}

# === Main ===

case "${1:-restart}" in
    start)   cmd_start ;;
    stop)    cmd_stop ;;
    restart) cmd_restart ;;
    status)  cmd_status ;;
    *)
        err "Uso: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
