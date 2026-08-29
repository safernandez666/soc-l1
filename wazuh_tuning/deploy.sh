#!/usr/bin/env bash
#
# deploy.sh — Deploy de un tuning de reglas de Wazuh (elegido con TUNING_FILE).
#
# Copia el XML a la ruleset del manager, VALIDA el ruleset antes de aplicar
# (si no valida, NO reinicia y revierte solo), reinicia wazuh-manager y verifica.
#
# Uso:
#   sudo ./deploy.sh              # deploy (con validación + restart)
#   sudo ./deploy.sh --dry-run    # muestra qué haría, sin tocar nada
#   sudo ./deploy.sh --rollback   # quita el tuning y reinicia
#   sudo ./deploy.sh --verify     # solo chequeos post-deploy (no cambia nada)
#
#   sudo TUNING_FILE=zz-kong-tuning.xml ./deploy.sh --dry-run   # otro tuning
#
set -euo pipefail

# ---- Config ---------------------------------------------------------------
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# OJO nombre: el archivo debe cargar DESPUÉS de custom-ad.xml (que define 100123/100126),
# si no Wazuh ignora las reglas hijas por 'if_sid' a un padre aún no cargado. Prefijo zz-
# garantiza que se lea último en /var/ossec/etc/rules/ (orden alfabético).
# Qué archivo se despliega. Por defecto el tuning de AD, para no cambiar el uso
# que ya estaba documentado. Se elige otro con TUNING_FILE=<archivo> delante del
# comando, p. ej. el de Kong:
#     sudo TUNING_FILE=zz-kong-tuning.xml ./deploy.sh --dry-run
TUNING_FILE="${TUNING_FILE:-zz-custom-ad-tuning.xml}"
SRC_FILE="${SRC_DIR}/${TUNING_FILE}"
RULES_DIR="/var/ossec/etc/rules"
DEST_FILE="${RULES_DIR}/${TUNING_FILE}"
# Nombre viejo del tuning de AD (cargaba antes de tiempo). Solo aplica a ese
# archivo: para cualquier otro TUNING_FILE queda vacío y no se toca nada ajeno.
if [ "$TUNING_FILE" = "zz-custom-ad-tuning.xml" ]; then
  LEGACY_FILE="${RULES_DIR}/custom-ad-tuning.xml"
else
  LEGACY_FILE=""
fi
ANALYSISD="/var/ossec/bin/wazuh-analysisd"   # test de ruleset: wazuh-analysisd -t
LOGTEST="/var/ossec/bin/wazuh-logtest"       # test funcional interactivo (pegar full_log)
SERVICE="wazuh-manager"

RED=$'\e[31m'; GRN=$'\e[32m'; YLW=$'\e[33m'; CLR=$'\e[0m'
info(){ printf '%s[*]%s %s\n' "$YLW" "$CLR" "$*"; }
ok(){   printf '%s[✓]%s %s\n' "$GRN" "$CLR" "$*"; }
err(){  printf '%s[✗]%s %s\n' "$RED" "$CLR" "$*" >&2; }
die(){  err "$*"; exit 1; }

require_root(){ [ "$(id -u)" -eq 0 ] || die "Correr como root (sudo)."; }

# ---- Acciones -------------------------------------------------------------
validate_ruleset(){
  # wazuh-analysisd -t carga decoders+reglas en modo test y sale != 0 si hay error.
  if [ ! -x "$ANALYSISD" ]; then
    err "No encuentro/ejecuto $ANALYSISD — no puedo validar. Abortando por seguridad."
    return 2
  fi
  info "Validando ruleset con wazuh-analysisd -t ..."
  if "$ANALYSISD" -t >/tmp/wz-ruleset-test.out 2>&1; then
    ok "Ruleset válido."
    return 0
  else
    err "El ruleset NO valida. Salida:"; sed 's/^/    /' /tmp/wz-ruleset-test.out >&2
    return 1
  fi
}

restart_manager(){
  info "Reiniciando $SERVICE ..."
  systemctl restart "$SERVICE"
  sleep 3
  if systemctl is-active --quiet "$SERVICE"; then
    ok "$SERVICE activo."
  else
    err "$SERVICE NO quedó activo tras el restart."; systemctl status "$SERVICE" --no-pager -l | tail -20 >&2
    return 1
  fi
}

do_deploy(){
  [ -f "$SRC_FILE" ] || die "No existe $SRC_FILE"
  # XML bien formado (xmllint si está, si no python3)
  if command -v xmllint >/dev/null 2>&1; then
    xmllint --noout "$SRC_FILE" || die "XML mal formado."
  else
    python3 -c "import xml.dom.minidom,sys; xml.dom.minidom.parse('$SRC_FILE')" || die "XML mal formado."
  fi
  ok "XML bien formado."

  # Baseline: validar el ruleset ACTUAL antes de tocar (para no atribuirnos un error previo)
  if ! validate_ruleset; then
    die "El ruleset YA estaba roto antes del deploy. Resolver eso primero (no toqué nada)."
  fi

  # Limpiar nombre viejo si quedó de un deploy previo (cargaba antes que su padre y era ignorado)
  if [ -f "$LEGACY_FILE" ]; then
    info "Quitando archivo viejo mal nombrado: $LEGACY_FILE ..."
    rm -f "$LEGACY_FILE"; ok "Legacy quitado."
  fi

  info "Instalando $DEST_FILE (root:wazuh 0660) ..."
  install -o root -g wazuh -m 0660 "$SRC_FILE" "$DEST_FILE"
  ok "Archivo instalado."

  # Validar CON el archivo nuevo. Si falla → rollback y salir.
  if ! validate_ruleset; then
    err "Falló la validación con el tuning nuevo. Revirtiendo ..."
    rm -f "$DEST_FILE"
    validate_ruleset && ok "Rollback OK, ruleset vuelve a validar." || err "OJO: ruleset sigue sin validar tras rollback."
    die "Deploy abortado (sin restart). Revisá $TUNING_FILE."
  fi

  # Restart. Si el manager no levanta → rollback + restart.
  if ! restart_manager; then
    err "Revirtiendo por fallo de restart ..."
    rm -f "$DEST_FILE"; restart_manager || err "OJO: el manager no levanta ni con rollback."
    die "Deploy abortado y revertido."
  fi

  ok "Deploy COMPLETO."
  post_verify
}

do_rollback(){
  local found=0
  for f in "$DEST_FILE" "$LEGACY_FILE"; do
    if [ -f "$f" ]; then info "Quitando $f ..."; rm -f "$f"; ok "Quitado."; found=1; fi
  done
  if [ "$found" -eq 1 ]; then
    restart_manager
    ok "Rollback COMPLETO."
  else
    info "No hay archivo de tuning — nada que revertir."
  fi
}

# La verificación depende de QUÉ tuning se desplegó: decirle a alguien que valide
# 100123 después de desplegar el de Kong lo manda a mirar la regla equivocada.
post_verify(){
  printf '\n%s=== Verificación post-deploy (%s) ===%s\n' "$GRN" "$TUNING_FILE" "$CLR"
  case "$TUNING_FILE" in
    zz-custom-ad-tuning.xml)
      cat <<EOF
1) Test funcional (pegá un full_log real y mirá el rule.id resultante):
     ${LOGTEST}          # evento MSOL/DC 100123  -> debe dar rule 100223/100224 level 0
                         # evento 100123 de mbaez-adm -> debe seguir en rule 100123 level 12
2) A las 24-48h el volumen de 100123/100126 debería desplomarse
   (dashboard o indexer: rule.id:100123 / rule.id:100126 last 24h).
EOF
      ;;
    zz-kong-tuning.xml)
      cat <<EOF
1) Test funcional (pegá un full_log real de Kong y mirá el rule.id resultante):
     ${LOGTEST}          # 404 desde 172.18.0.1 x10 -> 100207 debe quedar en rule 100307 level 0
                         # 404 desde una IP publica -> debe seguir en rule 100207 level 8
2) A las 24-48h, contra el indexer:
     rule.id:100241                      -> deberia quedar en CERO
     rule.id:100207 y data.srcip:172.18.* -> deberia quedar en CERO
     rule.id:100207 con srcip publica      -> debe SEGUIR disparando (es la deteccion real)
   Si 100207 se fue a cero del todo, algo se rompio: revisá el rollback.
EOF
      ;;
    *)
      echo "1) Verificá a mano las reglas que toca $TUNING_FILE."
      ;;
  esac
  printf '\nRevertir en cualquier momento:  sudo TUNING_FILE=%s %s --rollback\n' "$TUNING_FILE" "$0"
}

# ---- Main -----------------------------------------------------------------
ACTION="${1:-deploy}"
case "$ACTION" in
  --dry-run)
    echo "DRY-RUN — se haría:"
    echo "  install -o root -g wazuh -m 0660 $SRC_FILE $DEST_FILE"
    echo "  $ANALYSISD -t   (validar ruleset)"
    echo "  systemctl restart $SERVICE"
    echo "  (rollback automático si algo falla)"
    ;;
  --rollback) require_root; do_rollback ;;
  --verify)   post_verify ;;
  deploy|"")  require_root; do_deploy ;;
  *) die "Acción desconocida: $ACTION (usá: deploy | --dry-run | --rollback | --verify)" ;;
esac
