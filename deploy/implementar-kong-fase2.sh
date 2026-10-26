#!/usr/bin/env bash
#
# implementar-kong-fase2.sh — Kong Fase 2 (2026-09-27):
#   * codigo nuevo de SOC-L1: tras cada cuarentena revisa (y si puede, cierra) las
#     sesiones vivas del atacante en el FortiGate;
#   * regla Wazuh 100209 (enumeracion lenta, 15x404/1h) bloqueando en vivo;
#   * 100204/100240/100241 ruteadas a SOC-L1 en modo sombra.
#
# ORDEN (importa): primero el consumidor (soc-l1 con codigo + .env nuevos), despues
# el productor (reglas + ossec.conf + wazuh-manager). Al reves hay una ventana en la
# que llegan reglas que SOC-L1 no conoce como candidatas y caen al pipeline completo.
#
# Uso:
#   sudo bash deploy/implementar-kong-fase2.sh --dry-run   # muestra diffs, no toca nada
#   sudo bash deploy/implementar-kong-fase2.sh             # pide confirmacion
#   sudo bash deploy/implementar-kong-fase2.sh --yes
#
set -euo pipefail
BASE="/opt/soc-l1"
WZPY="/var/ossec/framework/python/bin/python3"
PATCH="$BASE/deploy/route-kong-rules-fase2.py"
DRY=0; YES=0
for a in "$@"; do case "$a" in --dry-run) DRY=1;; --yes|-y) YES=1;; *) echo "Opcion desconocida: $a" >&2; exit 2;; esac; done
RED=$'\e[31m'; GRN=$'\e[32m'; YLW=$'\e[33m'; BLD=$'\e[1m'; CLR=$'\e[0m'
info(){ printf '%s[*]%s %s\n' "$YLW" "$CLR" "$*"; }
ok(){   printf '%s[✓]%s %s\n' "$GRN" "$CLR" "$*"; }
die(){  printf '%s[✗]%s %s\n' "$RED" "$CLR" "$*" >&2; exit 1; }
paso(){ printf '\n%s===== %s =====%s\n' "$BLD" "$*" "$CLR"; }
cd "$BASE" || die "No puedo entrar a $BASE"

paso "1/4 Preflight"
[[ $DRY -eq 1 || $EUID -eq 0 ]] || die "Necesita root (sudo)."
grep -q 'async def close_sessions' src/tools/fortigate.py || die "Falta el codigo nuevo (close_sessions) en src/tools/fortigate.py"
grep -q 'FGT-AUTOBLOCK SESIONES' src/fortigate_autoblock.py || die "Falta el hook post-cuarentena en src/fortigate_autoblock.py"
systemctl is-active --quiet soc-l1.service && ok "soc-l1.service activo" || die "soc-l1.service no esta activo"
systemctl is-active --quiet wazuh-manager && ok "wazuh-manager activo" || die "wazuh-manager no esta activo"
[[ -x "$WZPY" ]] || die "No encuentro $WZPY"
ok "preflight"

paso "2/4 Parche (reglas + ossec.conf + .env)"
if [[ $DRY -eq 1 ]]; then
  "$WZPY" "$PATCH" --dry-run
  info "DRY-RUN: fin."; exit 0
fi
"$WZPY" "$PATCH" --dry-run
if [[ $YES -ne 1 ]]; then
  read -r -p "Aplicar y reiniciar soc-l1 y wazuh-manager? [s/N] " r
  [[ "$r" =~ ^[sSyY]$ ]] || die "Cancelado."
fi
"$WZPY" "$PATCH"

paso "3/4 Reinicio de SOC-L1 (consumidor primero)"
systemctl restart soc-l1.service
for i in $(seq 1 30); do
  curl -sf -o /dev/null http://127.0.0.1:8000/health && break
  sleep 1
done
curl -sf -o /dev/null http://127.0.0.1:8000/health || die "soc-l1 no responde /health tras el restart"
ok "soc-l1 arriba"
.venv/bin/python3 - <<'EOF'
from src.config import Settings
s = Settings()
auto, sombra = s.fortigate_auto_block_rules_set(), s.fortigate_observe_only_rules_set()
assert "100209" in auto, f"100209 no esta en auto-block: {sorted(auto)}"
assert {"100204", "100240", "100241"} <= sombra, f"sombra incompleta: {sorted(sombra)}"
print(f"   config OK: {len(auto)} reglas bloquean, sombra={sorted(sombra)}")
EOF

paso "4/4 Reinicio de wazuh-manager (productor)"
systemctl restart wazuh-manager
sleep 5
systemctl is-active --quiet wazuh-manager || die "wazuh-manager no levanto: revisar /var/ossec/logs/ossec.log"
grep -q '<rule id="100209"' /var/ossec/etc/rules/kong-rules.xml && ok "regla 100209 instalada"
grep -qE '<rule_id>100204,100207,100209,100240,100241</rule_id>' /var/ossec/etc/ossec.conf && ok "ruteo Kong: 100204,100207,100209,100240,100241"
if grep -iE 'error|critical' /var/ossec/logs/ossec.log | tail -n 200 | grep -qi 'kong-rules'; then
  die "ossec.log reporta errores en kong-rules.xml"
fi
ok "Listo. Verificar en unas horas:"
echo "   journalctl -u soc-l1.service | grep -E 'SESIONES|rule=10020(9|4)|rule=10024'"
echo "   tail -f /opt/soc-l1/fgt_observations.jsonl"
