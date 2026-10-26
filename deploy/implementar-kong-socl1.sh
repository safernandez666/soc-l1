#!/usr/bin/env bash
#
# implementar-kong-socl1.sh — Activa el ruteo de la enumeracion de Kong (100207)
# hacia SOC-L1 en MODO SOMBRA (observa y avisa, no bloquea).
#
# Que hace, en orden:
#   1. Preflight: root, commit presente, .env con la variable, servicios arriba.
#   2. Dry-run del parche de ossec.conf y muestra el diff.
#   3. Reinicia soc-l1.service para que tome el codigo y el .env nuevos.
#   4. Aplica el parche + reinicia wazuh-manager (corta ingestion unos segundos).
#   5. Verifica: regla ruteada, config cargada, servicios sanos, FortiGate intacto.
#
# ORDEN (importa): primero el consumidor, despues el productor. Al reves queda una
# ventana en la que wazuh ya rutea 100207 pero SOC-L1 corre codigo viejo que no conoce
# el modo sombra -> la alerta cae al pipeline completo (Narrator, ticket, aprobacion).
# Paso de verdad el 2026-09-21: 3m13s de ventana (13:53:32 -> 13:56:45). No entro
# ninguna alerta, pero el orden estaba mal.
#
# Uso:
#   sudo bash /tmp/implementar-kong-socl1.sh --dry-run   # no toca nada
#   sudo bash /tmp/implementar-kong-socl1.sh             # pide confirmacion
#   sudo bash /tmp/implementar-kong-socl1.sh --yes       # sin preguntar
#
# NO incluye el rate-limit de Kong: ese corre en 192.168.38.62, que no es
# alcanzable desde este box. Ver docs/kong-enumeracion-plan.md.
#
set -euo pipefail

BASE="/opt/soc-l1"
VENV="$BASE/.venv/bin/python"
WZPY="/var/ossec/framework/python/bin/python3"
PATCH="$BASE/deploy/route-kong-enumeration-rule.py"
OSSEC="/var/ossec/etc/ossec.conf"
COMMIT="31119b9"
REGLA="100207"

DRY=0; YES=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    --yes|-y)  YES=1 ;;
    *) echo "Opcion desconocida: $a" >&2; exit 2 ;;
  esac
done

RED=$'\e[31m'; GRN=$'\e[32m'; YLW=$'\e[33m'; BLD=$'\e[1m'; CLR=$'\e[0m'
info(){ printf '%s[*]%s %s\n' "$YLW" "$CLR" "$*"; }
ok(){   printf '%s[✓]%s %s\n' "$GRN" "$CLR" "$*"; }
err(){  printf '%s[✗]%s %s\n' "$RED" "$CLR" "$*" >&2; }
die(){  err "$*"; exit 1; }
paso(){ printf '\n%s===== %s =====%s\n' "$BLD" "$*" "$CLR"; }

# OJO: Settings() lee env_file=".env" por ruta RELATIVA. Si este script corre con
# otro CWD (p. ej. sudo bash /tmp/...), pydantic-settings NO encuentra el .env,
# devuelve los defaults del codigo y las verificaciones dan falsos negativos.
# Comprobado: desde /tmp da sombra=set() y 25 reglas en vez de 26.
cd "$BASE" || die "No puedo entrar a $BASE"

# ---------------------------------------------------------------- preflight --
paso "1/5 Preflight"

[ "$(id -u)" -eq 0 ] || die "Correr como root: sudo bash $0 $*"
[ -f "$PATCH" ] || die "No encuentro $PATCH (mal el BASE?)"
[ -x "$WZPY" ]  || die "No encuentro el python de Wazuh en $WZPY"
[ -r "$OSSEC" ] || die "No puedo leer $OSSEC"
ok "root, rutas y permisos OK"

# El servicio corre desde este checkout: si el commit no esta, reiniciar soc-l1
# levantaria codigo viejo y el modo sombra no existiria -> la regla caeria en el
# camino normal (Narrator, ticket, aprobacion). Mejor frenar aca.
if ! git -C "$BASE" merge-base --is-ancestor "$COMMIT" HEAD 2>/dev/null; then
  die "El commit $COMMIT no esta en HEAD ($(git -C "$BASE" rev-parse --short HEAD)).
     $BASE es el checkout VIVO de produccion. Sin ese commit no existe el modo
     sombra y 100207 arrancaria el pipeline completo. Revisar la rama primero."
fi
ok "commit $COMMIT presente en HEAD ($(git -C "$BASE" rev-parse --short HEAD))"

grep -q '^FORTIGATE_OBSERVE_ONLY_RULES=.*\b'"$REGLA"'\b' "$BASE/.env" \
  || die "Falta FORTIGATE_OBSERVE_ONLY_RULES=$REGLA en $BASE/.env"
ok "$BASE/.env tiene FORTIGATE_OBSERVE_ONLY_RULES=$REGLA"

# Que el autoblock siga en Fase 1 y que la regla NO este en la lista de bloqueo:
# si estuviera en las dos, gana observe-only igual, pero conviene saberlo.
"$VENV" - <<PY || die "La config no valida"
import sys
sys.path.insert(0, "$BASE")
from src.config import Settings
s = Settings()
sombra = s.fortigate_observe_only_rules_set()
vivo   = s.fortigate_auto_block_rules_set()
assert "$REGLA" in sombra, "la regla no quedo en modo sombra"
assert "$REGLA" not in vivo, "la regla tambien esta en la lista de bloqueo real"
print(f"    sombra={sorted(sombra)}  bloqueo_vivo={len(vivo)} reglas  "
      f"enabled={s.fortigate_autoblock_enabled}")
PY
ok "config de SOC-L1 coherente"

for u in wazuh-manager soc-l1.service; do
  systemctl is-active --quiet "$u" || die "$u no esta activo; resolver eso antes"
done
ok "wazuh-manager y soc-l1.service activos"

# Foto previa de la lista de baneados: al final tiene que estar igual.
BANNED_ANTES="$("$VENV" - <<PY 2>/dev/null || echo "?"
import sys, asyncio
sys.path.insert(0, "$BASE")
from src.config import Settings
from src.tools.fortigate import FortigateClient
async def m():
    async with FortigateClient(Settings()) as c:
        print(len(await c.list_banned()))
asyncio.run(m())
PY
)"
ok "FortiGate: $BANNED_ANTES IP(s) baneadas ahora (foto previa)"

# ------------------------------------------------------------------ dry-run --
paso "2/5 Dry-run del parche de ossec.conf"
"$WZPY" "$PATCH" --dry-run

if [ "$DRY" -eq 1 ]; then
  paso "Dry-run: no se toco nada"
  echo "Para aplicar de verdad:  sudo bash $0"
  exit 0
fi

if [ "$YES" -eq 0 ]; then
  printf '\n%sSe va a reiniciar wazuh-manager (corta ingestion unos segundos) y soc-l1.%s\n' "$YLW" "$CLR"
  read -r -p "Seguir? [s/N] " r
  case "$r" in s|S|si|SI|y|Y) ;; *) echo "Cancelado."; exit 0 ;; esac
fi

# ------------------------------------------------------------------- aplicar --
paso "3/5 Reiniciando soc-l1.service (PRIMERO: el consumidor)"
# Con el codigo nuevo pero el ruteo viejo, 100207 simplemente no llega: inocuo.
systemctl restart soc-l1.service
for i in $(seq 1 20); do
  sleep 1
  if curl -sf -o /dev/null http://localhost:8000/health; then break; fi
  [ "$i" -eq 20 ] && die "soc-l1 no respondio /health en 20s. Ver: journalctl -u soc-l1.service -n 50"
done
ok "soc-l1.service arriba y respondiendo /health"

# Que el proceso NUEVO vea la regla en sombra ANTES de abrirle el grifo a wazuh.
"$VENV" - <<PY || die "el proceso nuevo no ve el modo sombra; NO abro el ruteo"
import sys, json
sys.path.insert(0, "$BASE")
from src.config import Settings
from src.normalize import normalize
from src.fortigate_autoblock import evaluate
d = evaluate(normalize(json.load(open("$BASE/tests/fixtures/kong_enumeration_404.json"))), Settings())
assert d.candidate and d.observe_only
print(f"    100207 -> candidate={d.candidate} observe_only={d.observe_only} ip={d.ip}")
PY
ok "el codigo nuevo esta vivo y trata 100207 como sombra"

paso "4/5 Aplicando el ruteo y reiniciando wazuh-manager"
"$WZPY" "$PATCH" --restart
ok "ossec.conf parcheado y wazuh-manager reiniciado"

# ---------------------------------------------------------------- verificar --
paso "5/5 Verificacion"

grep -q "<rule_id>$REGLA</rule_id>" "$OSSEC" \
  && ok "ossec.conf: 100207 ruteada a custom-soc-l1" \
  || err "ossec.conf: NO veo el bloque de 100207"

systemctl is-active --quiet wazuh-manager \
  && ok "wazuh-manager activo" || err "wazuh-manager NO esta activo"

BANNED_DESPUES="$("$VENV" - <<PY 2>/dev/null || echo "?"
import sys, asyncio
sys.path.insert(0, "$BASE")
from src.config import Settings
from src.tools.fortigate import FortigateClient
async def m():
    async with FortigateClient(Settings()) as c:
        print(len(await c.list_banned()))
asyncio.run(m())
PY
)"
if [ "$BANNED_ANTES" = "$BANNED_DESPUES" ]; then
  ok "FortiGate intacto: $BANNED_DESPUES IP(s) baneadas (igual que antes)"
else
  info "FortiGate: $BANNED_ANTES -> $BANNED_DESPUES baneadas. Puede ser una IPS real"
  info "  bloqueando en paralelo; confirmar en el log que NO fue por rule=100207."
fi

cat <<TXT

$(printf '%s' "$BLD")Listo. 100207 esta en MODO SOMBRA: avisa que IP bloquearia, no bloquea.$(printf '%s' "$CLR")

Seguir el proximo disparo:
  journalctl -u soc-l1.service -f | grep FGT-AUTOBLOCK
  tail -f $BASE/fgt_observations.jsonl

Se espera una linea "WOULD quarantine ip=<x> rule=100207 ... (modo sombra: no ejecutado)"
y un registro con "would_block": true, "executed": null.

Rollback:
  sudo cp $OSSEC.bak-pre-kong-<sello> $OSSEC
  sudo /var/ossec/bin/wazuh-control restart
  # y sacar FORTIGATE_OBSERVE_ONLY_RULES del .env + systemctl restart soc-l1.service

Sigue pendiente el rate-limit en Kong (192.168.38.62), que es el fix de fondo.
Ver $BASE/docs/kong-enumeracion-plan.md
TXT
