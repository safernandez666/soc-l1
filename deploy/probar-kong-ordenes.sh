#!/usr/bin/env bash
#
# probar-kong-ordenes.sh — prueba de humo de la publicacion de la API de Ordenes en Kong.
# Pensado para correr desde afuera (casa). Solo hace GET inocuos y logins con un usuario
# INEXISTENTE; no toca datos. Nunca escribe la API key ni credenciales en disco/historial.
#
#   export ORD_APIKEY='...'            # o te la pide sin eco
#   bash probar-kong-ordenes.sh                          # usa DNS publico
#   bash probar-kong-ordenes.sh --resolve 200.41.220.54  # DNS aun no apunta a Kong
#   bash probar-kong-ordenes.sh --real                   # + login real y 1 GET de lectura
#
set -uo pipefail
HOST="ordenes.grupoalemana.com"; RESOLVE=""; REAL=0
while [[ $# -gt 0 ]]; do case "$1" in
  --resolve) RESOLVE="$2"; shift 2;;
  --host) HOST="$2"; shift 2;;
  --real) REAL=1; shift;;
  *) echo "Opcion desconocida: $1" >&2; exit 2;; esac; done

RES=(); [[ -n "$RESOLVE" ]] && RES=(--resolve "$HOST:443:$RESOLVE")
BASE="https://$HOST"
if [[ -z "${ORD_APIKEY:-}" ]]; then read -rs -p "API key (sin eco): " ORD_APIKEY; echo; fi
export ORD_APIKEY
FAIL=0
# curl lee headers de un config por stdin para que la key no aparezca en `ps`
c() { # c <metodo> <path> [curl args...] -> imprime solo el HTTP code
  local m="$1" p="$2"; shift 2
  curl -s -o /dev/null -w '%{http_code}' --max-time 20 "${RES[@]}" -X "$m" "$BASE$p" "$@"
}
withkey() { printf 'header = "apikey: %s"\n' "$ORD_APIKEY" | curl -K - "$@"; }
chk() { # chk <descripcion> <esperado> <obtenido>
  if [[ "$2" == "$3" ]]; then printf ' \e[32mOK \e[0m %s (%s)\n' "$1" "$3"
  else printf ' \e[31mFAIL\e[0m %s: esperado %s, obtuve %s\n' "$1" "$2" "$3"; FAIL=1; fi; }

echo "== Pruebas sin credenciales: Kong debe cortar ANTES de llegar al backend =="
chk "TLS/cert valido y Kong responde"            401 "$(c GET /api/MsGestion/abm/alicuotas/combo)"
chk "Login sin API key"                          401 "$(c POST /api/token -H 'Content-Type: application/json' -d '{}')"
chk "Host equivocado no cae en esta API"         404 "$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "${RES[@]}" -H 'Host: otro.invalid' -k "https://${RESOLVE:-$HOST}/api/MsGestion/abm/alicuotas/combo")"
chk "Panel admin de Kong NO expuesto"            404 "$(c GET /admin-api/status)"

echo "== Con API key: superficie de Fase 1 =="
chk "/state no publicado"                        404 "$(withkey -s -o /dev/null -w '%{http_code}' "${RES[@]}" "$BASE/state")"
chk "/health no publicado"                       404 "$(withkey -s -o /dev/null -w '%{http_code}' "${RES[@]}" "$BASE/health")"
chk "POST en ruta de lectura bloqueado (F2)"     404 "$(withkey -s -o /dev/null -w '%{http_code}' "${RES[@]}" -X POST -H 'Content-Type: application/json' -d '{}' "$BASE/api/MsGestion/abm/clientes/agregar")"
chk "PUT en ruta de lectura bloqueado (F2)"      404 "$(withkey -s -o /dev/null -w '%{http_code}' "${RES[@]}" -X PUT  -H 'Content-Type: application/json' -d '{}' "$BASE/api/MsOrdenTrabajo/abm/medicos/modificar")"
chk "GET sin token ERP: lo rechaza el backend"   401 "$(withkey -s -o /dev/null -w '%{http_code}' "${RES[@]}" "$BASE/api/MsGestion/abm/alicuotas/combo")"

echo "== Login con usuario inexistente (llega al backend; avisar a Matias/Juan que habra 1 intento fallido) =="
code=$(withkey -s -o /dev/null -w '%{http_code}' "${RES[@]}" -X POST -H 'Content-Type: application/json' \
  -d '{"Usuario":"kong-smoke-test","Password":"x","EmpresaId":2}' "$BASE/api/token")
chk "Backend alcanzable y rechaza credenciales" 401 "$code"

echo "== Rate limit del login (tope 10/min): 12 intentos con usuario inexistente =="
last=""; for i in $(seq 1 12); do
  last=$(withkey -s -o /dev/null -w '%{http_code}' "${RES[@]}" -X POST -H 'Content-Type: application/json' \
    -d '{"Usuario":"kong-smoke-test","Password":"x","EmpresaId":2}' "$BASE/api/token"); done
chk "Intento 12 devuelve 429" 429 "$last"

if [[ $REAL -eq 1 ]]; then
  echo "== Login REAL (usuario ERP que te dio Matias) =="
  echo "   (esperá 1 minuto si recien corriste el rate limit)"
  read -rp "Usuario ERP: " U; read -rs -p "Password: " P; echo; read -rp "EmpresaId [2]: " E; E=${E:-2}
  body=$(U="$U" P="$P" E="$E" python3 -c 'import json,os;print(json.dumps({"Usuario":os.environ["U"],"Password":os.environ["P"],"EmpresaId":int(os.environ["E"])}))')
  resp=$(withkey -s "${RES[@]}" -X POST -H 'Content-Type: application/json' -d "$body" "$BASE/api/token"); unset P body
  # La doc dice Datos.Token en un lado y Datos[0].Token en otro: probar ambas.
  TOKEN=$(printf '%s' "$resp" | python3 -c 'import sys,json
d=json.load(sys.stdin).get("Datos")
print((d.get("Token") if isinstance(d,dict) else d[0].get("Token")) if d else "")' 2>/dev/null)
  if [[ -z "$TOKEN" ]]; then printf " \e[31mFAIL\e[0m login real: %s\n" "$(printf "%s" "$resp" | head -c 300)"; FAIL=1
  else
    echo " OK  token obtenido ($(printf '%s' "$TOKEN" | python3 -c 'import sys;print(len(sys.stdin.read()))') chars; no se imprime). Estructura: ver nota doc."
    code=$(printf 'header = "apikey: %s"\nheader = "Authorization: Bearer %s"\n' "$ORD_APIKEY" "$TOKEN" \
      | curl -K - -s -o /dev/null -w '%{http_code}' "${RES[@]}" "$BASE/api/MsGestion/abm/alicuotas/combo")
    chk "GET de lectura con API key + Bearer" 200 "$code"
    unset TOKEN
  fi
fi

echo; [[ $FAIL -eq 0 ]] && echo "TODO OK" || { echo "HAY FALLAS"; exit 1; }
