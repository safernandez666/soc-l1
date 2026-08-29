#!/usr/bin/env python3
"""Política ISM de retención para los índices de alertas de Wazuh.

El indexer no tiene NINGUNA política de retención: 208 índices diarios, 624
shards y 15 GB que solo crecen. El heap está al 84% de 2 GB con 745 shards en
un nodo — la regla práctica de OpenSearch es ~20 shards por GB de heap, o sea
un presupuesto sano de ~40. Esto lo automatiza para que no vuelva a pasar.

La política tiene tres estados:

    activo        el índice del día y los 2 siguientes: no se toca
    consolidado   a los 3 días hace force_merge a 1 segmento (baja heap y disco)
    borrado       a los 180 días se elimina (6 meses: definido con Grupo Alemana)

**Qué borra y cuándo.** Crear la política no borra nada. Engancharla por
`ism_template` tampoco: eso solo aplica a índices que se creen DESPUÉS. Los
índices que ya existen quedan sin gestionar hasta correr `--apply-existing`,
que es la acción destructiva y por eso está separada y pide confirmación.

Credenciales por entorno (no se imprimen nunca):

    OPENSEARCH_URL, OPENSEARCH_USER, OPENSEARCH_PASS

    python3 deploy/ism-wazuh-retention.py --dry-run
    python3 deploy/ism-wazuh-retention.py --create
    python3 deploy/ism-wazuh-retention.py --apply-existing   # DESTRUCTIVO
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib3

try:
    import requests
except ImportError:
    sys.exit("ERROR: falta `requests`. Usar el python del venv de soc-l1.")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

POLICY_ID = "wazuh-alerts-retention"
PATRON = "wazuh-alerts-4.x-*"
RETENCION_DIAS = 180
EDAD_MERGE = "3d"


def politica(dias: int) -> dict:
    return {
        "policy": {
            "description": (
                f"Retencion de {PATRON}: force_merge a los {EDAD_MERGE}, borrado a "
                f"los {dias}d. Creada por deploy/ism-wazuh-retention.py del repo soc-l1."
            ),
            "default_state": "activo",
            "states": [
                {
                    "name": "activo",
                    "actions": [],
                    "transitions": [
                        {"state_name": "consolidado",
                         "conditions": {"min_index_age": EDAD_MERGE}}
                    ],
                },
                {
                    # force_merge a 1 segmento: los indices diarios quedan con
                    # muchos segmentos chicos y cada uno cuesta heap. No se pone
                    # read_only a proposito: agrega riesgo si llega un evento
                    # atrasado y el beneficio real lo da el merge.
                    "name": "consolidado",
                    "actions": [{"force_merge": {"max_num_segments": 1}}],
                    "transitions": [
                        {"state_name": "borrado",
                         "conditions": {"min_index_age": f"{dias}d"}}
                    ],
                },
                {"name": "borrado", "actions": [{"delete": {}}], "transitions": []},
            ],
            # Solo afecta a indices creados DESPUES de que exista la politica.
            "ism_template": [{"index_patterns": [PATRON], "priority": 100}],
        }
    }


class Cliente:
    def __init__(self) -> None:
        self.url = (os.getenv("OPENSEARCH_URL") or "").rstrip("/")
        user = os.getenv("OPENSEARCH_USER")
        pwd = os.getenv("OPENSEARCH_PASS")
        if not (self.url and user and pwd):
            sys.exit("ERROR: faltan OPENSEARCH_URL / OPENSEARCH_USER / OPENSEARCH_PASS.")
        self.auth = (user, pwd)

    def _req(self, metodo: str, ruta: str, **kw):
        return requests.request(metodo, self.url + ruta, auth=self.auth,
                                verify=False, timeout=60, **kw)

    def get(self, ruta): return self._req("GET", ruta)
    def put(self, ruta, body): return self._req("PUT", ruta, json=body)
    def post(self, ruta, body=None): return self._req("POST", ruta, json=body)


def estado_actual(c: Cliente) -> None:
    r = c.get("/_cat/indices/wazuh-alerts-*?h=index,store.size,pri&format=json")
    idx = r.json() if r.ok else []
    shards = sum(int(i["pri"]) for i in idx)
    print(f"  indices de alertas : {len(idx)}")
    print(f"  shards primarios   : {shards}")
    r = c.get("/_plugins/_ism/policies")
    pols = r.json().get("policies", []) if r.ok else []
    print(f"  politicas ISM      : {len(pols)}"
          + (f"  ({', '.join(p['_id'] for p in pols)})" if pols else "  <- ninguna"))
    return idx


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true",
                    help="muestra el estado y la politica que se crearia")
    ap.add_argument("--create", action="store_true",
                    help="crea/actualiza la politica y la engancha a indices NUEVOS")
    ap.add_argument("--apply-existing", action="store_true",
                    help="DESTRUCTIVO: pone la politica sobre los indices ya existentes")
    ap.add_argument("--dias", type=int, default=RETENCION_DIAS)
    args = ap.parse_args()

    if not (args.dry_run or args.create or args.apply_existing):
        ap.error("elegi --dry-run, --create o --apply-existing")

    c = Cliente()
    print("Estado actual:")
    idx = estado_actual(c)
    pol = politica(args.dias)

    if args.dry_run:
        print(f"\nPolitica que se crearia (id: {POLICY_ID}):")
        print(json.dumps(pol, indent=2, ensure_ascii=False))
        print(f"\nLos indices NUEVOS se borrarian a los {args.dias} dias.")
        print("Los", len(idx), "que ya existen NO se tocan sin --apply-existing.")
        return 0

    if args.create:
        r = c.get(f"/_plugins/_ism/policies/{POLICY_ID}")
        existe = r.status_code == 200
        ruta = f"/_plugins/_ism/policies/{POLICY_ID}"
        if existe:
            seq = r.json()["_seq_no"]; pt = r.json()["_primary_term"]
            ruta += f"?if_seq_no={seq}&if_primary_term={pt}"
        r = c.put(ruta, pol)
        if not r.ok:
            print(f"ERROR {r.status_code}: {r.text[:400]}", file=sys.stderr)
            return 1
        print(f"\nPolitica {'actualizada' if existe else 'creada'}: {POLICY_ID}")
        print(f"  force_merge a los {EDAD_MERGE} | borrado a los {args.dias}d")
        print(f"  enganchada por ism_template a {PATRON} (solo indices NUEVOS)")
        print(f"\nLos {len(idx)} indices existentes siguen SIN gestionar.")
        print("Para ponerlos bajo la politica (y que se borren los > "
              f"{args.dias}d):  --apply-existing")
        return 0

    if args.apply_existing:
        viejos = len(idx)
        print(f"\n*** ESTO VA A BORRAR indices de mas de {args.dias} dias ***")
        print(f"    {viejos} indices quedarian gestionados por {POLICY_ID}.")
        resp = input("    Escribi 'BORRAR' para confirmar: ")
        if resp.strip() != "BORRAR":
            print("    Cancelado.")
            return 1
        r = c.post("/_plugins/_ism/add/" + PATRON, {"policy_id": POLICY_ID})
        if not r.ok:
            print(f"ERROR {r.status_code}: {r.text[:400]}", file=sys.stderr)
            return 1
        d = r.json()
        print(f"  gestionados ahora: {len(d.get('updated_indices', [])) or d}")
        print("  ISM evalua cada 30-60 min por defecto; el borrado no es inmediato.")
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
