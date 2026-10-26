"""Reconciliación de tickets InvGate huérfanos del auto-block FortiGate.

Contexto: el auto-block abre un ticket y lo cierra en el acto. Antes del fix de
permisos (2026-07-23) y sin verificación read-back, muchos cierres fallaron en
silencio: el ticket quedó ABIERTO y el `fgt_tickets.jsonl` lo registró como
`closed:false`. Este script relee cada uno en InvGate y cierra los que sigan
abiertos, usando el `close_incident` con verificación (no vuelve a mentir).

Uso (desde /opt/soc-l1):
    uv run python scripts/invgate_reconcile_orphans.py            # DRY-RUN (default): solo reporta
    uv run python scripts/invgate_reconcile_orphans.py --apply    # cierra de verdad
    uv run python scripts/invgate_reconcile_orphans.py --ids 3011,3002   # subconjunto explícito

Idempotente: los que ya estén resueltos se saltean. Best-effort por ticket: un
fallo no aborta el resto. NO toca casos human-in-the-loop (pending_approvals):
solo mira el log del auto-block.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.config import Settings  # noqa: E402
from src.tools.invgate import InvgateClient, is_configured  # noqa: E402


def _orphan_ids_from_log(settings: Settings) -> list[int]:
    """request_ids del auto-block que el log marcó como no-cerrados (closed:false).
    Dedup preservando orden."""
    from src import fortigate_autoblock

    path = Path(fortigate_autoblock._ticket_path(settings))
    if not path.exists():
        return []
    seen: set[int] = set()
    ids: list[int] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get("closed") is False and rec.get("request_id") is not None:
            rid = int(rec["request_id"])
            if rid not in seen:
                seen.add(rid)
                ids.append(rid)
    return ids


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--apply", action="store_true", help="cierra de verdad (default: dry-run)")
    ap.add_argument("--ids", type=str, default="", help="lista explícita: 3011,3002,...")
    args = ap.parse_args()

    settings = Settings()
    if not is_configured(settings):
        print("!! InvGate no configurado en .env — nada que hacer")
        return 1

    if args.ids.strip():
        ids = [int(x) for x in args.ids.split(",") if x.strip().isdigit()]
    else:
        ids = _orphan_ids_from_log(settings)

    if not ids:
        print("No hay tickets candidatos.")
        return 0

    mode = "APPLY (cierra)" if args.apply else "DRY-RUN (solo reporta)"
    print(f"Modo: {mode} | candidatos: {len(ids)}\n")

    closed_now = still_open = already = failed = 0
    async with InvgateClient(settings) as client:
        for rid in ids:
            ticket = await client.get_incident(rid)
            if ticket is None:
                print(f"  {rid}: no se pudo leer (HTTP/permiso) — skip")
                failed += 1
                continue
            if client._ticket_is_resolved(ticket):  # noqa: SLF001 — script interno
                already += 1
                continue  # ya resuelto, nada que hacer
            sid = ticket.get("status_id")
            if not args.apply:
                print(f"  {rid}: ABIERTO (status_id={sid}) → se cerraría")
                still_open += 1
                continue
            res = await client.close_incident(
                rid,
                solution_comment=(
                    "Reconciliación SOC-L1: caso de auto-block ya contenido "
                    "(IP en quarantine en FortiGate). Cierre diferido — no requiere "
                    "acción humana."
                ),
            )
            if res.ok:
                print(f"  {rid}: CERRADO ✓ (status_id={res.status_id})")
                closed_now += 1
            else:
                print(f"  {rid}: no cerró — {res.error}")
                still_open += 1

    print("\n== Resumen ==")
    print(f"  ya resueltos:      {already}")
    if args.apply:
        print(f"  cerrados ahora:    {closed_now}")
        print(f"  siguen abiertos:   {still_open}")
    else:
        print(f"  se cerrarían:      {still_open}")
    print(f"  no legibles:       {failed}")
    if not args.apply and still_open:
        print("\n  → volvé a correr con --apply para cerrarlos.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
