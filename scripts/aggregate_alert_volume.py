#!/usr/bin/env python3
"""Agrega el volumen de alertas de Wazuh por mes para los KPIs del panel /ui.

Wazuh rota las alertas a `<archive>/<AAAA>/<Mon>/ossec-alerts-DD.json.gz`, una
alerta JSON por línea. Descomprimir todo en cada request del dashboard sería
inviable (decenas de GB), así que este script lo precalcula y deja un JSON chico
que el panel lee solo-lectura.

Para no saturar el disco de un SOC en prod, por defecto **muestrea** hasta N días
por mes (repartidos) y promedia; con --full cuenta todos los días.

Uso:
    python scripts/aggregate_alert_volume.py            # muestreo (8 días/mes)
    python scripts/aggregate_alert_volume.py --full     # todos los días (pesado)
    python scripts/aggregate_alert_volume.py --max-days-per-month 12 --out /tmp/x.json
"""
from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Carpetas de Wazuh usan %b en locale C: Jan..Dec
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}
_DAY_RE = re.compile(r"ossec-alerts-(\d+)\.json\.gz$")

# Marcadores byte-level para FortiGate (los logs del firewall llegan a Wazuh).
# El JSON de Wazuh es compacto (sin espacios), así que el match es exacto y barato.
_FG = b'"fortigate"'
_FG_BLOCK = (b'"action":"deny"', b'"action":"dropped"', b'"action":"blocked"',
             b'"action":"drop"', b'"action":"block"')


def _count_day_gz(path: Path) -> tuple[int, int, int]:
    """Cuenta (alertas_totales, fortigate_total, fortigate_bloqueos) de un .gz.

    Procesa por chunks partiendo en líneas (rápido, estilo wc). Por cada línea
    FortiGate chequea si la acción es de bloqueo. No parsea JSON.
    """
    total = fg_total = fg_block = 0
    carry = b""
    try:
        with gzip.open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                lines = (carry + chunk).split(b"\n")
                carry = lines.pop()
                for line in lines:
                    total += 1
                    if _FG in line:
                        fg_total += 1
                        if any(tok in line for tok in _FG_BLOCK):
                            fg_block += 1
    except (OSError, EOFError, gzip.BadGzipFile) as e:
        print(f"  ! {path.name}: {e}", file=sys.stderr)
        return (0, 0, 0)
    if carry.strip():
        total += 1
        if _FG in carry:
            fg_total += 1
            if any(tok in carry for tok in _FG_BLOCK):
                fg_block += 1
    return (total, fg_total, fg_block)


def _sample(files: list[Path], max_days: int) -> list[Path]:
    """Elige hasta max_days archivos repartidos parejo. max_days<=0 → todos."""
    if max_days <= 0 or len(files) <= max_days:
        return files
    step = len(files) / max_days
    return [files[int(i * step)] for i in range(max_days)]


def aggregate(archive_dir: Path, max_days_per_month: int) -> dict:
    months: list[dict] = []
    for year_dir in sorted(p for p in archive_dir.glob("[12][0-9][0-9][0-9]") if p.is_dir()):
        try:
            year = int(year_dir.name)
        except ValueError:
            continue
        for mon_dir in sorted(p for p in year_dir.iterdir() if p.is_dir()):
            month = _MONTHS.get(mon_dir.name)
            if month is None:
                continue
            files = sorted(
                (f for f in mon_dir.glob("ossec-alerts-*.json.gz") if _DAY_RE.search(f.name)),
                key=lambda f: int(_DAY_RE.search(f.name).group(1)),
            )
            if not files:
                continue
            sampled = _sample(files, max_days_per_month)
            rows = [_count_day_gz(f) for f in sampled]
            rows = [r for r in rows if r[0] > 0]
            if not rows:
                continue
            n = len(rows)
            avg = sum(r[0] for r in rows) // n
            fg_avg = sum(r[1] for r in rows) // n
            fg_block_avg = sum(r[2] for r in rows) // n
            days = len(files)
            months.append({
                "year": year,
                "month": month,
                "label": f"{year}-{month:02d}",
                "name": f"{mon_dir.name} {year}",
                "days_present": days,
                "days_sampled": n,
                "avg_per_day": avg,
                "total_estimate": avg * days,
                "min_day": min(r[0] for r in rows),
                "max_day": max(r[0] for r in rows),
                "fg_avg_per_day": fg_avg,
                "fg_blocks_avg_per_day": fg_block_avg,
                "fg_blocks_total_estimate": fg_block_avg * days,
            })
            print(f"  {year}-{month:02d} {mon_dir.name}: {avg:,}/día · "
                  f"FortiGate bloqueos {fg_block_avg:,}/día "
                  f"(muestra {n}/{days} días)", file=sys.stderr)

    months.sort(key=lambda m: m["label"])
    return {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "sampled": max_days_per_month > 0,
        "max_days_per_month": max_days_per_month,
        "archive_dir": str(archive_dir),
        "months": months,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--archive-dir", default=None,
                    help="Default: wazuh_alerts_archive_dir de Settings")
    ap.add_argument("--out", default=None,
                    help="Default: alert_volume_cache_path de Settings")
    ap.add_argument("--max-days-per-month", type=int, default=8,
                    help="Días a muestrear por mes (0 = todos). Default 8")
    ap.add_argument("--full", action="store_true", help="Atajo de --max-days-per-month 0")
    args = ap.parse_args()

    # Defaults desde Settings (respeta el .env de prod)
    archive_dir = args.archive_dir
    out_path = args.out
    if archive_dir is None or out_path is None:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from src.config import Settings
        s = Settings(_env_file=".env")
        archive_dir = archive_dir or s.wazuh_alerts_archive_dir
        out_path = out_path or s.alert_volume_cache_path

    max_days = 0 if args.full else args.max_days_per_month
    adir = Path(archive_dir)
    if not adir.is_dir():
        print(f"ERROR: archive dir no existe: {adir}", file=sys.stderr)
        return 1

    print(f"Agregando volumen desde {adir} (max_days/mes={max_days or 'todos'})...",
          file=sys.stderr)
    result = aggregate(adir, max_days)

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"OK: {len(result['months'])} meses → {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
