#!/usr/bin/env python3
"""
Parity check Fase 0: ¿bloquearía SOC-L1 lo mismo que el script viejo?

Compara, en una ventana de tiempo común:
  A) Lo que SOC-L1 OBSERVÓ que bloquearía  -> fgt_observations.jsonl  (would_block)
  B) Lo que el script viejo BLOQUEÓ de verdad -> integrations.log     (custom-email-unified)

Reporta:
  - ACUERDO   : IP bloqueada por el script Y observada por SOC-L1   (parity OK)
  - SOC-L1 MISS: IP que el script bloqueó pero SOC-L1 NO observó    (¡riesgo de regresión!)
  - SOC-L1 EXTRA: IP que SOC-L1 observó pero el script NO bloqueó    (cobertura extra / posible ruido)

La ventana arranca por defecto en la 1ª observación REAL de SOC-L1 (las de test 203.0.113.x se ignoran),
porque antes de eso SOC-L1 estaba ciego y la comparación no es justa.

Uso:
  python3 scripts/fgt_parity.py
  python3 scripts/fgt_parity.py --since "2026-06-23 12:16:00"   # ventana manual (hora local)
"""
import argparse
import json
import re
from datetime import datetime, timezone, timedelta

OBS_PATH = "/opt/soc-l1/fgt_observations.jsonl"
INTEG_LOG = "/var/ossec/logs/integrations.log"
LOCAL_TZ = timezone(timedelta(hours=-3))  # America/Argentina/Buenos_Aires

# IPs de test/documentación a ignorar (RFC 5737)
TEST_NETS = ("203.0.113.", "198.51.100.", "192.0.2.")

BLOCK_RE = re.compile(r"BLOQUEANDO\s+(\d+\.\d+\.\d+\.\d+)")
LOGTS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")


def is_test_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in TEST_NETS)


def load_observations():
    """SOC-L1 would-block -> list of (epoch, ip, rule_id)."""
    rows = []
    try:
        for line in open(OBS_PATH):
            line = line.strip()
            if not line:
                continue
            o = json.loads(line)
            if not o.get("would_block"):
                continue
            ip = o.get("ip", "")
            if not ip or is_test_ip(ip):
                continue
            ts = datetime.fromisoformat(o["ts"])  # UTC aware
            rows.append((ts.timestamp(), ip, str(o.get("rule_id", "?"))))
    except FileNotFoundError:
        pass
    return rows


def load_old_blocks():
    """Script viejo blocks -> list of (epoch, ip). Timestamps del log son hora LOCAL."""
    rows = []
    try:
        for line in open(INTEG_LOG, errors="ignore"):
            m = BLOCK_RE.search(line)
            if not m:
                continue
            tm = LOGTS_RE.match(line)
            if not tm:
                continue
            dt = datetime.strptime(tm.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=LOCAL_TZ)
            rows.append((dt.timestamp(), m.group(1)))
    except FileNotFoundError:
        pass
    return rows


def fmt(epoch):
    return datetime.fromtimestamp(epoch, LOCAL_TZ).strftime("%Y-%m-%d %H:%M")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", help="Inicio ventana (hora local, 'YYYY-MM-DD HH:MM:SS')")
    args = ap.parse_args()

    obs = load_observations()
    blocks = load_old_blocks()

    if args.since:
        since = datetime.strptime(args.since, "%Y-%m-%d %H:%M:%S").replace(tzinfo=LOCAL_TZ).timestamp()
    elif obs:
        since = min(e for e, _, _ in obs)  # 1ª observación real
    else:
        print("No hay observaciones reales todavía. Esperá a que entre tráfico IPS.")
        return

    obs_w = [(e, ip, r) for e, ip, r in obs if e >= since]
    blk_w = [(e, ip) for e, ip in blocks if e >= since]

    obs_ips = {ip for _, ip, _ in obs_w}
    blk_ips = {ip for _, ip in blk_w}

    agree = blk_ips & obs_ips
    miss = blk_ips - obs_ips      # el script bloqueó, SOC-L1 no observó -> RIESGO
    extra = obs_ips - blk_ips     # SOC-L1 observó, el script no bloqueó

    rule_count = {}
    for _, _, r in obs_w:
        rule_count[r] = rule_count.get(r, 0) + 1

    print("=" * 64)
    print(f"PARITY CHECK Fase 0  —  ventana desde {fmt(since)} (local)")
    print("=" * 64)
    print(f"  SOC-L1 observaciones (eventos): {len(obs_w)}  | IPs únicas: {len(obs_ips)}")
    print(f"  Script viejo bloqueos (eventos): {len(blk_w)} | IPs únicas: {len(blk_ips)}")
    print()
    print(f"  ✅ ACUERDO     (bloqueó y observó): {len(agree)}")
    print(f"  ❌ SOC-L1 MISS (bloqueó, NO observó): {len(miss)}   <- riesgo de regresión")
    print(f"  ➕ SOC-L1 EXTRA(observó, NO bloqueó): {len(extra)}  <- cobertura/ruido")
    if blk_ips:
        cov = 100.0 * len(agree) / len(blk_ips)
        print(f"\n  COBERTURA SOC-L1 sobre bloqueos probados: {cov:.0f}%")
    if miss:
        print("\n  --- MISS (revisar: por qué SOC-L1 no las vería) ---")
        for ip in sorted(miss):
            print(f"    {ip}")
    if extra:
        print("\n  --- EXTRA (SOC-L1 bloquearía de más) ---")
        for ip in sorted(extra):
            print(f"    {ip}")
    print("\n  --- volumen por regla (observaciones SOC-L1) ---")
    for r, n in sorted(rule_count.items(), key=lambda kv: -kv[1]):
        print(f"    rule {r}: {n}")
    print()


if __name__ == "__main__":
    main()
