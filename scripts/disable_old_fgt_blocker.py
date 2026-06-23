#!/usr/bin/env python3
"""Apaga el FortiGateBlocker del integration viejo (custom-email-unified).

Cutover Fase 1: SOC-L1 pasa a ser el único que bloquea (quarantine TTL).
Hace backup + setea fortigate.enabled=false en email-config.json.
Correr con sudo:  sudo python3 /opt/soc-l1/scripts/disable_old_fgt_blocker.py
"""
import json
import shutil
import time

P = "/var/ossec/etc/email-config.json"

bak = f"{P}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
shutil.copy2(P, bak)

with open(P) as f:
    cfg = json.load(f)

prev = cfg.get("fortigate", {}).get("enabled")
cfg.setdefault("fortigate", {})["enabled"] = False

with open(P, "w") as f:
    json.dump(cfg, f, indent=2)

print(f"backup    -> {bak}")
print(f"fortigate.enabled: {prev} -> {cfg['fortigate']['enabled']}")
print("OK. No hace falta reiniciar wazuh (la integración lee el config por alerta).")
