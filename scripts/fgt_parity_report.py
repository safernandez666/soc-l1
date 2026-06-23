#!/usr/bin/env python3
"""
One-shot: corre fgt_parity.py, manda el resultado por mail y borra su propio cron.
Pensado para dispararse desde crontab (línea marcada con '# fgt-parity-oneshot').
"""
import json
import smtplib
import subprocess
import sys
from email.mime.text import MIMEText

PARITY = "/opt/soc-l1/scripts/fgt_parity.py"
EMAIL_CFG = "/var/ossec/etc/email-config.json"
CRON_MARKER = "fgt-parity-oneshot"
TO = ["sfernandez@ironbox.com.ar"]  # solo el operador, NO la distro


def run_parity() -> str:
    r = subprocess.run([sys.executable, PARITY], capture_output=True, text=True)
    return (r.stdout or "") + (("\n[stderr]\n" + r.stderr) if r.stderr else "")


def send_mail(body: str) -> None:
    c = json.load(open(EMAIL_CFG))
    body = (
        "Recordatorio Fase 0 — parity check FortiGate autoblock SOC-L1.\n"
        "Revisar: 0 MISS (cobertura ok), volumen (¿filtrar por severidad?),\n"
        "y sacar reglas '*BLOCKED*' (ej 196205) de enforce antes de Fase 1.\n\n"
        + body
        + "\n\nDecidir si avanzar a Fase 1 o seguir observando.\n"
    )
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = "[SOC L1] Recordatorio Fase 0 — parity check FortiGate"
    msg["From"] = c.get("from", "wazuh@grupoalemana.com")
    msg["To"] = ", ".join(TO)
    with smtplib.SMTP(c["smtp_host"], int(c.get("smtp_port", 587)), timeout=30) as s:
        if c.get("use_tls", True):
            s.starttls()
        if c.get("username"):
            s.login(c["username"], c["password"])
        s.sendmail(msg["From"], TO, msg.as_string())


def remove_self_cron() -> None:
    try:
        cur = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        if cur.returncode != 0:
            return
        kept = [ln for ln in cur.stdout.splitlines() if CRON_MARKER not in ln]
        subprocess.run(["crontab", "-"], input="\n".join(kept) + "\n", text=True)
    except Exception:
        pass


def main():
    out = run_parity()
    try:
        send_mail(out)
    finally:
        remove_self_cron()


if __name__ == "__main__":
    main()
