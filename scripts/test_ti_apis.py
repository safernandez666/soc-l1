#!/usr/bin/env python3
"""Smoke test de las APIs de Threat Intel - 1 call real por cada una.

Verifica que:
  - Las API keys del .env están activas y bien formadas
  - El contrato de las APIs no cambió (parseo de response funciona)
  - El código del client maneja respuestas reales sin crashear

IOCs usados (públicos, conocidos):
  - VT:        EICAR test file SHA256 (siempre marca como malicious en todos los AV)
                = 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
  - AbuseIPDB: 8.8.8.8 (Google Public DNS, debería tener score=0)

Uso:
  python3 scripts/test_ti_apis.py             # corre todos
  python3 scripts/test_ti_apis.py --only vt   # solo VirusTotal
  python3 scripts/test_ti_apis.py --only ab   # solo AbuseIPDB

Exit codes:
  0 = todos OK
  1 = al menos uno falló
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

# Permitir importar src desde scripts/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config import Settings  # noqa: E402
from src.tools.threatintel import (  # noqa: E402
    AbuseipdbClient,
    ThreatIntelError,
    VirusTotalClient,
)

# IOCs conocidos para smoke test
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
TEST_IP_BENIGN = "8.8.8.8"  # Google DNS - score esperado: 0


def ok(msg: str) -> None:
    print(f"\033[0;32m✓\033[0m {msg}")


def fail(msg: str) -> None:
    print(f"\033[0;31m✗\033[0m {msg}", file=sys.stderr)


def info(msg: str) -> None:
    print(f"\033[0;34mℹ\033[0m {msg}")


async def test_virustotal(settings: Settings) -> bool:
    """Test VT con el hash de EICAR (test file de la EICAR antivirus standard)."""
    print()
    info(f"VirusTotal: GET /files/{EICAR_SHA256[:16]}...")

    if not settings.virustotal_api_key:
        fail("VIRUSTOTAL_API_KEY no está en el .env - skip")
        return False

    try:
        async with VirusTotalClient(settings) as vt:
            report = await vt.get_file_report(EICAR_SHA256)
    except ThreatIntelError as e:
        fail(f"VT error: {e}")
        return False

    if report is None:
        fail("VT devolvió 404 para EICAR - raro, debería ser conocido por todos los motores")
        return False

    ok(f"VT respondió OK. EICAR file report:")
    print(f"    sha256:           {report.sha256}")
    print(f"    malicious:        {report.malicious_count}/{report.total_engines} engines")
    print(f"    suspicious:       {report.suspicious_count}")
    print(f"    family:           {report.family}")
    print(f"    categories:       {report.categories}")
    print(f"    type:             {report.type_description}")
    print(f"    size:             {report.size} bytes")
    print(f"    first_submission: {report.first_submission}")
    print(f"    last_analysis:    {report.last_analysis}")

    if report.malicious_count < 30:
        fail(
            f"⚠  EICAR debería tener >30 detecciones, vino con solo {report.malicious_count}. "
            "Algo raro en VT (o el hash cambió - ver virustotal.com)."
        )
        return False

    ok(f"VT contract OK ({report.malicious_count} engines detectaron EICAR)")
    return True


async def test_abuseipdb(settings: Settings) -> bool:
    """Test AbuseIPDB con Google DNS (8.8.8.8) - debería tener score bajo o 0."""
    print()
    info(f"AbuseIPDB: GET /check?ipAddress={TEST_IP_BENIGN}")

    if not settings.abuseipdb_api_key:
        fail("ABUSEIPDB_API_KEY no está en el .env - skip")
        return False

    try:
        async with AbuseipdbClient(settings) as ab:
            report = await ab.check_ip(TEST_IP_BENIGN)
    except ThreatIntelError as e:
        fail(f"AbuseIPDB error: {e}")
        return False

    if report is None:
        fail(f"AbuseIPDB rechazó {TEST_IP_BENIGN} - raro, es IPv4 válida")
        return False

    ok(f"AbuseIPDB respondió OK. {TEST_IP_BENIGN} report:")
    print(f"    abuse_confidence_score: {report.abuse_confidence_score}/100")
    print(f"    country:                {report.country_code}")
    print(f"    isp:                    {report.isp}")
    print(f"    domain:                 {report.domain}")
    print(f"    total_reports:          {report.total_reports}")
    print(f"    distinct_reporters:     {report.distinct_reporters}")
    print(f"    is_whitelisted:         {report.is_whitelisted}")
    print(f"    is_tor:                 {report.is_tor}")
    print(f"    usage_type:             {report.usage_type}")

    if report.abuse_confidence_score > 50:
        fail(
            f"⚠  {TEST_IP_BENIGN} (Google DNS) vino con score {report.abuse_confidence_score}>50. "
            "Inesperado - revisar si AbuseIPDB cambió comportamiento."
        )
        return False

    ok(f"AbuseIPDB contract OK ({TEST_IP_BENIGN} score={report.abuse_confidence_score})")
    return True


async def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke test de APIs de Threat Intel")
    parser.add_argument(
        "--only",
        choices=["vt", "ab"],
        help="Solo corre una API (vt=VirusTotal, ab=AbuseIPDB). Sin esto, corre todas.",
    )
    args = parser.parse_args()

    settings = Settings()

    results: list[bool] = []
    if args.only in (None, "vt"):
        results.append(await test_virustotal(settings))
    if args.only in (None, "ab"):
        results.append(await test_abuseipdb(settings))

    print()
    failed = [r for r in results if not r]
    if failed:
        fail(f"{len(failed)}/{len(results)} APIs fallaron - revisar arriba")
        return 1
    ok(f"Todas las APIs OK ({len(results)}/{len(results)})")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
