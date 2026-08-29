"""Golden test del reporte de vulnerabilidades (scripts/vuln_priority.py).

Red de seguridad para el refactor que mueve el script a `src/vuln/`: fija el
HTML y el texto plano que el reporte genera HOY, byte a byte, a partir de un
inventario sintetico. Si el refactor cambia una sola etiqueta, el diff aparece
en el fallo.

Reglas de la casa:
  - CERO red y CERO credenciales: no se llama al indexer, ni a EPSS, ni a KEV,
    ni a la API de Wazuh. Todo entra por `tests/fixtures/vuln_report/input.json`.
  - CERO tiempo real: `datetime` esta congelado, asi que el run_id, la fecha del
    encabezado y los timestamps del resumen son estables.
  - CERO dependencia del entorno: las constantes que salen de variables de
    entorno (ORG_NAME, pesos del score, umbrales, marca del tema) se fijan a su
    valor por defecto antes de renderizar.

Para regenerar los goldens despues de un cambio DELIBERADO de diseño:

    UPDATE_VULN_GOLDEN=1 /opt/soc-l1/.venv/bin/python -m pytest \
        tests/test_vuln_report_regression.py

y revisar el diff de los archivos en tests/fixtures/vuln_report/ antes de commitear.
"""
from __future__ import annotations

import difflib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts import vuln_priority as vp
from src import report_theme as theme

FIXTURES = Path(__file__).parent / "fixtures" / "vuln_report"
INPUT = FIXTURES / "input.json"

# Snapshot anterior simulado: solo se usa para el rotulo "vs. dd/mm/aaaa" del
# encabezado de cumplimiento. El archivo NO se abre (compare_hosts ya recibe los
# conteos previos ya parseados), asi que la ruta puede no existir.
PREV_FILE = "/opt/wazuh-scripts/historical/snapshot_20260821_030112.csv"

TOP = 15

# Instante congelado. En UTC para el run_id / timestamps del resumen, y un naive
# fijo para `datetime.now()` sin tz (la fecha del encabezado), de modo que el
# resultado no dependa del huso horario de la maquina que corre el test.
FROZEN_UTC = datetime(2026, 8, 28, 6, 30, 0, tzinfo=UTC)
FROZEN_LOCAL = datetime(2026, 8, 28, 3, 30, 0)


class _FrozenDateTime(datetime):
    """`datetime` con `now()` clavado. `strptime` y demas siguen funcionando."""

    @classmethod
    def now(cls, tz=None):
        return FROZEN_UTC if tz is not None else FROZEN_LOCAL

    @classmethod
    def utcnow(cls):
        return FROZEN_UTC.replace(tzinfo=None)


# --------------------------------------------------------------------------
# Golden helpers
# --------------------------------------------------------------------------
def _assert_golden(name: str, actual: str) -> None:
    """Compara contra el golden y falla con un diff unificado legible."""
    path = FIXTURES / name

    if os.getenv("UPDATE_VULN_GOLDEN"):
        path.write_text(actual, encoding="utf-8")
        pytest.skip(f"golden regenerado: {path}")

    if not path.exists():
        pytest.fail(
            f"Falta el golden {path}. Generalo con:\n"
            f"  UPDATE_VULN_GOLDEN=1 python -m pytest {Path(__file__).name}"
        )

    expected = path.read_text(encoding="utf-8")
    if actual == expected:
        return

    diff = list(
        difflib.unified_diff(
            expected.splitlines(keepends=True),
            actual.splitlines(keepends=True),
            fromfile=f"{name} (esperado / pre-refactor)",
            tofile=f"{name} (obtenido)",
            n=2,
        )
    )
    recorte = 160
    cuerpo = "".join(diff[:recorte])
    if len(diff) > recorte:
        cuerpo += f"\n... ({len(diff) - recorte} lineas de diff mas)\n"
    pytest.fail(
        f"El render de {name} cambio respecto del golden.\n\n{cuerpo}\n"
        "Si el cambio es intencional, regenera con "
        "UPDATE_VULN_GOLDEN=1 y revisa el diff antes de commitear."
    )


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------
# Valor por defecto de cada constante que sale de una variable de entorno y
# termina impresa en el reporte. Se fijan en TODOS los modulos que las tengan.
_CONSTANTES = {
    "ORG_NAME": "Grupo Alemana",
    "W_CVSS": 5.0,
    "W_EPSS": 30.0,
    "W_KEV": 20.0,
    "EPSS_HIGH_THRESHOLD": 0.5,
    "PRIORITY_THRESHOLD": 80.0,
    "TOP_LIMIT": 15,
    "ORG_DEFAULT": "Grupo Alemana",
    "BRAND_DEFAULT": "SOC Grupo Alemana",
    "LEGAL_DEFAULT": "Grupo Alemana &middot; Seguridad de la Informaci&oacute;n",
}


def _modulos_bajo_test():
    """Modulos donde vive realmente el codigo que renderiza.

    Se descubren desde las propias funciones (`__module__`) en vez de asumir que
    todo esta en `scripts.vuln_priority`: asi el freeze del reloj y de las
    constantes sigue funcionando cuando el codigo se mueve a `src/vuln/*`.
    """
    mods = {vp, theme}
    for fn in (
        vp.build_summary, vp.group_by_cve, vp.assess_coverage, vp.compare_hosts,
        vp.compute_host_counts, vp.render_email, vp.render_fragment,
        vp.render_compliance_fragment, vp.render_coverage_notice, vp.render_plain,
    ):
        mods.add(sys.modules[fn.__module__])
    return mods


@pytest.fixture(autouse=True)
def _deterministic(monkeypatch):
    """Congela el reloj y fija las constantes que dependen del entorno."""
    for mod in _modulos_bajo_test():
        actual = getattr(mod, "datetime", None)
        if isinstance(actual, type) and issubclass(actual, datetime):
            monkeypatch.setattr(mod, "datetime", _FrozenDateTime)
        for nombre, valor in _CONSTANTES.items():
            if hasattr(mod, nombre):
                monkeypatch.setattr(mod, nombre, valor)


@pytest.fixture(scope="module")
def datos() -> dict:
    return json.loads(INPUT.read_text(encoding="utf-8"))


@pytest.fixture
def reporte(datos) -> dict:
    """Corre el pipeline completo desde el fixture, sin red ni base de datos.

    Reproduce el orden de main(): threat intel -> ciclo de vida -> resumen ->
    agrupacion por CVE -> calidad del dato -> cumplimiento por host.
    """
    activos = vp.apply_threat_intel(
        [dict(f) for f in datos["active_findings"]], datos["epss"], datos["kev"]
    )
    filas = activos + [dict(r) for r in datos["resolved_rows"]]

    summary = vp.build_summary(filas, baseline=False)
    grupos = vp.group_by_cve(activos)
    cov = vp.assess_coverage(activos, datos["agent_os"])
    comp = vp.compare_hosts(vp.compute_host_counts(activos), datos["previous_hosts"])
    return {"summary": summary, "grupos": grupos, "cov": cov, "comp": comp}


# --------------------------------------------------------------------------
# Contrato de los datos que alimentan el render
# --------------------------------------------------------------------------
def test_scoring_y_resumen(reporte):
    """Los numeros que el HTML muestra arriba de todo, antes de mirar el HTML."""
    s = reporte["summary"]
    assert s["run_id"] == "wazuh-20260828063000"
    assert s["total_active"] == 13
    assert s["resolved_count"] == 2
    assert (s["new_count"], s["ongoing_count"], s["reopened_count"]) == (4, 8, 1)
    assert s["critical_count"] == 6
    assert s["high_count"] == 2
    assert s["kev_count"] == 4          # 2x CVE-2024-21412, 44487, log4shell
    assert s["kev_ransomware_count"] == 3
    assert s["epss_high_count"] == 6    # EPSS >= 50%
    assert s["priority_high_count"] == 4
    assert s["hosts_affected"] == 5


def test_prioridad_por_cve(reporte):
    """El orden del Top y los casos de borde del score."""
    por_cve = {g["cve"]: g for g in reporte["grupos"]}

    # KEV + EPSS altisimo manda, aunque el CVSS no sea 10.
    assert reporte["grupos"][0]["cve"] == "CVE-2021-44228"
    assert por_cve["CVE-2021-44228"]["priority_score"] == 99.2
    assert por_cve["CVE-2021-44228"]["kev_ransomware"] is True

    # EPSS alto con CVSS bajo: 5.3 de CVSS pero entra por explotabilidad.
    assert por_cve["CVE-2024-3094"]["priority_score"] == 52.7
    assert por_cve["CVE-2024-3094"]["cisa_kev"] is False

    # Sin datos de EPSS: el score sale solo del CVSS.
    assert por_cve["CVE-2025-30215"]["epss_score"] == 0.0
    assert por_cve["CVE-2025-30215"]["priority_score"] == 49.0

    # Untriaged: Wazuh manda severidad "-" y score centinela -1.0. El score de
    # prioridad queda NEGATIVO y el hallazgo va al fondo del Top.
    untriaged = por_cve["CVE-2024-49040"]
    assert untriaged["severity"] == "-"
    assert untriaged["priority_score"] == -5.0
    assert reporte["grupos"][-1]["cve"] == "CVE-2024-49040"

    # Agrupacion: un CVE en varios hosts cuenta hosts distintos, no hallazgos.
    assert por_cve["CVE-2024-38063"]["hosts_count"] == 2
    assert por_cve["CVE-2024-38063"]["hosts_list"] == ["SRVDC01", "SRVFILE04"]

    # El badge "NUEVA" sale de la fila REPRESENTANTE del grupo (la de mayor
    # score), no de "aparecio en algun host nuevo": CVE-2024-21412 es nueva en
    # NB-GERENCIA&VENTAS pero ya venia de antes en SRVDC01, y el grupo no se
    # marca como nueva. Comportamiento actual, congelado a proposito.
    assert por_cve["CVE-2024-21412"]["is_new_group"] is False
    assert por_cve["CVE-2023-38545"]["is_new_group"] is True


def test_calidad_del_dato(reporte):
    """assess_coverage: desfasados (build viejo indexado) y hosts sin hallazgos."""
    cov = reporte["cov"]
    assert cov["disponible"] is True
    assert [d["host"] for d in cov["desfasados"]] == ["SRVDC01", "NB-GERENCIA&VENTAS"]
    assert cov["hallazgos_dudosos"] == 5
    assert cov["sin_datos"] == ["SRVWSUS"]
    # SRVFILE04 reporta el mismo build que tiene indexado: no es desfasado.
    assert "SRVFILE04" not in [d["host"] for d in cov["desfasados"]]


def test_cumplimiento_por_host(reporte):
    """compare_hosts: deltas, altas, bajas y SLA."""
    comp = reporte["comp"]
    assert comp["has_previous"] is True
    assert comp["total_hosts"] == 5
    assert comp["new_hosts"] == 2                    # NB-GERENCIA&VENTAS, SRVFILE04
    assert comp["removed_hosts"] == ["SRVOLD03"]     # no cuenta como mejora
    assert (comp["critical_now"], comp["high_now"]) == (6, 2)
    assert (comp["improved"], comp["worsened"], comp["stable"]) == (2, 1, 0)
    assert round(comp["sla"]) == 67

    por_host = {r["host"]: r for r in comp["rows"]}
    # Mismo CVE en dos paquetes del host cuenta UNA vez, con la severidad mas alta.
    assert por_host["SRVDC01"]["critical_now"] == 2
    assert por_host["LNXWEB01"]["trend"] == "worsened"
    assert por_host["SRVOLD03"]["was_removed"] is True


# --------------------------------------------------------------------------
# Goldens del render
# --------------------------------------------------------------------------
def test_golden_coverage_notice(reporte):
    _assert_golden("coverage_notice.html", vp.render_coverage_notice(reporte["cov"]))


def test_golden_compliance_fragment(reporte):
    _assert_golden(
        "compliance_fragment.html",
        vp.render_compliance_fragment(reporte["comp"], PREV_FILE),
    )


def test_golden_fragment(reporte):
    _assert_golden(
        "fragment.html",
        vp.render_fragment(reporte["summary"], reporte["grupos"], top_limit=TOP),
    )


def test_golden_email(reporte):
    _assert_golden(
        "report.html",
        vp.render_email(
            reporte["summary"], reporte["grupos"], TOP,
            comp=reporte["comp"], prev_file=PREV_FILE, cov=reporte["cov"],
        ),
    )


def test_golden_plain(reporte):
    _assert_golden(
        "report.txt",
        vp.render_plain(
            reporte["summary"], reporte["grupos"], TOP,
            comp=reporte["comp"], cov=reporte["cov"],
        ),
    )


def test_golden_email_baseline(datos):
    """Primera corrida: aviso de linea base, sin cumplimiento y sin calidad de dato.

    Ademas cambia el titulo y el badge del header, asi que es otra rama del shell.
    """
    activos = vp.apply_threat_intel(
        [dict(f) for f in datos["active_findings"] if not f.get("cisa_kev")
         and f["cve"] not in datos["kev"] and f["cve"] not in datos["epss"]],
        datos["epss"], datos["kev"],
    )
    summary = vp.build_summary(activos, baseline=True)
    grupos = vp.group_by_cve(activos)
    assert summary["kev_count"] == 0 and summary["epss_high_count"] == 0
    _assert_golden(
        "report_baseline.html",
        vp.render_email(summary, grupos, TOP, comp=None, prev_file="", cov={}),
    )


# --------------------------------------------------------------------------
# Ramas cortas del render que no necesitan golden
# --------------------------------------------------------------------------
def test_coverage_notice_vacio_si_no_hay_nada_que_avisar():
    assert vp.render_coverage_notice({}) == ""
    assert vp.render_coverage_notice({"disponible": False, "desfasados": [], "sin_datos": []}) == ""
    assert vp.render_coverage_notice(
        {"disponible": True, "desfasados": [], "sin_datos": [], "hallazgos_dudosos": 0}
    ) == ""


def test_compliance_sin_semana_anterior(reporte, datos):
    """Sin snapshot previo el encabezado lo dice explicitamente."""
    comp = vp.compare_hosts(vp.compute_host_counts(
        vp.apply_threat_intel([dict(f) for f in datos["active_findings"]],
                              datos["epss"], datos["kev"])), {})
    html = vp.render_compliance_fragment(comp, "")
    assert "sin semana anterior para comparar" in html
    # Rareza del calculo actual: sin snapshot previo todos los hosts son "nuevos",
    # el conjunto trackeado queda vacio y cae al fallback (todas las filas), asi
    # que TODO cuenta como empeorado y el SLA se muestra en 0%.
    assert comp["sla"] == 0.0
    assert comp["worsened"] == 5
    assert "Acci&oacute;n requerida" in html


def test_top_limit_recorta_la_tabla(reporte):
    html = vp.render_fragment(reporte["summary"], reporte["grupos"], top_limit=3)
    assert "Top 3 CVEs a parchear primero" in html
    assert "CVE-2021-44228" in html
    assert "CVE-2022-40982" not in html


def test_el_html_escapa_los_datos_del_parque(reporte):
    """El '&' del nombre de host y el '<' del paquete no salen crudos."""
    html = vp.render_email(
        reporte["summary"], reporte["grupos"], TOP,
        comp=reporte["comp"], prev_file=PREV_FILE, cov=reporte["cov"],
    )
    assert "NB-GERENCIA&amp;VENTAS" in html
    assert "NB-GERENCIA&VENTAS" not in html
    assert "Microsoft Edge (Chromium) &lt;120&gt;" in html
    # La URL de referencia con query string tambien va escapada en el href.
    assert "utm=soc&amp;src=wazuh" in html
