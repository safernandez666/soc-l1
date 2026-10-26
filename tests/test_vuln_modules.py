"""Fronteras de src/vuln/ y contrato público de scripts/vuln_priority.py.

El script pasó a ser un CLI fino y la lógica vive en `src/vuln/*`. Estos tests
fijan dos cosas:

  1. Que los nombres que otros consumen (tests de regresión del reporte, y más
     adelante la pantalla de /ui) se sigan importando desde
     `scripts.vuln_priority`, aunque el código haya cambiado de casa.
  2. Que cada módulo quede en su capa: nada de red ni de SQLite acá, solo las
     funciones puras que transforman datos.
"""
from __future__ import annotations

import importlib

import pytest

# El contrato con tests/test_vuln_report_regression.py: estos nombres se
# importan DESDE el script, no desde los módulos.
CONTRATO = (
    "render_fragment",
    "render_email",
    "render_coverage_notice",
    "render_compliance_fragment",
    "render_plain",
    "build_summary",
    "group_by_cve",
    "assess_coverage",
    "compare_hosts",
    "compute_host_counts",
)

# Dónde tiene que vivir realmente cada cosa después del corte.
CAPAS = {
    "src.vuln.indexer": ("fetch_inventory", "fetch_agent_os_versions"),
    "src.vuln.feeds": ("fetch_epss", "fetch_kev"),
    "src.vuln.scoring": ("apply_threat_intel",),
    "src.vuln.store": (
        "open_state", "compute_lifecycle", "persist_lifecycle", "build_summary",
        "persist_run", "group_by_cve", "assess_coverage", "compute_host_counts",
        "load_previous_snapshot", "save_snapshot", "compare_hosts",
    ),
    "src.vuln.report": (
        "render_coverage_notice", "render_compliance_fragment", "render_fragment",
        "render_plain", "render_email", "load_email_config", "send_email",
    ),
}


@pytest.fixture(scope="module")
def cli():
    return importlib.import_module("scripts.vuln_priority")


@pytest.mark.parametrize("nombre", CONTRATO)
def test_contrato_importable_desde_el_script(cli, nombre):
    assert hasattr(cli, nombre), f"{nombre} dejó de exportarse desde scripts.vuln_priority"


@pytest.mark.parametrize("modulo,nombres", CAPAS.items())
def test_cada_funcion_en_su_capa(modulo, nombres):
    mod = importlib.import_module(modulo)
    for nombre in nombres:
        assert hasattr(mod, nombre), f"falta {nombre} en {modulo}"


def test_el_script_no_reimplementa_nada(cli):
    """Todo lo del contrato es un re-export: nada se define en el script."""
    for nombre in CONTRATO:
        origen = getattr(cli, nombre).__module__
        assert origen.startswith("src.vuln."), f"{nombre} quedó definido en {origen}"


# --------------------------------------------------------------------------
# Funciones puras: mismo comportamiento que antes del corte
# --------------------------------------------------------------------------
def _hallazgo(**kw) -> dict:
    base = {
        "finding_key": "k", "cve": "CVE-2024-0001", "agent_id": "001",
        "agent_name": "SRV01", "package_name": "openssl", "package_version": "1.1",
        "severity": "Critical", "cvss_score": 9.8, "epss_score": 0.9,
        "priority_score": 95.0, "cisa_kev": True, "kev_ransomware": False,
        "lifecycle_status": "ongoing",
    }
    base.update(kw)
    return base


def test_apply_threat_intel_usa_la_formula_documentada():
    from src.vuln.scoring import W_CVSS, W_EPSS, W_KEV, apply_threat_intel

    f = {"cve": "CVE-2024-0001", "cvss_score": 5.0}
    (out,) = apply_threat_intel([f], {"CVE-2024-0001": {"epss": 0.5, "percentile": 0.9}}, {})
    assert out["priority_score"] == round(5.0 * W_CVSS + 0.5 * W_EPSS, 1)
    assert out["cisa_kev"] is False

    kev = {"CVE-2024-0001": {"ransomware": "Known"}}
    (out,) = apply_threat_intel([dict(f)], {}, kev)
    assert out["priority_score"] == round(5.0 * W_CVSS + W_KEV, 1)
    assert out["kev_ransomware"] is True


def test_apply_threat_intel_topea_en_100():
    from src.vuln.scoring import apply_threat_intel

    (out,) = apply_threat_intel(
        [{"cve": "CVE-2024-0001", "cvss_score": 10.0}],
        {"CVE-2024-0001": {"epss": 1.0}},
        {"CVE-2024-0001": {"vendor": "MS"}},
    )
    assert out["priority_score"] == 100.0


def test_apply_threat_intel_una_entrada_kev_vacia_no_suma():
    """Rareza actual, fijada a propósito: el peso KEV se decide por truthiness
    del dict, no por presencia de la clave. Una entrada vacía no puntúa."""
    from src.vuln.scoring import apply_threat_intel

    (out,) = apply_threat_intel(
        [{"cve": "CVE-2024-0001", "cvss_score": 10.0}], {}, {"CVE-2024-0001": {}}
    )
    assert out["cisa_kev"] is False
    assert out["priority_score"] == 50.0


def test_compute_host_counts_cuenta_cves_distintos_no_hallazgos():
    """Un mismo CVE en dos paquetes del host cuenta UNA vez.

    Es la condición para que el delta contra los snapshots de
    weekly_comparison.py no salga inflado.
    """
    from src.vuln.store import compute_host_counts

    activos = [
        _hallazgo(cve="CVE-1", package_name="openssl", severity="High"),
        _hallazgo(cve="CVE-1", package_name="curl", severity="High"),
        _hallazgo(cve="CVE-2", severity="Critical"),
        _hallazgo(cve="", severity="Critical"),          # sin CVE: se ignora
        _hallazgo(cve="CVE-3", severity="Informational"),  # severidad fuera de rango
    ]
    assert compute_host_counts(activos) == {
        "SRV01": {"Critical": 1, "High": 1, "Medium": 0, "Low": 0}
    }


def test_compute_host_counts_se_queda_con_la_severidad_mas_alta():
    from src.vuln.store import compute_host_counts

    activos = [
        _hallazgo(cve="CVE-1", severity="Low"),
        _hallazgo(cve="CVE-1", severity="Critical"),
        _hallazgo(cve="CVE-1", severity="Medium"),
    ]
    assert compute_host_counts(activos)["SRV01"]["Critical"] == 1


def test_compare_hosts_no_cuenta_como_mejora_al_host_que_dejo_de_reportar():
    from src.vuln.store import compare_hosts

    actual = {"VIVO": {"Critical": 1, "High": 1, "Medium": 0, "Low": 0}}
    previo = {
        "VIVO": {"Critical": 3, "High": 1, "Medium": 0, "Low": 0},
        "MUERTO": {"Critical": 5, "High": 5, "Medium": 0, "Low": 0},
    }
    comp = compare_hosts(actual, previo)

    assert comp["removed_hosts"] == ["MUERTO"]
    assert comp["improved"] == 1          # solo VIVO
    assert comp["total_hosts"] == 1       # el caído no suma al parque
    assert comp["critical_now"] == 1      # ni a los totales
    assert comp["sla"] == 100.0


def test_group_by_cve_agrupa_hosts_y_ordena_por_prioridad():
    from src.vuln.store import group_by_cve

    activos = [
        _hallazgo(cve="CVE-BAJA", agent_name="A", priority_score=10.0, epss_score=0.1),
        _hallazgo(cve="CVE-ALTA", agent_name="A", priority_score=90.0, epss_score=0.9),
        _hallazgo(cve="CVE-ALTA", agent_name="B", priority_score=95.0, epss_score=0.9,
                  package_name="curl", lifecycle_status="new"),
    ]
    grupos = group_by_cve(activos)

    assert [g["cve"] for g in grupos] == ["CVE-ALTA", "CVE-BAJA"]
    alta = grupos[0]
    assert alta["hosts_count"] == 2
    assert alta["hosts_list"] == ["A", "B"]
    assert alta["priority_score"] == 95.0      # gana el hallazgo más prioritario
    assert alta["is_new_group"] is True
    assert set(alta["packages"]) == {"openssl", "curl"}


def test_assess_coverage_separa_desfasados_de_sin_datos():
    from src.vuln.store import assess_coverage

    activos = [
        _hallazgo(agent_name="WIN01", package_name="Microsoft Windows 10",
                  package_version="10.0.19045.1000"),
        _hallazgo(agent_name="WIN01", cve="CVE-X"),
        _hallazgo(agent_name="WIN02", package_name="Microsoft Windows 11",
                  package_version="10.0.22631.4000"),
    ]
    agent_os = {
        "WIN01": "10.0.19045.9999",   # el agente reporta un build más nuevo
        "WIN02": "10.0.22631.4000",   # coincide
        "SRVWSUS": "10.0.17763.1",    # activo pero sin ningún hallazgo
    }
    cov = assess_coverage(activos, agent_os)

    assert cov["disponible"] is True
    assert [d["host"] for d in cov["desfasados"]] == ["WIN01"]
    assert cov["hallazgos_dudosos"] == 2
    assert cov["sin_datos"] == ["SRVWSUS"]


def test_assess_coverage_sin_api_no_bloquea_el_reporte():
    """Si la API de Wazuh no responde el reporte sale igual, solo que sin aviso."""
    from src.vuln.store import assess_coverage

    cov = assess_coverage([_hallazgo()], {})
    assert cov == {"disponible": False, "desfasados": [], "sin_datos": [], "hallazgos_dudosos": 0}


def test_build_summary_y_ciclo_de_vida_sobre_una_base_temporal(tmp_path):
    from src.vuln.store import build_summary, compute_lifecycle, open_state, persist_lifecycle

    conn = open_state(str(tmp_path / "lc.db"))
    hallazgos = [
        _hallazgo(finding_key="a", cve="CVE-A"),
        _hallazgo(finding_key="b", cve="CVE-B", severity="High", cisa_kev=False,
                  epss_score=0.1, priority_score=40.0),
    ]

    rows, baseline = compute_lifecycle(conn, hallazgos)
    assert baseline is True
    assert {r["lifecycle_status"] for r in rows} == {"new"}
    persist_lifecycle(conn, rows)

    # Segunda corrida sin el hallazgo "b": queda resuelto, no desaparece.
    rows, baseline = compute_lifecycle(conn, hallazgos[:1])
    assert baseline is False
    estados = {r["finding_key"]: r["lifecycle_status"] for r in rows}
    assert estados == {"a": "ongoing", "b": "resolved"}
    persist_lifecycle(conn, rows)

    resumen = build_summary(rows, baseline)
    assert resumen["total_active"] == 1
    assert resumen["resolved_count"] == 1
    assert resumen["kev_count"] == 1
    assert resumen["run_status"] == "completed"

    # Tercera corrida con "b" de vuelta: reabierta, no nueva.
    rows, _ = compute_lifecycle(conn, hallazgos)
    assert {r["finding_key"]: r["lifecycle_status"] for r in rows}["b"] == "reopened"
    conn.close()


def test_snapshot_ida_y_vuelta(tmp_path):
    """El formato tiene que seguir siendo el de weekly_comparison.py."""
    from src.vuln.store import load_previous_snapshot, save_snapshot

    counts = {"SRV01": {"Critical": 2, "High": 3, "Medium": 1, "Low": 0}}
    ruta = save_snapshot(counts, str(tmp_path))
    assert ruta

    cabecera = [ln for ln in open(ruta, encoding="utf-8") if not ln.startswith("#")]
    assert cabecera[0].strip() == "Host,Critical,High,Medium,Low,Total"
    assert cabecera[1].strip() == "SRV01,2,3,1,0,6"

    # load_previous_snapshot saltea los del día, así que el recién escrito no vuelve.
    datos, _ = load_previous_snapshot(str(tmp_path))
    assert datos == {}
