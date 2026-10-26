"""Tests de src/vuln/rescan.py: selección de agentes, bitácora y verificación.

Lo que se protege acá es que el script NO reinicie de más: un falso positivo en
`select_targets` es un reinicio de un servidor productivo.
"""
from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from src.vuln.rescan import (
    MOTIVO_DESFASADO,
    MOTIVO_SIN_DATOS,
    RescanTarget,
    load_last_rescans,
    record_rescan,
    restart_agents,
    select_targets,
    verify_pending,
)
from src.vuln.schema import ensure_schema

AHORA = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    ensure_schema(c)
    yield c
    c.close()


@pytest.fixture
def cov():
    return {
        "disponible": True,
        "desfasados": [
            {"host": "SRVDC2", "indexado": "10.0.17763.7009",
             "actual": "10.0.17763.9020", "hallazgos": 885},
            {"host": "SRVDCFICO1", "indexado": "10.0.17763.7009",
             "actual": "10.0.17763.8880", "hallazgos": 885},
        ],
        "sin_datos": ["SRVFILE2401", "SRVIIS", "SRVWSUS"],
        "hallazgos_dudosos": 1770,
    }


@pytest.fixture
def agentes():
    return {
        "SRVDC2": {"id": "002", "status": "active"},
        "SRVDCFICO1": {"id": "004", "status": "active"},
        "SRVIIS": {"id": "011", "status": "active"},
        "SRVFILE2401": {"id": "020", "status": "active"},
        "SRVWSUS": {"id": "024", "status": "active"},
        "SRVSANO": {"id": "007", "status": "active"},
    }


# --------------------------------------------------------------------------
# select_targets
# --------------------------------------------------------------------------
def test_elige_solo_los_hosts_de_la_cobertura(cov, agentes):
    sel = select_targets(cov, agentes, {}, ahora=AHORA)
    elegidos = {t.host for t in sel.elegibles}
    assert elegidos == {"SRVDC2", "SRVDCFICO1", "SRVFILE2401", "SRVIIS", "SRVWSUS"}
    # Un host sano nunca entra, ni siquiera como descartado.
    assert "SRVSANO" not in elegidos
    assert "SRVSANO" not in {h for h, _ in sel.descartados}


def test_desfasados_primero_y_por_volumen(cov, agentes):
    cov["desfasados"][0]["hallazgos"] = 10  # SRVDC2 pasa a ser el chico
    sel = select_targets(cov, agentes, {}, ahora=AHORA)
    assert [t.host for t in sel.elegibles[:2]] == ["SRVDCFICO1", "SRVDC2"]
    assert sel.elegibles[0].motivo == MOTIVO_DESFASADO
    assert sel.elegibles[-1].motivo == MOTIVO_SIN_DATOS


def test_no_toca_agentes_desconectados(cov, agentes):
    agentes["SRVWSUS"]["status"] = "disconnected"
    sel = select_targets(cov, agentes, {}, ahora=AHORA)
    assert "SRVWSUS" not in {t.host for t in sel.elegibles}
    assert any(h == "SRVWSUS" and "disconnected" in m for h, m in sel.descartados)


def test_nunca_reinicia_el_manager(cov, agentes):
    agentes["SRVWSUS"]["id"] = "000"
    sel = select_targets(cov, agentes, {}, ahora=AHORA)
    assert "SRVWSUS" not in {t.host for t in sel.elegibles}
    assert any(h == "SRVWSUS" and "manager" in m for h, m in sel.descartados)


def test_host_que_no_esta_en_el_manager_se_omite(cov, agentes):
    del agentes["SRVIIS"]
    sel = select_targets(cov, agentes, {}, ahora=AHORA)
    assert "SRVIIS" not in {t.host for t in sel.elegibles}


def test_cooldown_frena_el_reintento(cov, agentes):
    ultimos = {"SRVDC2": (AHORA - timedelta(days=2)).isoformat()}
    sel = select_targets(cov, agentes, ultimos, cooldown_days=7, ahora=AHORA)
    assert "SRVDC2" not in {t.host for t in sel.elegibles}
    assert any(h == "SRVDC2" and "cooldown" in m for h, m in sel.descartados)


def test_cooldown_vencido_vuelve_a_habilitar(cov, agentes):
    ultimos = {"SRVDC2": (AHORA - timedelta(days=9)).isoformat()}
    sel = select_targets(cov, agentes, ultimos, cooldown_days=7, ahora=AHORA)
    assert "SRVDC2" in {t.host for t in sel.elegibles}


def test_tope_por_corrida(cov, agentes):
    sel = select_targets(cov, agentes, {}, max_agents=2, ahora=AHORA)
    assert len(sel.elegibles) == 2
    assert any("tope" in m for _, m in sel.descartados)


def test_filtro_por_host(cov, agentes):
    sel = select_targets(cov, agentes, {}, solo_hosts=["srvwsus"], ahora=AHORA)
    assert [t.host for t in sel.elegibles] == ["SRVWSUS"]


def test_cobertura_no_disponible_no_elige_nada(agentes):
    sel = select_targets({"disponible": False}, agentes, {}, ahora=AHORA)
    assert sel.elegibles == []


def test_cobertura_limpia_no_elige_nada(agentes):
    sel = select_targets(
        {"disponible": True, "desfasados": [], "sin_datos": []}, agentes, {}, ahora=AHORA
    )
    assert sel.elegibles == []


# --------------------------------------------------------------------------
# Bitácora
# --------------------------------------------------------------------------
def test_el_dry_run_no_cuenta_para_el_cooldown(conn):
    t = RescanTarget(host="SRVWSUS", agent_id="024", motivo=MOTIVO_SIN_DATOS)
    record_rescan(conn, t, "simulado", "dry-run")
    assert load_last_rescans(conn) == {}
    record_rescan(conn, t, "ok")
    assert "SRVWSUS" in load_last_rescans(conn)


def test_record_guarda_el_estado_del_momento(conn):
    t = RescanTarget(host="SRVDC2", agent_id="002", motivo=MOTIVO_DESFASADO,
                     build_indexado="7009", build_real="9020", hallazgos=885)
    record_rescan(conn, t, "ok")
    row = conn.execute("SELECT * FROM vuln_rescans").fetchone()
    assert (row["build_indexado"], row["build_real"], row["hallazgos"]) == (
        "7009", "9020", 885)
    assert row["verificado"] is None


# --------------------------------------------------------------------------
# verify_pending
# --------------------------------------------------------------------------
def _verificado(conn):
    return conn.execute("SELECT verificado FROM vuln_rescans").fetchone()[0]


def _pedido(conn, host, motivo, cuando, build_indexado=""):
    conn.execute(
        "INSERT INTO vuln_rescans (host, agent_id, motivo, solicitado_at, resultado, "
        "build_indexado) "
        "VALUES (?,?,?,?,'ok',?)",
        (host, "002", motivo, cuando.isoformat(), build_indexado),
    )
    conn.commit()


def test_no_juzga_antes_de_la_ventana_de_gracia(conn, cov):
    _pedido(conn, "SRVWSUS", MOTIVO_SIN_DATOS, AHORA - timedelta(hours=3))
    verify_pending(conn, cov, grace_hours=24, ahora=AHORA)
    assert _verificado(conn) is None


def test_sin_datos_que_ya_reporta_convergio(conn, cov):
    _pedido(conn, "SRVWSUS", MOTIVO_SIN_DATOS, AHORA - timedelta(hours=30))
    cov["sin_datos"] = ["SRVFILE2401", "SRVIIS"]  # SRVWSUS ya no está
    fallos = verify_pending(conn, cov, grace_hours=24, ahora=AHORA)
    assert fallos == []
    assert _verificado(conn) == "convergio"


def test_sin_datos_que_sigue_mudo_es_sin_cambio(conn, cov):
    _pedido(conn, "SRVWSUS", MOTIVO_SIN_DATOS, AHORA - timedelta(hours=30))
    fallos = verify_pending(conn, cov, grace_hours=24, ahora=AHORA)
    assert [f["host"] for f in fallos] == ["SRVWSUS"]
    assert _verificado(conn) == "sin_cambio"


def test_desfasado_con_build_nuevo_convergio(conn, cov):
    _pedido(conn, "SRVDC2", MOTIVO_DESFASADO, AHORA - timedelta(hours=30),
            build_indexado="10.0.17763.7009")
    # El detector re-evaluó: el índice ya muestra otro build, aunque siga desfasado.
    cov["desfasados"][0]["indexado"] = "10.0.17763.8880"
    fallos = verify_pending(conn, cov, grace_hours=24, ahora=AHORA)
    assert fallos == []
    assert _verificado(conn) == "convergio"


def test_desfasado_congelado_es_sin_cambio(conn, cov):
    _pedido(conn, "SRVDC2", MOTIVO_DESFASADO, AHORA - timedelta(hours=30),
            build_indexado="10.0.17763.7009")
    fallos = verify_pending(conn, cov, grace_hours=24, ahora=AHORA)
    assert [f["host"] for f in fallos] == ["SRVDC2"]


def test_verificacion_es_idempotente(conn, cov):
    _pedido(conn, "SRVWSUS", MOTIVO_SIN_DATOS, AHORA - timedelta(hours=30))
    verify_pending(conn, cov, grace_hours=24, ahora=AHORA)
    assert verify_pending(conn, cov, grace_hours=24, ahora=AHORA) == []
    assert conn.execute(
        "SELECT COUNT(*) FROM vuln_rescans WHERE verificado IS NOT NULL").fetchone()[0] == 1


def test_no_verifica_si_no_hay_cobertura(conn):
    _pedido(conn, "SRVWSUS", MOTIVO_SIN_DATOS, AHORA - timedelta(hours=30))
    assert verify_pending(conn, {"disponible": False}, ahora=AHORA) == []
    assert _verificado(conn) is None


# --------------------------------------------------------------------------
# restart_agents: la respuesta del manager se traduce sin optimismo
# --------------------------------------------------------------------------
def test_restart_marca_error_lo_que_el_manager_no_confirmo(monkeypatch):
    class _Resp:
        status_code = 200

        def json(self):
            return {"data": {
                "affected_items": ["002"],
                "failed_items": [{"error": {"message": "Agent is not active"}, "id": ["024"]}],
            }}

    monkeypatch.setattr("src.vuln.rescan._manager", lambda: ("https://x", "tok"))
    monkeypatch.setattr("src.vuln.rescan.requests.put", lambda *a, **k: _Resp())

    out = restart_agents(["002", "024", "011"])
    assert out["002"] == "ok"
    assert "Agent is not active" in out["024"]
    assert out["011"].startswith("error:")  # el manager ni lo mencionó


def test_restart_sin_agentes_no_llama_a_la_api(monkeypatch):
    monkeypatch.setattr("src.vuln.rescan._manager", lambda: pytest.fail("no debería autenticar"))
    assert restart_agents([]) == {}
