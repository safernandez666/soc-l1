"""Tests de la API de vulnerabilidades del panel: /ui/api/vulns/summary y /cves.

La base de prueba se arma con el MISMO camino de escritura que producción
(`schema.ensure_schema` + `store.persist_lifecycle`), así los tests cubren
también las columnas nuevas (`plataforma`, `categoria`) y no sólo las consultas.

Nunca se toca la base real: `VULN_STATE_DB` apunta por default a la de
producción, así que todo acá pasa por `tmp_path`.
"""
from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from src.config import Settings
from src.main import app, get_settings
from src.vuln.indexer import _normalize
from src.vuln.schema import SCHEMA, ensure_schema
from src.vuln.store import open_state, persist_lifecycle
from src.web import queries

# ===== Fixtures: una base chica pero con todos los casos borde =====


def _finding(
    key: str,
    cve: str,
    agent: str,
    *,
    severity: str = "High",
    cvss: float = 7.5,
    epss: float = 0.01,
    kev: bool = False,
    priority: float = 40.0,
    package: str = "Google Chrome",
    categoria: str = "Packages",
    status: str = "ongoing",
    first_seen: str = "2026-08-01T00:00:00+00:00",
) -> dict[str, Any]:
    return {
        "finding_key": key,
        "cve": cve,
        "agent_id": agent[-3:],
        "agent_name": agent,
        "package_name": package,
        "package_version": "1.0",
        "severity": severity,
        "cvss_score": cvss,
        "epss_score": epss,
        "cisa_kev": kev,
        "kev": {"ransomware": "Known"} if kev else None,
        "epss_percentile": 0.5,
        "priority_score": priority,
        "lifecycle_status": status,
        "first_seen_at": first_seen,
        "last_seen_at": "2026-08-28T00:00:00+00:00",
        "resolved_at": "2026-08-28T00:00:00+00:00" if status == "resolved" else None,
        "detection_count": 2,
        "plataforma": "windows",
        "categoria": categoria,
    }


# CVE-2025-0001: el peor de todos (KEV + EPSS alto + priority alta), 3 hosts, OS.
# CVE-2025-0002: 6 hosts → prueba el tope de 5 nombres con hosts_count real.
# CVE-2025-0003: severity '-' y cvss -1 → bucket Untriaged.
# CVE-2025-0004: resuelto → no cuenta como activo.
_FINDINGS = [
    _finding("k1", "CVE-2025-0001", "SRVDC1", severity="Critical", cvss=9.8, epss=0.9,
             kev=True, priority=95.0, package="Windows Server 2019", categoria="OS",
             status="new", first_seen="2026-08-10T00:00:00+00:00"),
    _finding("k2", "CVE-2025-0001", "SRVDC2", severity="Critical", cvss=9.8, epss=0.9,
             kev=True, priority=95.0, package="Windows Server 2019", categoria="OS"),
    _finding("k3", "CVE-2025-0001", "SRVWEB", severity="High", cvss=8.0, epss=0.9,
             kev=True, priority=95.0, package="Windows Server 2022", categoria="OS"),
    *[
        _finding(f"k4{i}", "CVE-2025-0002", f"SRVAPP{i}", priority=60.0)
        for i in range(6)
    ],
    _finding("k5", "CVE-2025-0003", "SRVDC1", severity="-", cvss=-1.0, priority=0.0,
             package="WinRAR 5.91 (64-bit)"),
    _finding("k6", "CVE-2025-0004", "SRVDC1", status="resolved", priority=50.0),
    _finding("k7", "CVE-2025-0005", "SRVDC1", severity="Low", cvss=3.1, priority=15.0,
             package="7-Zip", categoria="Packages"),
]


@pytest.fixture(scope="module")
def _base_db(tmp_path_factory: pytest.TempPathFactory) -> str:
    """Base con los hallazgos, creada UNA sola vez para todo el módulo.

    `ensure_schema` son ~20 sentencias DDL con commit y en este box tardan varios
    segundos: crearla por test multiplicaba la suite. Cada test recibe una COPIA
    del archivo (instantánea), así sigue estando aislado.
    """
    path = str(tmp_path_factory.mktemp("vuln") / "base.db")
    conn = open_state(path)
    persist_lifecycle(conn, _FINDINGS)
    conn.close()
    return path


def _copia(base: str, destino: Path) -> str:
    path = str(destino / "vuln_lifecycle.db")
    shutil.copyfile(base, path)
    return path


def _agregar_runs(path: str, runs: list[tuple]) -> None:
    with sqlite3.connect(path) as conn:
        conn.executemany(
            "INSERT INTO vuln_runs (run_id, started_at, total_active, new_count, "
            "resolved_count) VALUES (?,?,?,?,?)",
            runs,
        )


@pytest.fixture
def db_path(_base_db: str, tmp_path: Path) -> str:
    path = _copia(_base_db, tmp_path)
    # Dos corridas el mismo día + una anterior: prueba el colapso diario de la tendencia.
    _agregar_runs(
        path,
        [
            ("r1", "2026-08-27T10:00:00+00:00", 8, 8, 0),
            ("r2", "2026-08-28T10:00:00+00:00", 9, 2, 1),
            ("r3", "2026-08-28T22:00:00+00:00", 10, 3, 2),
        ],
    )
    return path


@pytest.fixture
def settings_factory(db_path: str):
    def _make(**overrides) -> Settings:
        defaults = dict(
            wazuh_webhook_secret="x",
            vuln_state_db_path=db_path,
            dashboard_enabled=True,
            dashboard_password="test-pass",
            dashboard_session_secret="0" * 64,
        )
        defaults.update(overrides)
        return Settings(**defaults)

    return _make


@pytest.fixture
def client(settings_factory):
    app.dependency_overrides[get_settings] = lambda: settings_factory()
    get_settings.cache_clear()
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
    get_settings.cache_clear()


@pytest.fixture
def auth_client(client: TestClient, settings_factory):
    from src.web import auth

    client.cookies.set(auth.COOKIE_NAME, auth.issue_session(settings_factory()))
    return client


# ===== Ingesta: las dos columnas nuevas viajan del indexer a la base =====


def test_normalize_extrae_plataforma_y_categoria() -> None:
    hit = {
        "_id": "abc",
        "_source": {
            "agent": {"id": "001", "name": "SRVDC1"},
            "package": {"name": "Google Chrome", "version": "120.0"},
            "vulnerability": {
                "id": "cve-2025-0001",
                "severity": "High",
                "category": "Packages",
                "score": {"base": 8.8},
            },
            "host": {"os": {"platform": "windows", "name": "Microsoft Windows Server 2019"}},
        },
    }
    n = _normalize(hit)
    assert n["plataforma"] == "windows"
    assert n["categoria"] == "Packages"
    assert n["cve"] == "CVE-2025-0001"


def test_normalize_sin_host_ni_category_no_explota() -> None:
    """Un doc del indexer viejo (sin host.os ni vulnerability.category) sigue entrando."""
    n = _normalize({"_id": "x", "_source": {"vulnerability": {"id": "CVE-1"}}})
    assert n["plataforma"] == ""
    assert n["categoria"] == ""


def test_ensure_schema_agrega_categoria_sin_perder_datos(tmp_path: Path) -> None:
    """La migración es idempotente y no pisa lo que ya había."""
    path = str(tmp_path / "old.db")
    conn = sqlite3.connect(path)
    # SCHEMA es el esquema pre-migración: sin plataforma, reopened_at ni categoria.
    conn.executescript(SCHEMA)
    conn.execute("INSERT INTO vuln_lifecycle (finding_key, cve) VALUES ('k', 'CVE-2025-9999')")
    conn.commit()

    ensure_schema(conn)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(vuln_lifecycle)")}
    assert "categoria" in cols
    assert conn.execute("SELECT cve, categoria FROM vuln_lifecycle").fetchone()[:] == (
        "CVE-2025-9999", "",
    )

    conn.execute("UPDATE vuln_lifecycle SET categoria = 'OS'")
    conn.commit()
    ensure_schema(conn)  # segunda pasada: no debe tocar nada
    assert conn.execute("SELECT categoria FROM vuln_lifecycle").fetchone()[0] == "OS"
    conn.close()


def test_persist_lifecycle_guarda_plataforma_y_categoria(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT plataforma, categoria FROM vuln_lifecycle WHERE finding_key = 'k1'"
    ).fetchone()
    assert row == ("windows", "OS")
    conn.close()


def test_persist_lifecycle_no_pisa_categoria_con_vacio(db_path: str) -> None:
    """Un doc sin categoría no borra la que ya conocíamos ('' es 'no sé', no 'no tiene')."""
    conn = open_state(db_path)
    sin_dato = {**_FINDINGS[0], "categoria": "", "plataforma": ""}
    persist_lifecycle(conn, [sin_dato])
    assert conn.execute(
        "SELECT plataforma, categoria FROM vuln_lifecycle WHERE finding_key = 'k1'"
    ).fetchone()[:] == ("windows", "OS")
    conn.close()


# ===== /ui/api/vulns/summary =====


@pytest.mark.asyncio
async def test_summary_totales_solo_cuentan_activos(db_path: str) -> None:
    s = await queries.vulns_summary(db_path)
    assert s["available"] is True
    # 11 hallazgos activos de 12: el resuelto (k6) queda afuera de los totales.
    assert s["totals"] == {
        "activos": 11,
        "cves_unicos": 4,
        "agentes": 9,
        "resueltas_total": 1,
    }


@pytest.mark.asyncio
async def test_summary_untriaged_es_bucket_propio(db_path: str) -> None:
    """severity '-' no es Low ni desaparece: sin puntuar es desconocido, no inofensivo."""
    s = await queries.vulns_summary(db_path)
    assert s["por_severidad"] == {
        "Critical": 2, "High": 7, "Medium": 0, "Low": 1, "Untriaged": 1,
    }
    assert sum(s["por_severidad"].values()) == s["totals"]["activos"]


@pytest.mark.asyncio
async def test_summary_categoria_kev_y_umbrales(db_path: str) -> None:
    s = await queries.vulns_summary(db_path)
    assert s["por_categoria"] == {"OS": 3, "Packages": 8}
    assert s["kev"] == {"hallazgos": 3, "cves": 1}
    assert s["epss_alto"] == 3       # los 3 de CVE-2025-0001, epss 0.9 >= 0.5
    assert s["prioridad_alta"] == 3  # priority 95 >= 80


@pytest.mark.asyncio
async def test_summary_top_hosts_ordenado(db_path: str) -> None:
    s = await queries.vulns_summary(db_path)
    assert len(s["top_hosts"]) <= 10
    assert s["top_hosts"][0] == {
        "agent_name": "SRVDC1", "total": 3, "criticas": 1, "kev": 1,
    }
    totales = [h["total"] for h in s["top_hosts"]]
    assert totales == sorted(totales, reverse=True)


@pytest.mark.asyncio
async def test_summary_last_run_y_tendencia_por_dia(db_path: str) -> None:
    s = await queries.vulns_summary(db_path)
    assert s["last_run"] == {
        "started_at": "2026-08-28T22:00:00+00:00",
        "total_active": 10,
        "new_count": 3,
        "resolved_count": 2,
    }
    # Dos corridas el 28: activos es un nivel (vale la última), nuevas/resueltas se suman.
    assert s["tendencia"] == [
        {"fecha": "2026-08-27", "activos": 8, "nuevas": 8, "resueltas": 0},
        {"fecha": "2026-08-28", "activos": 10, "nuevas": 5, "resueltas": 3},
    ]


@pytest.mark.asyncio
async def test_summary_con_una_sola_corrida_igual_devuelve_serie(
    _base_db: str, tmp_path: Path
) -> None:
    path = _copia(_base_db, tmp_path)
    _agregar_runs(path, [("r1", "2026-08-28T10:00:00+00:00", 11, 11, 0)])
    s = await queries.vulns_summary(path)
    assert s["tendencia"] == [
        {"fecha": "2026-08-28", "activos": 11, "nuevas": 11, "resueltas": 0}
    ]


@pytest.mark.asyncio
async def test_summary_sin_corridas_devuelve_last_run_none(
    _base_db: str, tmp_path: Path
) -> None:
    """Sin corridas no se fabrica una de ceros al lado de N activos: last_run es null."""
    path = _copia(_base_db, tmp_path)
    s = await queries.vulns_summary(path)
    assert s["last_run"] is None
    assert s["tendencia"] == []
    assert s["totals"]["activos"] == 11  # los hallazgos están, lo que falta es la corrida


@pytest.mark.asyncio
async def test_summary_base_inexistente_no_explota(tmp_path: Path) -> None:
    s = await queries.vulns_summary(str(tmp_path / "no-existe.db"))
    assert s == {"available": False}


@pytest.mark.asyncio
async def test_summary_base_vieja_sin_columna_categoria(tmp_path: Path) -> None:
    """La base se abre read-only: si el pipeline no migró todavía, categoria se lee ''."""
    path = str(tmp_path / "vieja.db")
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE vuln_lifecycle (finding_key TEXT PRIMARY KEY, cve TEXT, agent_name TEXT, "
        "package_name TEXT, severity TEXT, cvss_score REAL, epss_score REAL, cisa_kev INTEGER, "
        "priority_score REAL, lifecycle_status TEXT, first_seen_at TEXT)"
    )
    conn.execute("CREATE TABLE vuln_runs (run_id TEXT PRIMARY KEY, started_at TEXT, "
                 "total_active INTEGER, new_count INTEGER, resolved_count INTEGER)")
    conn.execute(
        "INSERT INTO vuln_lifecycle VALUES ('k', 'CVE-2025-0001', 'SRVDC1', 'Chrome', "
        "'High', 8.0, 0.1, 0, 45.0, 'ongoing', '2026-08-01T00:00:00+00:00')"
    )
    conn.commit()
    conn.close()

    s = await queries.vulns_summary(path)
    assert s["available"] is True
    assert s["totals"]["activos"] == 1
    assert s["por_categoria"] == {"OS": 0, "Packages": 0}

    c = await queries.vulns_cves(path)
    assert c["cves"][0]["categoria"] == ""


# ===== /ui/api/vulns/cves =====


@pytest.mark.asyncio
async def test_cves_agrupa_y_ordena_por_prioridad(db_path: str) -> None:
    c = await queries.vulns_cves(db_path)
    assert c["total"] == 4  # 4 CVEs activos únicos (el resuelto no cuenta)
    assert c["per_page"] == 50
    # Orden por prioridad desc: 0001=95, 0002=60, 0005=15, 0003=0.
    assert [x["cve"] for x in c["cves"]] == [
        "CVE-2025-0001", "CVE-2025-0002", "CVE-2025-0005", "CVE-2025-0003",
    ]
    scores = [x["priority_score"] for x in c["cves"]]
    assert scores == sorted(scores, reverse=True)


@pytest.mark.asyncio
async def test_cves_fila_agregada(db_path: str) -> None:
    c = await queries.vulns_cves(db_path)
    fila = next(x for x in c["cves"] if x["cve"] == "CVE-2025-0001")
    assert fila["hosts_count"] == 3
    assert fila["hosts"] == ["SRVDC1", "SRVDC2", "SRVWEB"]
    assert fila["cisa_kev"] is True
    assert fila["cvss_score"] == 9.8
    assert fila["epss_score"] == 0.9
    assert fila["categoria"] == "OS"
    # El paquete más frecuente del CVE (2 de 3 hallazgos).
    assert fila["package_name"] == "Windows Server 2019"
    # Peor severidad del grupo (2 Critical + 1 High) y el primer avistaje real.
    assert fila["severity"] == "Critical"
    assert fila["first_seen_at"] == "2026-08-01T00:00:00+00:00"
    # Si algo del grupo es nuevo, el grupo se muestra como nuevo.
    assert fila["lifecycle_status"] == "new"


@pytest.mark.asyncio
async def test_cves_tope_de_hosts_pero_conteo_real(db_path: str) -> None:
    c = await queries.vulns_cves(db_path)
    fila = next(x for x in c["cves"] if x["cve"] == "CVE-2025-0002")
    assert fila["hosts_count"] == 6
    assert len(fila["hosts"]) == 5


@pytest.mark.asyncio
async def test_cves_severidad_untriaged(db_path: str) -> None:
    c = await queries.vulns_cves(db_path, severidad="Untriaged")
    assert [x["cve"] for x in c["cves"]] == ["CVE-2025-0003"]
    assert c["cves"][0]["severity"] == "Untriaged"
    assert c["filtros"]["severidad"] == "Untriaged"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("filtro", "esperados"),
    [
        ({"severidad": "Critical"}, ["CVE-2025-0001"]),
        ({"severidad": "Low"}, ["CVE-2025-0005"]),
        ({"categoria": "OS"}, ["CVE-2025-0001"]),
        ({"kev": True}, ["CVE-2025-0001"]),
        ({"agente": "SRVAPP0"}, ["CVE-2025-0002"]),
        ({"q": "chrome"}, ["CVE-2025-0002"]),           # case-insensitive
        ({"q": "CVE-2025-0005"}, ["CVE-2025-0005"]),    # busca por CVE
        ({"q": "7-Zip"}, ["CVE-2025-0005"]),            # y por paquete
        ({"q": "no-existe"}, []),
    ],
)
async def test_cves_filtros(db_path: str, filtro: dict, esperados: list[str]) -> None:
    c = await queries.vulns_cves(db_path, **filtro)
    assert [x["cve"] for x in c["cves"]] == esperados
    assert c["total"] == len(esperados)


@pytest.mark.asyncio
async def test_cves_q_neutraliza_comodines_de_like(db_path: str) -> None:
    """'_' y '%' del usuario son literales, no comodines: si no, buscar 'Win_AR' matchea todo."""
    assert (await queries.vulns_cves(db_path, q="Win_AR"))["total"] == 0
    assert (await queries.vulns_cves(db_path, q="%"))["total"] == 0
    assert (await queries.vulns_cves(db_path, q="WinRAR"))["total"] == 1


@pytest.mark.asyncio
async def test_cves_filtro_desconocido_se_ignora(db_path: str) -> None:
    c = await queries.vulns_cves(db_path, severidad="Altisima", categoria="Kernel")
    assert c["total"] == 4
    assert c["filtros"]["severidad"] is None
    assert c["filtros"]["categoria"] is None


@pytest.mark.asyncio
async def test_cves_pagina(_base_db: str, tmp_path: Path) -> None:
    """120 CVEs → 50 + 50 + 20, sin repetir ni perder ninguno."""
    path = _copia(_base_db, tmp_path)
    conn = sqlite3.connect(path)  # el esquema ya vino en la copia
    conn.execute("DELETE FROM vuln_lifecycle")
    persist_lifecycle(
        conn,
        [
            _finding(f"k{i}", f"CVE-2025-{i:04d}", "SRVDC1", priority=float(i))
            for i in range(120)
        ],
    )
    conn.close()

    vistos: list[str] = []
    for page, esperado in ((1, 50), (2, 50), (3, 20), (4, 0)):
        c = await queries.vulns_cves(path, page=page)
        assert c["total"] == 120
        assert c["page"] == page
        assert len(c["cves"]) == esperado
        vistos += [x["cve"] for x in c["cves"]]
    assert len(set(vistos)) == 120


@pytest.mark.asyncio
async def test_cves_base_inexistente_no_explota(tmp_path: Path) -> None:
    c = await queries.vulns_cves(str(tmp_path / "no-existe.db"))
    assert c["cves"] == []
    assert c["total"] == 0
    assert c["per_page"] == 50


# ===== Endpoints HTTP (auth + contrato) =====


@pytest.mark.parametrize("url", ["/ui/api/vulns/summary", "/ui/api/vulns/cves"])
def test_endpoints_requieren_sesion(client: TestClient, url: str) -> None:
    r = client.get(url)
    assert r.status_code == 401
    assert r.json()["error"] == "unauthorized"


def test_endpoint_summary_contrato(auth_client: TestClient) -> None:
    r = auth_client.get("/ui/api/vulns/summary")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {
        "available", "generated_at", "last_run", "totals", "por_severidad",
        "por_categoria", "kev", "epss_alto", "prioridad_alta", "top_hosts", "tendencia",
    }
    assert set(body["totals"]) == {"activos", "cves_unicos", "agentes", "resueltas_total"}
    assert list(body["por_severidad"]) == ["Critical", "High", "Medium", "Low", "Untriaged"]
    assert set(body["kev"]) == {"hallazgos", "cves"}
    assert set(body["top_hosts"][0]) == {"agent_name", "total", "criticas", "kev"}
    assert set(body["tendencia"][0]) == {"fecha", "activos", "nuevas", "resueltas"}


def test_endpoint_cves_contrato(auth_client: TestClient) -> None:
    r = auth_client.get("/ui/api/vulns/cves")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"cves", "total", "page", "per_page", "filtros"}
    assert body["per_page"] == 50
    assert set(body["cves"][0]) == {
        "cve", "priority_score", "cvss_score", "epss_score", "cisa_kev", "severity",
        "categoria", "hosts_count", "hosts", "package_name", "first_seen_at",
        "lifecycle_status",
    }
    assert body["filtros"] == {
        "severidad": None, "categoria": None, "agente": None, "kev": False, "q": None,
    }


def test_endpoint_cves_query_params(auth_client: TestClient) -> None:
    r = auth_client.get("/ui/api/vulns/cves?kev=1&severidad=Critical&q=windows&page=1")
    assert r.status_code == 200
    body = r.json()
    assert body["filtros"] == {
        "severidad": "Critical", "categoria": None, "agente": None,
        "kev": True, "q": "windows",
    }
    assert [x["cve"] for x in body["cves"]] == ["CVE-2025-0001"]


def test_endpoint_cves_page_invalida_cae_en_la_primera(auth_client: TestClient) -> None:
    r = auth_client.get("/ui/api/vulns/cves?page=-5")
    assert r.status_code == 200
    assert r.json()["page"] == 1
