"""Tests de src/vuln/schema.py: creación, migración de bases viejas e idempotencia."""
from __future__ import annotations

import ast
import json
import pathlib
import sqlite3

import pytest

from src.vuln.schema import SCHEMA, SQL_NOW, ensure_schema, now_iso, today_iso

# Esquema tal cual quedó en producción antes de esta migración (el que crea
# scripts/vuln_priority.py): sin plataforma ni reopened_at, sin tablas nuevas.
OLD_SCHEMA = """
CREATE TABLE vuln_lifecycle (
    finding_key      TEXT PRIMARY KEY,
    cve              TEXT,
    agent_id         TEXT,
    agent_name       TEXT,
    package_name     TEXT,
    package_version  TEXT,
    severity         TEXT,
    cvss_score       REAL,
    epss_score       REAL,
    cisa_kev         INTEGER,
    priority_score   REAL,
    lifecycle_status TEXT,
    first_seen_at    TEXT,
    last_seen_at     TEXT,
    resolved_at      TEXT,
    detection_count  INTEGER,
    context_object   TEXT
);
CREATE INDEX idx_lifecycle_cve ON vuln_lifecycle(cve);
CREATE INDEX idx_lifecycle_status ON vuln_lifecycle(lifecycle_status);
CREATE TABLE vuln_runs (
    run_id          TEXT PRIMARY KEY,
    started_at      TEXT,
    completed_at    TEXT,
    run_status      TEXT,
    total_active    INTEGER,
    new_count       INTEGER,
    ongoing_count   INTEGER,
    resolved_count  INTEGER,
    critical_count  INTEGER,
    high_count      INTEGER,
    summary_object  TEXT
);
"""

NEW_TABLES = (
    "vuln_lifecycle",
    "vuln_runs",
    "vuln_snapshots",
    "vuln_assignments",
    "vuln_kev_cache",
    "vuln_state_cache",
    "vuln_priority_brief",
)


@pytest.fixture()
def conn(tmp_path):
    """Base temporal, nunca la real."""
    c = sqlite3.connect(tmp_path / "vuln_lifecycle.db")
    c.row_factory = sqlite3.Row
    yield c
    c.close()


def _tables(c: sqlite3.Connection) -> set[str]:
    return {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _columns(c: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in c.execute(f"PRAGMA table_info({table})")}


def _seed_old(c: sqlite3.Connection, n: int = 3) -> None:
    c.executescript(OLD_SCHEMA)
    c.executemany(
        "INSERT INTO vuln_lifecycle (finding_key, cve, agent_id, lifecycle_status, "
        "priority_score, detection_count) VALUES (?, ?, ?, ?, ?, ?)",
        [(f"k{i}", f"CVE-2026-{i:04d}", "001", "ongoing", 80.0 + i, i) for i in range(n)],
    )
    c.execute(
        "INSERT INTO vuln_runs (run_id, started_at, run_status, total_active) VALUES (?,?,?,?)",
        ("run-1", now_iso(), "ok", n),
    )
    c.commit()


# --------------------------------------------------------------------------
# Base vacía
# --------------------------------------------------------------------------
def test_base_vacia_crea_todo(conn):
    ensure_schema(conn)
    assert set(NEW_TABLES) <= _tables(conn)

    cols = _columns(conn, "vuln_lifecycle")
    assert {"plataforma", "reopened_at"} <= cols

    indices = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
    assert {
        "idx_lifecycle_cve",
        "idx_lifecycle_status",
        "idx_lifecycle_agent",
        "idx_lifecycle_priority",
        "idx_assignments_owner",
        "idx_kev_fetched",
    } <= indices


def test_defaults_sqlite(conn):
    """plataforma default '' y los timestamps SQL con el formato de now_iso()."""
    ensure_schema(conn)
    conn.execute("INSERT INTO vuln_lifecycle (finding_key) VALUES ('k')")
    assert conn.execute("SELECT plataforma, reopened_at FROM vuln_lifecycle").fetchone()[:] == (
        "",
        None,
    )

    conn.execute("INSERT INTO vuln_assignments (cve) VALUES ('CVE-2026-0001')")
    conn.execute("INSERT INTO vuln_kev_cache (cve, data) VALUES ('CVE-2026-0001', '{}')")
    ts = conn.execute("SELECT updated_at FROM vuln_assignments").fetchone()[0]
    kts = conn.execute("SELECT fetched_at FROM vuln_kev_cache").fetchone()[0]
    # Mismo formato que now_iso(): 2026-08-28T22:51:38+00:00
    for value in (ts, kts):
        assert len(value) == len(now_iso())
        assert value.endswith("+00:00") and value[10] == "T"


def test_json_como_texto_consultable(conn):
    """JSONB → TEXT: se guarda serializado y json1 lo puede leer."""
    ensure_schema(conn)
    conn.execute(
        "INSERT INTO vuln_snapshots (fecha, total, criticas_altas, cves_unicos, "
        "por_severidad, por_servidor) VALUES (?,?,?,?,?,?)",
        (today_iso(), 12589, 300, 900, json.dumps({"Critical": 300}), json.dumps({"dc01": {}})),
    )
    row = conn.execute(
        "SELECT json_extract(por_severidad, '$.Critical') AS c FROM vuln_snapshots"
    ).fetchone()
    assert row["c"] == 300


def test_singletons_id_fijo(conn):
    """El equivalente de SMALLINT PK DEFAULT 1 CHECK (id = 1)."""
    ensure_schema(conn)
    for table, cols, values in (
        ("vuln_state_cache", "(id, updated_at, state)", (1, now_iso(), "{}")),
        ("vuln_priority_brief", "(id, updated_at, brief)", (1, now_iso(), "hola")),
    ):
        conn.execute(f"INSERT INTO {table} {cols} VALUES (?,?,?)", values)
        # Un segundo registro no entra: id autoincrementa y rebota el CHECK.
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(f"INSERT INTO {table} {cols} VALUES (?,?,?)", (2, *values[1:]))
        assert conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 1

    # El upsert por id sí funciona (ON CONFLICT nativo).
    conn.execute(
        "INSERT INTO vuln_state_cache (id, updated_at, state) VALUES (1, ?, ?) "
        "ON CONFLICT (id) DO UPDATE SET updated_at = excluded.updated_at, "
        "state = excluded.state",
        (now_iso(), '{"total": 1}'),
    )
    assert conn.execute("SELECT state FROM vuln_state_cache").fetchone()[0] == '{"total": 1}'


def test_sql_now_coincide_con_now_iso(conn):
    """SQL_NOW y now_iso() tienen que producir el mismo formato."""
    valor = conn.execute(f"SELECT {SQL_NOW}").fetchone()[0]
    assert len(valor) == len(now_iso())
    assert valor[:14] <= now_iso()[:14]  # mismo prefijo temporal, sin flakear por segundos


# --------------------------------------------------------------------------
# Base con esquema viejo
# --------------------------------------------------------------------------
def test_migra_esquema_viejo_sin_perder_datos(conn):
    _seed_old(conn, n=3)
    antes = conn.execute("SELECT * FROM vuln_lifecycle ORDER BY finding_key").fetchall()

    ensure_schema(conn)

    assert set(NEW_TABLES) <= _tables(conn)
    assert {"plataforma", "reopened_at"} <= _columns(conn, "vuln_lifecycle")

    despues = conn.execute("SELECT * FROM vuln_lifecycle ORDER BY finding_key").fetchall()
    assert len(despues) == len(antes) == 3
    assert [r["finding_key"] for r in despues] == [r["finding_key"] for r in antes]
    assert [r["priority_score"] for r in despues] == [r["priority_score"] for r in antes]
    # Las filas viejas quedan con el default, no con NULL.
    assert {r["plataforma"] for r in despues} == {""}
    assert {r["reopened_at"] for r in despues} == {None}
    assert conn.execute("SELECT count(*) FROM vuln_runs").fetchone()[0] == 1


def test_migracion_no_toca_columnas_ya_presentes(conn):
    """Si plataforma ya tiene valores, la migración no los pisa."""
    _seed_old(conn)
    ensure_schema(conn)
    conn.execute("UPDATE vuln_lifecycle SET plataforma = 'windows', reopened_at = ?", (now_iso(),))
    conn.commit()

    ensure_schema(conn)

    plataformas = {r[0] for r in conn.execute("SELECT plataforma FROM vuln_lifecycle")}
    assert plataformas == {"windows"}
    sin_reopen = conn.execute(
        "SELECT count(*) FROM vuln_lifecycle WHERE reopened_at IS NULL"
    ).fetchone()[0]
    assert sin_reopen == 0


# --------------------------------------------------------------------------
# Idempotencia
# --------------------------------------------------------------------------
@pytest.mark.parametrize("veces", [2, 3])
def test_correr_varias_veces_no_falla_ni_duplica(conn, veces):
    _seed_old(conn, n=5)
    for _ in range(veces):
        ensure_schema(conn)

    assert conn.execute("SELECT count(*) FROM vuln_lifecycle").fetchone()[0] == 5
    # Ni columnas ni tablas duplicadas.
    cols = [r[1] for r in conn.execute("PRAGMA table_info(vuln_lifecycle)")]
    assert len(cols) == len(set(cols))
    tablas = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
    assert len(tablas) == len(set(tablas))


def test_idempotente_sobre_base_vacia(conn):
    ensure_schema(conn)
    q = "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL"
    esquema_1 = sorted(r[0] for r in conn.execute(q))
    ensure_schema(conn)
    esquema_2 = sorted(r[0] for r in conn.execute(q))
    assert esquema_1 == esquema_2


def test_ensure_schema_commitea(tmp_path):
    """Lo escrito tiene que estar visible para otra conexión (hace commit)."""
    path = tmp_path / "vuln_lifecycle.db"
    c1 = sqlite3.connect(path)
    ensure_schema(c1)
    c1.close()

    c2 = sqlite3.connect(path)
    try:
        assert set(NEW_TABLES) <= _tables(c2)
    finally:
        c2.close()


# --------------------------------------------------------------------------
# SCHEMA: copia textual del DDL que ya existía
# --------------------------------------------------------------------------
def _schema_const(path: pathlib.Path) -> str | None:
    """Extrae la constante SCHEMA de un archivo sin importarlo."""
    if not path.exists():
        return None
    for node in ast.parse(path.read_text()).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "SCHEMA" for t in node.targets
        ):
            return ast.literal_eval(node.value)
    return None


def test_schema_es_copia_textual_del_original():
    """SCHEMA tiene que ser byte a byte el DDL de scripts/vuln_priority.py.

    Mientras dure el refactor hay una copia gemela en src/vuln/store.py; si
    alguna de las dos se toca, esto lo agarra antes de la consolidación.
    """
    raiz = pathlib.Path(__file__).resolve().parents[1]
    gemelas = {
        p.name: _schema_const(p)
        for p in (raiz / "src" / "vuln" / "store.py", raiz / "scripts" / "vuln_priority.py")
    }
    presentes = {k: v for k, v in gemelas.items() if v is not None}
    if not presentes:
        pytest.skip("no quedan copias del SCHEMA original que comparar")
    for nombre, texto in presentes.items():
        assert SCHEMA == texto, f"SCHEMA divergió de la copia de {nombre}"


def test_schema_solo_trae_las_tablas_base(conn):
    """SCHEMA por sí solo es el esquema VIEJO: sin columnas ni tablas nuevas."""
    conn.executescript(SCHEMA)
    assert _tables(conn) == {"vuln_lifecycle", "vuln_runs"}
    assert not {"plataforma", "reopened_at"} & _columns(conn, "vuln_lifecycle")


def test_ensure_schema_sobre_base_creada_con_schema(conn):
    """SCHEMA primero y migraciones después: el orden que aplica ensure_schema."""
    conn.executescript(SCHEMA)
    conn.execute("INSERT INTO vuln_lifecycle (finding_key, cve) VALUES ('k', 'CVE-2026-0001')")
    conn.commit()

    ensure_schema(conn)

    assert set(NEW_TABLES) <= _tables(conn)
    assert {"plataforma", "reopened_at"} <= _columns(conn, "vuln_lifecycle")
    assert conn.execute("SELECT cve, plataforma FROM vuln_lifecycle").fetchone()[:] == (
        "CVE-2026-0001",
        "",
    )
