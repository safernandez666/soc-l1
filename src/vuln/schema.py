"""Esquema y migración idempotente de vuln_lifecycle.db.

Este módulo es el dueño ÚNICO del DDL de la base de vulnerabilidades: tanto las
tablas que ya venían de `scripts/vuln_priority.py` (`vuln_lifecycle` y
`vuln_runs`, en la constante `SCHEMA`) como lo que se absorbió del motor de
Patch Genius (Postgres): snapshots diarios, asignación de remediación por CVE,
cache del catálogo CISA KEV y los dos singletons de estado precalculado.

`SCHEMA` es una copia TEXTUAL de la que vivía en `scripts/vuln_priority.py`
(líneas 279-315). No reformatear ni "mejorar" nombres ni tipos: mientras dure
el refactor hay una copia gemela en `src/vuln/store.py` y las dos se van a
consolidar en esta.

`ensure_schema()` es idempotente y barata: se puede llamar en cada arranque,
sobre una base vacía o sobre la de producción con 12.6k hallazgos, sin perder
datos. Hace las dos cosas en orden: primero aplica `SCHEMA` (crea si no
existen) y después las migraciones (columnas nuevas + tablas nuevas).

Adaptaciones de Postgres → SQLite:
  * `JSONB` → `TEXT` con JSON serializado (el módulo json1 está disponible, así
    que se puede consultar con json_extract si hace falta).
  * `TIMESTAMP WITH TIME ZONE DEFAULT NOW()` → TEXT ISO-8601 UTC con precisión
    de segundos, la misma convención que `scripts/vuln_priority.py::_now_iso`.
    Del lado SQL se replica con `SQL_NOW` (strftime), que devuelve exactamente
    el mismo formato que `now_iso()`.
  * `DATE` → TEXT ISO (YYYY-MM-DD), ordenable lexicográficamente.
  * `SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1)` → `INTEGER PRIMARY KEY
    CHECK (id = 1)`: hay que insertar el id explícito (`VALUES (1, ...)`)
    porque en SQLite la columna es alias de rowid y un INSERT que la omita
    autoincrementa y rebota contra el CHECK.
  * `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` no existe: se emula leyendo
    `PRAGMA table_info`.
  * `ON CONFLICT (...) DO UPDATE` funciona igual, no hace falta emularlo.
"""
from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

# Expresión SQL equivalente a now_iso(): ISO-8601 UTC con segundos.
SQL_NOW = "strftime('%Y-%m-%dT%H:%M:%S+00:00', 'now')"

# Estados válidos de remediación (mismos que Patch Genius). Se validan en
# Python, no con un CHECK, para poder sumar estados sin migrar la tabla.
ASSIGNMENT_STATUSES = ("pendiente", "en_curso", "parcial", "resuelto", "aceptado_riesgo")


def now_iso() -> str:
    """Timestamp ISO-8601 UTC, misma convención que scripts/vuln_priority.py."""
    return datetime.now(UTC).isoformat(timespec="seconds")


def today_iso() -> str:
    """Fecha de hoy en UTC (YYYY-MM-DD), para las columnas tipo DATE."""
    return datetime.now(UTC).date().isoformat()


# Tablas base, copia textual de scripts/vuln_priority.py (líneas 279-315).
# NO EDITAR el contenido: tiene que quedar byte a byte igual a la copia de
# src/vuln/store.py hasta que se consoliden.
SCHEMA = """
CREATE TABLE IF NOT EXISTS vuln_lifecycle (
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
CREATE INDEX IF NOT EXISTS idx_lifecycle_cve ON vuln_lifecycle(cve);
CREATE INDEX IF NOT EXISTS idx_lifecycle_status ON vuln_lifecycle(lifecycle_status);

CREATE TABLE IF NOT EXISTS vuln_runs (
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

# Tablas e índices nuevos. Se aplican DESPUÉS de SCHEMA.
MIGRATIONS_SQL = f"""
CREATE INDEX IF NOT EXISTS idx_lifecycle_agent ON vuln_lifecycle(agent_id);
CREATE INDEX IF NOT EXISTS idx_lifecycle_priority ON vuln_lifecycle(priority_score DESC);
CREATE INDEX IF NOT EXISTS idx_runs_started ON vuln_runs(started_at DESC);

-- Un snapshot por día con los totales: da la serie histórica del panel.
CREATE TABLE IF NOT EXISTS vuln_snapshots (
    fecha          TEXT PRIMARY KEY,          -- DATE ISO (YYYY-MM-DD)
    total          INTEGER NOT NULL,
    criticas_altas INTEGER NOT NULL,
    cves_unicos    INTEGER NOT NULL,
    por_severidad  TEXT NOT NULL DEFAULT '{{}}',  -- JSON objeto
    por_servidor   TEXT NOT NULL DEFAULT '{{}}'   -- JSON objeto
);

-- Owner + estado de remediación por CVE (clave: cve, sin agente; en Patch
-- Genius se colapsó a esa clave con una migración histórica).
CREATE TABLE IF NOT EXISTS vuln_assignments (
    cve         TEXT PRIMARY KEY,
    owner       TEXT NOT NULL DEFAULT '',
    owner_email TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'pendiente',
    due_date    TEXT,                          -- DATE ISO
    notes       TEXT NOT NULL DEFAULT '',
    updated_by  TEXT,
    updated_at  TEXT DEFAULT ({SQL_NOW})
);
CREATE INDEX IF NOT EXISTS idx_assignments_owner ON vuln_assignments(owner);
CREATE INDEX IF NOT EXISTS idx_assignments_status ON vuln_assignments(status);

-- Cache local del catálogo CISA KEV.
CREATE TABLE IF NOT EXISTS vuln_kev_cache (
    cve        TEXT PRIMARY KEY,
    data       TEXT NOT NULL,                  -- JSON objeto
    fetched_at TEXT NOT NULL DEFAULT ({SQL_NOW})
);
CREATE INDEX IF NOT EXISTS idx_kev_fetched ON vuln_kev_cache(fetched_at);

-- Singletons de estado precalculado (id fijo en 1).
CREATE TABLE IF NOT EXISTS vuln_state_cache (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    updated_at TEXT NOT NULL,
    state      TEXT NOT NULL                   -- JSON objeto
);

CREATE TABLE IF NOT EXISTS vuln_priority_brief (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    updated_at TEXT NOT NULL,
    brief      TEXT NOT NULL,
    cve_refs   TEXT NOT NULL DEFAULT '[]'      -- JSON array
);
"""

# Columnas que le faltan a las tablas de SCHEMA (tabla, columna, definición).
# Se emula ADD COLUMN IF NOT EXISTS mirando PRAGMA table_info.
_ADD_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("vuln_lifecycle", "plataforma", "TEXT NOT NULL DEFAULT ''"),
    ("vuln_lifecycle", "reopened_at", "TEXT"),
)


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
    ).fetchone()
    return row is not None


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Crea/actualiza el esquema de vuln_lifecycle.db. Idempotente.

    Segura de correr en cada arranque: no borra ni reescribe datos, sólo crea
    lo que falta y agrega columnas nuevas con su default.
    """
    # 1. Tablas base tal cual las creaba el script.
    conn.executescript(SCHEMA)

    # 2. Columnas nuevas sobre esas tablas (ADD COLUMN IF NOT EXISTS a mano).
    for table, column, definition in _ADD_COLUMNS:
        if not _table_exists(conn, table):
            continue  # la crea el executescript de arriba; defensivo
        if column in _columns(conn, table):
            continue
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    # 3. Tablas e índices nuevos.
    conn.executescript(MIGRATIONS_SQL)

    conn.commit()
