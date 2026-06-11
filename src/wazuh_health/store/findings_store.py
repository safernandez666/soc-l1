"""FindingsStore: persists DomainFindings with deterministic dedup."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone

from src.wazuh_health.contracts import DomainFinding


def compute_hash_key(domain: str, metric: str, evidence: dict) -> str:
    """Stable hash for dedup. Order-independent on evidence keys."""
    payload = {
        "domain": domain,
        "metric": metric,
        "evidence": {k: evidence[k] for k in sorted(evidence)},
    }
    blob = json.dumps(payload, sort_keys=True, default=str).encode()
    return hashlib.sha1(blob).hexdigest()


class FindingsStore:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def upsert(self, finding: DomainFinding, *, hash_key: str) -> int:
        now = datetime.now(tz=timezone.utc).isoformat()
        cur = self._conn.execute(
            "SELECT id FROM findings WHERE hash = ?", (hash_key,)
        )
        row = cur.fetchone()
        if row:
            self._conn.execute(
                "UPDATE findings SET last_seen = ?, severity = ?, body_md = ?, "
                "evidence_json = ? WHERE id = ?",
                (now, finding.severity, finding.body_md,
                 json.dumps(finding.evidence, sort_keys=True), row["id"]),
            )
            self._conn.commit()
            return int(row["id"])
        cur = self._conn.execute(
            "INSERT INTO findings(hash, domain, severity, title, body_md, "
            "evidence_json, suggested_action, proposed_artifact, "
            "first_seen, last_seen, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')",
            (
                hash_key, finding.domain, finding.severity, finding.title,
                finding.body_md, json.dumps(finding.evidence, sort_keys=True),
                finding.suggested_action, finding.proposed_artifact,
                now, now,
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def mark_resolved(self, finding_id: int) -> None:
        self._conn.execute(
            "UPDATE findings SET status = 'resolved' WHERE id = ?", (finding_id,)
        )
        self._conn.commit()

    def list_open(self, *, since_iso: str | None = None) -> list[DomainFinding]:
        q = "SELECT * FROM findings WHERE status = 'open'"
        args: tuple = ()
        if since_iso is not None:
            q += " AND last_seen >= ?"
            args = (since_iso,)
        q += " ORDER BY last_seen DESC"
        out: list[DomainFinding] = []
        for row in self._conn.execute(q, args):
            out.append(DomainFinding(
                domain=row["domain"],
                severity=row["severity"],
                title=row["title"],
                body_md=row["body_md"],
                evidence=json.loads(row["evidence_json"]),
                suggested_action=row["suggested_action"],
                proposed_artifact=row["proposed_artifact"],
                hash_key=row["hash"],
            ))
        return out
