"""PipelineTrace - captura de hitos del pipeline para el timeline de cierre.

Los agentes (triage, enricher, threat intel, narrator) corren ANTES de que exista
el approval en SQLite, así que sus hitos se acumulan en un PipelineTrace que se pasa
explícitamente por la cadena async y se persiste (timeline_json) al crear el approval.

El email de cierre ([[notify]] / mailer.send_closure_email) reconstruye estos eventos
y les agrega la decisión humana y la ejecución (que sí están en columnas del approval).

Dataclasses stdlib, sin deps. Cada evento lleva su propio timestamp ISO: el orden de
append puede ser no determinista (enricher y threat intel corren en paralelo), pero el
render ordena por `ts`.
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger("soc-l1")


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


@dataclass
class TimelineEvent:
    """Un hito del pipeline. `summary` reusa el texto que ya se computa para los logs."""

    stage: str  # "triage" | "enricher" | "threat_intel" | "narrator"
    ts: str  # ISO8601 UTC
    summary: str
    detail: str | None = None  # opcional: flags, counts, verdict


@dataclass
class PipelineTrace:
    """Acumula los hitos de una alerta mientras atraviesa el pipeline."""

    alert_id: str
    events: list[TimelineEvent] = field(default_factory=list)

    def add(self, stage: str, summary: str, detail: str | None = None) -> None:
        """Registra un hito con timestamp del momento de la llamada."""
        self.events.append(
            TimelineEvent(stage=stage, ts=_now_iso(), summary=summary or "", detail=detail)
        )

    def to_json(self) -> str:
        """Serializa los eventos para persistir en pending_approvals.timeline_json."""
        return json.dumps([asdict(e) for e in self.events], ensure_ascii=False)

    @staticmethod
    def events_from_json(s: str | None) -> list[dict]:
        """Parse robusto de timeline_json → list[dict]. Devuelve [] si None/inválido.

        Tolera approvals viejos (pre-migración, timeline_json NULL) sin romper el email.
        """
        if not s:
            return []
        try:
            data = json.loads(s)
        except (TypeError, ValueError):
            logger.warning("timeline_json inválido, ignorando (len=%s)", len(s) if s else 0)
            return []
        if not isinstance(data, list):
            return []
        return [e for e in data if isinstance(e, dict)]
