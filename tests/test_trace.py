"""Tests de PipelineTrace - captura y serialización de hitos del timeline."""
from __future__ import annotations

import json

from src.trace import PipelineTrace, TimelineEvent


def test_add_accumulates_events_with_timestamps() -> None:
    tr = PipelineTrace("alert-1")
    tr.add("triage", "ruido sospechoso", detail="verdict=analyze")
    tr.add("narrator", "plan generado")
    assert len(tr.events) == 2
    assert tr.events[0].stage == "triage"
    assert tr.events[0].summary == "ruido sospechoso"
    assert tr.events[0].detail == "verdict=analyze"
    assert tr.events[0].ts  # timestamp ISO no vacío
    assert tr.events[1].detail is None


def test_to_json_roundtrip() -> None:
    tr = PipelineTrace("alert-2")
    tr.add("triage", "x")
    tr.add("enricher", "y", detail="users=1")
    data = json.loads(tr.to_json())
    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]["stage"] == "triage"
    assert data[1]["detail"] == "users=1"
    assert "ts" in data[0]


def test_events_from_json_parses_valid() -> None:
    tr = PipelineTrace("alert-3")
    tr.add("triage", "x")
    events = PipelineTrace.events_from_json(tr.to_json())
    assert len(events) == 1
    assert events[0]["stage"] == "triage"


def test_events_from_json_none_returns_empty() -> None:
    assert PipelineTrace.events_from_json(None) == []
    assert PipelineTrace.events_from_json("") == []


def test_events_from_json_invalid_returns_empty() -> None:
    assert PipelineTrace.events_from_json("{not json") == []
    # JSON válido pero no lista
    assert PipelineTrace.events_from_json('{"a": 1}') == []
    # lista con elementos no-dict se filtran
    assert PipelineTrace.events_from_json('[1, 2, {"stage": "x"}]') == [{"stage": "x"}]


def test_summary_none_becomes_empty_string() -> None:
    tr = PipelineTrace("alert-4")
    tr.add("triage", None)  # type: ignore[arg-type]
    assert tr.events[0].summary == ""


def test_timeline_event_is_dataclass() -> None:
    e = TimelineEvent(stage="triage", ts="2026-06-06T00:00:00+00:00", summary="s")
    assert e.detail is None
