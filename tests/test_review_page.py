"""Tests del render de /review: el botón depende del tipo de plan.

Un plan 100% notify_only no tiene nada que ejecutar → botón único "Acuso recibo"
(no aprobar/rechazar). Un plan con acción destructiva mantiene checkboxes + aprobar/
rechazar. Plan vacío → solo cerrar.
"""
from __future__ import annotations

from src.agents.narrator import NarratorPlan, ProposedAction
from src.main import _render_review_page


def _render(actions: list[ProposedAction]) -> str:
    plan = NarratorPlan(
        executive_summary="test", rationale="r", risk_level="medium", actions=actions
    )
    return _render_review_page("TOK", plan, "AID", "#b45309", "medium").body.decode()


def test_notify_only_plan_muestra_boton_acuso_recibo() -> None:
    html = _render(
        [ProposedAction(type="notify_only", target="acceso VPN off-hours", justification="solo registro")]
    )
    assert "Acuso recibo y cerrar" in html
    assert 'value="approve"' in html           # internamente se procesa como approve
    assert 'type="hidden"' in html and 'name="action_idx" value="0"' in html
    # NO debe ofrecer aprobar selección / rechazar todo (no hay nada que decidir)
    assert "Aprobar selección" not in html
    assert "Rechazar todo" not in html
    assert 'type="checkbox"' not in html


def test_plan_con_accion_destructiva_mantiene_aprobar_rechazar() -> None:
    html = _render(
        [
            ProposedAction(type="force_password_change", target="mbaez", justification="x"),
            ProposedAction(type="notify_only", target="y", justification="z"),
        ]
    )
    assert "Aprobar selección" in html
    assert "Rechazar todo" in html
    assert 'type="checkbox"' in html
    assert "Acuso recibo" not in html


def test_plan_vacio_solo_cerrar() -> None:
    html = _render([])
    assert "Cerrar (rechazar)" in html
    assert "Acuso recibo" not in html
    assert "Aprobar selección" not in html
