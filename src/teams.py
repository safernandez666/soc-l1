"""Canal de notificación Microsoft Teams (Adaptive Cards vía Power Automate).

Reemplazo soportado de los Incoming Webhooks / O365 Connectors (deprecados por
Microsoft): un **Workflow de Power Automate** con el trigger "When a Teams webhook
request is received" expone una URL a la que POSTeamos una Adaptive Card.

Dos tarjetas:
  - send_teams_approval_request() → al ingreso, con botones Action.OpenUrl a
    /review y /approve (reusa el flujo de capability-URLs, igual que el email).
  - send_teams_closure()          → post-decisión, informativa (sin botones).

Todo es fire-and-forget: cualquier fallo se loguea y NO propaga (una notificación
caída nunca debe romper el pipeline ni un cierre ya consumado).

⚠️ SEAM: la forma EXACTA del cuerpo HTTP que espera el flow de Power Automate de
Matías vive SOLO en _wrap(). Si su flow parsea la card completa, el default de acá
sirve; si parsea campos sueltos, se ajusta ahí y nada más.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from src.agents.narrator import NarratorPlan
from src.config import Settings
from src.models import NormalizedAlert

logger = logging.getLogger("soc-l1")

# Adaptive Card schema version (soportada por Teams).
_ADAPTIVE_SCHEMA = "http://adaptivecards.io/schemas/adaptive-card.json"
_ADAPTIVE_VERSION = "1.4"

# risk_level del Narrator → color de Adaptive Card ("attention"=rojo, "warning"=amarillo,
# "good"=verde, "accent"=azul). Se usa en el título y el badge de riesgo.
_RISK_COLOR = {
    "critical": "attention",
    "high": "attention",
    "medium": "warning",
    "low": "good",
}

# decisión de cierre → (emoji, color) del encabezado.
_DECISION_STYLE = {
    "approved": ("✅", "good"),
    "rejected": ("🚫", "attention"),
}


def is_configured(settings: Settings) -> bool:
    """True si hay una URL de Teams configurada (canal habilitado)."""
    return bool(settings.teams_webhook_url)


# ---------------------------------------------------------------------------
# SEAM — envelope HTTP. Ajustar acá para calzar con el flow de Power Automate.
# ---------------------------------------------------------------------------
def _wrap(card: dict[str, Any]) -> dict[str, Any]:
    """Envuelve el `content` de una Adaptive Card en el body que se POSTea.

    Forma estándar para un flow "Post adaptive card in a channel" que reenvía la
    attachment tal cual. Si el flow de Matías espera otra cosa (p.ej. campos planos
    a nivel raíz), este es el ÚNICO lugar a tocar.
    """
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": card,
            }
        ],
    }


def _card(body: list[dict[str, Any]], actions: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Arma el `content` de una Adaptive Card con body (y opcionalmente actions)."""
    card: dict[str, Any] = {
        "$schema": _ADAPTIVE_SCHEMA,
        "type": "AdaptiveCard",
        "version": _ADAPTIVE_VERSION,
        "body": body,
    }
    if actions:
        card["actions"] = actions
    return card


def _facts(pairs: list[tuple[str, str | None]]) -> dict[str, Any]:
    """FactSet a partir de pares (título, valor); descarta valores vacíos."""
    return {
        "type": "FactSet",
        "facts": [
            {"title": t, "value": str(v)} for t, v in pairs if v not in (None, "")
        ],
    }


def _title_block(text: str, color: str) -> dict[str, Any]:
    return {
        "type": "TextBlock",
        "text": text,
        "weight": "Bolder",
        "size": "Large",
        "color": color,
        "wrap": True,
    }


def _text(text: str, *, wrap: bool = True, spacing: str = "Default",
          weight: str = "Default", is_subtle: bool = False) -> dict[str, Any]:
    return {
        "type": "TextBlock",
        "text": text,
        "wrap": wrap,
        "spacing": spacing,
        "weight": weight,
        "isSubtle": is_subtle,
    }


async def _post_card(settings: Settings, card: dict[str, Any], *, kind: str,
                     alert_id: str) -> None:
    """POSTea la card al webhook de Teams. Fire-and-forget (nunca propaga)."""
    url = settings.teams_webhook_url
    if not url:
        return
    body = _wrap(card)
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=5.0)) as client:
            resp = await client.post(url, json=body)
        if resp.status_code >= 300:
            logger.warning(
                "teams: POST %s devolvió %s | alert=%s body=%.200s",
                kind, resp.status_code, alert_id, resp.text,
            )
        else:
            logger.info("teams: %s enviado | alert=%s status=%s",
                        kind, alert_id, resp.status_code)
    except httpx.HTTPError as e:
        logger.warning("teams: POST %s falló | alert=%s err=%s", kind, alert_id, e)
    except Exception:
        logger.exception("teams: POST %s error inesperado | alert=%s", kind, alert_id)


def _risk_color(risk: str) -> str:
    return _RISK_COLOR.get((risk or "").lower(), "accent")


def _actions_summary(plan: NarratorPlan) -> str:
    """Una línea por acción propuesta, o '(sin acciones concretas)'."""
    if not plan.actions:
        return "_(sin acciones concretas — monitor/notify only)_"
    return "\n".join(f"- **{a.type}** → {a.target}" for a in plan.actions)


# ---------------------------------------------------------------------------
# Tarjeta 1 — pedido de aprobación (al ingreso)
# ---------------------------------------------------------------------------
async def send_teams_approval_request(
    settings: Settings,
    alert: NormalizedAlert,
    plan: NarratorPlan,
    token: str,
) -> None:
    """Notifica un caso pendiente de decisión, con botones a /review y /approve.

    Los botones son Action.OpenUrl → el analista clickea, abre el browser y decide,
    exactamente como con el email. Cero infra extra (Fase 1).
    """
    if not is_configured(settings):
        return

    base = settings.approval_base_url.rstrip("/")
    review_url = f"{base}/review/{token}"
    approve_url = f"{base}/approve/{token}"

    risk = (plan.risk_level or "").upper()
    color = _risk_color(plan.risk_level)
    host = alert.device.hostname or "unknown"

    body = [
        _title_block(f"🛡️ SOC-L1 · Caso pendiente · {risk}", color),
        _text(alert.title or "Alerta sin título", weight="Bolder"),
        _facts([
            ("Host", host),
            ("Riesgo", risk),
            ("Severidad Wazuh", (alert.severity_source or "").upper() or None),
            ("Regla Wazuh", f"{alert.wazuh_rule.id} (nivel {alert.wazuh_rule.level})"
             if alert.wazuh_rule else None),
            ("Fuente", alert.source),
            ("Acciones propuestas", str(len(plan.actions))),
        ]),
        _text(plan.executive_summary, spacing="Medium"),
        _text("**Acciones propuestas:**", spacing="Medium"),
        _text(_actions_summary(plan)),
    ]

    # Botones: siempre "Revisar" (abre /review con el detalle completo y permite
    # aprobar/rechazar/acusar recibo). "Aprobar" como atajo directo.
    actions = [
        {"type": "Action.OpenUrl", "title": "🔍 Revisar", "url": review_url},
    ]
    if plan.actions:  # atajo de aprobación solo si hay acciones concretas a ejecutar
        actions.append(
            {"type": "Action.OpenUrl", "title": "✅ Aprobar", "url": approve_url}
        )

    await _post_card(settings, _card(body, actions),
                     kind="approval_request", alert_id=alert.alert_id)


# ---------------------------------------------------------------------------
# Tarjeta 2 — cierre de caso (post-decisión, sin botones)
# ---------------------------------------------------------------------------
def _execution_summary(execution_results: list[dict] | None) -> str:
    """Resumen legible de la ejecución. None=rechazo, []=aprobado sin acciones."""
    if execution_results is None:
        return "_Plan rechazado — no se ejecutó ninguna acción._"
    if not execution_results:
        return "_Aprobado sin acciones concretas._"
    lines = []
    for r in execution_results:
        action = r.get("action") or r.get("type") or "acción"
        ok = r.get("ok", r.get("success"))
        status = "✅" if ok else "❌"
        target = r.get("target") or r.get("detail") or ""
        lines.append(f"- {status} **{action}** {target}".rstrip())
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tarjeta 3 — auto-bloqueo FortiGate (IP contenida, informativa, sin botones)
# ---------------------------------------------------------------------------
async def send_teams_block(
    settings: Settings,
    *,
    alert_id: str,
    ip: str | None,
    rule_id: str | int | None,
    host: str | None,
    ttl_hours: int | None,
    expires_at: str | None = None,
    invgate_request_id: int | None = None,
    invgate_closed: bool | None = None,
) -> None:
    """Notifica por Teams un auto-bloqueo de IP ya ejecutado en FortiGate.

    Espejo de mailer.send_fgt_block_email: el bloqueo IPS cortocircuita antes del
    Narrator (la IP ya está contenida), así que no pasa por los hooks de
    approval/closure. Esta card cubre ese path. Informativa, sin botones.
    """
    if not is_configured(settings):
        return

    ticket = f"#{invgate_request_id}" if invgate_request_id else None
    ticket_state = None
    if invgate_request_id:
        # InvGate no cierra por API: el ticket queda abierto como registro de auditoría.
        ticket_state = "cerrado" if invgate_closed else "abierto (registro — cierre manual)"

    body = [
        _title_block("🚫 SOC-L1 · IP bloqueada automáticamente", "attention"),
        _text(f"IP `{ip}` puesta en quarantine en FortiGate.", weight="Bolder"),
        _facts([
            ("IP bloqueada", ip),
            ("Regla FortiGate", str(rule_id) if rule_id is not None else None),
            ("Host", host),
            ("TTL", f"{ttl_hours}h" if ttl_hours else None),
            ("Vence", expires_at),
            ("Ticket InvGate", ticket),
            ("Estado ticket", ticket_state),
        ]),
        _text(
            "Contención automática por SOC-L1 (ataque IPS de baja severidad, ya bloqueado). "
            "No requiere acción humana — queda como registro de auditoría.",
            spacing="Medium", is_subtle=True,
        ),
    ]

    await _post_card(settings, _card(body), kind="fgt_block", alert_id=alert_id)


# ---------------------------------------------------------------------------
# Tarjeta 4 — observación FortiGate Fase 0 ("bloquearía X", sin ejecutar)
# ---------------------------------------------------------------------------
async def send_teams_observation(
    settings: Settings,
    *,
    alert_id: str,
    ip: str | None,
    rule_id: str | int | None,
    host: str | None,
    ttl_hours: int | None,
) -> None:
    """Notifica por Teams una observación Fase 0 (qué bloquearía, sin ejecutar).

    Espejo de mailer.send_fgt_observation_email. Solo se dispara si el autoblock
    está en Fase 0 (observe). Informativa, sin botones.
    """
    if not is_configured(settings):
        return

    body = [
        _title_block("👀 SOC-L1 · IP candidata a bloqueo (observación)", "warning"),
        _text(f"Se bloquearía la IP `{ip}` (Fase 0 — no ejecutado).", weight="Bolder"),
        _facts([
            ("IP", ip),
            ("Regla FortiGate", str(rule_id) if rule_id is not None else None),
            ("Host", host),
            ("TTL propuesto", f"{ttl_hours}h" if ttl_hours else None),
        ]),
        _text(
            "Observación: el bloqueo real lo sigue haciendo el integration de Wazuh. "
            "Sin acción de SOC-L1 hasta el cutover a Fase 1.",
            spacing="Medium", is_subtle=True,
        ),
    ]

    await _post_card(settings, _card(body), kind="fgt_observation", alert_id=alert_id)


# ---------------------------------------------------------------------------
# Tarjeta 5 — cambio de cuenta AD (informativa, espejo del email de Wazuh)
# ---------------------------------------------------------------------------
async def send_teams_account_change(
    settings: Settings,
    *,
    alert_id: str,
    severity: str | None,
    rule_id: str | None,
    rule_desc: str | None,
    event_id: str | None,
    target_user: str | None,
    subject_user: str | None,
    host: str | None,
) -> None:
    """Notifica por Teams un cambio de cuenta en Active Directory (alta/baja/grupo).

    Informativa, sin botones: el correo con el detalle lo sigue mandando el
    integration custom-email-unified de Wazuh (reglas 100080-100085). Esta card
    solo lo espeja en Teams — SOC-L1 no triagea ni pide aprobación para estos
    eventos, corta en el ingest y notifica.
    """
    if not is_configured(settings):
        return

    color = _RISK_COLOR.get((severity or "").lower(), "accent")
    body = [
        _title_block("👤 SOC-L1 · Cambio de cuenta en Active Directory", color),
        _text(rule_desc or "Evento de Active Directory", weight="Bolder"),
        _facts([
            ("Usuario", target_user),
            ("Realizado por", subject_user),
            ("Controlador de dominio", host),
            ("Event ID", event_id),
            ("Regla Wazuh", rule_id),
            ("Severidad", severity.capitalize() if severity else None),
        ]),
        _text(
            "Notificación informativa de identidad. El correo con el detalle completo "
            "lo sigue enviando Wazuh. Sin acción automática de SOC-L1.",
            spacing="Medium", is_subtle=True,
        ),
    ]

    await _post_card(settings, _card(body), kind="ad_account_change", alert_id=alert_id)


async def send_teams_closure(
    settings: Settings,
    alert: NormalizedAlert,
    plan: NarratorPlan,
    *,
    decision: str,
    timeline_events: list[dict],
    execution_results: list[dict] | None,
    decided_by_ip: str | None = None,
    decided_at: str | None = None,
    executed_at: str | None = None,
    invgate_request_id: int | None = None,
) -> None:
    """Notifica el cierre del caso (aprobado/rechazado). Informativa, sin botones."""
    if not is_configured(settings):
        return

    emoji, color = _DECISION_STYLE.get(decision, ("ℹ️", "accent"))
    decision_label = {"approved": "Aprobado", "rejected": "Rechazado"}.get(
        decision, decision
    )
    host = alert.device.hostname or "unknown"
    risk = (plan.risk_level or "").upper()

    body = [
        _title_block(f"{emoji} SOC-L1 · Caso {decision_label} · {risk}", color),
        _text(alert.title or "Alerta sin título", weight="Bolder"),
        _facts([
            ("Host", host),
            ("Riesgo", risk),
            ("Decisión", decision_label),
            ("Decidido", decided_at),
            ("Ejecutado", executed_at),
            ("Origen decisión", decided_by_ip),
            ("Ticket InvGate", f"#{invgate_request_id}" if invgate_request_id else None),
        ]),
        _text("**Ejecución:**", spacing="Medium"),
        _text(_execution_summary(execution_results)),
    ]

    await _post_card(settings, _card(body),
                     kind="closure", alert_id=alert.alert_id)
