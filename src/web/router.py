"""Router del panel /ui. SPA React (Vite) + API JSON, solo-lectura sobre state.db,
detrás de login por cookie.

Rutas reales (tienen prioridad sobre el catch-all del SPA):
  GET/POST /ui/login   GET /ui/logout       login por password compartido
  GET  /ui/api/session /metrics /kpis /queue /case/{rowid}   datos JSON
  GET  /ui/static/robot.svg  /static/app.css  estáticos heredados

Todo el resto de /ui lo sirve el SPA (build en frontend/dist): /ui carga el shell
y react-router resuelve /ui/queue, /ui/case/{id}, /ui/kpis client-side.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi import status as http_status
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)

from src.config import Settings, get_settings
from src.web import auth, config_io, queries, render

logger = logging.getLogger("soc-l1")

router = APIRouter(prefix="/ui", tags=["dashboard"])


SettingsDep = Annotated[Settings, Depends(get_settings)]


def _authed(request: Request, settings: Settings) -> bool:
    return auth.session_valid(settings, request.cookies.get(auth.COOKIE_NAME))


# ===== Estáticos =====


@router.get("/static/app.css")
async def app_css() -> Response:
    return Response(content=render.CSS, media_type="text/css")


_STATIC_DIR = Path(__file__).parent / "static"
_FRONTEND_DIST = (Path(__file__).parent / "frontend" / "dist").resolve()


@router.get("/static/robot.svg")
async def robot_svg() -> Response:
    try:
        svg = (_STATIC_DIR / "robot.svg").read_text(encoding="utf-8")
    except OSError:
        return Response(status_code=http_status.HTTP_404_NOT_FOUND)
    return Response(content=svg, media_type="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=86400"})


@router.get("/static/zebra-logo.svg")
async def zebra_logo_svg() -> Response:
    try:
        svg = (_STATIC_DIR / "zebra-logo.svg").read_text(encoding="utf-8")
    except OSError:
        return Response(status_code=http_status.HTTP_404_NOT_FOUND)
    return Response(content=svg, media_type="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=86400"})


@router.get("/static/favicon.svg")
async def favicon_svg() -> Response:
    try:
        svg = (_STATIC_DIR / "favicon.svg").read_text(encoding="utf-8")
    except OSError:
        return Response(status_code=http_status.HTTP_404_NOT_FOUND)
    return Response(content=svg, media_type="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=86400"})


# ===== Auth =====


@router.get("/login")
async def login_form(request: Request, settings: SettingsDep) -> HTMLResponse:
    if _authed(request, settings):
        return RedirectResponse(url="/ui", status_code=http_status.HTTP_303_SEE_OTHER)
    return HTMLResponse(render.login_page(settings))


@router.post("/login")
async def login_submit(
    request: Request, settings: SettingsDep, password: Annotated[str, Form()] = ""
) -> Response:
    ip = request.client.host if request.client else "unknown"
    if auth.login_rate_limited(ip):
        logger.warning("dashboard login rate-limited | ip=%s", ip)
        return HTMLResponse(
            render.login_page(settings, "Demasiados intentos. Esperá unos minutos."),
            status_code=http_status.HTTP_429_TOO_MANY_REQUESTS,
        )
    if not auth.password_ok(settings, password):
        auth.record_login_failure(ip)
        return HTMLResponse(
            render.login_page(settings, "Contraseña incorrecta."),
            status_code=http_status.HTTP_401_UNAUTHORIZED,
        )
    auth.clear_login_attempts(ip)
    resp = RedirectResponse(url="/ui", status_code=http_status.HTTP_303_SEE_OTHER)
    resp.set_cookie(
        auth.COOKIE_NAME,
        auth.issue_session(settings),
        max_age=auth.cookie_max_age(settings),
        httponly=True,
        samesite="lax",
        # Secure según el esquema del request del dashboard (http interno), NO según
        # approval_base_url: esa es la URL pública de los emails y es https, pero el
        # panel /ui se sirve por http en la LAN. Atarlas hacía que la cookie Secure
        # no viajara sobre http y rompía el login interno tras el cutover a FQDN.
        secure=request.url.scheme == "https",
    )
    return resp


@router.get("/logout")
async def logout() -> Response:
    resp = RedirectResponse(url="/ui/login", status_code=http_status.HTTP_303_SEE_OTHER)
    resp.delete_cookie(auth.COOKIE_NAME)
    return resp


# ===== API JSON (consumida por el SPA React) =====
#
# Mismo login por cookie que el panel server-rendered, pero ante sesión inválida
# devuelve 401 JSON (no redirect) para que el frontend lo maneje como fetch.

_QUEUE_STATUSES = {"pending", "approved", "executed", "rejected", "expired"}
_QUEUE_PER_PAGE = 50


def _api_unauthorized() -> JSONResponse:
    return JSONResponse(
        {"error": "unauthorized"}, status_code=http_status.HTTP_401_UNAUTHORIZED
    )


@router.get("/api/session")
async def api_session(request: Request, settings: SettingsDep) -> Response:
    """Chequeo liviano de sesión para el bootstrap del SPA.

    Devuelve además el modo de ejecución efectivo, para que la UI pueda decir en
    todo momento si las contenciones se aplican o se simulan. Sin esto el panel
    mostraba "ok" en acciones que nunca tocaron FortiGate, AD ni Defender.
    """
    authed = _authed(request, settings)
    if not authed:
        return JSONResponse({"authed": False})
    families = settings.dry_run_state()
    return JSONResponse({
        "authed": True,
        "dry_run_master": settings.dry_run_mode,
        "dry_run_families": families,
        # "dry_run" = se simula todo; "live" = se ejecuta todo; "mixed" = por familia.
        "mode": (
            "dry_run" if all(families.values())
            else "live" if not any(families.values())
            else "mixed"
        ),
    })


@router.get("/api/metrics")
async def api_metrics(request: Request, settings: SettingsDep) -> Response:
    if not _authed(request, settings):
        return _api_unauthorized()
    metrics = await queries.dashboard_metrics(
        settings.state_db_path, settings.metrics_baseline_at
    )
    return JSONResponse(metrics)


@router.get("/api/fgt-observations")
async def api_fgt_observations(request: Request, settings: SettingsDep) -> Response:
    """Observación Fase 0 del auto-block FortiGate: resumen + últimas decisiones."""
    if not _authed(request, settings):
        return _api_unauthorized()
    from src import fortigate_autoblock

    path = fortigate_autoblock._observation_path(settings)
    return JSONResponse({
        "summary": fortigate_autoblock.summarize(path),
        "tickets": fortigate_autoblock.summarize_tickets(
            fortigate_autoblock._ticket_path(settings)
        ),
        "recent": fortigate_autoblock.load_recent(path, limit=50),
        "enabled": settings.fortigate_autoblock_enabled,
        "rules_count": len(settings.fortigate_auto_block_rules_set()),
        "ttl_hours": settings.fortigate_block_ttl_hours,
    })


_REPORT_RISKS = {"critical", "high", "medium", "low", "unknown"}


@router.get("/api/reports")
async def api_reports(
    request: Request,
    settings: SettingsDep,
    date_from: str | None = None,
    date_to: str | None = None,
    status: str | None = None,
    risk: str | None = None,
) -> Response:
    """Casos en un rango de fechas (hub de reportería). Lista completa filtrable."""
    if not _authed(request, settings):
        return _api_unauthorized()
    status = status if status in _QUEUE_STATUSES else None
    risk = risk if risk in _REPORT_RISKS else None
    cases = await queries.cases_in_range(
        settings.state_db_path, date_from, date_to, status, risk
    )
    return JSONResponse({
        "cases": cases,
        "total": len(cases),
        "filters": {"date_from": date_from, "date_to": date_to, "status": status, "risk": risk},
    })


@router.get("/api/reports.csv")
async def api_reports_csv(
    request: Request,
    settings: SettingsDep,
    date_from: str | None = None,
    date_to: str | None = None,
    status: str | None = None,
    risk: str | None = None,
) -> Response:
    """Export CSV de los casos del rango (mismos filtros que /api/reports)."""
    if not _authed(request, settings):
        return _api_unauthorized()
    import csv
    import io

    status = status if status in _QUEUE_STATUSES else None
    risk = risk if risk in _REPORT_RISKS else None
    cases = await queries.cases_in_range(
        settings.state_db_path, date_from, date_to, status, risk
    )
    cols = [
        "rowid", "alert_id", "created_at", "status", "risk_level", "host",
        "title", "n_actions", "decided_at", "decided_by_ip", "executed_at",
        "invgate_request_id",
    ]
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for c in cases:
        w.writerow(c)
    fname = f"soc-l1-casos-{date_from or 'inicio'}_{date_to or 'hoy'}.csv"
    return Response(
        content=buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@router.get("/api/kpis")
async def api_kpis(request: Request, settings: SettingsDep) -> Response:
    if not _authed(request, settings):
        return _api_unauthorized()
    metrics = await queries.kpis_metrics(settings)
    # El SPA usa dry_run para el label "simulada (dry-run)" y el banner, igual que
    # la vista server-rendered (render.kpis_page lee settings.dry_run_mode).
    metrics["dry_run"] = settings.dry_run_mode
    return JSONResponse(metrics)


@router.get("/api/queue")
async def api_queue(
    request: Request, settings: SettingsDep, status: str | None = None, page: int = 1
) -> Response:
    if not _authed(request, settings):
        return _api_unauthorized()
    page = max(1, page)
    status = status if status in _QUEUE_STATUSES else None
    cases, total = await queries.list_cases(
        settings.state_db_path,
        status=status,
        limit=_QUEUE_PER_PAGE,
        offset=(page - 1) * _QUEUE_PER_PAGE,
        baseline_iso=settings.metrics_baseline_at,
    )
    return JSONResponse(
        {
            "cases": cases,
            "total": total,
            "page": page,
            "per_page": _QUEUE_PER_PAGE,
            "status": status,
        }
    )


@router.get("/api/invgate")
async def api_invgate(request: Request, settings: SettingsDep) -> Response:
    """Reconciliación InvGate: InvGate como fuente de verdad. Resumen + casos con
    ticket abierto (snapshot escrito por el sweeper periódico)."""
    if not _authed(request, settings):
        return _api_unauthorized()
    data = await queries.invgate_reconcile_view(settings.state_db_path)
    return JSONResponse(data)


@router.get("/api/case/{rowid}")
async def api_case(request: Request, settings: SettingsDep, rowid: int) -> Response:
    if not _authed(request, settings):
        return _api_unauthorized()
    case = await queries.get_case(settings.state_db_path, rowid)
    if case is None:
        return JSONResponse(
            {"error": "not_found"}, status_code=http_status.HTTP_404_NOT_FOUND
        )
    return JSONResponse(case)


_DECISIONS = {"approved", "rejected"}

# state de DecisionOutcome → (HTTP, mensaje para el analista)
_DECIDE_HTTP = {
    "not_found": (http_status.HTTP_404_NOT_FOUND, "El caso ya no tiene un approval pendiente."),
    "expired": (http_status.HTTP_409_CONFLICT, "El approval venció y no se puede decidir."),
    "already": (http_status.HTTP_409_CONFLICT, "Este caso ya fue decidido."),
    "plan_error": (
        http_status.HTTP_500_INTERNAL_SERVER_ERROR,
        "Quedó registrada la decisión, pero el plan guardado no se pudo leer: no se ejecutó nada.",
    ),
}


@router.post("/api/case/{rowid}/decide")
async def api_case_decide(request: Request, settings: SettingsDep, rowid: int) -> Response:
    """Aprobar o rechazar un caso desde el panel.

    Hasta acá el panel era solo-lectura y la única forma de decidir era el link del
    correo. Esto no abre un segundo camino: reusa la misma ruta de decisión que
    /approve, /reject y /decide (_decide_and_apply), así que valen los mismos
    guardrails, el mismo TTL, el mismo single-use y los mismos efectos — InvGate,
    mail de cierre y executor. El token no viaja nunca al browser: se resuelve
    server-side a partir del rowid, para no convertir el panel en un repartidor de
    capabilities de aprobación.
    """
    if not _authed(request, settings):
        return _api_unauthorized()

    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}

    decision = str(body.get("decision") or "")
    if decision not in _DECISIONS:
        return JSONResponse(
            {"error": "bad_decision"}, status_code=http_status.HTTP_400_BAD_REQUEST
        )

    selected = body.get("selected_action_indices")
    if selected is not None and not (
        isinstance(selected, list)
        and all(isinstance(i, int) and not isinstance(i, bool) and i >= 0 for i in selected)
    ):
        return JSONResponse(
            {"error": "bad_selection"}, status_code=http_status.HTTP_400_BAD_REQUEST
        )

    found = await queries.get_case_token(settings.state_db_path, rowid)
    if found is None:
        return JSONResponse(
            {"error": "not_found", "message": "No existe ese caso."},
            status_code=http_status.HTTP_404_NOT_FOUND,
        )

    # Import tardío: src.main monta este router, importarlo arriba sería circular.
    from src.main import _decide_and_apply

    ip = request.client.host if request.client else None
    logger.info(
        "DASHBOARD_DECISION | rowid=%s alert=%s decision=%s ip=%s selected=%s",
        rowid, found.get("alert_id"), decision, ip, selected,
    )

    outcome = await _decide_and_apply(
        request, settings, found["token"], decision, selected
    )

    if outcome.state != "ok":
        code, message = _DECIDE_HTTP[outcome.state]
        return JSONResponse(
            {
                "error": outcome.state,
                "message": message,
                "prev_status": outcome.prev_status,
            },
            status_code=code,
        )

    n = len(outcome.actions_to_run)
    if decision == "rejected":
        message = "Caso rechazado. No se ejecuta ninguna acción."
    elif n == 0:
        message = "Aprobado sin acciones seleccionadas: no se ejecutó nada."
    else:
        simulated = all(settings.dry_run_for(a.type) for a in outcome.actions_to_run)
        verbo = "simulando" if simulated else "ejecutando"
        message = f"Aprobado. {verbo.capitalize()} {n} acción{'' if n == 1 else 'es'}."

    return JSONResponse({
        "ok": True,
        "state": "ok",
        "decision": decision,
        "alert_id": outcome.alert_id,
        "n_actions": n,
        "skipped": outcome.skipped,
        "message": message,
    })


@router.get("/api/config")
async def api_config(request: Request, settings: SettingsDep) -> Response:
    """Settings operativos editables, con secretos enmascarados (write-only)."""
    if not _authed(request, settings):
        return _api_unauthorized()
    return JSONResponse(config_io.public_config())


@router.post("/api/config")
async def api_config_update(request: Request, settings: SettingsDep) -> Response:
    if not _authed(request, settings):
        return _api_unauthorized()
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"error": "invalid JSON"}, status_code=http_status.HTTP_400_BAD_REQUEST
        )
    try:
        result = config_io.apply_updates(body)
    except config_io.ConfigError as e:
        return JSONResponse(
            {"error": str(e)}, status_code=http_status.HTTP_400_BAD_REQUEST
        )
    ip = request.client.host if request.client else "unknown"
    logger.info("dashboard config updated | ip=%s fields=%s", ip, result["applied"])
    return JSONResponse({"ok": True, **result})


# ===== SPA React (build de Vite, única UI, servido en /ui) =====
#
# El SPA ocupa todo el namespace /ui salvo las rutas reales declaradas arriba
# (/ui/login, /ui/logout, /ui/static/*, /ui/api/*), que tienen prioridad por estar
# registradas primero. El shell (HTML/JS/CSS) es público; los datos viven detrás
# del login en /ui/api/*. Si la sesión no es válida, el propio SPA redirige a
# /ui/login. Las rutas client-side (/ui/queue, /ui/case/{id}, /ui/kpis) caen al
# fallback de index.html y las resuelve react-router.


def _spa_response(path: str = "") -> Response:
    if not _FRONTEND_DIST.is_dir():
        return HTMLResponse(
            "<h1>UI no compilada</h1>"
            "<p>Corré <code>pnpm build</code> en <code>src/web/frontend/</code>.</p>",
            status_code=http_status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    # Servir el archivo real si existe y queda dentro de dist (anti path-traversal);
    # si no, devolver index.html para que react-router resuelva client-side.
    if path:
        candidate = (_FRONTEND_DIST / path).resolve()
        if candidate.is_file() and _FRONTEND_DIST in candidate.parents:
            return FileResponse(candidate)
    return FileResponse(_FRONTEND_DIST / "index.html")


@router.get("")
async def spa_root() -> Response:
    return _spa_response()


@router.get("/{path:path}")
async def spa_catchall(path: str) -> Response:
    return _spa_response(path)
