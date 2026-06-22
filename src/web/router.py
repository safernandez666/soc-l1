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
    """Chequeo liviano de sesión para el bootstrap del SPA."""
    return JSONResponse({"authed": _authed(request, settings)})


@router.get("/api/metrics")
async def api_metrics(request: Request, settings: SettingsDep) -> Response:
    if not _authed(request, settings):
        return _api_unauthorized()
    metrics = await queries.dashboard_metrics(
        settings.state_db_path, settings.metrics_baseline_at
    )
    return JSONResponse(metrics)


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
