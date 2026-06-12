"""Router del panel /ui. Solo-lectura sobre state.db, detrás de login por cookie.

Rutas:
  GET  /ui/login   /ui/logout   POST /ui/login
  GET  /ui                 panel (KPIs, charts, modo)
  GET  /ui/queue           cola de casos (filtro ?status= , paginado ?page=)
  GET  /ui/case/{rowid}    detalle de un caso
  GET  /ui/static/app.css  hoja de estilos (ZebraSecurity)
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi import status as http_status
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from src.config import Settings
from src.web import auth, queries, render

router = APIRouter(prefix="/ui", tags=["dashboard"])


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Singleton local (mismo patrón que main.get_settings; evita import circular)."""
    return Settings()


SettingsDep = Annotated[Settings, Depends(get_settings)]


def _authed(request: Request, settings: Settings) -> bool:
    return auth.session_valid(settings, request.cookies.get(auth.COOKIE_NAME))


def _redirect_login() -> RedirectResponse:
    return RedirectResponse(url="/ui/login", status_code=http_status.HTTP_303_SEE_OTHER)


# ===== Estáticos =====


@router.get("/static/app.css")
async def app_css() -> Response:
    return Response(content=render.CSS, media_type="text/css")


_STATIC_DIR = Path(__file__).parent / "static"


@router.get("/static/robot.svg")
async def robot_svg() -> Response:
    try:
        svg = (_STATIC_DIR / "robot.svg").read_text(encoding="utf-8")
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
    settings: SettingsDep, password: Annotated[str, Form()] = ""
) -> Response:
    if not auth.password_ok(settings, password):
        return HTMLResponse(
            render.login_page(settings, "Contraseña incorrecta."),
            status_code=http_status.HTTP_401_UNAUTHORIZED,
        )
    resp = RedirectResponse(url="/ui", status_code=http_status.HTTP_303_SEE_OTHER)
    resp.set_cookie(
        auth.COOKIE_NAME,
        auth.issue_session(settings),
        max_age=auth.cookie_max_age(settings),
        httponly=True,
        samesite="lax",
        secure=settings.approval_base_url.startswith("https"),
    )
    return resp


@router.get("/logout")
async def logout() -> Response:
    resp = RedirectResponse(url="/ui/login", status_code=http_status.HTTP_303_SEE_OTHER)
    resp.delete_cookie(auth.COOKIE_NAME)
    return resp


# ===== Panel =====


@router.get("")
async def panel(request: Request, settings: SettingsDep) -> Response:
    if not _authed(request, settings):
        return _redirect_login()
    metrics = await queries.dashboard_metrics(settings.state_db_path)
    return HTMLResponse(render.panel_page(settings, metrics))


@router.get("/queue")
async def queue(
    request: Request, settings: SettingsDep, status: str | None = None, page: int = 1
) -> Response:
    if not _authed(request, settings):
        return _redirect_login()
    page = max(1, page)
    per_page = 50
    valid = {"pending", "approved", "executed", "rejected", "expired"}
    status = status if status in valid else None
    cases, total = await queries.list_cases(
        settings.state_db_path, status=status, limit=per_page, offset=(page - 1) * per_page
    )
    return HTMLResponse(render.queue_page(settings, cases, status, page, total))


@router.get("/case/{rowid}")
async def case_detail(request: Request, settings: SettingsDep, rowid: int) -> Response:
    if not _authed(request, settings):
        return _redirect_login()
    case = await queries.get_case(settings.state_db_path, rowid)
    if case is None:
        return HTMLResponse(
            render._shell("/ui/queue", settings, '<div class="empty">Case not found.</div>', "404"),
            status_code=http_status.HTTP_404_NOT_FOUND,
        )
    return HTMLResponse(render.case_page(settings, case))
