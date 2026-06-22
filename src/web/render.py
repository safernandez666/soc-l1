"""Render del panel /ui — HTML por funciones (sin Jinja, sin deps).

Diseño SaaS moderno: sidebar fija, tarjetas con aire, tablas limpias y
paleta oscura con acento índigo. Todo dato dinámico sigue pasando por h().
"""
from __future__ import annotations

import html
from typing import Any

from src.config import Settings
from src.web.queries import humanize_age

# ===== Tokens de severidad/estado → token semántico =====
_RISK_TOKEN = {
    "low": "ok",
    "medium": "warn",
    "high": "elevated",
    "critical": "danger",
    "informational": "muted",
    "unknown": "muted",
}
_STATUS_TOKEN = {
    "pending": "warn",
    "approved": "primary",
    "executed": "ok",
    "rejected": "danger",
    "expired": "muted",
}
_STATUS_LABEL = {
    "pending": "Pending",
    "approved": "Approved",
    "executed": "Executed",
    "rejected": "Rejected",
    "expired": "Expired",
}
_ACTION_LABEL = {
    "disable_user": "Disable User",
    "force_password_change": "Force Password Reset",
    "block_ip": "Block IP",
    "scan_host": "Scan Host",
    "isolate_host": "Isolate Host",
    "notify_only": "Notify Only",
    "escalate_l2": "Escalate (L2)",
}


def action_label(action_type: str | None) -> str:
    """Etiqueta legible para un action_type. Fallback: snake_case → Title Case."""
    t = (action_type or "").strip()
    if not t:
        return "—"
    return _ACTION_LABEL.get(t, t.replace("_", " ").title())


def h(s: Any) -> str:
    return html.escape(str(s if s is not None else ""))


# ===== Íconos stroke (Lucide, currentColor) =====
_ICON_PATHS = {
    "dashboard": '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/>',
    "list": '<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><circle cx="3.5" cy="6" r="1"/><circle cx="3.5" cy="12" r="1"/><circle cx="3.5" cy="18" r="1"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><polyline points="12 7 12 12 15 14"/>',
    "layers": '<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>',
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>',
    "timer": '<circle cx="12" cy="13" r="8"/><path d="M12 9v4l2 2"/><path d="M9 2h6"/>',
    "zap": '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
    "check": '<path d="M20 6 9 17l-5-5"/>',
    "alert": '<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    "activity": '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
    "bar": '<line x1="12" y1="20" x2="12" y2="10"/><line x1="18" y1="20" x2="18" y2="4"/><line x1="6" y1="20" x2="6" y2="16"/>',
    "trend": '<polyline points="22 7 13.5 15.5 8.5 10.5 2 17"/><polyline points="16 7 22 7 22 13"/>',
    "server": '<rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><line x1="6" y1="7" x2="6.01" y2="7"/><line x1="6" y1="17" x2="6.01" y2="17"/>',
    "users": '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
    "git": '<line x1="6" y1="3" x2="6" y2="15"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M18 9a9 9 0 0 1-9 9"/>',
    "x": '<path d="M18 6 6 18"/><path d="M6 6l12 12"/>',
    "lock": '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    "gauge": '<path d="M12 14 16 9"/><path d="M3.5 18a9 9 0 1 1 17 0"/><circle cx="12" cy="14" r="1.5"/>',
    "home": '<path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>',
}


def icon(name: str, size: int = 16) -> str:
    p = _ICON_PATHS.get(name, "")
    return (
        f'<svg class="icon" width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
        f'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" '
        f'stroke-linejoin="round">{p}</svg>'
    )


# ===== CSS (tokens + componentes) =====

CSS = """
:root{
  --bg:#0b0d10;
  --bg-elevated:#101318;
  --surface:#15171c;
  --surface-hover:#1b1e25;
  --surface-pressed:#20242c;
  --border:#23262d;
  --border-strong:#2c3039;
  --text:#f0f1f5;
  --text-secondary:#b4b8c0;
  --text-muted:#8a8f98;
  --primary:#6366f1;
  --primary-light:#818cf8;
  --primary-dark:#4f46e5;
  --primary-soft:rgba(99,102,241,0.12);
  --ok:#22c55e;
  --ok-soft:rgba(34,197,94,0.12);
  --warn:#eab308;
  --warn-soft:rgba(234,179,8,0.12);
  --elevated:#f97316;
  --elevated-soft:rgba(249,115,22,0.12);
  --danger:#ef4444;
  --danger-soft:rgba(239,68,68,0.12);
  --info:#0ea5e9;
  --info-soft:rgba(14,165,233,0.12);
  --radius-sm:8px;
  --radius:12px;
  --radius-lg:16px;
  --shadow:0 1px 2px rgba(0,0,0,0.24), 0 0 0 1px rgba(255,255,255,0.03);
  --shadow-lg:0 10px 30px -10px rgba(0,0,0,0.5);
  --font-sans:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;
  --font-mono:ui-monospace,SFMono-Regular,Menlo,Monaco,monospace;
}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{
  background:var(--bg);
  color:var(--text);
  font-family:var(--font-sans);
  font-size:14px;
  line-height:1.5;
  -webkit-font-smoothing:antialiased;
}
a{color:inherit;text-decoration:none}
.icon{display:inline-block;vertical-align:middle;flex-shrink:0;color:currentColor}

/* layout */
.app{display:flex;min-height:100vh}
.sidebar{
  width:240px;
  background:var(--bg-elevated);
  border-right:1px solid var(--border);
  display:flex;
  flex-direction:column;
  position:sticky;
  top:0;
  height:100vh;
  flex-shrink:0;
}
.sidebar__brand{
  display:flex;
  align-items:center;
  gap:10px;
  padding:20px 20px 16px;
  font-weight:700;
  font-size:18px;
  letter-spacing:-0.02em;
  color:var(--text);
}
.sidebar__brand .logo{color:var(--primary)}
.sidebar__nav{display:flex;flex-direction:column;gap:2px;padding:0 12px}
.sidebar__nav a{
  display:flex;
  align-items:center;
  gap:10px;
  padding:10px 12px;
  border-radius:var(--radius-sm);
  color:var(--text-secondary);
  font-weight:500;
  font-size:14px;
  transition:.15s ease;
}
.sidebar__nav a:hover{background:var(--surface-hover);color:var(--text)}
.sidebar__nav a.active{background:var(--primary-soft);color:var(--primary-light)}
.sidebar__bottom{
  margin-top:auto;
  padding:16px;
  border-top:1px solid var(--border);
  color:var(--text-muted);
  font-size:12px;
}
.main{flex:1;display:flex;flex-direction:column;min-width:0}
.topbar{
  height:60px;
  border-bottom:1px solid var(--border);
  background:var(--bg);
  display:flex;
  align-items:center;
  justify-content:space-between;
  padding:0 28px;
  position:sticky;
  top:0;
  z-index:10;
}
.topbar__actions{display:flex;align-items:center;gap:14px}
.content{padding:28px;flex:1;overflow:auto}

/* typography */
.page-title{font-size:22px;font-weight:600;letter-spacing:-0.02em;margin:0}
.eyebrow{font-size:12px;font-weight:500;color:var(--text-muted);margin-bottom:4px}
.text-muted{color:var(--text-muted)}
.text-secondary{color:var(--text-secondary)}

/* cards */
.card{
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:var(--radius);
  box-shadow:var(--shadow);
  overflow:hidden;
}
.card__header{
  display:flex;
  align-items:center;
  justify-content:space-between;
  padding:16px 20px;
  border-bottom:1px solid var(--border);
  gap:16px;
}
.card__title{
  display:flex;
  align-items:center;
  gap:10px;
  font-size:15px;
  font-weight:600;
  color:var(--text);
  margin:0;
}
.card__body{padding:20px}
.card--flush .card__body{padding:0}

/* badges */
.badge{
  display:inline-flex;
  align-items:center;
  gap:6px;
  padding:4px 10px;
  border-radius:999px;
  font-size:11px;
  font-weight:600;
  text-transform:uppercase;
  letter-spacing:0.04em;
  border:1px solid transparent;
}
.badge--primary{background:var(--primary-soft);color:var(--primary-light);border-color:rgba(99,102,241,0.25)}
.badge--ok{background:var(--ok-soft);color:var(--ok);border-color:rgba(34,197,94,0.25)}
.badge--warn{background:var(--warn-soft);color:var(--warn);border-color:rgba(234,179,8,0.25)}
.badge--elevated{background:var(--elevated-soft);color:var(--elevated);border-color:rgba(249,115,22,0.25)}
.badge--danger{background:var(--danger-soft);color:var(--danger);border-color:rgba(239,68,68,0.25)}
.badge--muted{background:rgba(255,255,255,0.04);color:var(--text-muted);border-color:var(--border)}
.badge--info{background:var(--info-soft);color:var(--info);border-color:rgba(14,165,233,0.25)}

/* KPIs */
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px}
.kpi{padding:18px 20px}
.kpi__label{display:flex;align-items:center;gap:6px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);margin-bottom:8px}
.kpi__value{font-size:28px;font-weight:700;letter-spacing:-0.03em;color:var(--text);line-height:1.1}
.kpi__sub{font-size:12px;color:var(--text-muted);margin-top:6px}

/* tables */
.table-container{overflow-x:auto}
.table{width:100%;border-collapse:collapse;font-size:13px}
.table th{
  text-align:left;
  padding:12px 16px;
  font-size:11px;
  font-weight:600;
  text-transform:uppercase;
  letter-spacing:0.05em;
  color:var(--text-muted);
  border-bottom:1px solid var(--border);
  white-space:nowrap;
}
.table td{padding:14px 16px;color:var(--text-secondary);border-bottom:1px solid var(--border);vertical-align:top}
.table tbody tr:last-child td{border-bottom:none}
.table tbody tr:hover td{background:var(--surface-hover)}
.table td.strong{color:var(--text);font-weight:500}
.table .row-link{cursor:pointer}

/* chips / filters */
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:18px}
.chip{
  display:inline-flex;
  align-items:center;
  padding:7px 14px;
  border-radius:999px;
  font-size:12px;
  font-weight:500;
  color:var(--text-secondary);
  background:var(--surface);
  border:1px solid var(--border);
  transition:.15s ease;
}
.chip:hover{border-color:var(--border-strong);color:var(--text)}
.chip--active{background:var(--primary-soft);color:var(--primary-light);border-color:rgba(99,102,241,0.3)}

/* bars */
.bar-row{display:grid;grid-template-columns:130px 1fr 48px;align-items:center;gap:14px;margin:8px 0;font-size:13px}
.bar-label{color:var(--text-secondary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar-track{height:8px;background:var(--bg-elevated);border-radius:999px;overflow:hidden}
.bar-fill{height:100%;background:linear-gradient(90deg,var(--primary),var(--primary-light));border-radius:999px}
.bar-value{text-align:right;color:var(--text);font-weight:500;font-variant-numeric:tabular-nums}

/* sparkline */
.spark{display:flex;align-items:flex-end;gap:3px;height:90px}
.spark__col{flex:1;background:linear-gradient(180deg,var(--primary-light),var(--primary));border-radius:4px 4px 0 0;min-height:2px;opacity:0.85;transition:opacity .15s}
.spark__col:hover{opacity:1}
.spark__labels{display:flex;justify-content:space-between;font-size:12px;color:var(--text-muted);margin-top:8px}

/* timeline */
.timeline{list-style:none;margin:0;padding:0;position:relative}
.timeline::before{content:"";position:absolute;left:7px;top:4px;bottom:4px;width:1px;background:var(--border)}
.timeline__item{position:relative;padding:0 0 22px 24px}
.timeline__item:last-child{padding-bottom:0}
.timeline__dot{position:absolute;left:2px;top:3px;width:11px;height:11px;border-radius:50%;background:var(--primary);border:2px solid var(--surface)}
.timeline__stage{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;color:var(--primary-light)}
.timeline__time{font-size:12px;color:var(--text-muted);margin-top:2px}
.timeline__text{color:var(--text-secondary);margin-top:4px;font-size:13px}
.timeline__detail{color:var(--text-muted);font-size:12px;margin-top:4px}

/* key/value */
.kv{display:grid;grid-template-columns:140px 1fr;gap:10px 16px;font-size:13px}
.kv__key{color:var(--text-muted)}
.kv__value{color:var(--text);word-break:break-word}

/* pager */
.pager{display:flex;align-items:center;justify-content:space-between;margin-top:18px;gap:12px}
.pager__btn{
  padding:8px 14px;
  border-radius:var(--radius-sm);
  background:var(--surface);
  border:1px solid var(--border);
  color:var(--text-secondary);
  font-weight:500;
  font-size:13px;
  transition:.15s ease;
}
.pager__btn:hover{border-color:var(--border-strong);color:var(--text)}
.pager__btn[aria-disabled="true"]{opacity:0.4;cursor:not-allowed}
.pager__info{font-size:13px;color:var(--text-muted)}

/* banners */
.banner{display:flex;align-items:center;gap:10px;padding:12px 16px;border-radius:var(--radius-sm);font-size:13px;font-weight:500;margin-bottom:20px;border:1px solid transparent}
.banner--live{background:var(--ok-soft);color:var(--ok);border-color:rgba(34,197,94,0.25)}
.banner--dry{background:var(--warn-soft);color:var(--warn);border-color:rgba(234,179,8,0.25)}

/* buttons / forms */
.btn{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  gap:8px;
  padding:10px 18px;
  border-radius:var(--radius-sm);
  font-weight:600;
  font-size:14px;
  border:1px solid transparent;
  cursor:pointer;
  transition:.15s ease;
}
.btn--primary{background:var(--primary);color:#fff}
.btn--primary:hover{background:var(--primary-dark)}
.btn--secondary{background:var(--surface);border-color:var(--border);color:var(--text-secondary)}
.btn--secondary:hover{border-color:var(--border-strong);color:var(--text)}
.btn--block{width:100%}
.input{
  width:100%;
  background:var(--bg-elevated);
  border:1px solid var(--border);
  border-radius:var(--radius-sm);
  color:var(--text);
  padding:11px 14px;
  font-size:14px;
  outline:none;
  transition:.15s ease;
}
.input:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-soft)}
.form-group{margin-bottom:18px}
.form-label{display:block;font-size:12px;font-weight:600;color:var(--text-secondary);margin-bottom:6px}

/* login */
.login-page{
  min-height:100vh;
  display:flex;
  align-items:center;
  justify-content:center;
  padding:24px;
  background:radial-gradient(circle at 50% 0%,rgba(99,102,241,0.12),transparent 40%),var(--bg);
}
.login-card{
  width:100%;
  max-width:420px;
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:var(--radius-lg);
  box-shadow:var(--shadow-lg);
  padding:36px;
}
.login__brand{display:flex;align-items:center;gap:12px;margin-bottom:24px}
.login__brand .logo{color:var(--primary)}
.login__title{font-size:22px;font-weight:600;letter-spacing:-0.02em;margin:0}
.login__subtitle{color:var(--text-muted);font-size:14px;margin:6px 0 24px}
.alert{display:flex;align-items:center;gap:10px;padding:12px 14px;border-radius:var(--radius-sm);font-size:13px;margin-bottom:18px}
.alert--danger{background:var(--danger-soft);color:var(--danger);border:1px solid rgba(239,68,68,0.25)}
.alert--warning{background:var(--warn-soft);color:var(--warn);border:1px solid rgba(234,179,8,0.25)}

/* utilities */
.empty{text-align:center;padding:48px 20px;color:var(--text-muted);font-size:14px}
.section-title{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;gap:12px}
.section-title h2{font-size:16px;font-weight:600;margin:0;display:flex;align-items:center;gap:8px}
.grid{display:grid;gap:20px}
.grid--2{grid-template-columns:repeat(2,minmax(0,1fr))}
.grid--3{grid-template-columns:repeat(3,minmax(0,1fr))}
@media (max-width:1024px){.grid--2,.grid--3{grid-template-columns:1fr}}
@media (max-width:768px){
  .sidebar{display:none}
  .content{padding:16px}
  .topbar{padding:0 16px}
  .kpi-grid{grid-template-columns:1fr}
  .bar-row{grid-template-columns:1fr 64px}
  .bar-label{display:none}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
"""


# ===== Componentes =====


def _logo(size: int = 28) -> str:
    return (
        f'<svg class="logo" width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
        f'stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        f'<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'
        f'<path d="M9 12l2 2 4-4"/></svg>'
    )


def _badge(token: str, text: str) -> str:
    return f'<span class="badge badge--{token}">{h(text)}</span>'


def risk_pill(level: str | None) -> str:
    lvl = (level or "unknown").lower()
    token = _RISK_TOKEN.get(lvl, "muted")
    return _badge(token, lvl)


def status_badge(status: str | None) -> str:
    st = (status or "pending").lower()
    token = _STATUS_TOKEN.get(st, "muted")
    return _badge(token, _STATUS_LABEL.get(st, st))


def _kpi(label: str, value: Any, sub: str = "", ico: str | None = None) -> str:
    sub_html = f'<div class="kpi__sub">{h(sub)}</div>' if sub else ""
    ico_html = icon(ico, 16) if ico else ""
    return (
        f'<div class="card kpi"><div class="kpi__label">{ico_html}{h(label)}</div>'
        f'<div class="kpi__value">{h(value)}</div>{sub_html}</div>'
    )


def _card(title: str, body: str, ico: str | None = None, flush: bool = False) -> str:
    ico_html = icon(ico, 16) if ico else ""
    flush_class = " card--flush" if flush else ""
    return (
        f'<div class="card{flush_class}">'
        f'<div class="card__header"><h2 class="card__title">{ico_html}{h(title)}</h2></div>'
        f'<div class="card__body">{body}</div></div>'
    )


def _ministat(num: Any, label: str) -> str:
    return (
        f'<div><div class="kpi__value" style="font-size:22px">{h(num)}</div>'
        f'<div class="kpi__sub">{h(label)}</div></div>'
    )


def _bars(data: list[tuple[str, int]]) -> str:
    if not data:
        return '<div class="empty">No data.</div>'
    mx = max((v for _, v in data), default=0) or 1
    rows = []
    for label, val in data:
        pct = round(100 * val / mx)
        rows.append(
            f'<div class="bar-row">'
            f'<div class="bar-label" title="{h(label)}">{h(label)}</div>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{pct}%"></div></div>'
            f'<div class="bar-value">{h(val)}</div></div>'
        )
    return "".join(rows)


def _spark(per_day: list[tuple[str, int]]) -> str:
    if not per_day:
        return '<div class="empty">No data.</div>'
    mx = max((v for _, v in per_day), default=0) or 1
    cols = "".join(
        f'<div class="spark__col" style="height:{max(2, round(100 * v / mx))}%" '
        f'title="{h(d)}: {h(v)}"></div>'
        for d, v in per_day
    )
    return (
        f'<div class="spark">{cols}</div>'
        f'<div class="spark__labels">'
        f'<span>{h(per_day[0][0])}</span><span>{h(per_day[-1][0])}</span></div>'
    )


# ===== Páginas =====

_NAV = [
    ("/ui", "Overview", "dashboard"),
    ("/ui/kpis", "KPIs", "gauge"),
    ("/ui/queue", "Queue", "list"),
    ("/ui/queue?status=pending", "Pending", "clock"),
]


def _shell(active: str, settings: Settings, body: str, title: str = "SOC-L1") -> str:
    mode = "DRY-RUN" if settings.dry_run_mode else "LIVE"
    mode_token = "warn" if settings.dry_run_mode else "ok"
    nav = "".join(
        f'<a href="{href}" class="{"active" if href == active else ""}">'
        f'{icon(ico)}<span>{h(label)}</span></a>'
        for href, label, ico in _NAV
    )
    return f"""<!doctype html><html lang="en" class="dark"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{h(title)} · SOC-L1</title><link rel="stylesheet" href="/ui/static/app.css"></head>
<body><div class="app">
<aside class="sidebar">
  <div class="sidebar__brand">{_logo(24)}<span>SOC-L1</span></div>
  <nav class="sidebar__nav">{nav}</nav>
  <div class="sidebar__bottom">ZebraSecurity · SOC-L1</div>
</aside>
<div class="main">
  <header class="topbar">
    <div class="page-title">{h(title)}</div>
    <div class="topbar__actions">
      <span class="badge badge--{mode_token}">{mode}</span>
      <a class="btn btn--secondary" href="/ui/logout" style="padding:7px 12px;font-size:13px">Sign out</a>
    </div>
  </header>
  <main class="content">{body}</main>
</div>
</div>
<script>document.querySelectorAll('tr[data-href]').forEach(function(el){{el.addEventListener('click',function(){{location.href=el.dataset.href}})}});</script>
</body></html>"""


def login_page(settings: Settings, error: str = "") -> str:
    """Login server-rendered, autocontenido (no depende del app.css viejo).

    Mismo lenguaje visual que el SPA: negro/lima, glow radial, punto 'en vivo'.
    """
    err = (
        f'<div class="ls-alert ls-alert--danger">{h(error)}</div>' if error else ""
    )
    disabled = not (settings.dashboard_enabled and settings.dashboard_password)
    note = (
        '<div class="ls-alert ls-alert--warn">El acceso a la consola está deshabilitado.</div>'
        if disabled else ""
    )
    form = "" if disabled else """
  <form method="post" action="/ui/login" class="ls-form">
    <label class="ls-label" for="pw">Contraseña</label>
    <input class="ls-input" type="password" id="pw" name="password"
           autocomplete="current-password" required autofocus>
    <button class="ls-btn" type="submit">Ingresar a la consola</button>
  </form>"""
    return f"""<!doctype html><html lang="es" class="dark"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Acceso · SOC-L1</title>
<style>
  :root {{
    --bg:#0a0a0b; --card:#131316; --fg:#f4f5f0; --muted:#8b8f87;
    --primary:#a3e635; --border:#26262c;
  }}
  * {{ box-sizing:border-box; }}
  body {{
    margin:0; min-height:100svh; display:grid; place-items:center; padding:24px;
    font-family:'Geist Variable',system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
    color:var(--fg);
    background:
      radial-gradient(46rem 30rem at 15% -10%, color-mix(in oklab, var(--primary) 12%, transparent), transparent 60%),
      radial-gradient(38rem 26rem at 100% 0%, color-mix(in oklab, #eaff00 6%, transparent), transparent 55%),
      var(--bg);
  }}
  .ls-card {{
    position:relative; overflow:hidden; width:100%; max-width:380px;
    border:1px solid var(--border); border-radius:18px; padding:32px 30px;
    background:
      radial-gradient(28rem 14rem at 100% -40%, color-mix(in oklab, var(--primary) 16%, transparent), transparent 60%),
      linear-gradient(135deg, color-mix(in oklab, var(--primary) 6%, var(--card)) 0%, var(--card) 60%);
  }}
  .ls-card::before {{
    content:""; position:absolute; inset:0; pointer-events:none;
    background-image:
      linear-gradient(to right, color-mix(in oklab, var(--fg) 5%, transparent) 1px, transparent 1px),
      linear-gradient(to bottom, color-mix(in oklab, var(--fg) 5%, transparent) 1px, transparent 1px);
    background-size:32px 32px;
    -webkit-mask-image:radial-gradient(80% 70% at 50% 0%, #000 20%, transparent 78%);
    mask-image:radial-gradient(80% 70% at 50% 0%, #000 20%, transparent 78%);
  }}
  .ls-card > * {{ position:relative; }}
  .ls-eyebrow {{
    display:inline-flex; align-items:center; gap:8px; color:var(--primary);
    font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:.2em;
    margin-bottom:18px;
  }}
  .ls-dot {{
    width:7px; height:7px; border-radius:9999px; background:var(--primary);
    box-shadow:0 0 0 0 color-mix(in oklab, var(--primary) 60%, transparent);
    animation:ls-pulse 2s ease-out infinite;
  }}
  @keyframes ls-pulse {{
    0% {{ box-shadow:0 0 0 0 color-mix(in oklab, var(--primary) 60%, transparent); }}
    70% {{ box-shadow:0 0 0 7px transparent; }}
    100% {{ box-shadow:0 0 0 0 transparent; }}
  }}
  .ls-brand {{ display:flex; align-items:center; gap:12px; }}
  .ls-brand .logo {{ color:var(--primary); }}
  .ls-title {{ font-size:22px; font-weight:600; letter-spacing:-.02em; }}
  .ls-sub {{ color:var(--muted); font-size:13px; margin:14px 0 22px; }}
  .ls-form {{ display:flex; flex-direction:column; gap:8px; }}
  .ls-label {{ font-size:12px; color:var(--muted); }}
  .ls-input {{
    width:100%; padding:11px 13px; border-radius:10px; font-size:14px;
    color:var(--fg); background:#0a0a0b; border:1px solid var(--border); outline:none;
  }}
  .ls-input:focus {{ border-color:var(--primary); box-shadow:0 0 0 3px color-mix(in oklab, var(--primary) 25%, transparent); }}
  .ls-btn {{
    margin-top:8px; padding:11px 14px; border:none; border-radius:10px; cursor:pointer;
    font-size:14px; font-weight:600; color:#0a0a0b; background:var(--primary);
    transition:filter .15s;
  }}
  .ls-btn:hover {{ filter:brightness(1.08); }}
  .ls-alert {{ font-size:13px; padding:10px 12px; border-radius:10px; margin-bottom:14px; }}
  .ls-alert--danger {{ color:#fecaca; background:color-mix(in oklab,#ef4444 15%,transparent); border:1px solid color-mix(in oklab,#ef4444 40%,transparent); }}
  .ls-alert--warn {{ color:#fef08a; background:color-mix(in oklab,#eaff00 10%,transparent); border:1px solid color-mix(in oklab,#eaff00 30%,transparent); }}
</style></head>
<body><div class="ls-card">
  <div class="ls-eyebrow"><span class="ls-dot"></span>SOC-L1 · ZebraSecurity</div>
  <div class="ls-brand">{_logo(30)}<div class="ls-title">Centro de Operaciones</div></div>
  <p class="ls-sub">Ingresá para revisar casos, KPIs y la cola de aprobaciones.</p>
  {note}{err}{form}
</div></body></html>"""


def panel_page(settings: Settings, m: dict[str, Any]) -> str:
    banner = (
        '<div class="banner banner--dry">{ico}DRY-RUN mode — actions are simulated, not executed.</div>'
        .format(ico=icon("alert", 16))
        if settings.dry_run_mode
        else '<div class="banner banner--live">{ico}LIVE mode — approved actions are executed for real.</div>'
        .format(ico=icon("check", 16))
    )
    rate = f'{m["approval_rate"]}%' if m["approval_rate"] is not None else "—"
    success = f'{m["act_success_rate"]}%' if m["act_success_rate"] is not None else "—"
    expiry = f'{m["expiry_rate"]}% undecided' if m["expiry_rate"] is not None else "—"
    kpis = "".join([
        _kpi("Pending", m["pending"], f'oldest: {m["oldest_pending_human"]}', "clock"),
        _kpi("Total cases", m["total"], "", "layers"),
        _kpi("Approval rate", rate, "", "shield"),
        _kpi("Action success", success, f'{m["act_ok"]}/{m["act_total"]} ok', "check"),
        _kpi("Expired", m["expired"], expiry, "alert"),
        _kpi("MTTA / MTTR", f'{m["mtta_human"]} / {m["mttr_human"]}',
             "decision / execution", "timer"),
    ])

    if m["trend_7d"] is None:
        trend = '<span class="text-muted">no prior baseline</span>'
    else:
        up = m["trend_7d"] >= 0
        token = "danger" if up else "ok"
        sign = "+" if up else ""
        trend = f'<span class="badge badge--{token}">{sign}{m["trend_7d"]}% vs prev 7d</span>'

    volumen = (
        f'<div class="grid grid--3">'
        f'{_ministat(m["vol_24"], "last 24h")}'
        f'{_ministat(m["vol_7"], "7 days")}'
        f'{_ministat(m["vol_30"], "30 days")}</div>'
    )

    status_bars = _bars([
        (_STATUS_LABEL.get(s, s), m["status_counts"].get(s, 0))
        for s in ["pending", "approved", "executed", "rejected", "expired"]
    ])
    actions_bars = _bars(
        [(action_label(k), v) for k, v in sorted(m["actions_exec"].items(), key=lambda kv: -kv[1])]
    )
    risk_bars = _bars([
        (lvl, m["risk_counts"].get(lvl, 0))
        for lvl in ["critical", "high", "medium", "low"]
        if m["risk_counts"].get(lvl, 0)
    ] or list(m["risk_counts"].items()))
    hosts_bars = _bars(m["top_hosts"])
    users_bars = _bars(m["top_users"])

    flags = [
        ("Triage", settings.enable_triage),
        ("Enricher", settings.enable_enricher),
        ("Threat Intel", settings.enable_threat_intel),
        ("Narrator", settings.enable_narrator),
    ]
    flag_lines = "".join(
        f'<div class="bar-row" style="grid-template-columns:1fr auto;margin:10px 0">'
        f'<div class="bar-label">{h(name)}</div>'
        f'<span class="badge badge--{"ok" if on else "muted"}">{"on" if on else "off"}</span></div>'
        for name, on in flags
    )

    if m["failed_actions"]:
        frows = "".join(
            f'<tr class="row-link" data-href="/ui/case/{h(f["rowid"])}">'
            f'<td class="strong">{h(action_label(f["action_type"]))}</td>'
            f'<td>{h(f["target"])}</td>'
            f'<td class="text-muted">{h(f["message"])}</td></tr>'
            for f in m["failed_actions"]
        )
        failed_card = _card(
            "Failed actions",
            f'<div class="table-container"><table class="table">'
            f'<thead><tr><th>Action</th><th>Target</th><th>Message</th></tr></thead>'
            f'<tbody>{frows}</tbody></table></div>',
            "x",
            flush=True,
        )
    else:
        failed_card = ""

    body = f"""{banner}
<div class="grid kpi-grid">{kpis}</div>
<div class="grid grid--2">
  {_card("Recent volume", f'<div class="section-title"><h2>{icon("trend")} Cases</h2>{trend}</div>{volumen}', "activity")}
  {_card("Cases by status", status_bars, "bar")}
</div>
<div class="grid grid--2">
  {_card("Executed actions", actions_bars, "zap")}
  {_card("Top hosts", hosts_bars, "server")}
</div>
<div class="grid grid--2">
  {_card("Top users", users_bars, "users")}
  {_card("Risk distribution", risk_bars, "shield")}
</div>
<div class="grid grid--2">
  {_card("Volume (14 days)", _spark(m["per_day"]), "activity")}
  {_card("Pipeline", flag_lines, "git")}
</div>
{failed_card}"""
    return _shell("/ui", settings, body, "Overview")


def _num(x: Any) -> str:
    """Formatea enteros con separador de miles; deja el resto como viene."""
    if isinstance(x, bool) or x is None:
        return "—" if x is None else str(x)
    if isinstance(x, int):
        return f"{x:,}"
    if isinstance(x, float):
        return f"{x:g}"
    return h(x)


def kpis_page(settings: Settings, k: dict[str, Any]) -> str:
    c = k.get("containment") or {}
    av = k.get("alert_volume") or {}

    firsts: list[str] = []
    lasts: list[str] = []
    if c.get("available") and (c.get("period") or {}).get("first"):
        firsts.append(c["period"]["first"])
        lasts.append(c["period"]["last"])
    if av.get("available") and av.get("months"):
        firsts.append(av["months"][0]["label"])
        lasts.append(av["months"][-1]["label"])
    since = min(firsts) if firsts else None
    last = max(lasts) if lasts else "—"
    since_line = (
        f'Data from <strong>{h(since)}</strong> to <strong>{h(last)}</strong>' if since
        else "No data yet"
    )

    # ---- Containment ----
    if c.get("available") and c.get("total_cases"):
        exec_sub = "simulated (dry-run)" if settings.dry_run_mode else "executed"
        rate = f'{c["containment_rate"]}%' if c.get("containment_rate") is not None else "—"
        cont_kpis = "".join([
            _kpi("Containment actions", c["proposed_total"], "proposed", "lock"),
            _kpi("Executed", c["executed_total"], exec_sub, "zap"),
            _kpi("Cases with block", c["cases_with_containment"],
                 f'{rate} of {c["total_cases"]} cases', "shield"),
            _kpi("Hosts affected", c["hosts_contained"], "≥1 containment", "server"),
        ])
        if c["by_type"]:
            trows = "".join(
                f'<tr><td class="strong">{h(action_label(t))}</td>'
                f'<td>{h(prop)}</td><td class="text-muted">{h(ex)}</td></tr>'
                for t, prop, ex in c["by_type"]
            )
            by_type = _card(
                "Containment by type",
                f'<div class="table-container"><table class="table">'
                f'<thead><tr><th>Action</th><th>Proposed</th><th>Executed</th></tr></thead>'
                f'<tbody>{trows}</tbody></table></div>',
                "bar",
                flush=True,
            )
        else:
            by_type = '<div class="empty">No containment actions in the period.</div>'
        dry_note = (
            '<div class="banner banner--dry">{ico}DRY-RUN — containments are logged but simulated.</div>'
            .format(ico=icon("alert", 16))
            if settings.dry_run_mode else ""
        )
        containment_block = f"""<div class="section-title"><h2>{icon("lock")}Containment / blocks</h2><span class="text-muted">{h(c["period"]["label"])}</span></div>
{dry_note}
<div class="grid kpi-grid">{cont_kpis}</div>
{by_type}"""
    else:
        containment_block = (
            f'<div class="section-title"><h2>{icon("lock")}Containment / blocks</h2></div>'
            f'<div class="empty">No cases in state.db yet.</div>'
        )

    # ---- Wazuh posture ----
    p = k.get("posture") or {}
    if p.get("available"):
        ag = p.get("agents") or {}
        os_list = p.get("os") or []
        posture_kpis = "".join([
            _kpi("Monitored agents", _num(ag.get("total")),
                 f'{_num(ag.get("active"))} active', "users"),
            _kpi("Disconnected", _num(ag.get("disconnected")),
                 f'{_num(ag.get("never_connected"))} never connected', "server"),
            _kpi("Active rules", _num(p.get("rules_total")), "ruleset loaded", "shield"),
            _kpi("Wazuh version", h(p.get("manager_version") or "—"),
                 ", ".join(os_list) or "—", "gauge"),
        ])
        posture_block = f"""<div class="section-title"><h2>{icon("server")}Wazuh posture · today</h2><span class="text-muted">snapshot via Management API</span></div>
<div class="grid kpi-grid">{posture_kpis}</div>"""
    else:
        posture_block = (
            f'<div class="section-title"><h2>{icon("server")}Wazuh posture · today</h2></div>'
            f'<div class="empty">Wazuh API unavailable: {h(p.get("error") or "no data")}</div>'
        )

    # ---- Alert volume ----
    if av.get("available") and av.get("months"):
        months = av["months"]
        cur = months[-1]
        peak = max(months, key=lambda m: m["avg_per_day"])
        low = min(months, key=lambda m: m["avg_per_day"])
        red = (round(100 * (peak["avg_per_day"] - low["avg_per_day"]) / peak["avg_per_day"])
               if peak["avg_per_day"] else None)
        av_kpis = "".join([
            _kpi("Noise peak", _num(peak["avg_per_day"]),
                 f'{h(peak["name"])} · alerts/day', "trend"),
            _kpi("Lowest point", _num(low["avg_per_day"]),
                 f'{h(low["name"])} · -{red}% vs peak' if red is not None else h(low["name"]), "check"),
            _kpi("Current month", _num(cur["avg_per_day"]),
                 f'{h(cur["name"])} · alerts/day', "activity"),
        ])
        vol_bars = _bars([(m["label"], m["avg_per_day"]) for m in months])
        note = (f'sampled {av.get("max_days_per_month")} days/month'
                if av.get("sampled") else "full count")
        alert_block = f"""<div class="section-title"><h2>{icon("activity")}Alert volume · how the infra changed</h2><span class="text-muted">{h(months[0]["name"])} → {h(cur["name"])} · {h(note)}</span></div>
<div class="grid kpi-grid">{av_kpis}</div>
{_card("Alerts/day by month", vol_bars, "bar")}"""
    else:
        alert_block = (
            f'<div class="section-title"><h2>{icon("activity")}Alert volume</h2></div>'
            f'<div class="empty">No volume cache. Run <code>scripts/aggregate_alert_volume.py</code>.</div>'
        )

    # ---- FortiGate blocks ----
    fg = k.get("fortigate") or {}
    fg_months = [m for m in (av.get("months") or []) if "fg_blocks_avg_per_day" in m]
    now_banned = fg.get("count") if fg.get("available") else None
    now_line = (f' · {_num(now_banned)} in quarantine now'
                if now_banned is not None else "")
    if fg_months:
        total_blocks = sum(m.get("fg_blocks_total_estimate", 0) for m in fg_months)
        cur = fg_months[-1]
        peak = max(fg_months, key=lambda m: m["fg_blocks_avg_per_day"])
        fg_caveat = (
            '<div class="banner banner--warn">{ico}'
            'These are <strong>events logged to Wazuh</strong>, not the current firewall policy. '
            'The drop in Jan-2026 was log tuning, not less protection.</div>'
            .format(ico=icon("alert", 16))
        )
        fg_kpis = "".join([
            _kpi("Block events", _num(total_blocks),
                 f'~estimate · {len(fg_months)} months logged', "lock"),
            _kpi("Monthly peak", _num(peak["fg_blocks_avg_per_day"]),
                 f'{h(peak["name"])} · /day', "trend"),
            _kpi("Currently logged", _num(cur["fg_blocks_avg_per_day"]),
                 f'{h(cur["name"])} · /day', "activity"),
            _kpi("In quarantine now",
                 _num(now_banned) if now_banned is not None else "—",
                 "active bans", "clock"),
        ])
        fg_bars = _bars([(m["label"], m["fg_blocks_avg_per_day"]) for m in fg_months])
        fortigate_block = f"""<div class="section-title"><h2>{icon("lock")}FortiGate blocks · events in Wazuh</h2><span class="text-muted">deny / dropped / blocked{now_line}</span></div>
{fg_caveat}
<div class="grid kpi-grid">{fg_kpis}</div>
{_card("Block events/day by month", fg_bars, "bar")}"""
    else:
        fortigate_block = (
            f'<div class="section-title"><h2>{icon("lock")}FortiGate blocks</h2></div>'
            f'<div class="empty">No block data in cache. '
            f'Run <code>scripts/aggregate_alert_volume.py</code>.</div>'
        )

    body = f"""<p class="text-muted" style="margin:-6px 0 20px">{since_line}</p>
{posture_block}
{alert_block}
{containment_block}
{fortigate_block}"""
    return _shell("/ui/kpis", settings, body, "KPIs")


def queue_page(
    settings: Settings, cases: list[dict[str, Any]], status: str | None, page: int, total: int
) -> str:
    statuses = [("", "All"), ("pending", "Pending"), ("approved", "Approved"),
                ("executed", "Executed"), ("rejected", "Rejected"), ("expired", "Expired")]
    chips = "".join(
        f'<a class="chip {"chip--active" if (status or "") == val else ""}" '
        f'href="/ui/queue{("?status=" + val) if val else ""}">{h(label)}</a>'
        for val, label in statuses
    )

    if not cases:
        rows = '<tr><td colspan="6"><div class="empty">No cases for this filter.</div></td></tr>'
    else:
        rows = "".join(
            f'<tr class="row-link" data-href="/ui/case/{h(c["rowid"])}">'
            f'<td class="strong">{h(c["title"])}<div class="text-muted" style="font-size:12px">{h(c["alert_id"])}</div></td>'
            f'<td>{risk_pill(c["risk_level"])}</td>'
            f'<td>{status_badge(c["status"])}</td>'
            f'<td>{h(c["host"])}</td>'
            f'<td class="text-muted">{h(humanize_age(c["created_at"]))}</td>'
            f'<td class="text-muted">{h(c["n_actions"])} action(s)</td></tr>'
            for c in cases
        )

    per_page = 50
    pages = max(1, (total + per_page - 1) // per_page)
    qbase = f"?status={status}&" if status else "?"
    prev_btn = (
        f'<a class="pager__btn" href="/ui/queue{qbase}page={page-1}">← Previous</a>'
        if page > 1 else '<span class="pager__btn" aria-disabled="true">← Previous</span>'
    )
    next_btn = (
        f'<a class="pager__btn" href="/ui/queue{qbase}page={page+1}">Next →</a>'
        if page < pages else '<span class="pager__btn" aria-disabled="true">Next →</span>'
    )
    pager = f'<div class="pager">{prev_btn}<span class="pager__info">Page {page} of {pages} · {total} cases</span>{next_btn}</div>'

    table_card = _card(
        "Cases",
        f'<div class="table-container"><table class="table">'
        f'<thead><tr><th>Case</th><th>Risk</th><th>Status</th><th>Host</th><th>Age</th><th>Plan</th></tr></thead>'
        f'<tbody>{rows}</tbody></table></div>',
        "list",
        flush=True,
    )

    body = f"""<div class="chips">{chips}</div>
{table_card}
{pager}"""
    return _shell("/ui/queue", settings, body, "Queue")


def case_page(settings: Settings, c: dict[str, Any]) -> str:
    alert = c["alert"]
    plan = c["plan"]
    device = alert.get("device") or {}
    users = alert.get("users_involved") or []
    user_str = ", ".join(u.get("sam", "?") for u in users) or "—"

    # Timeline
    events = list(c["timeline"])
    if c["decided_at"]:
        events.append({
            "stage": "decision", "ts": c["decided_at"],
            "summary": f'{_STATUS_LABEL.get(c["status"], c["status"])} by {c["decided_by_ip"] or "?"}',
            "detail": (c.get("decided_by_ua") or "")[:120],
        })
    if c["executed_at"]:
        n_ok = sum(1 for er in c["execution_result"] if isinstance(er, dict) and er.get("ok"))
        events.append({
            "stage": "execution", "ts": c["executed_at"],
            "summary": f'{n_ok}/{len(c["execution_result"])} actions ok',
            "detail": None,
        })
    events.sort(key=lambda e: e.get("ts") or "")
    tl = "".join(
        f'<li class="timeline__item"><span class="timeline__dot"></span>'
        f'<div class="timeline__stage">{h(e.get("stage"))}</div>'
        f'<div class="timeline__time">{h(e.get("ts"))}</div>'
        f'<div class="timeline__text">{h(e.get("summary"))}</div>'
        + (f'<div class="timeline__detail">{h(e.get("detail"))}</div>' if e.get("detail") else "")
        + "</li>"
        for e in events
    ) or '<li class="timeline__item"><span class="timeline__dot"></span><div class="text-muted">No events.</div></li>'

    # Proposed actions
    selected = set(c.get("selected_actions") or [])
    actions = plan.get("actions") or []
    act_rows = ""
    for i, a in enumerate(actions):
        chosen = (not c.get("selected_actions")) or (i in selected)
        mark = _badge("ok", "yes") if chosen else _badge("muted", "no")
        act_rows += (
            f'<tr><td class="strong">{h(action_label(a.get("type")))}</td><td>{h(a.get("target"))}</td>'
            f'<td class="text-muted">{h(a.get("justification"))}</td><td>{mark}</td></tr>'
        )
    act_table = (
        f'<div class="table-container"><table class="table">'
        f'<thead><tr><th>Action</th><th>Target</th><th>Justification</th><th></th></tr></thead>'
        f'<tbody>{act_rows}</tbody></table></div>'
        if actions else '<div class="empty">The plan proposes no actions.</div>'
    )

    # Execution results
    exec_rows = ""
    for er in c["execution_result"]:
        if not isinstance(er, dict):
            continue
        ok = er.get("ok")
        badge = _badge("ok", "ok") if ok else _badge("danger", "fail")
        exec_rows += (
            f'<tr><td class="strong">{h(action_label(er.get("action_type")))}</td><td>{h(er.get("target"))}</td>'
            f'<td>{badge}</td><td class="text-muted">{h(er.get("message"))}</td></tr>'
        )
    exec_table = (
        f'<div class="table-container"><table class="table">'
        f'<thead><tr><th>Action</th><th>Target</th><th>Result</th><th>Message</th></tr></thead>'
        f'<tbody>{exec_rows}</tbody></table></div>'
        if exec_rows else '<div class="empty">Not executed yet.</div>'
    )

    invgate = f'#{h(c["invgate_request_id"])}' if c.get("invgate_request_id") else "—"

    header = f"""<div class="card" style="margin-bottom:20px">
  <div class="card__body">
    <div class="eyebrow">{h(c["alert_id"])}</div>
    <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap;margin-top:6px">
      <h1 class="page-title">{h(alert.get("title") or "Case")}</h1>
      <div style="display:flex;gap:8px">{risk_pill(plan.get("risk_level"))}{status_badge(c["status"])}</div>
    </div>
  </div>
</div>"""

    summary_card = _card(
        "Executive summary",
        f'<p class="text-secondary">{h(plan.get("executive_summary") or "—")}</p>',
        "activity",
    )
    context_card = _card(
        "Context",
        f'<div class="kv">'
        f'<div class="kv__key">Host</div><div class="kv__value">{h(device.get("hostname") or device.get("fqdn") or "—")}</div>'
        f'<div class="kv__key">Internal IP</div><div class="kv__value">{h(device.get("internal_ip") or "—")}</div>'
        f'<div class="kv__key">Users</div><div class="kv__value">{h(user_str)}</div>'
        f'<div class="kv__key">Source severity</div><div class="kv__value">{h(alert.get("severity_source") or "—")}</div>'
        f'<div class="kv__key">Category</div><div class="kv__value">{h(alert.get("category") or "—")}</div>'
        f'<div class="kv__key">InvGate ticket</div><div class="kv__value">{invgate}</div>'
        f'<div class="kv__key">Decided by</div><div class="kv__value">{h(c.get("decided_by_ip") or "—")}</div>'
        f'</div>',
        "server",
    )

    actions_card = _card("Proposed actions", act_table, "shield", flush=bool(actions))
    exec_card = _card("Execution result", exec_table, "check", flush=bool(exec_rows))
    timeline_card = _card("Timeline", f'<ul class="timeline">{tl}</ul>', "clock")
    rationale_card = _card(
        "Analysis (rationale)",
        f'<p class="text-secondary">{h(plan.get("rationale") or "—")}</p>',
        "git",
    )

    body = f"""{header}
<div class="grid grid--2">
  {summary_card}
  {context_card}
</div>
{actions_card}
{exec_card}
<div class="grid grid--2">
  {timeline_card}
  {rationale_card}
</div>"""
    return _shell("/ui/queue", settings, body, alert.get("title") or "Case")
