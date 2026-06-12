"""Render del panel /ui — HTML por funciones (sin Jinja, sin deps).

Implementa el sistema de diseño ZebraSecurity (dark-first, acento lima) como CSS
plano con tokens semánticos. Todo el texto que viene de datos pasa por h() (escape).
"""
from __future__ import annotations

import html
from typing import Any

from src.config import Settings
from src.web.queries import humanize_age

# ===== Tokens de severidad/estado → token semántico =====
# low|medium|high|critical → ok|warn|elevated|danger (regla del sistema de diseño)
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
# Nombres técnicos de acción → etiqueta legible para la UI
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
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
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
  --bg:#050505; --bg-2:#0a0a0a; --panel:#101010; --panel-2:#151515;
  --surface:#1d1d1d; --surface-hover:#282828; --line:#2a2a2a; --line-strong:#3a3a3a;
  --text:#f4f4f0; --muted:#8f938b; --muted-2:#c8cdc0;
  --primary:#b6ff00; --primary-2:#84cc16; --primary-foreground:#11120f;
  --focus:#b6ff00; --lime-glow:rgba(182,255,0,.55);
  --ok:#a3e635; --warn:#facc15; --elevated:#fb923c; --danger:#f87171;
  --radius-sm:.5rem; --radius-md:.75rem; --radius-lg:1rem; --radius-xl:1.5rem;
  --shadow:0 18px 50px rgba(0,0,0,.34);
  --chart-1:#b6ff00; --chart-2:#84cc16; --chart-3:#facc15; --chart-4:#fb923c; --chart-5:#f87171;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
  background:var(--bg); color:var(--text); min-height:100vh;
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;
  font-size:15px; line-height:1.55; -webkit-font-smoothing:antialiased;
}
a{color:inherit; text-decoration:none}
.muted{color:var(--muted)} .muted-2{color:var(--muted-2)}
.eyebrow{font-size:11px; font-weight:800; letter-spacing:.2em; text-transform:uppercase; color:var(--muted)}
h1,h2{margin:0; letter-spacing:-.05em}
h1{font-size:clamp(40px,5.8vw,78px); font-weight:800; line-height:.96}
h2{font-size:clamp(30px,4vw,56px); font-weight:800; line-height:1.02}
h3{margin:0; font-size:19px; font-weight:700; letter-spacing:-.035em; line-height:1.14}
.page-title{font-size:clamp(24px,2.6vw,34px); font-weight:800; letter-spacing:-.04em; line-height:1.06; margin:0}
em{color:var(--primary); font-style:normal; text-shadow:0 0 34px rgba(182,255,0,.32)}

/* layout */
.shell{display:grid; grid-template-columns:236px 1fr; min-height:100vh}
.side{background:var(--bg-2); border-right:1px solid var(--line); padding:22px 16px; position:sticky; top:0; height:100vh}
.brand{display:flex; align-items:center; gap:10px; font-weight:900; letter-spacing:-.04em; font-size:18px; margin-bottom:26px}
.brand .mark{width:10px; height:10px; border-radius:50%; background:var(--primary); box-shadow:0 0 18px var(--lime-glow)}
.nav a{display:flex; align-items:center; gap:10px; padding:10px 12px; border-radius:var(--radius-md); color:var(--muted-2); font-weight:600; margin-bottom:4px; border:1px solid transparent; transition:.2s ease}
.nav a:hover{background:var(--surface); color:var(--text)}
.nav a.active{background:rgba(182,255,0,.08); border-color:rgba(182,255,0,.32); color:var(--primary)}
.main{padding:26px 30px; max-width:1200px}
.topbar{display:flex; align-items:center; justify-content:space-between; margin-bottom:22px; gap:16px; flex-wrap:wrap}
.logout{font-size:13px; color:var(--muted)} .logout:hover{color:var(--primary)}

/* cards & grid */
.card{background:var(--panel); border:1px solid var(--line); border-radius:var(--radius-xl); padding:22px; box-shadow:var(--shadow)}
.card.interactive{transition:border-color .3s ease, transform .3s ease; cursor:pointer}
.card.interactive:hover{border-color:rgba(182,255,0,.32); transform:translateY(-2px)}
.grid{display:grid; gap:16px}
/* KPI strip: columnas explícitas → filas siempre parejas (6 cards: 3·2 / 2·3 / 2) */
.kpis{grid-template-columns:repeat(3,minmax(0,1fr))}
@media (min-width:1240px){.kpis{grid-template-columns:repeat(6,minmax(0,1fr))}}
@media (max-width:680px){.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}}
.cols-2{grid-template-columns:repeat(auto-fit,minmax(320px,1fr))}
.card.kpi{padding:16px 18px}
.kpi .label{font-size:11px; font-weight:800; letter-spacing:.16em; text-transform:uppercase; color:var(--muted)}
.kpi .value{font-size:27px; font-weight:800; letter-spacing:-.05em; margin-top:6px; line-height:1.05}
.kpi .sub{font-size:12px; color:var(--muted); margin-top:3px}

/* mode banner */
.banner{display:flex; align-items:center; gap:12px; padding:14px 18px; border-radius:var(--radius-lg); margin-bottom:20px; font-weight:600}
.banner.dry{background:rgba(250,204,21,.15); border:1px solid rgba(250,204,21,.40); color:var(--warn)}
.banner.live{background:rgba(163,230,53,.15); border:1px solid rgba(163,230,53,.40); color:var(--ok)}

/* pills */
.pill{display:inline-flex; align-items:center; padding:6px 14px; border-radius:999px; font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.16em}
.pill.ok{color:var(--ok); background:rgba(163,230,53,.15); border:1px solid rgba(163,230,53,.40)}
.pill.warn{color:var(--warn); background:rgba(250,204,21,.15); border:1px solid rgba(250,204,21,.40)}
.pill.elevated{color:var(--elevated); background:rgba(251,146,60,.15); border:1px solid rgba(251,146,60,.40)}
.pill.danger{color:var(--danger); background:rgba(248,113,113,.15); border:1px solid rgba(248,113,113,.40)}
.pill.primary{color:var(--primary); background:rgba(182,255,0,.12); border:1px solid rgba(182,255,0,.40)}
.pill.muted{color:var(--muted); background:rgba(255,255,255,.04); border:1px solid var(--line)}

/* dots */
.dot{display:inline-block; width:10px; height:10px; border-radius:50%}
.dot.on{background:var(--primary); box-shadow:0 0 18px var(--lime-glow); animation:stationPulse 2.6s ease-out infinite}
.dot.off{background:var(--line-strong)}
@keyframes stationPulse{
  0%{box-shadow:0 0 18px var(--lime-glow), 0 0 0 0 rgba(182,255,0,.5)}
  100%{box-shadow:0 0 18px var(--lime-glow), 0 0 0 18px rgba(182,255,0,0)}
}
.statline{display:flex; align-items:center; gap:8px; padding:6px 0; color:var(--muted-2); font-size:14px}

/* table */
table{width:100%; border-collapse:collapse; font-size:14px}
th{text-align:left; font-size:11px; font-weight:800; letter-spacing:.18em; text-transform:uppercase; color:var(--muted); padding:10px 12px; border-bottom:1px solid var(--line)}
td{padding:12px; border-bottom:1px solid var(--line); color:var(--muted-2)}
tr:hover td{background:rgba(255,255,255,.02)}
td.strong{color:var(--text); font-weight:600}
.row-link:hover td{background:rgba(182,255,0,.04); cursor:pointer}

/* filter chips */
.chips{display:flex; gap:8px; flex-wrap:wrap; margin-bottom:16px}
.chip{padding:7px 14px; border-radius:999px; font-size:12px; font-weight:700; letter-spacing:.16em; text-transform:uppercase; background:rgba(255,255,255,.04); border:1px solid var(--line); color:var(--muted-2); transition:.2s ease}
.chip:hover{border-color:var(--primary); color:var(--primary)}
.chip.active{background:rgba(182,255,0,.10); border-color:rgba(182,255,0,.40); color:var(--primary)}

/* bars */
.bar-row{display:grid; grid-template-columns:120px 1fr 44px; align-items:center; gap:10px; margin:8px 0; font-size:13px}
.bar-track{height:10px; background:var(--surface); border-radius:999px; overflow:hidden}
.bar-fill{height:100%; background:linear-gradient(90deg,var(--primary-2),var(--primary)); border-radius:999px}
.bar-num{text-align:right; color:var(--muted-2); font-variant-numeric:tabular-nums}

/* sparkline columns */
.spark{display:flex; align-items:flex-end; gap:3px; height:80px}
.spark .col{flex:1; background:linear-gradient(180deg,var(--primary),var(--primary-2)); border-radius:3px 3px 0 0; min-height:2px; opacity:.85}
.spark .col:hover{opacity:1}

/* timeline */
.tl{list-style:none; margin:0; padding:0}
.tl li{position:relative; padding:0 0 18px 24px; border-left:1px solid var(--line)}
.tl li:last-child{border-left-color:transparent}
.tl .node{position:absolute; left:-5px; top:3px; width:10px; height:10px; border-radius:50%; background:var(--primary); box-shadow:0 0 12px var(--lime-glow)}
.tl .stage{font-size:11px; font-weight:800; letter-spacing:.18em; text-transform:uppercase; color:var(--primary)}
.tl .ts{font-size:12px; color:var(--muted)}
.tl .sum{color:var(--text); margin-top:2px}
.tl .det{color:var(--muted); font-size:13px; margin-top:2px}

/* misc */
.section-title{display:flex; align-items:center; justify-content:space-between; margin:6px 0 12px}
.section-title h3{display:inline-flex; align-items:center; gap:8px}
.icon{display:inline-block; vertical-align:middle; flex:0 0 auto; color:var(--muted)}
.nav a .icon{color:inherit}
.kpi .label{display:inline-flex; align-items:center; gap:6px}
.ministat .num{font-size:28px; font-weight:800; letter-spacing:-.05em}
.kv{display:grid; grid-template-columns:160px 1fr; gap:8px 14px; font-size:14px}
.kv .k{color:var(--muted)} .kv .v{color:var(--text)}
.btn{display:inline-flex; align-items:center; gap:8px; padding:12px 22px; border-radius:10px; font-weight:900; cursor:pointer; border:0; transition:filter .2s ease, transform .2s ease, border-color .2s ease, color .2s ease}
.btn-primary{background:linear-gradient(135deg,var(--primary),var(--primary-2)); color:var(--primary-foreground); box-shadow:0 14px 34px rgba(182,255,0,.14)}
.btn-primary:hover{filter:brightness(1.04); transform:translateY(-1px)}
.btn-secondary{background:rgba(255,255,255,.04); border:1px solid var(--line); color:var(--muted-2); font-weight:700}
.btn-secondary:hover{border-color:var(--primary); color:var(--primary)}
.pager{display:flex; gap:10px; margin-top:16px; align-items:center}
.pager a{padding:8px 14px; border:1px solid var(--line); border-radius:var(--radius-md); color:var(--muted-2)}
.pager a:hover{border-color:var(--primary); color:var(--primary)}
.empty{text-align:center; color:var(--muted); padding:50px 0}
.codeblock{background:#050505; border:1px solid var(--line-strong); border-radius:9px; padding:14px; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:13px; color:var(--muted-2); white-space:pre-wrap; overflow:auto}

/* ===== login — SOC-L1 Command Surface ===== */
.login-page{min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px;
  background:
    radial-gradient(900px 520px at 10% -12%, rgba(182,255,0,.10), transparent 60%),
    radial-gradient(760px 520px at 112% 118%, rgba(182,255,0,.06), transparent 60%),
    #050505;}
.login-page::before{content:""; position:fixed; inset:0; pointer-events:none;
  background:
    repeating-linear-gradient(0deg, rgba(182,255,0,.03) 0 1px, transparent 1px 40px),
    repeating-linear-gradient(90deg, rgba(182,255,0,.022) 0 1px, transparent 1px 40px);
  -webkit-mask-image:radial-gradient(ellipse at center, #000 25%, transparent 78%);
  mask-image:radial-gradient(ellipse at center, #000 25%, transparent 78%)}
.login-wrap{position:relative; width:min(1040px,100%); display:grid; grid-template-columns:1.08fr .92fr;
  background:rgba(13,15,13,.86); border:1px solid var(--line); border-radius:var(--radius-xl);
  box-shadow:0 30px 100px rgba(0,0,0,.6); overflow:hidden}
.login-wrap::before{content:""; position:absolute; top:0; left:0; right:0; height:2px; z-index:2;
  background:linear-gradient(90deg, transparent, var(--primary), transparent); opacity:.75}
.login-hero{position:relative; padding:48px 44px; border-right:1px solid var(--line);
  background:
    linear-gradient(180deg, rgba(182,255,0,.045), transparent 38%),
    repeating-linear-gradient(0deg, rgba(255,255,255,.016) 0 1px, transparent 1px 42px)}
.login-brand{display:flex; align-items:center; gap:14px}
.login-mark{width:46px; height:46px; flex:0 0 auto; filter:drop-shadow(0 0 16px rgba(182,255,0,.45))}
.login-wordmark{font-weight:900; letter-spacing:-.04em; font-size:18px; line-height:1.1}
.login-wordmark .sub{display:block; font-size:10px; font-weight:800; letter-spacing:.26em; text-transform:uppercase; color:var(--muted); margin-top:2px}
.login-hero h1{margin-top:32px; font-size:clamp(30px,3.3vw,44px); font-weight:800; letter-spacing:-.045em; line-height:1.02}
.login-tagline{margin-top:14px; color:var(--muted-2); font-size:15px; max-width:42ch; line-height:1.6}
.telemetry{margin-top:30px; border:1px solid var(--line); border-radius:var(--radius-lg); background:rgba(5,5,5,.55);
  padding:14px 16px; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12.5px}
.telemetry .trow{display:flex; align-items:center; gap:10px; padding:4px 0; color:var(--muted-2)}
.telemetry .trow .nm{color:var(--text)}
.telemetry .trow .st{margin-left:auto; color:var(--primary); letter-spacing:.12em}
.telemetry .trow .st.idle{color:var(--muted)}
.telemetry .flow{margin-top:10px; padding-top:10px; border-top:1px dashed var(--line); color:var(--muted); letter-spacing:.03em}
.telemetry .flow b{color:var(--primary-2); font-weight:700}
.dot-sm{width:8px; height:8px; border-radius:50%; flex:0 0 auto}
.dot-sm.live{background:var(--primary); box-shadow:0 0 10px var(--lime-glow); animation:stationPulse 2.6s ease-out infinite}
.dot-sm.idle{background:var(--line-strong)}
.login-form-panel{padding:48px 44px; background:linear-gradient(180deg,#0c0d0c,#070807); display:flex; flex-direction:column; justify-content:center}
.login-kicker{font-size:11px; font-weight:800; letter-spacing:.2em; text-transform:uppercase; color:var(--primary); margin-bottom:16px; display:flex; align-items:center; gap:8px}
.login-form-panel h2{font-size:23px; font-weight:800; letter-spacing:-.03em; margin-bottom:6px}
.input{width:100%; background:#050505; border:1px solid var(--line-strong); border-radius:10px; color:var(--text); padding:13px 14px; font-size:15px; margin:8px 0 18px; transition:border-color .2s ease, box-shadow .2s ease}
.input:focus{outline:0; border-color:var(--primary); box-shadow:0 0 0 3px rgba(182,255,0,.14)}
.login-err{color:var(--danger); font-size:13px; margin-bottom:12px; display:flex; align-items:center; gap:8px}
.login-foot{margin-top:22px; padding-top:16px; border-top:1px solid var(--line); display:flex; align-items:center; gap:8px;
  color:var(--muted); font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:11.5px; letter-spacing:.06em}
.login-kicker .icon, .login-foot .icon, .login-err .icon{color:inherit}
label{font-size:11px; font-weight:800; letter-spacing:.18em; text-transform:uppercase; color:var(--muted)}

@media (max-width:820px){ .shell{grid-template-columns:1fr} .side{display:none} .login-wrap{grid-template-columns:1fr} .login-hero{display:none} }
@media (prefers-reduced-motion:reduce){ *{transition:none!important; animation:none!important} }
"""


# ===== Componentes =====


def risk_pill(level: str | None) -> str:
    lvl = (level or "unknown").lower()
    token = _RISK_TOKEN.get(lvl, "muted")
    return f'<span class="pill {token}">{h(lvl)}</span>'


def status_badge(status: str | None) -> str:
    st = (status or "pending").lower()
    token = _STATUS_TOKEN.get(st, "muted")
    return f'<span class="pill {token}">{h(_STATUS_LABEL.get(st, st))}</span>'


def _kpi(label: str, value: Any, sub: str = "", ico: str | None = None) -> str:
    sub_html = f'<div class="sub">{h(sub)}</div>' if sub else ""
    ico_html = icon(ico, 14) if ico else ""
    return (
        f'<div class="card kpi"><div class="label">{ico_html}{h(label)}</div>'
        f'<div class="value">{h(value)}</div>{sub_html}</div>'
    )


def _bars(data: list[tuple[str, int]]) -> str:
    if not data:
        return '<div class="muted">No data.</div>'
    mx = max((v for _, v in data), default=0) or 1
    rows = []
    for label, val in data:
        pct = round(100 * val / mx)
        rows.append(
            f'<div class="bar-row"><div class="muted-2">{h(label)}</div>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{pct}%"></div></div>'
            f'<div class="bar-num">{h(val)}</div></div>'
        )
    return "".join(rows)


def _spark(per_day: list[tuple[str, int]]) -> str:
    if not per_day:
        return '<div class="muted">No data.</div>'
    mx = max((v for _, v in per_day), default=0) or 1
    cols = "".join(
        f'<div class="col" style="height:{max(2, round(100 * v / mx))}%" title="{h(d)}: {h(v)}"></div>'
        for d, v in per_day
    )
    first = per_day[0][0]
    last = per_day[-1][0]
    return (
        f'<div class="spark">{cols}</div>'
        f'<div class="statline" style="justify-content:space-between">'
        f'<span class="muted">{h(first)}</span><span class="muted">{h(last)}</span></div>'
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
        f'<a href="{href}" class="{"active" if href == active else ""}">{icon(ico)}<span>{h(label)}</span></a>'
        for href, label, ico in _NAV
    )
    return f"""<!doctype html><html lang="en" class="dark"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{h(title)} · SOC-L1</title><link rel="stylesheet" href="/ui/static/app.css"></head>
<body><div class="shell">
<aside class="side"><div class="brand"><span class="mark"></span>SOC<em>L1</em></div>
<nav class="nav">{nav}</nav></aside>
<main class="main">
<div class="topbar"><div class="eyebrow">ZebraSecurity · SOC-L1</div>
<div style="display:flex;gap:14px;align-items:center">
<span class="pill {mode_token}">{mode}</span><a class="logout" href="/ui/logout">Sign out</a></div></div>
{body}
</main></div>
<script>document.querySelectorAll('tr[data-href]').forEach(function(el){{el.addEventListener('click',function(){{location.href=el.dataset.href}})}});</script>
</body></html>"""


def login_page(settings: Settings, error: str = "") -> str:
    err = f'<div class="login-err">{icon("alert", 14)}{h(error)}</div>' if error else ""
    disabled = not (settings.dashboard_enabled and settings.dashboard_password)
    note = (
        f'<div class="login-err">{icon("alert", 14)}Console offline: DASHBOARD_PASSWORD is not set.</div>'
        if disabled else ""
    )
    agents = [
        ("Triage agent", "ONLINE", True),
        ("Enricher", "ONLINE", True),
        ("Threat Intel", "ONLINE", True),
        ("Narrator", "STANDBY", False),
    ]
    trows = "".join(
        f'<div class="trow"><span class="dot-sm {"live" if live else "idle"}"></span>'
        f'<span class="nm">{h(name)}</span><span class="st {"" if live else "idle"}">{h(state)}</span></div>'
        for name, state, live in agents
    )
    return f"""<!doctype html><html lang="en" class="dark"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Access · SOC-L1 Command Surface</title><link rel="stylesheet" href="/ui/static/app.css"></head>
<body><div class="login-page"><div class="login-wrap">
<div class="login-hero">
  <div class="login-brand">
    <img src="/ui/static/robot.svg" alt="" class="login-mark">
    <div class="login-wordmark">SOC-L1<span class="sub">Command Surface</span></div>
  </div>
  <h1>Agentic security<br><em>operations cockpit</em></h1>
  <p class="login-tagline">Agents investigate alerts, enrich evidence, and propose response actions — every action waits for human approval before it executes.</p>
  <div class="telemetry">
    {trows}
    <div class="flow">alert <b>→</b> enrich <b>→</b> triage <b>→</b> approve <b>→</b> execute</div>
  </div>
</div>
<div class="login-form-panel">
  <div class="login-kicker">{icon("shield", 13)}Restricted access</div>
  <h2>Authenticate to continue</h2>
  <p class="muted" style="font-size:13px;margin:0 0 18px">Enter your console credentials to open the Command Surface.</p>
  {note}{err}
  <form method="post" action="/ui/login">
    <label for="pw">Password</label>
    <input class="input" type="password" id="pw" name="password" autofocus autocomplete="current-password" required>
    <button class="btn btn-primary" type="submit" style="width:100%;justify-content:center">Access console</button>
  </form>
  <div class="login-foot">{icon("check", 12)}SECURE SESSION · ANALYST ACCESS ONLY</div>
</div></div></div></body></html>"""


def panel_page(settings: Settings, m: dict[str, Any]) -> str:
    banner = (
        '<div class="banner dry"><span class="dot on"></span>DRY-RUN mode — actions are simulated, not executed.</div>'
        if settings.dry_run_mode
        else '<div class="banner live"><span class="dot on"></span>LIVE mode — approved actions are executed for real.</div>'
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
        trend = '<span class="muted">no prior baseline</span>'
    else:
        up = m["trend_7d"] >= 0
        token = "danger" if up else "ok"
        sign = "+" if up else ""
        trend = f'<span class="pill {token}">{sign}{m["trend_7d"]}% vs prev 7d</span>'

    def _ministat(num: Any, label: str) -> str:
        return f'<div class="ministat"><div class="num">{h(num)}</div><div class="muted">{h(label)}</div></div>'
    volumen = (
        '<div style="display:flex; gap:32px; margin-top:6px">'
        f'{_ministat(m["vol_24"], "last 24h")}{_ministat(m["vol_7"], "7 days")}'
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
        f'<div class="statline"><span class="dot {"on" if on else "off"}"></span>{h(name)}'
        f'<span class="muted" style="margin-left:auto">{"active" if on else "off"}</span></div>'
        for name, on in flags
    )

    if m["failed_actions"]:
        frows = "".join(
            f'<tr class="row-link" data-href="/ui/case/{h(f["rowid"])}">'
            f'<td class="strong">{h(action_label(f["action_type"]))}</td>'
            f'<td>{h(f["target"])}</td><td class="muted">{h(f["message"])}</td></tr>'
            for f in m["failed_actions"]
        )
        failed_card = (
            '<div class="card" style="margin-bottom:18px">'
            f'<div class="section-title"><h3>{icon("x")}Failed actions</h3></div>'
            '<table><thead><tr><th>Action</th><th>Target</th><th>Message</th></tr></thead>'
            f'<tbody>{frows}</tbody></table></div>'
        )
    else:
        failed_card = ""

    body = f"""<div class="section-title"><h1 class="page-title">Security <em>overview</em></h1></div>
{banner}
<div class="grid kpis" style="margin-bottom:18px">{kpis}</div>
<div class="card" style="margin-bottom:18px"><div class="section-title"><h3>{icon("trend")}Recent volume</h3>{trend}</div>{volumen}</div>
<div class="grid cols-2" style="margin-bottom:18px">
  <div class="card"><div class="section-title"><h3>{icon("bar")}Cases by status</h3></div>{status_bars}</div>
  <div class="card"><div class="section-title"><h3>{icon("activity")}Executed actions</h3></div>{actions_bars}</div>
</div>
<div class="grid cols-2" style="margin-bottom:18px">
  <div class="card"><div class="section-title"><h3>{icon("server")}Top hosts</h3></div>{hosts_bars}</div>
  <div class="card"><div class="section-title"><h3>{icon("users")}Top users</h3></div>{users_bars}</div>
</div>
{failed_card}<div class="grid cols-2" style="margin-bottom:18px">
  <div class="card"><div class="section-title"><h3>{icon("activity")}Volume (14 days)</h3></div>{_spark(m["per_day"])}</div>
  <div class="card"><div class="section-title"><h3>{icon("shield")}Risk</h3></div>{risk_bars}</div>
</div>
<div class="card"><div class="section-title"><h3>{icon("git")}Pipeline</h3></div>{flag_lines}</div>"""
    return _shell("/ui", settings, body, "Overview")


def _num(x: Any) -> str:
    """Formatea enteros con separador de miles para slides; deja el resto como viene."""
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

    # Período "desde que arrancamos con Wazuh": el más temprano entre el primer mes
    # de alertas (curva de volumen) y el primer caso SOAR.
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
        f'Desde <em>{h(since)}</em> · datos al {h(last)}' if since else "Sin datos todavía"
    )

    # ---- Bloque 1: Contención / Bloqueos (state.db) ----
    if c.get("available") and c.get("total_cases"):
        exec_sub = "simuladas (dry-run)" if settings.dry_run_mode else "ejecutadas de verdad"
        rate = f'{c["containment_rate"]}%' if c.get("containment_rate") is not None else "—"
        cont_kpis = "".join([
            _kpi("Acciones de contención", c["proposed_total"], "propuestas por los agentes", "lock"),
            _kpi("Ejecutadas", c["executed_total"], exec_sub, "zap"),
            _kpi("Casos con bloqueo", c["cases_with_containment"],
                 f'{rate} de {c["total_cases"]} casos', "shield"),
            _kpi("Hosts alcanzados", c["hosts_contained"], "con ≥1 contención", "server"),
        ])
        if c["by_type"]:
            trows = "".join(
                f'<tr><td class="strong">{h(action_label(t))}</td>'
                f'<td>{h(prop)}</td><td class="muted">{h(ex)}</td></tr>'
                for t, prop, ex in c["by_type"]
            )
            by_type = (
                '<div class="card"><div class="section-title">'
                f'<h3>{icon("bar")}Contención por tipo</h3></div>'
                '<table><thead><tr><th>Acción</th><th>Propuestas</th>'
                '<th>Ejecutadas</th></tr></thead>'
                f'<tbody>{trows}</tbody></table></div>'
            )
        else:
            by_type = '<div class="card"><div class="muted">Sin acciones de contención en el período.</div></div>'
        dry_note = (
            '<div class="banner dry"><span class="dot on"></span>'
            'DRY-RUN — las contenciones se registran pero se simulan; "Ejecutadas" = decididas, no aplicadas.</div>'
            if settings.dry_run_mode else ""
        )
        containment_block = f"""<div class="section-title"><h3>{icon("lock")}Bloqueos / contención</h3>
<span class="muted">{h(c["period"]["label"])}</span></div>
{dry_note}
<div class="grid kpis" style="margin-bottom:18px">{cont_kpis}</div>
{by_type}"""
    else:
        containment_block = (
            f'<div class="section-title"><h3>{icon("lock")}Bloqueos / contención</h3></div>'
            '<div class="card"><div class="empty">Todavía no hay casos en state.db.</div></div>'
        )

    # ---- Bloque 3: Posture de Wazuh HOY (Management API) ----
    p = k.get("posture") or {}
    if p.get("available"):
        ag = p.get("agents") or {}
        os_list = p.get("os") or []
        posture_kpis = "".join([
            _kpi("Agentes monitoreados", _num(ag.get("total")),
                 f'{_num(ag.get("active"))} activos', "users"),
            _kpi("Desconectados", _num(ag.get("disconnected")),
                 f'{_num(ag.get("never_connected"))} nunca conectados', "server"),
            _kpi("Reglas activas", _num(p.get("rules_total")), "ruleset cargado", "shield"),
            _kpi("Versión Wazuh", h(p.get("manager_version") or "—"),
                 ", ".join(os_list) or "—", "gauge"),
        ])
        posture_block = f"""<div class="section-title"><h3>{icon("server")}Posture de Wazuh · hoy</h3>
<span class="muted">snapshot vía Management API</span></div>
<div class="grid kpis" style="margin-bottom:18px">{posture_kpis}</div>"""
    else:
        posture_block = (
            f'<div class="section-title"><h3>{icon("server")}Posture de Wazuh · hoy</h3></div>'
            f'<div class="card"><div class="empty">Wazuh API no disponible: '
            f'{h(p.get("error") or "sin datos")}</div></div>'
        )

    # ---- Bloque 4: Volumen de alertas (cómo cambió la infra) ----
    av = k.get("alert_volume") or {}
    if av.get("available") and av.get("months"):
        months = av["months"]
        cur = months[-1]
        peak = max(months, key=lambda m: m["avg_per_day"])
        low = min(months, key=lambda m: m["avg_per_day"])
        red = (round(100 * (peak["avg_per_day"] - low["avg_per_day"]) / peak["avg_per_day"])
               if peak["avg_per_day"] else None)
        av_kpis = "".join([
            _kpi("Pico de ruido", _num(peak["avg_per_day"]),
                 f'{h(peak["name"])} · alertas/día', "trend"),
            _kpi("Piso alcanzado", _num(low["avg_per_day"]),
                 f'{h(low["name"])} · -{red}% vs pico' if red is not None else h(low["name"]), "check"),
            _kpi("Mes actual", _num(cur["avg_per_day"]),
                 f'{h(cur["name"])} · alertas/día', "activity"),
        ])
        vol_bars = _bars([(m["label"], m["avg_per_day"]) for m in months])
        note = (f'muestreo de {av.get("max_days_per_month")} días/mes'
                if av.get("sampled") else "conteo completo")
        alert_block = f"""<div class="section-title"><h3>{icon("activity")}Volumen de alertas · cómo cambió la infra</h3>
<span class="muted">{h(months[0]["name"])} → {h(cur["name"])} · {h(note)}</span></div>
<div class="grid kpis" style="margin-bottom:18px">{av_kpis}</div>
<div class="card" style="margin-bottom:18px"><div class="section-title"><h3>{icon("bar")}Alertas/día por mes</h3></div>{vol_bars}</div>"""
    else:
        alert_block = (
            f'<div class="section-title"><h3>{icon("activity")}Volumen de alertas</h3></div>'
            '<div class="card"><div class="empty">Sin cache de volumen. Corré '
            '<code>scripts/aggregate_alert_volume.py</code>.</div></div>'
        )

    # ---- Bloque 5: Bloqueos en FortiGate (hoy) ----
    fg = k.get("fortigate") or {}
    if fg.get("available"):
        cnt = fg.get("count", 0)
        if fg.get("banned"):
            frows = "".join(
                f'<tr><td class="strong">{h(b.get("ip"))}</td>'
                f'<td class="muted">{h(b.get("expires") or "sin vencimiento")}</td></tr>'
                for b in fg["banned"]
            )
            fg_inner = ('<table><thead><tr><th>IP</th><th>Expira</th></tr></thead>'
                        f'<tbody>{frows}</tbody></table>')
        else:
            fg_inner = ('<div class="empty">No hay IPs bloqueadas activas en FortiGate. '
                        'soc-l1 puede bloquear IPs (block_ip) pero todavía no se usó.</div>')
        fortigate_block = f"""<div class="section-title"><h3>{icon("lock")}Bloqueos en FortiGate · hoy</h3>
<span class="muted">{_num(cnt)} IP(s) en quarantine</span></div>
<div class="card" style="margin-bottom:18px">{fg_inner}</div>"""
    else:
        fortigate_block = (
            f'<div class="section-title"><h3>{icon("lock")}Bloqueos en FortiGate · hoy</h3></div>'
            f'<div class="card"><div class="empty">FortiGate no disponible: '
            f'{h(fg.get("error") or "sin datos")}</div></div>'
        )

    body = f"""<div class="section-title"><h1 class="page-title">KPIs · <em>Wazuh</em></h1></div>
<p class="muted" style="margin:-6px 0 20px">{since_line}</p>
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
        f'<a class="chip {"active" if (status or "") == val else ""}" '
        f'href="/ui/queue{("?status=" + val) if val else ""}">{h(label)}</a>'
        for val, label in statuses
    )

    if not cases:
        rows = '<tr><td colspan="6"><div class="empty">No cases for this filter.</div></td></tr>'
    else:
        rows = "".join(
            f'<tr class="row-link" data-href="/ui/case/{h(c["rowid"])}">'
            f'<td class="strong">{h(c["title"])}<div class="muted" style="font-size:12px">{h(c["alert_id"])}</div></td>'
            f'<td>{risk_pill(c["risk_level"])}</td>'
            f'<td>{status_badge(c["status"])}</td>'
            f'<td>{h(c["host"])}</td>'
            f'<td class="muted">{h(humanize_age(c["created_at"]))}</td>'
            f'<td class="muted">{h(c["n_actions"])} action(s)</td></tr>'
            for c in cases
        )

    per_page = 50
    pages = max(1, (total + per_page - 1) // per_page)
    qbase = f'?status={status}&' if status else "?"
    pager = ""
    if pages > 1:
        prev = f'<a href="/ui/queue{qbase}page={page-1}">← Previous</a>' if page > 1 else ""
        nxt = f'<a href="/ui/queue{qbase}page={page+1}">Next →</a>' if page < pages else ""
        pager = f'<div class="pager">{prev}<span class="muted">Page {page} of {pages} · {total} cases</span>{nxt}</div>'

    body = f"""<div class="section-title"><h1 class="page-title">Cola de <em>casos</em></h1></div>
<div class="chips">{chips}</div>
<div class="card" style="padding:6px 6px">
<table><thead><tr><th>Case</th><th>Risk</th><th>Status</th><th>Host</th><th>Age</th><th>Plan</th></tr></thead>
<tbody>{rows}</tbody></table></div>{pager}"""
    return _shell("/ui/queue", settings, body, "Cola")


def case_page(settings: Settings, c: dict[str, Any]) -> str:
    alert = c["alert"]
    plan = c["plan"]
    device = alert.get("device") or {}
    users = alert.get("users_involved") or []
    user_str = ", ".join(u.get("sam", "?") for u in users) or "—"

    # Timeline: eventos del pipeline + decisión + ejecución
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
        f'<li><span class="node"></span>'
        f'<div class="stage">{h(e.get("stage"))}</div>'
        f'<div class="ts">{h(e.get("ts"))}</div>'
        f'<div class="sum">{h(e.get("summary"))}</div>'
        + (f'<div class="det">{h(e.get("detail"))}</div>' if e.get("detail") else "")
        + "</li>"
        for e in events
    ) or '<li class="muted">No events.</li>'

    # Acciones propuestas vs ejecutadas
    selected = set(c.get("selected_actions") or [])
    actions = plan.get("actions") or []
    act_rows = ""
    for i, a in enumerate(actions):
        chosen = (not c.get("selected_actions")) or (i in selected)
        mark = '<span class="pill ok">yes</span>' if chosen else '<span class="pill muted">no</span>'
        act_rows += (
            f'<tr><td class="strong">{h(action_label(a.get("type")))}</td><td>{h(a.get("target"))}</td>'
            f'<td class="muted">{h(a.get("justification"))}</td><td>{mark}</td></tr>'
        )
    act_table = (
        f'<table><thead><tr><th>Action</th><th>Target</th><th>Justification</th><th></th></tr></thead>'
        f'<tbody>{act_rows}</tbody></table>'
        if actions else '<div class="muted">The plan proposes no actions.</div>'
    )

    # Resultados de ejecución
    exec_rows = ""
    for er in c["execution_result"]:
        if not isinstance(er, dict):
            continue
        ok = er.get("ok")
        badge = '<span class="pill ok">ok</span>' if ok else '<span class="pill danger">fail</span>'
        exec_rows += (
            f'<tr><td class="strong">{h(action_label(er.get("action_type")))}</td><td>{h(er.get("target"))}</td>'
            f'<td>{badge}</td><td class="muted">{h(er.get("message"))}</td></tr>'
        )
    exec_table = (
        f'<table><thead><tr><th>Action</th><th>Target</th><th>Result</th><th>Message</th></tr></thead>'
        f'<tbody>{exec_rows}</tbody></table>'
        if exec_rows else '<div class="muted">Not executed yet.</div>'
    )

    invgate = (
        f'#{h(c["invgate_request_id"])}' if c.get("invgate_request_id") else "—"
    )

    body = f"""<div class="section-title">
<div><div class="eyebrow">{h(c["alert_id"])}</div><h1 class="page-title" style="margin-top:6px">{h(alert.get("title") or "Case")}</h1></div>
<div style="display:flex;gap:10px">{risk_pill(plan.get("risk_level"))}{status_badge(c["status"])}</div></div>

<div class="grid cols-2" style="margin-bottom:18px">
  <div class="card"><div class="section-title"><h3>{icon("activity")}Executive summary</h3></div>
    <p class="muted-2">{h(plan.get("executive_summary") or "—")}</p></div>
  <div class="card"><div class="section-title"><h3>{icon("server")}Context</h3></div>
    <div class="kv">
      <div class="k">Host</div><div class="v">{h(device.get("hostname") or device.get("fqdn") or "—")}</div>
      <div class="k">Internal IP</div><div class="v">{h(device.get("internal_ip") or "—")}</div>
      <div class="k">Users</div><div class="v">{h(user_str)}</div>
      <div class="k">Source severity</div><div class="v">{h(alert.get("severity_source") or "—")}</div>
      <div class="k">Category</div><div class="v">{h(alert.get("category") or "—")}</div>
      <div class="k">InvGate ticket</div><div class="v">{invgate}</div>
      <div class="k">Decided by</div><div class="v">{h(c.get("decided_by_ip") or "—")}</div>
    </div></div>
</div>

<div class="card" style="margin-bottom:18px"><div class="section-title"><h3>{icon("shield")}Proposed actions</h3></div>{act_table}</div>
<div class="card" style="margin-bottom:18px"><div class="section-title"><h3>{icon("check")}Execution result</h3></div>{exec_table}</div>

<div class="grid cols-2">
  <div class="card"><div class="section-title"><h3>{icon("clock")}Timeline</h3></div><ul class="tl">{tl}</ul></div>
  <div class="card"><div class="section-title"><h3>{icon("git")}Analysis (rationale)</h3></div>
    <p class="muted-2">{h(plan.get("rationale") or "—")}</p></div>
</div>"""
    return _shell("/ui/queue", settings, body, alert.get("title") or "Case")
