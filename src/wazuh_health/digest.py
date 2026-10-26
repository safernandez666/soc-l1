"""Deterministic email digest of probe results (no LLM, plain template).

Used by `wazuh-health once --email` so the operator gets a quick read of the
last hygiene/capacity/coverage run without spending OpenAI tokens.
"""
from __future__ import annotations

from datetime import datetime, timezone

from src.wazuh_health.contracts import ProbeResult
from src.wazuh_health.store.audit_store import AuditStore


def _format_metrics(metrics: dict[str, float | int]) -> list[str]:
    if not metrics:
        return ["- (no metrics)"]
    return [f"- `{k}`: **{v}**" for k, v in sorted(metrics.items())]


def _format_top_buckets(buckets: list[dict]) -> list[str]:
    if not buckets:
        return ["_(no noisy buckets above threshold)_"]
    lines = []
    for b in buckets[:5]:
        lines.append(
            f"- **{b.get('rule_id')}** ({b.get('rule_description', '')[:60]}) — "
            f"count: {b.get('count')}, level: {b.get('rule_level')}, "
            f"score: {b.get('noise_score')}"
        )
    return lines


def _format_recommendations(recs: list[dict]) -> list[str]:
    if not recs:
        return ["_(no recommendations)_"]
    lines = []
    for r in recs[:10]:
        lines.append(
            f"- `{r.get('type')}` [{r.get('risk')}] — **rule {r.get('rule_id')}**: "
            f"{r.get('title', '')[:80]}"
        )
        if reason := r.get("reason"):
            lines.append(f"  - {reason}")
    return lines


def build_email_digest(audit: AuditStore) -> tuple[str, str]:
    """Compose (subject, markdown_body) from the latest probe runs.

    Reads the most recent run of each probe (capacity, hygiene, coverage) and
    summarises metrics + hygiene recommendations. Returns plain Markdown.
    """
    now_iso = datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
    capacity: ProbeResult | None = audit.latest_probe_run("capacity")
    hygiene: ProbeResult | None = audit.latest_probe_run("hygiene")
    coverage: ProbeResult | None = audit.latest_probe_run("coverage")

    bucket_count = 0
    rec_count = 0
    if hygiene:
        bucket_count = int(hygiene.metrics.get("noise.bucket_count", 0))
        rec_count = int(hygiene.metrics.get("noise.recommendations_count", 0))
    disk_free_pct = None
    if capacity:
        disk_free_pct = capacity.metrics.get("disk.var_ossec.free_pct")
    disconnected_agents = None
    if coverage:
        disconnected_agents = int(coverage.metrics.get("agents.disconnected", 0))

    subject_bits = []
    if disk_free_pct is not None and disk_free_pct < 15:
        subject_bits.append(f"⚠ disk {disk_free_pct}%")
    if rec_count:
        subject_bits.append(f"{rec_count} hygiene recs")
    if disconnected_agents:
        subject_bits.append(f"{disconnected_agents} agents disconnected")
    if not subject_bits:
        subject_bits.append("nominal")
    subject = "Wazuh Health digest — " + ", ".join(subject_bits)

    lines: list[str] = [
        "# Wazuh Health digest",
        "",
        f"_Generated at {now_iso}_",
        "",
        "## Capacity",
        "",
    ]
    if capacity:
        lines += _format_metrics(capacity.metrics)
        if capacity.errors:
            lines += ["", "**Probe errors:**", *[f"- `{e}`" for e in capacity.errors]]
    else:
        lines.append("_(no capacity probe results)_")

    lines += ["", "## Hygiene", ""]
    if hygiene:
        lines += [f"- Total alerts analysed: **{hygiene.metrics.get('noise.total_alerts', 0)}**"]
        lines += [f"- Bucket count: **{bucket_count}** | recommendations: **{rec_count}**"]
        lines += [
            "- Combined reduction (if applied): "
            f"**{hygiene.metrics.get('noise.combined_reduction_pct', 0)}%**"
        ]
        lines += ["", "### Top noisy buckets", ""]
        lines += _format_top_buckets(hygiene.artifacts.get("top_buckets", []))
        lines += ["", "### Conservative recommendations", ""]
        lines += _format_recommendations(hygiene.artifacts.get("recommendations", []))
    else:
        lines.append("_(no hygiene probe results)_")

    lines += ["", "## Coverage", ""]
    if coverage:
        lines += _format_metrics(coverage.metrics)
        if coverage.errors:
            lines += ["", "**Probe errors:**", *[f"- `{e}`" for e in coverage.errors]]
    else:
        lines.append("_(no coverage probe results)_")

    lines += [
        "",
        "---",
        "",
        "This digest is template-generated (no LLM). For the narrated report run "
        "`wazuh-health report` (uses the heavy model).",
        "",
    ]

    return subject, "\n".join(lines)


# ---------------------------------------------------------------------------
# Versión HTML
# ---------------------------------------------------------------------------
# El digest se mandaba como Markdown crudo en texto plano: en el cliente de
# correo se veían los `#` y los `**` literales, y era el único correo del SOC
# sin la marca. El Markdown se conserva como la parte text/plain del mensaje.
def build_email_digest_html(audit: AuditStore) -> tuple[str, str, str]:
    """Devuelve (asunto, html, texto_plano) del digest de salud del SIEM."""
    from datetime import datetime

    from src import report_theme as T

    capacity: ProbeResult | None = audit.latest_probe_run("capacity")
    hygiene: ProbeResult | None = audit.latest_probe_run("hygiene")
    coverage: ProbeResult | None = audit.latest_probe_run("coverage")

    disk_free = capacity.metrics.get("disk.var_ossec.free_pct") if capacity else None
    desconectados = int(coverage.metrics.get("agents.disconnected", 0)) if coverage else 0
    reportando = int(coverage.metrics.get("agents.active", 0)) if coverage else 0
    recs = int(hygiene.metrics.get("noise.recommendations_count", 0)) if hygiene else 0
    reduccion = hygiene.metrics.get("noise.combined_reduction_pct", 0) if hygiene else 0
    alertas = int(hygiene.metrics.get("noise.total_alerts", 0)) if hygiene else 0

    # El estado lo manda el peor indicador, no el promedio: 5% de disco libre es
    # DEGRADADO aunque todo lo demás esté impecable.
    if disk_free is not None and disk_free < 10:
        estado, badge = "DEGRADADO", "critico"
    elif (disk_free is not None and disk_free < 20) or desconectados:
        estado, badge = "ATENCION", "atencion"
    else:
        estado, badge = "OPERATIVO", "ok"

    color_disco = (
        T.C_MUTED if disk_free is None
        else T.C_CRIT if disk_free < 10
        else T.C_HIGH if disk_free < 20
        else T.C_GREEN
    )
    cards = [
        T.metric_card(
            "Disco libre en /var/ossec",
            "n/d" if disk_free is None else f"{disk_free}%",
            color_disco,
            "watermark de bloqueo al 10%",
        ),
        T.metric_card(
            "Agentes desconectados", T.num(desconectados),
            T.C_CRIT if desconectados else T.C_GREEN,
            f"de {T.num(reportando + desconectados)} registrados" if reportando else "",
        ),
        T.metric_card(
            "Reglas candidatas a tuning", T.num(recs), T.C_GREEN if recs else T.C_MUTED,
            f"hasta -{reduccion}% de ruido" if recs else "sin candidatas",
        ),
    ]

    cuerpo = T.section(
        "Estado del SIEM",
        f"{alertas and T.num(alertas) or 'sin'} alertas analizadas en la ventana",
        T.metric_row(cards),
    )

    if capacity:
        cuerpo += T.section(
            "Capacidad", "Disco, shards y tareas pendientes del indexer",
            T.kv_rows([(k, f"<strong>{v}</strong>") for k, v in sorted(capacity.metrics.items())])
            + (T.notice("<strong>Errores del probe:</strong><br>"
                        + "<br>".join(T.code(e) for e in capacity.errors), accent=T.C_CRIT,
                        bg=T.C_BAD_BG) if capacity.errors else ""),
        )

    if hygiene:
        buckets = hygiene.artifacts.get("top_buckets", []) or []
        tabla = ""
        if buckets:
            tabla = T.table_open([
                ("REGLA", "80", "left"), ("DESCRIPCI&Oacute;N", None, "left"),
                ("NIVEL", "60", "center"), ("EVENTOS", "80", "right"),
            ])
            for i, b in enumerate(buckets[:8]):
                tabla += T.table_row([
                    (T.code(b.get("rule_id")), "left", ""),
                    (str(b.get("rule_description", ""))[:70], "left", ""),
                    (str(b.get("rule_level", "-")), "center", ""),
                    (T.num(b.get("count", 0)), "right", "font-weight:bold;"),
                ], i)
            tabla += T.TABLE_CLOSE

        lista = hygiene.artifacts.get("recommendations", []) or []
        items = [
            (f"<strong>Regla {r.get('rule_id')}</strong> &mdash; {str(r.get('title',''))[:90]}"
             + (f'<div style="color:{T.C_MUTED};font-size:12px;padding-top:2px;">'
                f"{r.get('reason')}</div>" if r.get("reason") else ""),
             T.C_HIGH if str(r.get("risk", "")).lower() in ("high", "alto") else T.C_GREEN)
            for r in lista[:10]
        ]
        cuerpo += T.section(
            "Higiene del ruleset",
            "Reglas m&aacute;s ruidosas y qu&eacute; se podr&iacute;a suprimir sin quedar ciego",
            tabla
            + (T.spacer(16) + T.bullet_list(items) if items else "")
            + T.notice(
                "Ninguna regla de autenticaci&oacute;n o pol&iacute;tica, ninguna de nivel &ge; 8 "
                "y ninguna en la lista blanca del SOAR entra como candidata a supresi&oacute;n: "
                "silenciar cualquiera de esas deja al SOC ciego justo donde mira.",
                accent=T.C_MUTED, bg=T.C_SOFT,
            ),
        )

    if coverage:
        cuerpo += T.section(
            "Cobertura", "Agentes reportando y fuentes que dejaron de mandar logs",
            T.kv_rows([(k, f"<strong>{v}</strong>") for k, v in sorted(coverage.metrics.items())]),
        )

    hoy = datetime.now().strftime("%d/%m/%Y")
    html = T.document(
        title="Salud del SIEM",
        subtitle=f"Digest diario &nbsp;&middot;&nbsp; {hoy}",
        body=cuerpo,
        footer="Correo <strong>interno</strong> del SOC, no va al cliente.<br>"
               "Generado con plantilla determin&iacute;stica, sin LLM.",
        doc_title="Salud del SIEM - Grupo Alemana",
        badge_kind=badge,
        preheader=(
            f"{estado} &middot; disco {disk_free if disk_free is not None else 'n/d'}% libre "
            f"&middot; {desconectados} agentes desconectados"
        ),
    )
    _, markdown = build_email_digest(audit)
    detalle = f"{desconectados} agentes desconectados" if desconectados else ""
    return T.subject("SIEM", estado, detalle), html, markdown
