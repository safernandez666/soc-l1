import { Link, useParams } from "react-router-dom"
import { api, type CaseDetail, type TimelineEvent } from "@/lib/api"
import { useFetch } from "@/lib/useFetch"
import { StateView } from "@/components/StateView"

const STATUS_LABEL: Record<string, string> = {
  pending: "Pendiente",
  approved: "Aprobado",
  executed: "Ejecutado",
  rejected: "Rechazado",
  expired: "Expirado",
}

const RISK_LABEL: Record<string, string> = {
  critical: "Crítico",
  high: "Alto",
  medium: "Medio",
  low: "Bajo",
}

function buildTimeline(c: CaseDetail): TimelineEvent[] {
  const events: TimelineEvent[] = [...(c.timeline || [])]
  if (c.decided_at) {
    events.push({
      stage: "decision",
      ts: c.decided_at,
      summary: `${STATUS_LABEL[c.status] ?? c.status} por ${c.decided_by_ip ?? "?"}`,
      detail: (c.decided_by_ua || "").slice(0, 160) || null,
    })
  }
  if (c.executed_at) {
    const nOk = c.execution_result.filter((er) => er && er.ok).length
    events.push({
      stage: "execution",
      ts: c.executed_at,
      summary: `${nOk}/${c.execution_result.length} acciones ejecutadas ok`,
      detail: null,
    })
  }
  events.sort((a, b) => (a.ts || "").localeCompare(b.ts || ""))
  return events
}

function fmtTs(ts: string | null | undefined): string {
  if (!ts) return "—"
  const d = new Date(ts)
  return isNaN(d.getTime()) ? ts : d.toLocaleString("es-AR")
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mt-7 break-inside-avoid">
      <h2 className="mb-2 border-b border-zinc-200 pb-1 text-[11px] font-bold uppercase tracking-[0.14em] text-zinc-500">
        {title}
      </h2>
      {children}
    </section>
  )
}

export function ReportPage() {
  const { rowid } = useParams()
  const state = useFetch(() => api.case(rowid!), [rowid])

  return (
    <div
      className="min-h-svh bg-zinc-200 py-8 print:bg-white print:py-0"
      style={{ printColorAdjust: "exact", WebkitPrintColorAdjust: "exact" } as React.CSSProperties}
    >
      <div className="mx-auto max-w-3xl overflow-hidden rounded-lg bg-white text-zinc-900 shadow-lg print:max-w-none print:rounded-none print:shadow-none">
        <StateView state={state}>
          {(c) => {
            const alert = c.alert || {}
            const plan = c.plan || {}
            const device = alert.device || {}
            const users =
              (alert.users_involved || []).map((u) => u.sam || "?").join(", ") || "—"
            const actions = plan.actions || []
            const selected = new Set(c.selected_actions || [])
            const hasSel = (c.selected_actions || []).length > 0
            const timeline = buildTimeline(c)

            return (
              <>
                {/* Toolbar (no se imprime) */}
                <div className="flex items-center justify-between bg-zinc-100 px-6 py-3 print:hidden">
                  <Link
                    to={`/case/${rowid}`}
                    className="text-sm text-zinc-500 hover:text-zinc-900"
                  >
                    ← Volver al caso
                  </Link>
                  <button
                    onClick={() => window.print()}
                    className="rounded-md bg-[#0a0a0b] px-4 py-1.5 text-sm font-medium text-[#a3e635] hover:opacity-90"
                  >
                    Imprimir / Guardar PDF
                  </button>
                </div>

                {/* Header de marca */}
                <header className="flex items-center justify-between bg-[#0a0a0b] px-8 py-6 text-white">
                  <img
                    src="/ui/static/zebra-logo.svg"
                    alt="ZebraSecurity"
                    className="h-10 w-auto"
                  />
                  <div className="text-right">
                    <div className="text-sm font-semibold">Informe de caso</div>
                    <div className="text-xs text-zinc-400">SOC-L1 · ZebraSecurity</div>
                  </div>
                </header>

                <div className="px-8 py-7">
                  {/* Título + meta */}
                  <div className="font-mono text-[11px] text-zinc-400">{c.alert_id}</div>
                  <h1 className="mt-1 text-2xl font-semibold leading-tight">
                    {alert.title || "Caso"}
                  </h1>
                  <div className="mt-3 flex flex-wrap gap-2 text-xs">
                    <span className="rounded-full border border-[#a3e635] bg-[#a3e635]/10 px-3 py-1 font-semibold text-[#3f6212]">
                      Riesgo: {plan.risk_level ? RISK_LABEL[plan.risk_level] ?? plan.risk_level : "—"}
                    </span>
                    <span className="rounded-full border border-zinc-300 px-3 py-1 font-medium text-zinc-600">
                      {STATUS_LABEL[c.status] ?? c.status}
                    </span>
                  </div>

                  <Section title="Resumen ejecutivo (IA)">
                    <p className="text-sm leading-relaxed text-zinc-700">
                      {plan.executive_summary || "—"}
                    </p>
                  </Section>

                  <Section title="Contexto">
                    <dl className="grid grid-cols-[140px_1fr] gap-x-4 gap-y-1.5 text-sm">
                      {[
                        ["Host", device.hostname || device.fqdn || "—"],
                        ["IP interna", device.internal_ip || "—"],
                        ["Usuarios", users],
                        ["Severidad origen", alert.severity_source || "—"],
                        ["Categoría", alert.category || "—"],
                        ["Ticket InvGate", c.invgate_request_id ? `#${c.invgate_request_id}` : "—"],
                        ["Creado", fmtTs(c.created_at)],
                        ["Decidido", `${fmtTs(c.decided_at)}${c.decided_by_ip ? ` · ${c.decided_by_ip}` : ""}`],
                      ].map(([k, v]) => (
                        <div key={k} className="contents">
                          <dt className="text-zinc-500">{k}</dt>
                          <dd className="font-medium text-zinc-800">{v}</dd>
                        </div>
                      ))}
                    </dl>
                  </Section>

                  <Section title="Análisis (IA)">
                    <p className="whitespace-pre-wrap text-sm leading-relaxed text-zinc-700">
                      {plan.rationale || "—"}
                    </p>
                  </Section>

                  <Section title={`Acciones propuestas (${actions.length})`}>
                    {actions.length === 0 ? (
                      <p className="text-sm text-zinc-500">El plan no propone acciones.</p>
                    ) : (
                      <table className="w-full text-left text-sm">
                        <thead>
                          <tr className="border-b border-zinc-200 text-[11px] uppercase tracking-wide text-zinc-400">
                            <th className="py-1.5 pr-3 font-medium">Acción</th>
                            <th className="py-1.5 pr-3 font-medium">Target</th>
                            <th className="py-1.5 pr-3 font-medium">Justificación</th>
                            <th className="py-1.5 font-medium">Elegida</th>
                          </tr>
                        </thead>
                        <tbody>
                          {actions.map((a, i) => (
                            <tr key={i} className="border-b border-zinc-100 align-top">
                              <td className="py-1.5 pr-3 font-mono text-xs">{a.type}</td>
                              <td className="py-1.5 pr-3 font-mono text-xs">{a.target || "—"}</td>
                              <td className="py-1.5 pr-3 text-xs text-zinc-600">{a.justification || "—"}</td>
                              <td className="py-1.5 text-xs">
                                {!hasSel || selected.has(i) ? "Sí" : "No"}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </Section>

                  {c.execution_result.length > 0 && (
                    <Section title="Resultado de ejecución">
                      <table className="w-full text-left text-sm">
                        <thead>
                          <tr className="border-b border-zinc-200 text-[11px] uppercase tracking-wide text-zinc-400">
                            <th className="py-1.5 pr-3 font-medium">Acción</th>
                            <th className="py-1.5 pr-3 font-medium">Target</th>
                            <th className="py-1.5 pr-3 font-medium">Resultado</th>
                            <th className="py-1.5 font-medium">Mensaje</th>
                          </tr>
                        </thead>
                        <tbody>
                          {c.execution_result.map((er, i) => (
                            <tr key={i} className="border-b border-zinc-100 align-top">
                              <td className="py-1.5 pr-3 font-mono text-xs">{er.action_type}</td>
                              <td className="py-1.5 pr-3 font-mono text-xs">{er.target || "—"}</td>
                              <td className="py-1.5 pr-3 text-xs font-semibold" style={{ color: er.ok ? "#3f6212" : "#b91c1c" }}>
                                {er.ok ? "OK" : "FALLÓ"}
                              </td>
                              <td className="py-1.5 text-xs text-zinc-600">{er.message || "—"}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </Section>
                  )}

                  <Section title="Timeline">
                    {timeline.length === 0 ? (
                      <p className="text-sm text-zinc-500">Sin eventos.</p>
                    ) : (
                      <ul className="space-y-2.5">
                        {timeline.map((e, i) => (
                          <li key={i} className="grid grid-cols-[150px_1fr] gap-3 text-sm">
                            <div className="text-xs text-zinc-400">{fmtTs(e.ts)}</div>
                            <div>
                              <span className="text-[11px] font-semibold uppercase tracking-wide text-zinc-500">
                                {e.stage}
                              </span>
                              <div className="text-zinc-800">{e.summary}</div>
                              {e.detail && <div className="text-xs text-zinc-500">{e.detail}</div>}
                            </div>
                          </li>
                        ))}
                      </ul>
                    )}
                  </Section>

                  <footer className="mt-8 border-t border-zinc-200 pt-3 text-[11px] text-zinc-400">
                    Generado por SOC-L1 · ZebraSecurity — {new Date().toLocaleString("es-AR")}
                  </footer>
                </div>
              </>
            )
          }}
        </StateView>
      </div>
    </div>
  )
}
