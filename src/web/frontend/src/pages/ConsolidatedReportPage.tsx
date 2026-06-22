import { Link, useSearchParams } from "react-router-dom"
import { api, type ReportFilters, type CaseSummary } from "@/lib/api"
import { useFetch } from "@/lib/useFetch"
import { StateView } from "@/components/StateView"

const RISK_ORDER = ["critical", "high", "medium", "low", "unknown"]
const RISK_LABEL: Record<string, string> = {
  critical: "Crítico",
  high: "Alto",
  medium: "Medio",
  low: "Bajo",
  unknown: "—",
}
const STATUS_ORDER = ["pending", "approved", "executed", "rejected", "expired"]
const STATUS_LABEL: Record<string, string> = {
  pending: "Pendiente",
  approved: "Aprobado",
  executed: "Ejecutado",
  rejected: "Rechazado",
  expired: "Expirado",
}

function fmtDate(s: string | null): string {
  if (!s) return "—"
  const d = new Date(s.length <= 10 ? `${s}T00:00:00` : s)
  return isNaN(d.getTime()) ? s : d.toLocaleDateString("es-AR")
}

function count<T extends string>(cases: CaseSummary[], key: (c: CaseSummary) => T) {
  const m: Record<string, number> = {}
  for (const c of cases) m[key(c)] = (m[key(c)] ?? 0) + 1
  return m
}

function Cell({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-zinc-200 px-3 py-2">
      <div className="text-[10px] uppercase tracking-wide text-zinc-500">{label}</div>
      <div className="text-xl font-semibold tabular-nums">{value}</div>
    </div>
  )
}

export function ConsolidatedReportPage() {
  const [sp] = useSearchParams()
  const filters: ReportFilters = {
    date_from: sp.get("date_from") ?? undefined,
    date_to: sp.get("date_to") ?? undefined,
    status: sp.get("status") ?? undefined,
    risk: sp.get("risk") ?? undefined,
  }
  const state = useFetch(
    () => api.reports(filters),
    [filters.date_from, filters.date_to, filters.status, filters.risk]
  )

  return (
    <div
      className="min-h-svh bg-zinc-200 py-8 print:bg-white print:py-0"
      style={{ printColorAdjust: "exact", WebkitPrintColorAdjust: "exact" } as React.CSSProperties}
    >
      <div className="mx-auto max-w-3xl overflow-hidden rounded-lg bg-white text-zinc-900 shadow-lg print:max-w-none print:rounded-none print:shadow-none">
        <StateView state={state}>
          {(d) => {
            const byRisk = count(d.cases, (c) => c.risk_level || "unknown")
            const byStatus = count(d.cases, (c) => c.status)
            const decided = (byStatus.approved ?? 0) + (byStatus.executed ?? 0) + (byStatus.rejected ?? 0)
            const approved = (byStatus.approved ?? 0) + (byStatus.executed ?? 0)
            const approvalRate = decided ? Math.round((100 * approved) / decided) : null

            return (
              <>
                <div className="flex items-center justify-between bg-zinc-100 px-6 py-3 print:hidden">
                  <Link to="/reportes" className="text-sm text-zinc-500 hover:text-zinc-900">
                    ← Volver a Reportes
                  </Link>
                  <button
                    onClick={() => window.print()}
                    className="rounded-md bg-[#0a0a0b] px-4 py-1.5 text-sm font-medium text-[#a3e635] hover:opacity-90"
                  >
                    Imprimir / Guardar PDF
                  </button>
                </div>

                <header className="flex items-center justify-between bg-[#0a0a0b] px-8 py-6 text-white">
                  <img src="/ui/static/zebra-logo.svg" alt="ZebraSecurity" className="h-10 w-auto" />
                  <div className="text-right">
                    <div className="text-sm font-semibold">Informe consolidado</div>
                    <div className="text-xs text-zinc-400">SOC-L1 · ZebraSecurity</div>
                  </div>
                </header>

                <div className="px-8 py-7">
                  <h1 className="text-2xl font-semibold">Resumen del período</h1>
                  <p className="mt-1 text-sm text-zinc-500">
                    {fmtDate(filters.date_from ?? null)} → {fmtDate(filters.date_to ?? null)}
                    {filters.status ? ` · estado: ${filters.status}` : ""}
                    {filters.risk ? ` · riesgo: ${filters.risk}` : ""}
                  </p>

                  <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
                    <Cell label="Casos" value={d.total} />
                    <Cell label="Decididos" value={decided} />
                    <Cell label="Aprobados" value={approved} />
                    <div className="rounded-md border border-zinc-200 px-3 py-2">
                      <div className="text-[10px] uppercase tracking-wide text-zinc-500">
                        Tasa aprobación
                      </div>
                      <div className="text-xl font-semibold tabular-nums">
                        {approvalRate === null ? "—" : `${approvalRate}%`}
                      </div>
                    </div>
                  </div>

                  <div className="mt-6 grid gap-6 sm:grid-cols-2">
                    <div>
                      <h2 className="mb-2 border-b border-zinc-200 pb-1 text-[11px] font-bold uppercase tracking-[0.14em] text-zinc-500">
                        Por riesgo
                      </h2>
                      {RISK_ORDER.filter((r) => byRisk[r]).map((r) => (
                        <div key={r} className="flex justify-between py-0.5 text-sm">
                          <span className="text-zinc-600">{RISK_LABEL[r]}</span>
                          <span className="tabular-nums">{byRisk[r]}</span>
                        </div>
                      ))}
                    </div>
                    <div>
                      <h2 className="mb-2 border-b border-zinc-200 pb-1 text-[11px] font-bold uppercase tracking-[0.14em] text-zinc-500">
                        Por estado
                      </h2>
                      {STATUS_ORDER.filter((s) => byStatus[s]).map((s) => (
                        <div key={s} className="flex justify-between py-0.5 text-sm">
                          <span className="text-zinc-600">{STATUS_LABEL[s]}</span>
                          <span className="tabular-nums">{byStatus[s]}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <h2 className="mt-7 mb-2 border-b border-zinc-200 pb-1 text-[11px] font-bold uppercase tracking-[0.14em] text-zinc-500">
                    Casos ({d.cases.length})
                  </h2>
                  {d.cases.length === 0 ? (
                    <p className="text-sm text-zinc-500">Sin casos en el período.</p>
                  ) : (
                    <table className="w-full text-left text-sm">
                      <thead>
                        <tr className="border-b border-zinc-200 text-[11px] uppercase tracking-wide text-zinc-400">
                          <th className="py-1.5 pr-3 font-medium">Fecha</th>
                          <th className="py-1.5 pr-3 font-medium">Host</th>
                          <th className="py-1.5 pr-3 font-medium">Caso</th>
                          <th className="py-1.5 pr-3 font-medium">Riesgo</th>
                          <th className="py-1.5 font-medium">Estado</th>
                        </tr>
                      </thead>
                      <tbody>
                        {d.cases.map((c) => (
                          <tr key={c.rowid} className="border-b border-zinc-100 align-top">
                            <td className="py-1.5 pr-3 text-xs text-zinc-500 whitespace-nowrap">
                              {fmtDate(c.created_at)}
                            </td>
                            <td className="py-1.5 pr-3 font-mono text-xs">{c.host}</td>
                            <td className="py-1.5 pr-3">{c.title}</td>
                            <td className="py-1.5 pr-3 text-xs">
                              {RISK_LABEL[c.risk_level] ?? c.risk_level}
                            </td>
                            <td className="py-1.5 text-xs">
                              {STATUS_LABEL[c.status] ?? c.status}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}

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
