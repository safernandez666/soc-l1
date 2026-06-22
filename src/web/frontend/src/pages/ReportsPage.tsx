import { useState } from "react"
import { Link } from "react-router-dom"
import { api, type ReportFilters } from "@/lib/api"
import { useFetch } from "@/lib/useFetch"
import { StateView } from "@/components/StateView"
import { RiskPill, StatusBadge } from "@/components/badges"
import { Card, CardContent } from "@/components/ui/card"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

const STATUSES = ["pending", "approved", "executed", "rejected", "expired"]
const RISKS = ["critical", "high", "medium", "low", "unknown"]

function isoDate(d: Date): string {
  return d.toISOString().slice(0, 10)
}

function defaultFrom(): string {
  const d = new Date()
  d.setDate(d.getDate() - 30)
  return isoDate(d)
}

function fmtTs(ts: string | null): string {
  if (!ts) return "—"
  const d = new Date(ts)
  return isNaN(d.getTime()) ? ts : d.toLocaleString("es-AR")
}

const inputCls =
  "rounded-md border border-border bg-background px-2 py-1.5 text-sm outline-none focus:border-primary"

export function ReportsPage() {
  const [filters, setFilters] = useState<ReportFilters>({
    date_from: defaultFrom(),
    date_to: isoDate(new Date()),
    status: "",
    risk: "",
  })

  const state = useFetch(
    () => api.reports(filters),
    [filters.date_from, filters.date_to, filters.status, filters.risk]
  )

  const set = (k: keyof ReportFilters, v: string) =>
    setFilters((f) => ({ ...f, [k]: v }))

  const qs = new URLSearchParams()
  if (filters.date_from) qs.set("date_from", filters.date_from)
  if (filters.date_to) qs.set("date_to", filters.date_to)
  if (filters.status) qs.set("status", filters.status)
  if (filters.risk) qs.set("risk", filters.risk)
  const qsStr = qs.toString()

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <h1 className="text-2xl font-semibold tracking-tight">Reportes</h1>
        <div className="flex gap-2">
          <Link
            to={`/reportes/consolidado?${qsStr}`}
            className="rounded-md border border-primary/40 bg-primary/10 px-3 py-1.5 text-sm font-medium text-primary hover:bg-primary/20"
          >
            Informe consolidado
          </Link>
          <a
            href={api.reportsCsvUrl(filters)}
            className="rounded-md border border-border px-3 py-1.5 text-sm text-muted-foreground hover:text-foreground"
          >
            Export CSV
          </a>
        </div>
      </div>

      {/* Filtros */}
      <Card>
        <CardContent className="flex flex-wrap items-end gap-4">
          <label className="flex flex-col gap-1 text-xs text-muted-foreground">
            Desde
            <input
              type="date"
              className={inputCls}
              value={filters.date_from ?? ""}
              onChange={(e) => set("date_from", e.target.value)}
            />
          </label>
          <label className="flex flex-col gap-1 text-xs text-muted-foreground">
            Hasta
            <input
              type="date"
              className={inputCls}
              value={filters.date_to ?? ""}
              onChange={(e) => set("date_to", e.target.value)}
            />
          </label>
          <label className="flex flex-col gap-1 text-xs text-muted-foreground">
            Estado
            <select
              className={inputCls}
              value={filters.status ?? ""}
              onChange={(e) => set("status", e.target.value)}
            >
              <option value="">Todos</option>
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs text-muted-foreground">
            Riesgo
            <select
              className={inputCls}
              value={filters.risk ?? ""}
              onChange={(e) => set("risk", e.target.value)}
            >
              <option value="">Todos</option>
              {RISKS.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </label>
        </CardContent>
      </Card>

      <StateView state={state}>
        {(d) => (
          <Card>
            <CardContent className="p-0">
              <div className="border-b border-border px-4 py-2 text-xs text-muted-foreground">
                {d.total} caso{d.total === 1 ? "" : "s"} en el período
              </div>
              {d.cases.length === 0 ? (
                <p className="px-4 py-8 text-center text-sm text-muted-foreground">
                  Sin casos para esos filtros.
                </p>
              ) : (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Fecha</TableHead>
                        <TableHead>Host</TableHead>
                        <TableHead>Caso</TableHead>
                        <TableHead>Riesgo</TableHead>
                        <TableHead>Estado</TableHead>
                        <TableHead className="text-right">Informe</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {d.cases.map((c) => (
                        <TableRow key={c.rowid}>
                          <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                            {fmtTs(c.created_at)}
                          </TableCell>
                          <TableCell className="font-mono text-xs">{c.host}</TableCell>
                          <TableCell className="max-w-xs truncate">
                            <Link
                              to={`/case/${c.rowid}`}
                              className="text-foreground hover:text-primary"
                            >
                              {c.title}
                            </Link>
                          </TableCell>
                          <TableCell>
                            <RiskPill risk={c.risk_level} />
                          </TableCell>
                          <TableCell>
                            <StatusBadge status={c.status} />
                          </TableCell>
                          <TableCell className="text-right">
                            <Link
                              to={`/case/${c.rowid}/report`}
                              className="text-primary hover:underline"
                            >
                              Ver
                            </Link>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>
        )}
      </StateView>
    </div>
  )
}
