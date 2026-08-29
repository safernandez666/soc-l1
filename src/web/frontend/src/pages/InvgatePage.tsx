import { Link } from "react-router-dom"
import { api, type InvgateReconcile, type InvgateState, type CaseSummary } from "@/lib/api"
import { useFetch } from "@/lib/useFetch"
import { StateView } from "@/components/StateView"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

const STATE_META: Record<InvgateState, { label: string; color: string }> = {
  resuelto: { label: "Resuelto", color: "var(--zs-ok)" },
  abierto: { label: "Abierto", color: "var(--zs-danger)" },
  sin_verificar: { label: "Sin verificar", color: "var(--zs-warn)" },
  sin_ticket: { label: "Sin ticket", color: "var(--zs-text-muted)" },
}

const TERMINAL = new Set(["executed", "rejected", "expired"])

function fmtTs(ts: string | null): string {
  if (!ts) return "—"
  const d = new Date(ts)
  return isNaN(d.getTime()) ? ts : d.toLocaleString("es-AR")
}

function StateBadge({ state }: { state: InvgateState }) {
  const m = STATE_META[state]
  return (
    <Badge variant="outline" style={{ borderColor: m.color, color: m.color }}>
      {m.label}
    </Badge>
  )
}

function Stat({
  label,
  value,
  accent,
}: {
  label: string
  value: number
  accent?: string
}) {
  return (
    <Card className="gap-2">
      <CardHeader className="pb-0">
        <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          {label}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div
          className="text-3xl font-semibold tabular-nums"
          style={accent ? { color: accent } : undefined}
        >
          {value}
        </div>
      </CardContent>
    </Card>
  )
}

function Body({ d }: { d: InvgateReconcile }) {
  const c = d.counts
  return (
    <div className="space-y-8">
      <section className="flex flex-wrap items-center gap-3">
        <h1 className="text-2xl font-semibold tracking-tight">InvGate · fuente de verdad</h1>
        <span className="text-xs text-muted-foreground">
          {d.total_with_ticket} casos con ticket · última verificación: {fmtTs(d.last_checked)}
        </span>
      </section>

      <section className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Stat label="Resueltos" value={c.resuelto ?? 0} accent="var(--zs-ok)" />
        <Stat label="Abiertos" value={c.abierto ?? 0} accent={(c.abierto ?? 0) > 0 ? "var(--zs-danger)" : undefined} />
        <Stat label="Sin verificar" value={c.sin_verificar ?? 0} accent={(c.sin_verificar ?? 0) > 0 ? "var(--zs-warn)" : undefined} />
        <Stat label="Con ticket" value={d.total_with_ticket} />
      </section>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">
            Tickets abiertos / sin verificar ({d.open_cases.length})
          </CardTitle>
        </CardHeader>
        <CardContent className={d.open_cases.length ? "p-0" : ""}>
          {d.open_cases.length === 0 ? (
            <p className="px-6 py-8 text-center text-sm text-muted-foreground">
              🎉 Todos los tickets con caso están resueltos en InvGate.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Caso</TableHead>
                    <TableHead>Título</TableHead>
                    <TableHead>Host</TableHead>
                    <TableHead>Estado zSOC</TableHead>
                    <TableHead>Ticket</TableHead>
                    <TableHead>Estado InvGate</TableHead>
                    <TableHead>Verificado</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {d.open_cases.map((c: CaseSummary) => (
                    <TableRow key={c.rowid}>
                      <TableCell>
                        <Link className="text-primary hover:underline" to={`/case/${c.rowid}`}>
                          #{c.rowid}
                        </Link>
                      </TableCell>
                      <TableCell className="max-w-[24ch] truncate" title={c.title}>
                        {c.title}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{c.host}</TableCell>
                      <TableCell>
                        <span
                          className="text-xs"
                          style={TERMINAL.has(c.status) ? { color: "var(--zs-danger)" } : undefined}
                          title={
                            TERMINAL.has(c.status)
                              ? "Nuestro lado ya terminó pero el ticket sigue abierto"
                              : undefined
                          }
                        >
                          {c.status}
                        </span>
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {c.invgate_request_id ? `#${c.invgate_request_id}` : "—"}
                        {c.invgate_status_id != null && (
                          <span className="text-muted-foreground"> (st {c.invgate_status_id})</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <StateBadge state={c.invgate_state} />
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {fmtTs(c.invgate_checked_at)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

export function InvgatePage() {
  const state = useFetch(() => api.invgate(), [])
  return (
    <StateView state={state}>
      {(d) => <Body d={d} />}
    </StateView>
  )
}
