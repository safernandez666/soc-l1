import { Link, useParams } from "react-router-dom"
import { api, type CaseDetail, type TimelineEvent } from "@/lib/api"
import { useFetch } from "@/lib/useFetch"
import { StateView } from "@/components/StateView"
import { StatusBadge, RiskPill } from "@/components/badges"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

const STATUS_LABEL: Record<string, string> = {
  pending: "Pendiente",
  approved: "Aprobado",
  executed: "Ejecutado",
  rejected: "Rechazado",
  expired: "Expirado",
}

// Reconstruye el timeline igual que render.case_page: eventos base + decisión + ejecución.
function buildTimeline(c: CaseDetail): TimelineEvent[] {
  const events: TimelineEvent[] = [...(c.timeline || [])]
  if (c.decided_at) {
    events.push({
      stage: "decision",
      ts: c.decided_at,
      summary: `${STATUS_LABEL[c.status] ?? c.status} por ${c.decided_by_ip ?? "?"}`,
      detail: (c.decided_by_ua || "").slice(0, 120) || null,
    })
  }
  if (c.executed_at) {
    const nOk = c.execution_result.filter((er) => er && er.ok).length
    events.push({
      stage: "execution",
      ts: c.executed_at,
      summary: `${nOk}/${c.execution_result.length} acciones ok`,
      detail: null,
    })
  }
  events.sort((a, b) => (a.ts || "").localeCompare(b.ts || ""))
  return events
}

function Kv({ k, v }: { k: string; v: string }) {
  return (
    <>
      <div className="text-muted-foreground">{k}</div>
      <div className="font-mono text-xs break-all">{v}</div>
    </>
  )
}

export function CasePage() {
  const { rowid } = useParams()
  const state = useFetch(() => api.case(rowid!), [rowid])

  return (
    <StateView state={state}>
      {(c) => {
        const alert = c.alert || {}
        const plan = c.plan || {}
        const device = alert.device || {}
        const users = (alert.users_involved || [])
          .map((u) => u.sam || "?")
          .join(", ") || "—"
        const actions = plan.actions || []
        const selected = new Set(c.selected_actions || [])
        const hasSelection = (c.selected_actions || []).length > 0
        const timeline = buildTimeline(c)

        return (
          <div className="space-y-5">
            <Link
              to="/queue"
              className="text-sm text-muted-foreground hover:text-foreground"
            >
              ← Volver a la cola
            </Link>

            {/* Header */}
            <Card>
              <CardContent className="space-y-2">
                <div className="text-xs font-mono text-muted-foreground">
                  {c.alert_id}
                </div>
                <div className="flex items-start justify-between gap-4 flex-wrap">
                  <h1 className="text-2xl font-semibold">
                    {alert.title || "Caso"}
                  </h1>
                  <div className="flex gap-2">
                    <RiskPill risk={plan.risk_level} />
                    <StatusBadge status={c.status} />
                  </div>
                </div>
              </CardContent>
            </Card>

            <div className="grid gap-5 lg:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">Resumen ejecutivo</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-[var(--zs-text-secondary)]">
                    {plan.executive_summary || "—"}
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">Contexto</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
                    <Kv k="Host" v={device.hostname || device.fqdn || "—"} />
                    <Kv k="IP interna" v={device.internal_ip || "—"} />
                    <Kv k="Usuarios" v={users} />
                    <Kv k="Severidad origen" v={alert.severity_source || "—"} />
                    <Kv k="Categoría" v={alert.category || "—"} />
                    <Kv
                      k="Ticket InvGate"
                      v={c.invgate_request_id ? `#${c.invgate_request_id}` : "—"}
                    />
                    <Kv k="Decidido por" v={c.decided_by_ip || "—"} />
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Acciones propuestas */}
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Acciones propuestas</CardTitle>
              </CardHeader>
              <CardContent className={actions.length ? "p-0" : ""}>
                {actions.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    El plan no propone acciones.
                  </p>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Acción</TableHead>
                        <TableHead>Target</TableHead>
                        <TableHead>Justificación</TableHead>
                        <TableHead className="text-right">Elegida</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {actions.map((a, i) => {
                        const chosen = !hasSelection || selected.has(i)
                        return (
                          <TableRow key={i}>
                            <TableCell className="font-mono text-xs">
                              {a.type}
                            </TableCell>
                            <TableCell className="font-mono text-xs">
                              {a.target || "—"}
                            </TableCell>
                            <TableCell className="text-xs text-muted-foreground">
                              {a.justification || "—"}
                            </TableCell>
                            <TableCell className="text-right">
                              <Badge
                                variant="outline"
                                style={{
                                  borderColor: chosen
                                    ? "var(--zs-ok)"
                                    : "var(--zs-text-muted)",
                                  color: chosen
                                    ? "var(--zs-ok)"
                                    : "var(--zs-text-muted)",
                                }}
                              >
                                {chosen ? "sí" : "no"}
                              </Badge>
                            </TableCell>
                          </TableRow>
                        )
                      })}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>

            {/* Resultado de ejecución */}
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Resultado de ejecución</CardTitle>
              </CardHeader>
              <CardContent className={c.execution_result.length ? "p-0" : ""}>
                {c.execution_result.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    Todavía no ejecutado.
                  </p>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Acción</TableHead>
                        <TableHead>Target</TableHead>
                        <TableHead>Resultado</TableHead>
                        <TableHead>Mensaje</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {c.execution_result.map((er, i) => (
                        <TableRow key={i}>
                          <TableCell className="font-mono text-xs">
                            {er.action_type}
                          </TableCell>
                          <TableCell className="font-mono text-xs">
                            {er.target || "—"}
                          </TableCell>
                          <TableCell>
                            <Badge
                              variant="outline"
                              style={{
                                borderColor: er.ok
                                  ? "var(--zs-ok)"
                                  : "var(--zs-danger)",
                                color: er.ok
                                  ? "var(--zs-ok)"
                                  : "var(--zs-danger)",
                              }}
                            >
                              {er.ok ? "ok" : "fail"}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            {er.message || "—"}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>

            <div className="grid gap-5 lg:grid-cols-2">
              {/* Timeline */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">Timeline</CardTitle>
                </CardHeader>
                <CardContent>
                  {timeline.length === 0 ? (
                    <p className="text-sm text-muted-foreground">Sin eventos.</p>
                  ) : (
                    <ul className="space-y-4">
                      {timeline.map((e, i) => (
                        <li key={i} className="relative pl-5">
                          <span className="absolute left-0 top-1.5 h-2 w-2 rounded-full bg-primary" />
                          <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                            {e.stage}
                          </div>
                          <div className="text-[11px] text-muted-foreground">
                            {e.ts}
                          </div>
                          <div className="text-sm">{e.summary}</div>
                          {e.detail && (
                            <div className="text-xs text-muted-foreground">
                              {e.detail}
                            </div>
                          )}
                        </li>
                      ))}
                    </ul>
                  )}
                </CardContent>
              </Card>

              {/* Rationale */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">Análisis (rationale)</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-[var(--zs-text-secondary)] whitespace-pre-wrap">
                    {plan.rationale || "—"}
                  </p>
                </CardContent>
              </Card>
            </div>
          </div>
        )
      }}
    </StateView>
  )
}
