import { useState } from "react"
import { Link, useParams } from "react-router-dom"
import {
  api,
  type PlanAction,
  type CaseDetail,
  type ExecMode,
  type Session,
  type TimelineEvent,
} from "@/lib/api"
import { useFetch } from "@/lib/useFetch"
import { simulatedFamilies, useExecMode } from "@/lib/useExecMode"
import { statusLabel } from "@/lib/status"
import { StateView } from "@/components/StateView"
import { StatusBadge, RiskPill } from "@/components/badges"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

// Reconstruye el timeline igual que render.case_page: eventos base + decisión + ejecución.
function buildTimeline(c: CaseDetail): TimelineEvent[] {
  const events: TimelineEvent[] = [...(c.timeline || [])]
  if (c.decided_at) {
    events.push({
      stage: "decision",
      ts: c.decided_at,
      summary: `${statusLabel(c.status)} por ${c.decided_by_ip ?? "?"}`,
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

/** Aviso de modo simulación. Sin esto el panel mostraba "ok" en acciones
 *  que nunca tocaron FortiGate, AD ni Defender. */
function DryRunNotice({
  mode,
  session,
  pending,
}: {
  mode: ExecMode
  session: Session | null
  pending: boolean
}) {
  const familias = simulatedFamilies(session)
  const detalle =
    mode === "mixed" && familias.length > 0
      ? `Se simulan: ${familias.join(", ")}. El resto se ejecuta de verdad.`
      : "Las acciones quedan registradas pero no se aplican en FortiGate, AD ni Defender."
  return (
    <div
      className="flex items-start gap-3 rounded-xl px-4 py-3.5"
      style={{
        background: "color-mix(in oklab, var(--zs-warn) 7%, transparent)",
        boxShadow: "inset 0 0 0 1px color-mix(in oklab, var(--zs-warn) 30%, transparent)",
      }}
    >
      <svg
        viewBox="0 0 24 24"
        fill="none"
        stroke="var(--zs-warn)"
        strokeWidth={2}
        strokeLinecap="round"
        strokeLinejoin="round"
        className="mt-0.5 h-[18px] w-[18px] shrink-0"
        aria-hidden
      >
        <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3z" />
        <path d="M12 9v4" />
        <path d="M12 17h.01" />
      </svg>
      <div className="flex flex-col gap-0.5">
        <div className="text-sm font-semibold" style={{ color: "var(--zs-warn)" }}>
          {pending ? "Al aprobar, se simula" : "Modo simulación activo"}
        </div>
        <div className="text-[13px] leading-relaxed text-[var(--zs-text-secondary)]">
          {detalle}
        </div>
      </div>
    </div>
  )
}

/** Barra de decisión. Hasta acá el panel era solo-lectura y la única forma de
 *  aprobar era el link del correo; esto pega contra la misma ruta de decisión. */
function DecisionBar({
  rowid,
  actions,
  mode,
  onDecided,
}: {
  rowid: string
  actions: PlanAction[]
  mode: ExecMode | null
  onDecided: () => void
}) {
  const [selected, setSelected] = useState<Set<number>>(
    () => new Set(actions.map((_, i) => i))
  )
  const [busy, setBusy] = useState<null | "approved" | "rejected">(null)
  const [error, setError] = useState<string | null>(null)

  const toggle = (i: number) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(i)) next.delete(i)
      else next.add(i)
      return next
    })
  }

  const decide = async (decision: "approved" | "rejected") => {
    setBusy(decision)
    setError(null)
    try {
      await api.decide(
        rowid,
        decision,
        decision === "approved" ? [...selected].sort((a, b) => a - b) : null
      )
      onDecided()
    } catch (e) {
      setError(e instanceof Error ? e.message : "No se pudo registrar la decisión")
      setBusy(null)
    }
  }

  const n = selected.size
  const approveLabel =
    mode === "live"
      ? "Aprobar y ejecutar"
      : mode === "dry_run"
        ? "Aprobar y simular"
        : "Aprobar"

  return (
    <Card style={{ boxShadow: "inset 0 0 0 1px color-mix(in oklab, var(--primary) 30%, transparent)" }}>
      <CardHeader>
        <CardTitle className="text-sm">Decisión</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {actions.length > 0 && (
          <div className="flex flex-col gap-2">
            {actions.map((a, i) => (
              <label
                key={i}
                className="flex cursor-pointer items-start gap-3 rounded-md px-2 py-1.5 hover:bg-muted/50"
              >
                <input
                  type="checkbox"
                  checked={selected.has(i)}
                  onChange={() => toggle(i)}
                  disabled={busy !== null}
                  className="mt-0.5 h-4 w-4 shrink-0 accent-[var(--primary)]"
                />
                <span className="flex flex-col gap-0.5">
                  <span className="font-mono text-xs">
                    {a.type} → {a.target || "—"}
                  </span>
                  {a.justification && (
                    <span className="text-xs text-muted-foreground">
                      {a.justification}
                    </span>
                  )}
                </span>
              </label>
            ))}
          </div>
        )}

        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex flex-col gap-0.5">
            <div className="text-sm font-medium">
              {actions.length === 0
                ? "El plan no propone acciones"
                : `${n} de ${actions.length} acción${actions.length === 1 ? "" : "es"} elegida${n === 1 ? "" : "s"}`}
            </div>
            <div className="text-xs text-muted-foreground">
              Queda registrado con tu IP y timestamp en el timeline del caso.
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              onClick={() => decide("rejected")}
              disabled={busy !== null}
              style={{ borderColor: "color-mix(in oklab, var(--zs-danger) 45%, transparent)", color: "var(--zs-danger)" }}
            >
              {busy === "rejected" ? "Rechazando…" : "Rechazar"}
            </Button>
            <Button
              onClick={() => decide("approved")}
              disabled={busy !== null}
            >
              {busy === "approved" ? "Aprobando…" : approveLabel}
            </Button>
          </div>
        </div>

        {error && (
          <p className="text-sm" style={{ color: "var(--zs-danger)" }}>
            {error}
          </p>
        )}
      </CardContent>
    </Card>
  )
}

export function CasePage() {
  const { rowid } = useParams()
  // Se incrementa al decidir para refrescar el caso sin recargar la página.
  const [reload, setReload] = useState(0)
  const state = useFetch(() => api.case(rowid!), [rowid, reload])
  const { mode, session } = useExecMode()

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
        const isPending = c.status === "pending"
        const anySimulated = c.execution_result.some((er) => er?.simulated)
        const showNotice =
          (mode === "dry_run" || mode === "mixed") && (isPending || anySimulated)

        return (
          <div className="space-y-5">
            <Link
              to="/queue"
              className="text-sm text-muted-foreground hover:text-foreground"
            >
              ← Volver a la cola
            </Link>

            {showNotice && mode && (
              <DryRunNotice mode={mode} session={session} pending={isPending} />
            )}

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
                  <div className="flex items-center gap-2">
                    <RiskPill risk={plan.risk_level} />
                    <StatusBadge status={c.status} />
                    <Link
                      to={`/case/${rowid}/report`}
                      className="rounded-md border border-primary/40 bg-primary/10 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/20"
                    >
                      Informe
                    </Link>
                  </div>
                </div>
              </CardContent>
            </Card>

            {isPending && rowid && (
              <DecisionBar
                rowid={rowid}
                actions={actions}
                mode={mode}
                onDecided={() => setReload((r) => r + 1)}
              />
            )}

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

            {/* Acciones propuestas — cuando el caso ya se decidió. Mientras está
                pendiente, las acciones se eligen arriba en la barra de decisión. */}
            {!isPending && (
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
            )}

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
                            <div className="flex items-center gap-1.5">
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
                              {er.simulated && (
                                <Badge
                                  variant="outline"
                                  className="text-[10px] uppercase tracking-wide"
                                  style={{
                                    borderColor:
                                      "color-mix(in oklab, var(--zs-warn) 45%, transparent)",
                                    color: "var(--zs-warn)",
                                  }}
                                  title="Simulada: no se aplicó en el sistema destino"
                                >
                                  simulada
                                </Badge>
                              )}
                            </div>
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
