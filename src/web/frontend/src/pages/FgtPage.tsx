import { api, type FgtObservations } from "@/lib/api"
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

const REASON_LABEL: Record<string, string> = {
  would_block: "Bloquearía",
  protected: "IP protegida",
  no_srcip: "Sin srcip",
  invalid_ip: "IP inválida",
}

function Stat({
  label,
  value,
  hint,
  accent,
}: {
  label: string
  value: string | number
  hint?: string
  accent?: boolean
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
          className={`text-3xl font-semibold tabular-nums ${accent ? "text-primary" : ""}`}
        >
          {value}
        </div>
        {hint && <div className="mt-1 text-xs text-muted-foreground">{hint}</div>}
      </CardContent>
    </Card>
  )
}

function fmtTs(ts: string | null): string {
  if (!ts) return "—"
  const d = new Date(ts)
  return isNaN(d.getTime()) ? ts : d.toLocaleString("es-AR")
}

function Body({ d }: { d: FgtObservations }) {
  const s = d.summary
  const window =
    s.ventana.desde && s.ventana.hasta
      ? `${fmtTs(s.ventana.desde)} → ${fmtTs(s.ventana.hasta)}`
      : "sin datos aún"

  const topRules = Object.entries(s.por_regla)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)

  return (
    <div className="space-y-8">
      {/* Encabezado de estado */}
      <section className="flex flex-wrap items-center gap-3">
        <h1 className="text-2xl font-semibold tracking-tight">Auto-block FortiGate</h1>
        <Badge
          variant="outline"
          style={{
            borderColor: d.enabled ? "var(--zs-danger)" : "var(--zs-ok)",
            color: d.enabled ? "var(--zs-danger)" : "var(--zs-ok)",
          }}
        >
          {d.enabled ? "Fase 1 · BLOQUEANDO" : "Fase 0 · observación"}
        </Badge>
        <span className="text-xs text-muted-foreground">
          {d.rules_count} reglas · TTL {d.ttl_hours}h · ventana: {window}
        </span>
      </section>

      {/* Stats */}
      <section className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Stat label="Observaciones" value={s.total_observaciones} />
        <Stat
          label={d.enabled ? "Bloqueos" : "Bloquearía"}
          value={s.would_block}
          accent={s.would_block > 0}
        />
        <Stat label="IPs distintas" value={s.ips_distintas_que_bloquearia} />
        <Stat
          label="IPs protegidas evitadas"
          value={s.ips_protegidas_evitadas.length}
          hint={s.ips_protegidas_evitadas.length ? "el script viejo las bloquearía" : undefined}
          accent={s.ips_protegidas_evitadas.length > 0}
        />
      </section>

      {s.total_observaciones === 0 && (
        <Card>
          <CardContent className="py-8 text-center text-sm text-muted-foreground">
            Todavía sin observaciones. Aplicá el ruteo de las reglas FortiGate IPS a SOC-L1
            en <code className="text-foreground">ossec.conf</code> y reiniciá wazuh-manager
            (ver <code className="text-foreground">docs/fortigate-autoblock-runbook.md</code>).
          </CardContent>
        </Card>
      )}

      {s.ips_protegidas_evitadas.length > 0 && (
        <Card style={{ borderColor: "var(--zs-warn)" }}>
          <CardHeader>
            <CardTitle className="text-sm">
              IPs protegidas que se evitaron ({s.ips_protegidas_evitadas.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            {s.ips_protegidas_evitadas.map((ip) => (
              <span
                key={ip}
                className="rounded-md bg-secondary px-2 py-1 font-mono text-xs"
              >
                {ip}
              </span>
            ))}
          </CardContent>
        </Card>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        {/* Top reglas */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Reglas que más disparan</CardTitle>
          </CardHeader>
          <CardContent className={topRules.length ? "p-0" : ""}>
            {topRules.length === 0 ? (
              <p className="text-sm text-muted-foreground">Sin datos.</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Regla</TableHead>
                    <TableHead className="text-right">Eventos</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {topRules.map(([rule, n]) => (
                    <TableRow key={rule}>
                      <TableCell className="font-mono text-xs">{rule}</TableCell>
                      <TableCell className="text-right tabular-nums">{n}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        {/* Desglose por motivo */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Por motivo</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {Object.entries(s.por_reason).length === 0 ? (
              <p className="text-sm text-muted-foreground">Sin datos.</p>
            ) : (
              Object.entries(s.por_reason).map(([reason, n]) => (
                <div key={reason} className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">
                    {REASON_LABEL[reason] ?? reason}
                  </span>
                  <span className="tabular-nums">{n}</span>
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>

      {/* Últimas observaciones */}
      {d.recent.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Últimas decisiones</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Fecha</TableHead>
                    <TableHead>IP</TableHead>
                    <TableHead>Regla</TableHead>
                    <TableHead>Decisión</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {d.recent.map((r, i) => (
                    <TableRow key={`${r.alert_id}-${i}`}>
                      <TableCell className="text-xs text-muted-foreground">
                        {fmtTs(r.ts)}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{r.ip ?? "—"}</TableCell>
                      <TableCell className="font-mono text-xs">{r.rule_id ?? "—"}</TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          style={{
                            borderColor: r.would_block
                              ? "var(--zs-ok)"
                              : r.reason === "protected"
                                ? "var(--zs-warn)"
                                : "var(--zs-text-muted)",
                            color: r.would_block
                              ? "var(--zs-ok)"
                              : r.reason === "protected"
                                ? "var(--zs-warn)"
                                : "var(--zs-text-muted)",
                          }}
                        >
                          {REASON_LABEL[r.reason] ?? r.reason}
                          {r.reason === "protected" && r.protected_match
                            ? ` (${r.protected_match})`
                            : ""}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

export function FgtPage() {
  const state = useFetch(() => api.fgtObservations(), [])
  return (
    <StateView state={state}>
      {(d) => <Body d={d} />}
    </StateView>
  )
}
