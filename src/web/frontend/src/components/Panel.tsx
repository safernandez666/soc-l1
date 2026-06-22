import { Link } from "react-router-dom"
import type { Metrics } from "@/lib/api"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { StatusPie, OpenClosedLine } from "@/components/charts"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

function Kpi({
  label,
  value,
  hint,
  highlight,
}: {
  label: string
  value: string | number
  hint?: string
  highlight?: boolean
}) {
  return (
    <Card
      className="gap-2"
      style={
        highlight
          ? { borderColor: "var(--primary)", background: "color-mix(in oklab, var(--primary) 7%, var(--card))" }
          : undefined
      }
    >
      <CardHeader className="pb-0">
        <CardTitle className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
          {label}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="text-3xl font-semibold tabular-nums">{value}</div>
        {hint && (
          <div className="mt-1 text-xs text-muted-foreground">{hint}</div>
        )}
      </CardContent>
    </Card>
  )
}

function pct(n: number | null): string {
  return n === null ? "—" : `${n}%`
}

export function Panel({ m }: { m: Metrics }) {
  const trend =
    m.trend_7d === null
      ? null
      : `${m.trend_7d > 0 ? "+" : ""}${m.trend_7d}% vs 7d previos`

  return (
    <div className="space-y-8">
      {/* KPIs — Pendientes destacado */}
      <section className="grid grid-cols-2 gap-4 md:grid-cols-3 lg:grid-cols-6">
        <Kpi
          label="Pendientes"
          value={m.pending}
          hint={m.pending ? `más viejo: ${m.oldest_pending_human}` : "al día"}
          highlight={m.pending > 0}
        />
        <Kpi label="Casos totales" value={m.total} hint={`${m.vol_24} en 24h`} />
        <Kpi label="Tasa aprobación" value={pct(m.approval_rate)} />
        <Kpi label="MTTA" value={m.mtta_human} hint="tiempo a decisión" />
        <Kpi label="MTTR" value={m.mttr_human} hint="tiempo a ejecución" />
        <Kpi
          label="Éxito acciones"
          value={pct(m.act_success_rate)}
          hint={`${m.act_ok}/${m.act_total}`}
        />
      </section>

      {/* Charts: por estado (pie) + abierto vs cerrado (line) */}
      <section className="grid gap-4 lg:grid-cols-2">
        <Card className="flex flex-col">
          <CardHeader>
            <CardTitle className="text-sm">Por estado</CardTitle>
          </CardHeader>
          <CardContent className="flex-1 pb-2">
            <StatusPie m={m} />
          </CardContent>
        </Card>

        <Card className="flex flex-col">
          <CardHeader>
            <CardTitle className="text-sm">
              Abierto vs cerrado · últimos 14 días
            </CardTitle>
          </CardHeader>
          <CardContent className="flex-1 space-y-2">
            <OpenClosedLine m={m} />
            <p className="text-xs text-muted-foreground">
              {m.vol_7} abiertos en 7d · {m.vol_30} en 30d
              {trend ? ` · ${trend}` : ""}
            </p>
          </CardContent>
        </Card>
      </section>

      {/* Top hosts / usuarios */}
      <section className="grid gap-4 lg:grid-cols-2">
        <TopTable title="Top hosts" col="Host" rows={m.top_hosts} />
        <TopTable title="Top usuarios" col="Usuario" rows={m.top_users} />
      </section>

      {/* Acciones fallidas */}
      {m.failed_actions.length > 0 && (
        <section>
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">
                Últimas acciones fallidas
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Caso</TableHead>
                      <TableHead>Acción</TableHead>
                      <TableHead>Target</TableHead>
                      <TableHead>Mensaje</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {m.failed_actions.map((f, i) => (
                      <TableRow key={`${f.rowid}-${i}`}>
                        <TableCell>
                          <Link
                            className="text-primary hover:underline"
                            to={`/case/${f.rowid}`}
                          >
                            #{f.rowid}
                          </Link>
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {f.action_type}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {f.target ?? "—"}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground max-w-md truncate">
                          {f.message ?? "—"}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </section>
      )}
    </div>
  )
}

function TopTable({
  title,
  col,
  rows,
}: {
  title: string
  col: string
  rows: [string, number][]
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">{title}</CardTitle>
      </CardHeader>
      <CardContent className={rows.length === 0 ? "" : "p-0"}>
        {rows.length === 0 ? (
          <p className="text-sm text-muted-foreground">Sin datos.</p>
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{col}</TableHead>
                  <TableHead className="text-right">Casos</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map(([name, n]) => (
                  <TableRow key={name}>
                    <TableCell className="font-mono text-xs">{name}</TableCell>
                    <TableCell className="text-right tabular-nums">{n}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
