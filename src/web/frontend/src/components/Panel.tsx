import { Link } from "react-router-dom"
import type { Metrics } from "@/lib/api"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { StatusPie, OpenClosedLine } from "@/components/charts"
import { Particles } from "@/components/Particles"
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

function HeroStat({
  label,
  value,
  accent,
}: {
  label: string
  value: string | number
  accent?: boolean
}) {
  return (
    <div className="min-w-[5.5rem] rounded-xl border border-border bg-background/40 px-4 py-3 backdrop-blur-sm">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">
        {label}
      </div>
      <div
        className={`text-2xl font-semibold tabular-nums ${
          accent ? "text-primary" : ""
        }`}
      >
        {value}
      </div>
    </div>
  )
}

export function Panel({ m }: { m: Metrics }) {
  const trend =
    m.trend_7d === null
      ? null
      : `${m.trend_7d > 0 ? "+" : ""}${m.trend_7d}% vs 7d previos`

  return (
    <div className="space-y-8">
      {/* Hero */}
      <section className="zs-hero px-6 py-7 md:px-9 md:py-9">
        <Particles className="opacity-80" />
        <div className="flex flex-col gap-6 md:flex-row md:items-end md:justify-between">
          <div className="space-y-3">
            <div className="inline-flex items-center gap-2 text-[11px] font-medium uppercase tracking-[0.2em] text-primary">
              <span className="zs-live-dot" />
              SOC-L1 · ZebraSecurity
            </div>
            <h1 className="text-2xl font-semibold tracking-tight md:text-[2rem] md:leading-tight">
              Centro de Operaciones
            </h1>
            <p className="max-w-xl text-sm text-muted-foreground">
              Triage autónomo de alertas Wazuh con enriquecimiento, threat
              intel y aprobación humana en el loop.
            </p>
          </div>
          <div className="flex shrink-0 gap-3">
            <HeroStat
              label="Pendientes"
              value={m.pending}
              accent={m.pending > 0}
            />
            <HeroStat label="Casos 24h" value={m.vol_24} />
            <HeroStat label="Aprobación" value={pct(m.approval_rate)} />
          </div>
        </div>
      </section>

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

      {/* Charts: por estado (pie) + abierto vs cerrado (line).
          Sin casos → una sola card resumen en vez de dos gráficos vacíos. */}
      {m.total === 0 ? (
        <section>
          <Card>
            <CardContent className="py-12 text-center">
              <p className="text-sm font-medium">
                No hay incidentes en los últimos 14 días.
              </p>
              <p className="mt-1 text-xs text-muted-foreground">
                Cuando lleguen alertas vas a ver acá el flujo diario y el
                desglose por estado.
              </p>
            </CardContent>
          </Card>
        </section>
      ) : (
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
                Flujo diario · ingresados vs cerrados (14 días)
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
      )}

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
          <p className="text-sm text-muted-foreground">
            Aún no hay datos suficientes.
          </p>
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
