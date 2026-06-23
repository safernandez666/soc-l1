import { api, type Kpis, type VolumeMonth } from "@/lib/api"
import { useFetch } from "@/lib/useFetch"
import { StateView } from "@/components/StateView"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

function num(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—"
  return new Intl.NumberFormat("es-AR").format(Math.round(n))
}

function Stat({
  label,
  value,
  hint,
}: {
  label: string
  value: string | number
  hint?: string
}) {
  return (
    <Card className="gap-2">
      <CardHeader className="pb-0">
        <CardTitle className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
          {label}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-semibold tabular-nums">{value}</div>
        {hint && <div className="mt-1 text-xs text-muted-foreground">{hint}</div>}
      </CardContent>
    </Card>
  )
}

function Bars({ data }: { data: [string, number][] }) {
  const max = Math.max(1, ...data.map(([, n]) => n))
  return (
    <div className="flex items-end gap-1 h-28">
      {data.map(([label, n]) => (
        <div
          key={label}
          className="flex-1 rounded-t-sm bg-slate-500/60 hover:bg-slate-400 transition-colors"
          style={{ height: `${Math.max(3, (n / max) * 100)}%` }}
          title={`${label}: ${num(n)}`}
        />
      ))}
    </div>
  )
}

function Section({
  title,
  subtitle,
  children,
}: {
  title: string
  subtitle?: string
  children: React.ReactNode
}) {
  return (
    <section className="space-y-3">
      <div className="flex items-baseline justify-between gap-3">
        <h2 className="text-base font-semibold">{title}</h2>
        {subtitle && (
          <span className="text-xs text-muted-foreground">{subtitle}</span>
        )}
      </div>
      {children}
    </section>
  )
}

function Empty({ children }: { children: React.ReactNode }) {
  return (
    <Card>
      <CardContent className="py-8 text-center text-sm text-muted-foreground">
        {children}
      </CardContent>
    </Card>
  )
}

function PostureBlock({ k }: { k: Kpis }) {
  const p = k.posture
  if (!p.available) {
    return (
      <Section title="Posture Wazuh · hoy">
        <Empty>Wazuh API no disponible: {p.error || "sin datos"}</Empty>
      </Section>
    )
  }
  const ag = p.agents || {}
  return (
    <Section title="Posture Wazuh · hoy" subtitle="snapshot vía Management API">
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Stat label="Agentes" value={num(ag.total)} hint={`${num(ag.active)} activos`} />
        <Stat
          label="Desconectados"
          value={num(ag.disconnected)}
          hint={`${num(ag.never_connected)} nunca conectaron`}
        />
        <Stat label="Reglas activas" value={num(p.rules_total)} hint="ruleset cargado" />
        <Stat
          label="Versión Wazuh"
          value={p.manager_version || "—"}
          hint={(p.os || []).join(", ") || "—"}
        />
      </div>
    </Section>
  )
}

function VolumeBlock({ k }: { k: Kpis }) {
  const months = k.alert_volume.months || []
  if (!k.alert_volume.available || months.length === 0) {
    return (
      <Section title="Volumen de alertas">
        <Empty>
          Sin cache de volumen. Corré{" "}
          <code>scripts/aggregate_alert_volume.py</code>.
        </Empty>
      </Section>
    )
  }
  const cur = months[months.length - 1]
  const peak = months.reduce((a, b) => (b.avg_per_day > a.avg_per_day ? b : a))
  const low = months.reduce((a, b) => (b.avg_per_day < a.avg_per_day ? b : a))
  const red = peak.avg_per_day
    ? Math.round((100 * (peak.avg_per_day - low.avg_per_day)) / peak.avg_per_day)
    : null
  const note = k.alert_volume.sampled
    ? `muestreo ${k.alert_volume.max_days_per_month} días/mes`
    : "conteo completo"
  return (
    <Section
      title="Volumen de alertas · cómo cambió la infra"
      subtitle={`${months[0].name} → ${cur.name} · ${note}`}
    >
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Stat label="Pico de ruido" value={num(peak.avg_per_day)} hint={`${peak.name} · alertas/día`} />
        <Stat
          label="Punto más bajo"
          value={num(low.avg_per_day)}
          hint={red !== null ? `${low.name} · -${red}% vs pico` : low.name}
        />
        <Stat label="Mes actual" value={num(cur.avg_per_day)} hint={`${cur.name} · alertas/día`} />
      </div>
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Alertas/día por mes</CardTitle>
        </CardHeader>
        <CardContent>
          <Bars data={months.map((m) => [m.label, m.avg_per_day])} />
        </CardContent>
      </Card>
    </Section>
  )
}

function ContainmentBlock({ k }: { k: Kpis }) {
  const c = k.containment
  if (!c.available || !c.total_cases) {
    return (
      <Section title="Contención / bloqueos">
        <Empty>No hay acciones de contención registradas aún.</Empty>
      </Section>
    )
  }
  const execSub = k.dry_run ? "simulada (dry-run)" : "ejecutada"
  const rate = c.containment_rate != null ? `${c.containment_rate}%` : "—"
  return (
    <Section title="Contención / bloqueos" subtitle={c.period?.label}>
      {k.dry_run && (
        <Card style={{ borderColor: "var(--zs-warn)" }}>
          <CardContent className="py-3 text-sm" style={{ color: "var(--zs-warn)" }}>
            DRY-RUN — las contenciones se registran pero se simulan.
          </CardContent>
        </Card>
      )}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Stat label="Acciones de contención" value={num(c.proposed_total)} hint="propuestas" />
        <Stat label="Ejecutadas" value={num(c.executed_total)} hint={execSub} />
        <Stat
          label="Casos con bloqueo"
          value={num(c.cases_with_containment)}
          hint={`${rate} de ${num(c.total_cases)} casos`}
        />
        <Stat label="Hosts afectados" value={num(c.hosts_contained)} hint="≥1 contención" />
      </div>
      {c.by_type && c.by_type.length > 0 && (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Acción</TableHead>
                  <TableHead>Propuestas</TableHead>
                  <TableHead>Ejecutadas</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {c.by_type.map(([t, prop, ex]) => (
                  <TableRow key={t}>
                    <TableCell className="font-mono text-xs">{t}</TableCell>
                    <TableCell className="tabular-nums">{num(prop)}</TableCell>
                    <TableCell className="tabular-nums text-muted-foreground">
                      {num(ex)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </Section>
  )
}

function FortigateBlock({ k }: { k: Kpis }) {
  const fgMonths: VolumeMonth[] = (k.alert_volume.months || []).filter(
    (m) => m.fg_blocks_avg_per_day !== undefined
  )
  const nowBanned = k.fortigate.available ? k.fortigate.count ?? null : null
  if (fgMonths.length === 0) {
    return (
      <Section title="Bloqueos FortiGate">
        <Empty>
          Sin datos de bloqueos en cache. Corré{" "}
          <code>scripts/aggregate_alert_volume.py</code>.
        </Empty>
      </Section>
    )
  }
  const total = fgMonths.reduce((a, m) => a + (m.fg_blocks_total_estimate || 0), 0)
  const cur = fgMonths[fgMonths.length - 1]
  const peak = fgMonths.reduce((a, b) =>
    (b.fg_blocks_avg_per_day || 0) > (a.fg_blocks_avg_per_day || 0) ? b : a
  )
  return (
    <Section
      title="Bloqueos FortiGate · eventos en Wazuh"
      subtitle={nowBanned !== null ? `${num(nowBanned)} en cuarentena ahora` : undefined}
    >
      <Card style={{ borderColor: "var(--zs-warn)" }}>
        <CardContent className="py-3 text-xs" style={{ color: "var(--zs-warn)" }}>
          Son <strong>eventos logueados en Wazuh</strong>, no la política actual del
          firewall. La caída de Ene-2026 fue tuning de logs, no menos protección.
        </CardContent>
      </Card>
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Stat label="Eventos de bloqueo" value={num(total)} hint={`~estimado · ${fgMonths.length} meses`} />
        <Stat label="Pico mensual" value={num(peak.fg_blocks_avg_per_day)} hint={`${peak.name} · /día`} />
        <Stat label="Logueado actual" value={num(cur.fg_blocks_avg_per_day)} hint={`${cur.name} · /día`} />
        <Stat
          label="En cuarentena ahora"
          value={nowBanned !== null ? num(nowBanned) : "—"}
          hint="bans activos"
        />
      </div>
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Eventos de bloqueo/día por mes</CardTitle>
        </CardHeader>
        <CardContent>
          <Bars data={fgMonths.map((m) => [m.label, m.fg_blocks_avg_per_day || 0])} />
        </CardContent>
      </Card>
    </Section>
  )
}

export function KpisPage() {
  const state = useFetch(() => api.kpis(), [])
  return (
    <StateView state={state}>
      {(k) => (
        <div className="space-y-14">
          <PostureBlock k={k} />
          <VolumeBlock k={k} />
          <ContainmentBlock k={k} />
          <FortigateBlock k={k} />
        </div>
      )}
    </StateView>
  )
}
