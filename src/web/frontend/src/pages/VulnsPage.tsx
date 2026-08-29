import { useEffect, useState } from "react"
import { useSearchParams } from "react-router-dom"
import { CartesianGrid, Line, LineChart, XAxis, YAxis } from "recharts"
import {
  api,
  type VulnCategoria,
  type VulnCobertura,
  type VulnCve,
  type VulnCvesPage,
  type VulnSeveridad,
  type VulnSummary,
} from "@/lib/api"
import { useFetch } from "@/lib/useFetch"
import { humanizeAge } from "@/lib/format"
import { StateView } from "@/components/StateView"
import { RiskPill } from "@/components/badges"
import { RISK_COLOR } from "@/lib/status"
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
import {
  ChartContainer,
  ChartLegend,
  ChartLegendContent,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart"

// ===== Formato =====

function num(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—"
  return new Intl.NumberFormat("es-AR").format(Math.round(n))
}

function dec(n: number | null | undefined, digits = 1): string {
  if (n === null || n === undefined) return "—"
  return new Intl.NumberFormat("es-AR", {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  }).format(n)
}

// EPSS viene 0..1 pero se lee como probabilidad: "94,6%", no "0.946".
function pctEpss(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—"
  return `${dec(n * 100)}%`
}

// ===== Diccionarios =====

const SEV_ORDER: VulnSeveridad[] = [
  "Critical",
  "High",
  "Medium",
  "Low",
  "Untriaged",
]

const SEV_LABEL: Record<VulnSeveridad, string> = {
  Critical: "Críticas",
  High: "Altas",
  Medium: "Medias",
  Low: "Bajas",
  Untriaged: "Sin puntuar",
}

// Los colores salen de la paleta compartida (lib/status) para no abrir otra
// escala. Untriaged no tiene color propio a propósito: es desconocido.
const SEV_COLOR: Record<VulnSeveridad, string> = {
  Critical: RISK_COLOR.critical,
  High: RISK_COLOR.high,
  Medium: RISK_COLOR.medium,
  Low: RISK_COLOR.low,
  Untriaged: RISK_COLOR.unknown,
}

const CAT_ORDER: VulnCategoria[] = ["OS", "Packages"]

const CAT_LABEL: Record<VulnCategoria, string> = {
  OS: "Sistema operativo",
  Packages: "Paquetes",
}

// Qué hay que hacer para cerrar el hallazgo: es el motivo por el que este corte
// importa más que cualquier otro en un parque 100% Windows.
const CAT_FIX: Record<VulnCategoria, string> = {
  OS: "Se cierran con el acumulativo / KB del mes",
  Packages: "Se cierran actualizando cada aplicación",
}

const LIFECYCLE_LABEL: Record<string, string> = {
  new: "Nueva",
  nueva: "Nueva",
  persistent: "Persistente",
  persistente: "Persistente",
  resolved: "Resuelta",
  resuelta: "Resuelta",
}

function lifecycleLabel(s: string | null | undefined): string {
  if (!s) return "—"
  return LIFECYCLE_LABEL[s.toLowerCase()] ?? s
}

const inputCls =
  "rounded-md border border-border bg-background px-2 py-1.5 text-sm outline-none focus:border-primary"

// ===== Piezas chicas =====

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

/** Chip de CISA KEV. Explotación confirmada in-the-wild: la señal más fuerte. */
function KevPill({ on }: { on: boolean }) {
  if (!on) return <span className="text-xs text-muted-foreground">—</span>
  return (
    <Badge
      variant="outline"
      className="text-[10px] font-semibold tracking-wide"
      style={{
        borderColor: "var(--zs-danger)",
        background: "color-mix(in oklab, var(--zs-danger) 14%, transparent)",
        color: "var(--zs-danger)",
      }}
      title="CISA KEV — explotación confirmada in-the-wild"
    >
      KEV
    </Badge>
  )
}

/** Aviso de cobertura: qué NO está representado en los números de arriba.
 *
 * Sin esto la pantalla miente por omisión. Un agente al que el detector nunca le
 * generó un hallazgo no deja ninguna fila en la base, así que no aparece — y un
 * servidor sin medir termina leyéndose igual que uno limpio. Los desfasados son el
 * problema inverso: siguen contando hallazgos que el host ya parcheó.
 */
function CoverageNotice({ c }: { c?: VulnCobertura }) {
  if (!c?.disponible) return null
  const sinDatos = c.sin_datos ?? []
  const desfasados = c.desfasados ?? []
  if (sinDatos.length === 0 && desfasados.length === 0) return null

  return (
    <Card
      style={{
        borderColor: "color-mix(in oklab, var(--zs-warn) 55%, transparent)",
        background: "color-mix(in oklab, var(--zs-warn) 7%, transparent)",
      }}
    >
      <CardContent className="space-y-3 py-4">
        <div className="flex items-baseline justify-between gap-3">
          <h3 className="text-sm font-semibold" style={{ color: "var(--zs-warn)" }}>
            Los números de esta pantalla no cubren todo el parque
          </h3>
          <span className="text-xs tabular-nums text-muted-foreground">
            {c.agentes_con_datos ?? 0} de {c.agentes_total ?? 0} agentes con datos
          </span>
        </div>

        {sinDatos.length > 0 && (
          <p className="text-sm text-muted-foreground">
            <span className="font-medium text-foreground">
              Sin ningún hallazgo ({sinDatos.length}):
            </span>{" "}
            {sinDatos.map((h, i) => (
              <span key={h}>
                {i > 0 && ", "}
                <span className="font-mono text-xs text-foreground">{h}</span>
              </span>
            ))}
            . Están activos y reportando inventario, pero el detector de Wazuh no
            genera hallazgos para ellos: no aparecen acá, y eso no significa que
            estén limpios.
          </p>
        )}

        {desfasados.length > 0 && (
          <p className="text-sm text-muted-foreground">
            <span className="font-medium text-foreground">
              Con inventario desactualizado ({desfasados.length}):
            </span>{" "}
            {desfasados.map((d, i) => (
              <span key={d.host}>
                {i > 0 && ", "}
                <span className="font-mono text-xs text-foreground">{d.host}</span>{" "}
                <span className="tabular-nums">({d.hallazgos})</span>
              </span>
            ))}
            . El índice conserva un build de SO anterior al que el agente reporta
            hoy, así que sus{" "}
            <span className="tabular-nums font-medium text-foreground">
              {c.hallazgos_dudosos ?? 0}
            </span>{" "}
            hallazgos probablemente ya estén parcheados y sigan contando.
          </p>
        )}
      </CardContent>
    </Card>
  )
}

// ===== Bloques del resumen =====


function HeadlineBlock({ s }: { s: VulnSummary }) {
  const t = s.totals
  const kev = s.kev ?? { hallazgos: 0, cves: 0 }
  const run = s.last_run
  return (
    <Section
      title="Superficie expuesta"
      subtitle={
        run?.started_at
          ? `último escaneo hace ${humanizeAge(run.started_at)}`
          : undefined
      }
    >
      <div className="grid gap-4 lg:grid-cols-5">
        {/* El KEV manda: no es una card más de la grilla, ocupa el doble y usa
            el rojo de marca. Un CVSS 9.8 sin exploit espera; un KEV no. */}
        <Card
          className="lg:col-span-2"
          style={{
            borderColor: "color-mix(in oklab, var(--zs-danger) 55%, transparent)",
            background: "color-mix(in oklab, var(--zs-danger) 8%, transparent)",
          }}
        >
          <CardHeader className="pb-0">
            <CardTitle
              className="text-xs font-semibold tracking-wide uppercase"
              style={{ color: "var(--zs-danger)" }}
            >
              En CISA KEV
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div
              className="text-5xl font-bold tabular-nums"
              style={{ color: "var(--zs-danger)" }}
            >
              {num(kev.hallazgos)}
            </div>
            <div className="mt-1 text-sm font-medium">
              {num(kev.cves)} CVE distintos con explotación confirmada
            </div>
            <p className="mt-2 text-xs text-muted-foreground">
              Catálogo de CISA: se están explotando in-the-wild ahora. Van
              primero, incluso por encima de un CVSS más alto.
            </p>
          </CardContent>
        </Card>

        <div className="grid grid-cols-2 gap-4 lg:col-span-3">
          <Stat
            label="Hallazgos activos"
            value={num(t?.activos)}
            hint={`${num(t?.resueltas_total)} resueltas históricas`}
          />
          <Stat
            label="CVEs únicos"
            value={num(t?.cves_unicos)}
            hint="deduplicados por host"
          />
          <Stat
            label="Prioridad alta"
            value={num(s.prioridad_alta)}
            hint={`${num(s.epss_alto)} con EPSS alto`}
          />
          <Stat
            label="Agentes cubiertos"
            value={num(t?.agentes)}
            hint="reportando inventario"
          />
        </div>
      </div>
    </Section>
  )
}

function SeverityBlock({ s }: { s: VulnSummary }) {
  const sev = s.por_severidad ?? {}
  const rows = SEV_ORDER.map((k) => [k, sev[k] ?? 0] as [VulnSeveridad, number])
  const total = rows.reduce((a, [, n]) => a + n, 0)
  const untriaged = sev.Untriaged ?? 0

  if (total === 0) return <Empty>Sin hallazgos puntuados.</Empty>

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">Por severidad</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Barra apilada: la proporción entre buckets se lee de un vistazo. */}
        <div className="flex h-2.5 w-full overflow-hidden rounded-full">
          {rows
            .filter(([, n]) => n > 0)
            .map(([k, n]) => (
              <div
                key={k}
                style={{
                  width: `${(n / total) * 100}%`,
                  background: SEV_COLOR[k],
                  opacity: k === "Untriaged" ? 0.5 : 1,
                }}
                title={`${SEV_LABEL[k]}: ${num(n)}`}
              />
            ))}
        </div>

        <div className="space-y-1.5">
          {rows.map(([k, n]) => (
            <div key={k} className="flex items-center gap-2 text-sm">
              <span
                className="inline-block h-2.5 w-2.5 shrink-0 rounded-full"
                style={
                  k === "Untriaged"
                    ? { border: `2px dashed ${SEV_COLOR[k]}` }
                    : { background: SEV_COLOR[k] }
                }
              />
              <span className="text-muted-foreground">{SEV_LABEL[k]}</span>
              <span className="ml-auto font-medium tabular-nums">{num(n)}</span>
              <span className="w-12 text-right text-xs tabular-nums text-muted-foreground">
                {total ? `${dec((100 * n) / total)}%` : "—"}
              </span>
            </div>
          ))}
        </div>

        {untriaged > 0 && (
          <p
            className="rounded-md border border-dashed px-3 py-2 text-xs"
            style={{
              borderColor: "color-mix(in oklab, var(--zs-warn) 45%, transparent)",
              color: "var(--zs-warn)",
            }}
          >
            {num(untriaged)} hallazgos llegan <strong>sin puntuar</strong> desde
            Wazuh. Sin severidad no significa sin riesgo: quedan sin triage hasta
            que alguien los mire.
          </p>
        )}
      </CardContent>
    </Card>
  )
}

function CategoryBlock({ s }: { s: VulnSummary }) {
  const cat = s.por_categoria ?? {}
  const total = CAT_ORDER.reduce((a, k) => a + (cat[k] ?? 0), 0)

  if (total === 0) return <Empty>Sin desglose por categoría.</Empty>

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">Sistema operativo vs. paquetes</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex h-2.5 w-full overflow-hidden rounded-full">
          {CAT_ORDER.map((k, i) => (
            <div
              key={k}
              style={{
                width: `${((cat[k] ?? 0) / total) * 100}%`,
                background: i === 0 ? "var(--zs-info)" : "var(--zs-warn)",
              }}
              title={`${CAT_LABEL[k]}: ${num(cat[k])}`}
            />
          ))}
        </div>

        <div className="grid grid-cols-2 gap-4">
          {CAT_ORDER.map((k, i) => (
            <div key={k}>
              <div
                className="text-2xl font-semibold tabular-nums"
                style={{ color: i === 0 ? "var(--zs-info)" : "var(--zs-warn)" }}
              >
                {num(cat[k])}
              </div>
              <div className="text-sm font-medium">{CAT_LABEL[k]}</div>
              <div className="mt-1 text-xs text-muted-foreground">
                {CAT_FIX[k]}
              </div>
            </div>
          ))}
        </div>

        <p className="text-xs text-muted-foreground">
          Parque 100% Windows: la remediación no se parte por sistema operativo
          sino por quién la aplica — un acumulativo cierra medio backlog de una,
          los paquetes se persiguen aplicación por aplicación.
        </p>
      </CardContent>
    </Card>
  )
}

// Dos escalas distintas: el backlog vive en los 16.000 y el flujo diario en los
// cientos. En un solo eje las líneas de nuevas/resueltas quedaban pegadas al
// piso, así que van en gráficos separados en vez de en un eje secundario.
const nivelConfig = {
  activos: { label: "Activos", color: "var(--zs-warn)" },
} satisfies ChartConfig

const flujoConfig = {
  nuevas: { label: "Nuevas", color: "var(--zs-danger)" },
  resueltas: { label: "Resueltas", color: "var(--zs-ok)" },
} satisfies ChartConfig

type TrendRow = { fecha: string; activos: number; nuevas: number; resueltas: number }

function TrendChart({
  data,
  config,
  series,
}: {
  data: TrendRow[]
  config: ChartConfig
  series: (keyof TrendRow)[]
}) {
  return (
    <ChartContainer
      config={config}
      className="h-[220px] w-full [&_.recharts-cartesian-axis-tick_text]:fill-[var(--zs-text-secondary)]"
    >
      <LineChart
        accessibilityLayer
        data={data}
        margin={{ left: 4, right: 12, top: 8 }}
      >
        <CartesianGrid
          vertical={false}
          stroke="var(--border)"
          strokeOpacity={0.8}
        />
        <XAxis
          dataKey="fecha"
          tickLine={false}
          axisLine={false}
          tickMargin={8}
          minTickGap={16}
        />
        <YAxis
          tickLine={false}
          axisLine={false}
          width={44}
          tickFormatter={(v: number) => num(v)}
        />
        <ChartTooltip content={<ChartTooltipContent />} />
        {series.map((k) => (
          <Line
            key={k}
            dataKey={k}
            type="monotone"
            stroke={`var(--color-${k})`}
            strokeWidth={2}
            dot={false}
          />
        ))}
        <ChartLegend content={<ChartLegendContent />} />
      </LineChart>
    </ChartContainer>
  )
}

function TrendBlock({ s }: { s: VulnSummary }) {
  const puntos = s.tendencia ?? []
  const run = s.last_run
  const sub = run
    ? `última corrida: +${num(run.new_count)} nuevas / -${num(
        run.resolved_count
      )} resueltas`
    : undefined

  if (puntos.length === 0) {
    return (
      <Section title="Ciclo de vida" subtitle={sub}>
        <Empty>Todavía no hay historial de corridas para graficar.</Empty>
      </Section>
    )
  }

  const data: TrendRow[] = puntos.map((p) => ({
    fecha: p.fecha.slice(5), // MM-DD
    activos: p.activos,
    nuevas: p.nuevas,
    resueltas: p.resueltas,
  }))

  return (
    <Section title="Ciclo de vida" subtitle={sub}>
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Backlog activo</CardTitle>
          </CardHeader>
          <CardContent>
            <TrendChart data={data} config={nivelConfig} series={["activos"]} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Entra vs. sale</CardTitle>
          </CardHeader>
          <CardContent>
            <TrendChart
              data={data}
              config={flujoConfig}
              series={["nuevas", "resueltas"]}
            />
          </CardContent>
        </Card>
      </div>
    </Section>
  )
}

function HostsBlock({
  s,
  agente,
  onPick,
}: {
  s: VulnSummary
  agente: string
  onPick: (a: string) => void
}) {
  const hosts = s.top_hosts ?? []
  if (hosts.length === 0) return null
  return (
    <Section title="Hosts más expuestos" subtitle="clic para filtrar el ranking">
      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Agente</TableHead>
                  <TableHead className="text-right">Hallazgos</TableHead>
                  <TableHead className="text-right">Críticas</TableHead>
                  <TableHead className="text-right">KEV</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {hosts.map((h) => (
                  <TableRow
                    key={h.agent_name}
                    onClick={() =>
                      onPick(agente === h.agent_name ? "" : h.agent_name)
                    }
                    className="cursor-pointer"
                  >
                    <TableCell className="font-mono text-xs">
                      {h.agent_name}
                      {agente === h.agent_name && (
                        <span className="ml-2 text-[10px] tracking-wide text-primary uppercase">
                          filtrando
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {num(h.total)}
                    </TableCell>
                    <TableCell
                      className="text-right tabular-nums"
                      style={{ color: h.criticas ? SEV_COLOR.Critical : undefined }}
                    >
                      {num(h.criticas)}
                    </TableCell>
                    <TableCell className="text-right tabular-nums font-semibold">
                      {h.kev ? (
                        <span style={{ color: "var(--zs-danger)" }}>
                          {num(h.kev)}
                        </span>
                      ) : (
                        <span className="text-muted-foreground">0</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </Section>
  )
}

// ===== Ranking de CVEs =====

function hostsTitle(c: VulnCve): string {
  const shown = c.hosts.slice(0, 12).join(", ")
  const rest = c.hosts_count - Math.min(c.hosts.length, 12)
  return rest > 0 ? `${shown} y ${rest} más` : shown || "sin detalle"
}

function CveRows({ q }: { q: VulnCvesPage }) {
  return (
    <>
      {/* Mobile: cards apiladas */}
      <div className="space-y-3 md:hidden">
        {q.cves.map((c) => (
          <Card key={c.cve}>
            <CardContent className="space-y-2 py-4">
              <div className="flex items-start justify-between gap-2">
                <div className="font-mono text-sm font-medium">{c.cve}</div>
                <div className="flex shrink-0 items-center gap-1.5">
                  <KevPill on={c.cisa_kev} />
                  <RiskPill risk={c.severity} />
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
                <span className="tabular-nums">
                  prioridad{" "}
                  <strong className="text-foreground">
                    {dec(c.priority_score)}
                  </strong>
                </span>
                <span className="tabular-nums">CVSS {dec(c.cvss_score)}</span>
                <span className="tabular-nums">EPSS {pctEpss(c.epss_score)}</span>
                <span className="tabular-nums">{num(c.hosts_count)} hosts</span>
              </div>
              <div className="truncate font-mono text-xs text-muted-foreground">
                {c.package_name || "—"}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Desktop: tabla */}
      <Card className="hidden md:block">
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>CVE</TableHead>
                  <TableHead className="text-right">Prioridad</TableHead>
                  <TableHead>Severidad</TableHead>
                  <TableHead className="text-right">CVSS</TableHead>
                  <TableHead className="text-right">EPSS</TableHead>
                  <TableHead>KEV</TableHead>
                  <TableHead>Categoría</TableHead>
                  <TableHead className="text-right">Hosts</TableHead>
                  <TableHead>Paquete</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {q.cves.map((c) => (
                  <TableRow key={c.cve}>
                    <TableCell>
                      <div className="font-mono text-xs font-medium">{c.cve}</div>
                      <div className="text-[11px] text-muted-foreground">
                        {lifecycleLabel(c.lifecycle_status)}
                        {c.first_seen_at &&
                          ` · vista hace ${humanizeAge(c.first_seen_at)}`}
                      </div>
                    </TableCell>
                    <TableCell className="text-right font-semibold tabular-nums">
                      {dec(c.priority_score)}
                    </TableCell>
                    <TableCell>
                      <RiskPill risk={c.severity} />
                    </TableCell>
                    <TableCell className="text-right tabular-nums text-muted-foreground">
                      {dec(c.cvss_score)}
                    </TableCell>
                    <TableCell className="text-right tabular-nums text-muted-foreground">
                      {pctEpss(c.epss_score)}
                    </TableCell>
                    <TableCell>
                      <KevPill on={c.cisa_kev} />
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {CAT_LABEL[c.categoria as VulnCategoria] ?? c.categoria}
                    </TableCell>
                    <TableCell
                      className="text-right tabular-nums"
                      title={hostsTitle(c)}
                    >
                      {num(c.hosts_count)}
                    </TableCell>
                    <TableCell
                      className="max-w-[180px] truncate font-mono text-xs text-muted-foreground"
                      title={c.package_name ?? undefined}
                    >
                      {c.package_name || "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </>
  )
}

// ===== Página =====

type Filtros = {
  severidad: string
  categoria: string
  agente: string
  kev: boolean
  q: string
  page: number
}

export function VulnsPage() {
  const [params, setParams] = useSearchParams()
  const severidad = params.get("severidad") || ""
  const categoria = params.get("categoria") || ""
  const agente = params.get("agente") || ""
  const kev = params.get("kev") === "1"
  const q = params.get("q") || ""
  const page = Math.max(1, Number(params.get("page") || "1"))

  const summary = useFetch(() => api.vulnsSummary(), [])
  const listado = useFetch(
    () => api.vulnsCves({ severidad, categoria, agente, kev, q, page }),
    [severidad, categoria, agente, kev, q, page]
  )

  // Cambiar cualquier filtro vuelve a la página 1: con ~4.300 CVEs el offset
  // viejo queda fuera de rango apenas se recorta el total.
  const apply = (next: Partial<Filtros>) => {
    const f: Filtros = {
      severidad,
      categoria,
      agente,
      kev,
      q,
      page: 1,
      ...next,
    }
    const qs = new URLSearchParams()
    if (f.severidad) qs.set("severidad", f.severidad)
    if (f.categoria) qs.set("categoria", f.categoria)
    if (f.agente) qs.set("agente", f.agente)
    if (f.kev) qs.set("kev", "1")
    if (f.q) qs.set("q", f.q)
    if (f.page > 1) qs.set("page", String(f.page))
    setParams(qs)
  }

  // Buscador: input local + debounce, para no pegarle a la API en cada tecla.
  const [texto, setTexto] = useState(q)
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setTexto(q)
  }, [q])
  useEffect(() => {
    if (texto === q) return
    const t = setTimeout(() => apply({ q: texto }), 350)
    return () => clearTimeout(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [texto])

  const hayFiltros = Boolean(severidad || categoria || agente || kev || q)

  // El select de agentes se arma con los hosts del resumen; si el filtro activo
  // no está entre ellos igual lo listamos para no perder la selección.
  const agentesTop = (
    summary.kind === "ready" ? summary.data.top_hosts ?? [] : []
  ).map((h) => h.agent_name)
  const agentes = agentesTop.includes(agente) || !agente
    ? agentesTop
    : [agente, ...agentesTop]

  return (
    <div className="space-y-10">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">
            Vulnerabilidades
          </h1>
          <p className="text-sm text-muted-foreground">
            Backlog de parcheo priorizado por explotabilidad real, no solo por
            CVSS.
          </p>
        </div>
      </div>

      <StateView state={summary}>
        {(s) =>
          !s.available ? (
            <Empty>
              Todavía no hay datos de vulnerabilidades{s.error ? `: ${s.error}` : "."}
            </Empty>
          ) : (
            <div className="space-y-10">
              <CoverageNotice c={s.cobertura} />

              <HeadlineBlock s={s} />

              <Section title="Cómo se reparte el backlog">
                <div className="grid gap-4 md:grid-cols-2">
                  <SeverityBlock s={s} />
                  <CategoryBlock s={s} />
                </div>
              </Section>

              <TrendBlock s={s} />

              <HostsBlock
                s={s}
                agente={agente}
                onPick={(a) => apply({ agente: a })}
              />
            </div>
          )
        }
      </StateView>

      <Section
        title="Ranking de CVEs"
        subtitle="ordenado por prioridad (KEV + EPSS + CVSS)"
      >
        {/* Filtros */}
        <div className="space-y-3">
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => apply({ severidad: "" })}
              className={`rounded-full border px-3 py-1 text-sm transition-colors ${
                severidad === ""
                  ? "border-primary bg-primary/10 text-foreground"
                  : "border-border text-muted-foreground hover:text-foreground"
              }`}
            >
              Todas
            </button>
            {SEV_ORDER.map((s) => (
              <button
                key={s}
                onClick={() => apply({ severidad: s })}
                className={`rounded-full border px-3 py-1 text-sm transition-colors ${
                  severidad === s
                    ? "bg-primary/10 text-foreground"
                    : "text-muted-foreground hover:text-foreground"
                }`}
                style={{
                  borderColor:
                    severidad === s ? SEV_COLOR[s] : "var(--border)",
                  borderStyle: s === "Untriaged" ? "dashed" : "solid",
                }}
              >
                {SEV_LABEL[s]}
              </button>
            ))}
          </div>

          <Card>
            <CardContent className="flex flex-wrap items-end gap-4">
              <label className="flex flex-col gap-1 text-xs text-muted-foreground">
                Categoría
                <select
                  className={inputCls}
                  value={categoria}
                  onChange={(e) => apply({ categoria: e.target.value })}
                >
                  <option value="">Todas</option>
                  {CAT_ORDER.map((c) => (
                    <option key={c} value={c}>
                      {CAT_LABEL[c]}
                    </option>
                  ))}
                </select>
              </label>

              <label className="flex flex-col gap-1 text-xs text-muted-foreground">
                Agente
                <select
                  className={inputCls}
                  value={agente}
                  onChange={(e) => apply({ agente: e.target.value })}
                >
                  <option value="">Todos</option>
                  {agentes.map((a) => (
                    <option key={a} value={a}>
                      {a}
                    </option>
                  ))}
                </select>
              </label>

              <label className="flex min-w-[220px] flex-1 flex-col gap-1 text-xs text-muted-foreground">
                Buscar
                <input
                  type="search"
                  className={inputCls}
                  placeholder="CVE-2024-… o nombre de paquete"
                  value={texto}
                  onChange={(e) => setTexto(e.target.value)}
                />
              </label>

              {/* El toggle de KEV no es un filtro más: es el atajo al trabajo
                  que hay que hacer hoy, y por eso va con el rojo de marca. */}
              <button
                type="button"
                onClick={() => apply({ kev: !kev })}
                aria-pressed={kev}
                className="rounded-full border px-3 py-1.5 text-sm font-medium transition-colors"
                style={
                  kev
                    ? {
                        borderColor: "var(--zs-danger)",
                        background:
                          "color-mix(in oklab, var(--zs-danger) 16%, transparent)",
                        color: "var(--zs-danger)",
                      }
                    : { borderColor: "var(--border)", color: "var(--zs-text-muted)" }
                }
              >
                Solo KEV
              </button>

              {hayFiltros && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() =>
                    apply({
                      severidad: "",
                      categoria: "",
                      agente: "",
                      kev: false,
                      q: "",
                    })
                  }
                >
                  Limpiar
                </Button>
              )}
            </CardContent>
          </Card>
        </div>

        <StateView state={listado}>
          {(l) => {
            const pages = Math.max(1, Math.ceil(l.total / (l.per_page || 50)))
            if (l.cves.length === 0) {
              return <Empty>No hay CVEs para este filtro.</Empty>
            }
            return (
              <div className="space-y-4">
                <CveRows q={l} />
                <div className="flex items-center justify-between">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page <= 1}
                    onClick={() => apply({ page: page - 1 })}
                  >
                    ← Anterior
                  </Button>
                  <span className="text-sm text-muted-foreground">
                    Página {page} de {num(pages)} · {num(l.total)} CVEs
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page >= pages}
                    onClick={() => apply({ page: page + 1 })}
                  >
                    Siguiente →
                  </Button>
                </div>
              </div>
            )
          }}
        </StateView>
      </Section>
    </div>
  )
}
