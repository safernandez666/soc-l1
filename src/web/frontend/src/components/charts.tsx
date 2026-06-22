import { CartesianGrid, Line, LineChart, Pie, PieChart, XAxis } from "recharts"
import type { Metrics, StatusKey } from "@/lib/api"
import {
  ChartContainer,
  ChartLegend,
  ChartLegendContent,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart"

const STATUS_ORDER: StatusKey[] = [
  "pending",
  "approved",
  "executed",
  "rejected",
  "expired",
]

// Config del pie por estado. Los colores salen de la paleta de marca (--zs-*).
const statusConfig = {
  value: { label: "Casos" },
  pending: { label: "Pendientes", color: "var(--zs-warn)" },
  approved: { label: "Aprobados", color: "var(--zs-info)" },
  executed: { label: "Ejecutados", color: "var(--zs-ok)" },
  rejected: { label: "Rechazados", color: "var(--zs-danger)" },
  expired: { label: "Expirados", color: "var(--zs-text-muted)" },
} satisfies ChartConfig

export function StatusPie({ m }: { m: Metrics }) {
  const data = STATUS_ORDER.filter((s) => m.status_counts[s] > 0).map((s) => ({
    status: s,
    value: m.status_counts[s],
    fill: `var(--color-${s})`,
  }))

  if (data.length === 0) {
    return (
      <div className="flex h-[240px] items-center justify-center text-sm text-muted-foreground">
        Sin casos en el período.
      </div>
    )
  }

  return (
    <ChartContainer
      config={statusConfig}
      className="mx-auto aspect-square max-h-[240px]"
    >
      <PieChart>
        <ChartTooltip
          content={<ChartTooltipContent nameKey="status" hideLabel />}
        />
        <Pie
          data={data}
          dataKey="value"
          nameKey="status"
          innerRadius={55}
          strokeWidth={2}
        />
        <ChartLegend
          content={<ChartLegendContent nameKey="status" />}
          className="flex-wrap gap-x-3 gap-y-1"
        />
      </PieChart>
    </ChartContainer>
  )
}

// Config del line abierto vs cerrado: lima para abiertos, amarillo fluo para cerrados.
const flowConfig = {
  open: { label: "Ingresados", color: "var(--zs-ok)" },
  closed: { label: "Cerrados", color: "var(--zs-warn)" },
} satisfies ChartConfig

export function OpenClosedLine({ m }: { m: Metrics }) {
  const data = m.per_day.map(([day, n], i) => ({
    day: day.slice(5), // MM-DD
    open: n,
    closed: m.per_day_closed[i]?.[1] ?? 0,
  }))

  return (
    <ChartContainer config={flowConfig} className="h-[240px] w-full">
      <LineChart accessibilityLayer data={data} margin={{ left: 4, right: 12, top: 8 }}>
        <CartesianGrid vertical={false} />
        <XAxis
          dataKey="day"
          tickLine={false}
          axisLine={false}
          tickMargin={8}
          minTickGap={16}
        />
        <ChartTooltip content={<ChartTooltipContent />} />
        <Line
          dataKey="open"
          type="monotone"
          stroke="var(--color-open)"
          strokeWidth={2}
          dot={false}
        />
        <Line
          dataKey="closed"
          type="monotone"
          stroke="var(--color-closed)"
          strokeWidth={2}
          dot={false}
        />
        <ChartLegend content={<ChartLegendContent />} />
      </LineChart>
    </ChartContainer>
  )
}
