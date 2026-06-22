import { Badge } from "@/components/ui/badge"
import type { StatusKey } from "@/lib/api"

const STATUS_COLOR: Record<string, string> = {
  pending: "var(--zs-warn)",
  approved: "var(--zs-info)",
  executed: "var(--zs-ok)",
  rejected: "var(--zs-danger)",
  expired: "var(--zs-text-muted)",
}

const STATUS_LABEL: Record<string, string> = {
  pending: "Pendiente",
  approved: "Aprobado",
  executed: "Cerrado",
  rejected: "Rechazado",
  expired: "Expirado",
}

const RISK_COLOR: Record<string, string> = {
  critical: "var(--zs-danger)",
  high: "#f97316",
  medium: "var(--zs-warn)",
  low: "var(--zs-ok)",
  info: "var(--zs-info)",
  unknown: "var(--zs-text-muted)",
}

export function StatusBadge({ status }: { status: StatusKey | string }) {
  const color = STATUS_COLOR[status] ?? "var(--zs-text-muted)"
  return (
    <Badge variant="outline" className="gap-1.5" style={{ borderColor: color }}>
      <span
        className="inline-block h-2 w-2 rounded-full"
        style={{ background: color }}
      />
      {STATUS_LABEL[status] ?? status}
    </Badge>
  )
}

export function RiskPill({ risk }: { risk: string | undefined }) {
  const key = (risk ?? "unknown").toLowerCase()
  const color = RISK_COLOR[key] ?? "var(--zs-text-muted)"
  return (
    <Badge
      variant="outline"
      className="uppercase text-[10px] tracking-wide"
      style={{ borderColor: color, color }}
    >
      {key}
    </Badge>
  )
}
