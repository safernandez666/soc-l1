import { Badge } from "@/components/ui/badge"
import type { StatusKey } from "@/lib/api"
import { RISK_COLOR, STATUS_COLOR, statusLabel } from "@/lib/status"

export function StatusBadge({ status }: { status: StatusKey | string }) {
  const color = STATUS_COLOR[status] ?? "var(--zs-text-muted)"
  return (
    <Badge variant="outline" className="gap-1.5" style={{ borderColor: color }}>
      <span
        className="inline-block h-2 w-2 rounded-full"
        style={{ background: color }}
      />
      {statusLabel(status)}
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

/** Chip de modo de ejecución. Sin esto el panel mostraba "ok" en acciones simuladas. */
export function ModeChip({ mode }: { mode: "live" | "dry_run" | "mixed" }) {
  if (mode === "live") {
    return (
      <Badge
        variant="outline"
        className="gap-1.5 text-[11px] font-semibold tracking-wide"
        style={{ borderColor: "var(--zs-ok)", color: "var(--zs-ok)" }}
      >
        <span
          className="inline-block h-2 w-2 rounded-full"
          style={{ background: "var(--zs-ok)" }}
        />
        LIVE
      </Badge>
    )
  }
  const label = mode === "dry_run" ? "DRY-RUN" : "DRY-RUN PARCIAL"
  return (
    <Badge
      variant="outline"
      className="gap-1.5 text-[11px] font-semibold tracking-wide"
      style={{
        borderColor: "color-mix(in oklab, var(--zs-warn) 45%, transparent)",
        background: "color-mix(in oklab, var(--zs-warn) 12%, transparent)",
        color: "var(--zs-warn)",
      }}
      title={
        mode === "dry_run"
          ? "Las acciones se registran pero no se aplican"
          : "Algunas familias simulan y otras ejecutan de verdad"
      }
    >
      {label}
    </Badge>
  )
}
