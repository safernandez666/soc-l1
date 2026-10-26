// Diccionario único de estados y riesgo.
//
// Antes cada pantalla traía el suyo y `executed` se llamaba "Cerrado" en el badge,
// "Ejecutado" en el detalle del caso y "Ejecutados" en el filtro de la cola. Un
// solo lugar, con el plural derivado, evita que vuelvan a divergir.

import type { StatusKey } from "@/lib/api"

export const STATUS_LABEL: Record<string, string> = {
  pending: "Pendiente",
  approved: "Aprobado",
  executed: "Cerrado",
  rejected: "Rechazado",
  expired: "Expirado",
}

export const STATUS_ORDER: StatusKey[] = [
  "pending",
  "approved",
  "executed",
  "rejected",
  "expired",
]

export function statusLabel(status: string): string {
  return STATUS_LABEL[status] ?? status
}

export function statusLabelPlural(status: string): string {
  const label = STATUS_LABEL[status]
  return label ? `${label}s` : status
}

// Color por estado. La escala baja de intensidad a medida que el caso se resuelve:
// pendiente grita (relleno), aprobado espera (contorno), cerrado se apaga (texto).
export const STATUS_COLOR: Record<string, string> = {
  pending: "var(--zs-warn)",
  approved: "var(--zs-info)",
  executed: "var(--zs-ok)",
  rejected: "var(--zs-danger)",
  expired: "var(--zs-text-muted)",
}

export const RISK_COLOR: Record<string, string> = {
  critical: "var(--zs-danger)",
  high: "#f97316",
  medium: "var(--zs-warn)",
  low: "var(--zs-ok)",
  info: "var(--zs-info)",
  unknown: "var(--zs-text-muted)",
}
