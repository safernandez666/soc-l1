// Equivalente client-side de queries._human_duration / humanize_age.

export function humanDuration(seconds: number | null): string {
  if (seconds === null) return "—"
  const s = Math.floor(seconds)
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m`
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`
  return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`
}

export function humanizeAge(createdAt: string | null): string {
  if (!createdAt) return "—"
  const dt = new Date(createdAt)
  if (Number.isNaN(dt.getTime())) return "—"
  return humanDuration((Date.now() - dt.getTime()) / 1000)
}
