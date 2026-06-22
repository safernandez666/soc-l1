// Capa de acceso a la API JSON del backend (/ui/api/*). Mismo origen, cookie de
// sesión incluida automáticamente. Ante 401 redirige al login server-rendered.

const BASE = "/ui/api"

export class UnauthorizedError extends Error {}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { Accept: "application/json" },
    credentials: "same-origin",
  })
  if (res.status === 401) {
    throw new UnauthorizedError("unauthorized")
  }
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} en ${path}`)
  }
  return res.json() as Promise<T>
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(body),
  })
  if (res.status === 401) {
    throw new UnauthorizedError("unauthorized")
  }
  const data = (await res.json().catch(() => ({}))) as { error?: string }
  if (!res.ok) {
    throw new Error(data?.error || `HTTP ${res.status} en ${path}`)
  }
  return data as T
}

export function redirectToLogin(): void {
  window.location.href = "/ui/login"
}

// ===== Tipos (espejo de queries._metrics_sync) =====

export type StatusKey =
  | "pending"
  | "approved"
  | "executed"
  | "rejected"
  | "expired"

export interface FailedAction {
  rowid: number
  action_type: string
  target: string | null
  message: string | null
  ts: string | null
}

export interface Metrics {
  total: number
  status_counts: Record<StatusKey, number>
  risk_counts: Record<string, number>
  actions_exec: Record<string, number>
  actions_ok: Record<string, number>
  mtta_human: string
  mttr_human: string
  approval_rate: number | null
  pending: number
  oldest_pending_human: string
  per_day: [string, number][]
  per_day_closed: [string, number][]
  vol_24: number
  vol_7: number
  vol_30: number
  trend_7d: number | null
  act_total: number
  act_ok: number
  act_success_rate: number | null
  failed_actions: FailedAction[]
  expired: number
  expiry_rate: number | null
  top_hosts: [string, number][]
  top_users: [string, number][]
}

export interface Session {
  authed: boolean
}

// ===== Cola (espejo de queries._summarize_row + api_queue) =====

export interface CaseSummary {
  rowid: number
  alert_id: string
  status: StatusKey
  created_at: string | null
  decided_at: string | null
  decided_by_ip: string | null
  executed_at: string | null
  invgate_request_id: string | null
  risk_level: string
  title: string
  host: string
  n_actions: number
}

export interface QueuePage {
  cases: CaseSummary[]
  total: number
  page: number
  per_page: number
  status: StatusKey | null
}

// ===== Detalle de caso (espejo de queries._get_case_sync) =====

export interface PlanAction {
  type: string
  target?: string | null
  justification?: string | null
}

export interface Plan {
  risk_level?: string
  executive_summary?: string
  rationale?: string
  actions?: PlanAction[]
}

export interface AlertDevice {
  hostname?: string
  fqdn?: string
  internal_ip?: string
}

export interface Alert {
  title?: string
  device?: AlertDevice
  users_involved?: { sam?: string }[]
  severity_source?: string
  category?: string
}

export interface TimelineEvent {
  stage?: string
  ts?: string
  summary?: string
  detail?: string | null
}

export interface ExecResult {
  action_type?: string
  target?: string | null
  ok?: boolean
  message?: string | null
}

export interface CaseDetail {
  rowid: number
  alert_id: string
  status: StatusKey
  created_at: string | null
  decided_at: string | null
  decided_by_ip: string | null
  decided_by_ua: string | null
  executed_at: string | null
  invgate_request_id: string | null
  selected_actions: number[] | null
  plan: Plan
  alert: Alert
  timeline: TimelineEvent[]
  execution_result: ExecResult[]
}

// ===== KPIs (espejo de queries.kpis_metrics) =====

export interface Period {
  first: string | null
  last: string | null
  days: number
  label: string
}

export interface Containment {
  available: boolean
  period?: Period
  total_cases?: number
  cases_with_containment?: number
  containment_rate?: number | null
  proposed_total?: number
  executed_total?: number
  hosts_contained?: number
  by_type?: [string, number, number][]
}

export interface VolumeMonth {
  name: string
  label: string
  avg_per_day: number
  fg_blocks_avg_per_day?: number
  fg_blocks_total_estimate?: number
}

export interface AlertVolume {
  available: boolean
  months?: VolumeMonth[]
  sampled?: boolean
  max_days_per_month?: number
}

export interface Posture {
  available: boolean
  error?: string
  agents?: { total?: number; active?: number; disconnected?: number; never_connected?: number }
  os?: string[]
  rules_total?: number
  manager_version?: string
}

export interface Fortigate {
  available: boolean
  error?: string
  count?: number
  banned?: string[]
}

export interface Kpis {
  containment: Containment
  alert_volume: AlertVolume
  posture: Posture
  fortigate: Fortigate
  dry_run: boolean
}

// ===== Config (espejo de config_io.public_config) =====

export type ConfigKind = "str" | "csv" | "int" | "bool" | "secret"

export interface ConfigField {
  name: string
  label: string
  kind: ConfigKind
  help?: string
  options?: string[]
  value?: string | number | boolean // ausente en secretos
  set?: boolean // solo secretos: si ya tiene valor
  hint?: string // solo secretos: ••••last4
}

export interface ConfigSection {
  key: string
  title: string
  fields: ConfigField[]
}

export interface ConfigResponse {
  sections: ConfigSection[]
}

export type ConfigUpdate = Record<string, string | number | boolean>

export const api = {
  session: () => get<Session>("/session"),
  metrics: () => get<Metrics>("/metrics"),
  queue: (status: string | null, page: number) => {
    const qs = new URLSearchParams()
    if (status) qs.set("status", status)
    qs.set("page", String(page))
    return get<QueuePage>(`/queue?${qs.toString()}`)
  },
  case: (rowid: number | string) => get<CaseDetail>(`/case/${rowid}`),
  kpis: () => get<Kpis>("/kpis"),
  config: () => get<ConfigResponse>("/config"),
  saveConfig: (updates: ConfigUpdate) =>
    post<{ ok: boolean; applied: string[] }>("/config", updates),
}
