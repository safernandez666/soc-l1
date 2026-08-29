import { useNavigate, useSearchParams } from "react-router-dom"
import { api } from "@/lib/api"
import { useFetch } from "@/lib/useFetch"
import { humanizeAge } from "@/lib/format"
import { StateView } from "@/components/StateView"
import { StatusBadge, RiskPill } from "@/components/badges"
import { STATUS_ORDER, statusLabelPlural } from "@/lib/status"
import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

// Del diccionario compartido: antes "executed" era "Ejecutados" acá y "Cerrado"
// en el badge de la misma fila.
const FILTERS: [string, string][] = [
  ["", "Todos"],
  ...STATUS_ORDER.map((s) => [s, statusLabelPlural(s)] as [string, string]),
]

// Ventanas de tiempo — espejo de router._QUEUE_RANGES. El backend recorta por
// created_at, así que la paginación y el total ya vienen filtrados.
const RANGES: [string, string][] = [
  ["24h", "Últimas 24 h"],
  ["7d", "7 días"],
  ["30d", "30 días"],
  ["", "Todo"],
]

export function QueuePage() {
  const navigate = useNavigate()
  const [params, setParams] = useSearchParams()
  const status = params.get("status") || ""
  const since = params.get("since") || ""
  const page = Math.max(1, Number(params.get("page") || "1"))

  const state = useFetch(
    () => api.queue(status || null, page, since || null),
    [status, page, since],
  )

  // Cambiar cualquier filtro vuelve a la página 1: el offset viejo puede quedar
  // fuera de rango con el total nuevo.
  const apply = (next: { status?: string; since?: string; page?: number }) => {
    const qs = new URLSearchParams()
    const st = next.status ?? status
    const sc = next.since ?? since
    if (st) qs.set("status", st)
    if (sc) qs.set("since", sc)
    if (next.page && next.page > 1) qs.set("page", String(next.page))
    setParams(qs)
  }
  const setFilter = (val: string) => apply({ status: val })
  const setRange = (val: string) => apply({ since: val })
  const goPage = (p: number) => apply({ page: p })

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap gap-2">
          {FILTERS.map(([val, label]) => (
            <button
              key={val}
              onClick={() => setFilter(val)}
              className={`rounded-full border px-3 py-1 text-sm transition-colors ${
                status === val
                  ? "border-primary bg-primary/10 text-foreground"
                  : "border-border text-muted-foreground hover:text-foreground"
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {/* Picker de tiempo: segmentado, separado de los chips de estado para
            que se lea como otra dimensión de filtro y no como un estado más. */}
        <div className="flex items-center gap-1 rounded-full border border-border p-0.5">
          {RANGES.map(([val, label]) => (
            <button
              key={val || "all"}
              onClick={() => setRange(val)}
              className={`rounded-full px-3 py-1 text-sm transition-colors ${
                since === val
                  ? "bg-primary/15 text-foreground"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <StateView state={state}>
        {(q) => {
          const pages = Math.max(1, Math.ceil(q.total / q.per_page))

          if (q.cases.length === 0) {
            return (
              <Card>
                <CardContent className="flex flex-col items-center gap-3 py-12 text-center">
                  <p className="text-sm text-muted-foreground">
                    No hay casos para este filtro.
                  </p>
                  {(status || since) && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => apply({ status: "", since: "" })}
                    >
                      Limpiar filtros
                    </Button>
                  )}
                </CardContent>
              </Card>
            )
          }

          return (
            <>
              {/* Mobile: cards apiladas */}
              <div className="space-y-3 md:hidden">
                {q.cases.map((c) => (
                  <Card
                    key={c.rowid}
                    onClick={() => navigate(`/case/${c.rowid}`)}
                    className="cursor-pointer"
                  >
                    <CardContent className="space-y-2 py-4">
                      <div className="flex items-start justify-between gap-2">
                        <div className="font-medium">{c.title}</div>
                        <RiskPill risk={c.risk_level} />
                      </div>
                      <div className="font-mono text-xs text-muted-foreground">
                        {c.alert_id}
                      </div>
                      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
                        <StatusBadge status={c.status} />
                        <span className="font-mono">{c.host}</span>
                        <span>{humanizeAge(c.created_at)}</span>
                        <span>· {c.n_actions} acc.</span>
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
                          <TableHead>Caso</TableHead>
                          <TableHead>Riesgo</TableHead>
                          <TableHead>Estado</TableHead>
                          <TableHead>Host</TableHead>
                          <TableHead>Edad</TableHead>
                          <TableHead className="text-right">Plan</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {q.cases.map((c) => (
                          <TableRow
                            key={c.rowid}
                            onClick={() => navigate(`/case/${c.rowid}`)}
                            className="cursor-pointer"
                          >
                            <TableCell>
                              <div className="font-medium">{c.title}</div>
                              <div className="text-xs text-muted-foreground">
                                {c.alert_id}
                              </div>
                            </TableCell>
                            <TableCell>
                              <RiskPill risk={c.risk_level} />
                            </TableCell>
                            <TableCell>
                              <StatusBadge status={c.status} />
                            </TableCell>
                            <TableCell className="font-mono text-xs">
                              {c.host}
                            </TableCell>
                            <TableCell className="text-muted-foreground">
                              {humanizeAge(c.created_at)}
                            </TableCell>
                            <TableCell className="text-right text-muted-foreground">
                              {c.n_actions} acc.
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                </CardContent>
              </Card>

              {/* Paginación — solo si hay más de una página */}
              {pages > 1 && (
                <div className="flex items-center justify-between">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page <= 1}
                    onClick={() => goPage(page - 1)}
                  >
                    ← Anterior
                  </Button>
                  <span className="text-sm text-muted-foreground">
                    Página {page} de {pages} · {q.total} casos
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page >= pages}
                    onClick={() => goPage(page + 1)}
                  >
                    Siguiente →
                  </Button>
                </div>
              )}
            </>
          )
        }}
      </StateView>
    </div>
  )
}
