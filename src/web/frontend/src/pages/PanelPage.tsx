import { api } from "@/lib/api"
import { useFetch } from "@/lib/useFetch"
import { StateView } from "@/components/StateView"
import { Panel } from "@/components/Panel"
import { Skeleton } from "@/components/ui/skeleton"

export function PanelPage() {
  const state = useFetch(() => api.metrics(), [])
  return (
    <StateView
      state={state}
      skeleton={
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-4 md:grid-cols-3 lg:grid-cols-6">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-28" />
            ))}
          </div>
          <Skeleton className="h-40" />
        </div>
      }
    >
      {(m) => <Panel m={m} />}
    </StateView>
  )
}
