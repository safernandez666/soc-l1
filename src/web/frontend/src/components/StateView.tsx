import type { ReactNode } from "react"
import { Skeleton } from "@/components/ui/skeleton"

type State<T> =
  | { kind: "loading" }
  | { kind: "ready"; data: T }
  | { kind: "error"; message: string }

export function StateView<T>({
  state,
  children,
  skeleton,
}: {
  state: State<T>
  children: (data: T) => ReactNode
  skeleton?: ReactNode
}) {
  if (state.kind === "loading") {
    return (
      <>{skeleton ?? <Skeleton className="h-40 w-full" />}</>
    )
  }
  if (state.kind === "error") {
    return (
      <div className="py-16 text-center">
        <h2 className="text-lg font-semibold">No se pudo cargar</h2>
        <p className="mt-2 text-sm text-muted-foreground">{state.message}</p>
      </div>
    )
  }
  return <>{children(state.data)}</>
}
