import { useEffect, useState } from "react"
import { redirectToLogin, UnauthorizedError } from "@/lib/api"

type State<T> =
  | { kind: "loading" }
  | { kind: "ready"; data: T }
  | { kind: "error"; message: string }

// Hook genérico de fetch. Ante 401 redirige al login server-rendered.
// `deps` re-dispara el fetch (p. ej. cambia el filtro o la página de la cola).
export function useFetch<T>(fn: () => Promise<T>, deps: unknown[]): State<T> {
  const [state, setState] = useState<State<T>>({ kind: "loading" })

  useEffect(() => {
    let alive = true
    // Reset intencional a "loading" cuando cambian las deps (p. ej. página/filtro
    // de la cola) para mostrar el skeleton mientras llega el nuevo fetch.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setState({ kind: "loading" })
    fn()
      .then((data) => {
        if (alive) setState({ kind: "ready", data })
      })
      .catch((e) => {
        if (e instanceof UnauthorizedError) {
          redirectToLogin()
          return
        }
        if (alive)
          setState({
            kind: "error",
            message: e instanceof Error ? e.message : "Error desconocido",
          })
      })
    return () => {
      alive = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)

  return state
}
