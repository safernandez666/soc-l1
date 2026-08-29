import { useEffect, useState } from "react"
import { api, type ExecMode, type Session } from "@/lib/api"

/** Modo de ejecución efectivo del backend (LIVE / DRY-RUN / mixto).
 *
 * Se pide una sola vez por montaje: solo cambia por reinicio o por edición de
 * config. Si el fetch falla devolvemos null y la pantalla se dibuja igual — el
 * modo es informativo y no debe romper la navegación.
 */
export function useExecMode(): { mode: ExecMode | null; session: Session | null } {
  const [session, setSession] = useState<Session | null>(null)
  useEffect(() => {
    let alive = true
    api
      .session()
      .then((s) => {
        if (alive) setSession(s)
      })
      .catch(() => {
        /* informativo: ignorar */
      })
    return () => {
      alive = false
    }
  }, [])
  return { mode: session?.mode ?? null, session }
}

/** Familias que hoy simulan, en texto para mostrarle al analista. */
export function simulatedFamilies(session: Session | null): string[] {
  const fams = session?.dry_run_families
  if (!fams) return []
  const NAMES: Record<string, string> = {
    ad: "AD",
    fortigate: "FortiGate",
    defender: "Defender",
  }
  return Object.entries(fams)
    .filter(([, simulated]) => simulated)
    .map(([family]) => NAMES[family] ?? family)
}
