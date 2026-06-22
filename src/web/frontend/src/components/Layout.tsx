import { NavLink, Outlet } from "react-router-dom"
import type { ReactNode } from "react"

type NavItem = { to: string; label: string; end: boolean; icon: ReactNode }

const NAV: NavItem[] = [
  {
    to: "/",
    label: "Panel",
    end: true,
    icon: (
      <path d="M3 13h8V3H3v10Zm0 8h8v-6H3v6Zm10 0h8V11h-8v10Zm0-18v6h8V3h-8Z" />
    ),
  },
  {
    to: "/queue",
    label: "Cola",
    end: false,
    icon: <path d="M4 6h16M4 12h16M4 18h16" />,
  },
  {
    to: "/kpis",
    label: "KPIs",
    end: false,
    icon: <path d="M4 20V10M10 20V4M16 20v-7M22 20H2" />,
  },
  {
    to: "/config",
    label: "Configuración",
    end: false,
    icon: (
      <>
        <circle cx="12" cy="12" r="3" />
        <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z" />
      </>
    ),
  },
]

function NavIcon({ children }: { children: ReactNode }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      className="h-[18px] w-[18px] shrink-0"
      aria-hidden
    >
      {children}
    </svg>
  )
}

export function Layout() {
  return (
    <div className="min-h-svh md:flex">
      <aside className="md:fixed md:inset-y-0 md:left-0 md:w-60 flex flex-col border-b md:border-b-0 md:border-r border-sidebar-border bg-sidebar text-sidebar-foreground">
        <div className="flex items-center gap-3 px-5 py-4">
          <img src="/ui/static/robot.svg" alt="" className="h-8 w-8" />
          <div>
            <div className="text-base font-semibold leading-tight">SOC-L1</div>
            <div className="text-[11px] text-muted-foreground">ZebraSecurity</div>
          </div>
        </div>

        <nav className="flex flex-col gap-1 px-3 py-2">
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.end}
              className={({ isActive }) =>
                `relative flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors ${
                  isActive
                    ? "bg-sidebar-accent text-primary font-medium before:absolute before:left-0 before:top-1.5 before:bottom-1.5 before:w-0.5 before:rounded-full before:bg-primary"
                    : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground"
                }`
              }
            >
              <NavIcon>{n.icon}</NavIcon>
              {n.label}
            </NavLink>
          ))}
        </nav>

        <a
          href="/ui/logout"
          className="mt-auto flex items-center gap-3 px-3 py-2 m-3 rounded-md text-sm text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground"
        >
          <NavIcon>
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" />
          </NavIcon>
          Salir
        </a>
      </aside>

      <main className="flex-1 md:ml-60 px-6 py-8">
        <div className="mx-auto max-w-6xl">
          <Outlet />
        </div>
      </main>
    </div>
  )
}
