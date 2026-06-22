import { NavLink, Outlet } from "react-router-dom"
import type { ReactNode } from "react"

type NavItem = { to: string; label: string; end: boolean; icon: ReactNode }

const NAV: NavItem[] = [
  {
    to: "/",
    label: "Panel",
    end: true,
    // layout-dashboard
    icon: (
      <>
        <rect width="7" height="9" x="3" y="3" rx="1" />
        <rect width="7" height="5" x="14" y="3" rx="1" />
        <rect width="7" height="9" x="14" y="12" rx="1" />
        <rect width="7" height="5" x="3" y="16" rx="1" />
      </>
    ),
  },
  {
    to: "/queue",
    label: "Cola",
    end: false,
    // inbox
    icon: (
      <>
        <path d="M22 12h-6l-2 3h-4l-2-3H2" />
        <path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z" />
      </>
    ),
  },
  {
    to: "/kpis",
    label: "KPIs",
    end: false,
    // activity (pulso)
    icon: <path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2" />,
  },
  {
    to: "/config",
    label: "Configuración",
    end: false,
    // sliders-horizontal
    icon: (
      <>
        <line x1="21" x2="14" y1="4" y2="4" />
        <line x1="10" x2="3" y1="4" y2="4" />
        <line x1="21" x2="12" y1="12" y2="12" />
        <line x1="8" x2="3" y1="12" y2="12" />
        <line x1="21" x2="16" y1="20" y2="20" />
        <line x1="12" x2="3" y1="20" y2="20" />
        <line x1="14" x2="14" y1="2" y2="6" />
        <line x1="8" x2="8" y1="10" y2="14" />
        <line x1="16" x2="16" y1="18" y2="22" />
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
          <img
            src="/ui/static/zebra-logo.svg"
            alt="ZebraSecurity"
            className="h-9 w-auto"
          />
          <div className="leading-tight">
            <div className="text-base font-semibold">SOC-L1</div>
            <div className="text-[11px] tracking-wide text-muted-foreground">
              Zebra<span className="font-bold text-foreground">Security</span>
            </div>
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
