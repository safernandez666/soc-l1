import { createBrowserRouter, RouterProvider } from "react-router-dom"
import { Layout } from "@/components/Layout"
import { PanelPage } from "@/pages/PanelPage"
import { QueuePage } from "@/pages/QueuePage"
import { CasePage } from "@/pages/CasePage"
import { KpisPage } from "@/pages/KpisPage"
import { ConfigPage } from "@/pages/ConfigPage"
import { ReportPage } from "@/pages/ReportPage"
import { FgtPage } from "@/pages/FgtPage"
import { ReportsPage } from "@/pages/ReportsPage"
import { ConsolidatedReportPage } from "@/pages/ConsolidatedReportPage"

const router = createBrowserRouter(
  [
    {
      path: "/",
      element: <Layout />,
      children: [
        { index: true, element: <PanelPage /> },
        { path: "queue", element: <QueuePage /> },
        { path: "case/:rowid", element: <CasePage /> },
        { path: "kpis", element: <KpisPage /> },
        { path: "fortigate", element: <FgtPage /> },
        { path: "reportes", element: <ReportsPage /> },
        { path: "config", element: <ConfigPage /> },
      ],
    },
    // Informes imprimibles: fuera del Layout (sin sidebar), documento limpio para PDF.
    { path: "/case/:rowid/report", element: <ReportPage /> },
    { path: "/reportes/consolidado", element: <ConsolidatedReportPage /> },
  ],
  { basename: "/ui" }
)

export default function App() {
  return <RouterProvider router={router} />
}
