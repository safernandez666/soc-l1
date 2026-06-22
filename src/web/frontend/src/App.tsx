import { createBrowserRouter, RouterProvider } from "react-router-dom"
import { Layout } from "@/components/Layout"
import { PanelPage } from "@/pages/PanelPage"
import { QueuePage } from "@/pages/QueuePage"
import { CasePage } from "@/pages/CasePage"
import { KpisPage } from "@/pages/KpisPage"
import { ConfigPage } from "@/pages/ConfigPage"

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
        { path: "config", element: <ConfigPage /> },
      ],
    },
  ],
  { basename: "/ui" }
)

export default function App() {
  return <RouterProvider router={router} />
}
