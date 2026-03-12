import { Outlet, useLocation } from 'react-router-dom'
import { useDashboardStats } from '@/hooks/useDashboard'
import { useDocumentTitle } from '@/hooks/useDocumentTitle'
import { useKeyboardShortcuts } from '@/hooks/useKeyboardShortcuts'
import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'

export function Layout() {
  const location = useLocation()
  useDocumentTitle(location.pathname)
  useKeyboardShortcuts()
  const { data: stats, isRefetching, dataUpdatedAt } = useDashboardStats()

  const openAlertsCount = (stats?.open_critical ?? 0) + (stats?.open_high ?? 0)
  const lastUpdated = dataUpdatedAt ? new Date(dataUpdatedAt).toISOString() : undefined

  return (
    <div className="h-screen overflow-hidden bg-soc-bg flex relative">
      {/* Premium Dynamic Background (Dark Mode Only) */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden z-0 hidden dark:block">
        <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.02)_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)]" />
        <div className="absolute -top-[40%] -left-[10%] w-[70%] h-[70%] rounded-full bg-blue-900/10 blur-[120px] mix-blend-screen" />
        <div className="absolute top-[20%] -right-[20%] w-[60%] h-[60%] rounded-full bg-indigo-900/10 blur-[120px] mix-blend-screen" />
      </div>
      <a
        href="#main-content"
        className="absolute left-4 top-4 -translate-y-[9999px] focus:translate-y-0 z-[100] px-4 py-2 rounded-lg bg-blue-600 text-white text-sm font-medium focus:outline-none focus:ring-2 focus:ring-blue-400 focus:ring-offset-2 focus:ring-offset-soc-bg"
      >
        Skip to main content
      </a>
      <Sidebar
        openAlertsCount={openAlertsCount}
        openIncidentsCount={stats?.incidents_count ?? 0}
      />
      <div className="flex-1 flex flex-col min-w-0 min-h-0">
        <TopBar
          lastUpdated={lastUpdated}
          isRefetching={isRefetching}
        />
        <main id="main-content" className="flex-1 min-h-0 overflow-auto p-6 relative z-10" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
    </div>
  )
}
