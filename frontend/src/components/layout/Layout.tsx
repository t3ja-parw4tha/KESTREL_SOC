import { useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { AnimatePresence } from 'framer-motion'
import { useDashboardStats } from '@/hooks/useDashboard'
import { useDocumentTitle } from '@/hooks/useDocumentTitle'
import { useKeyboardShortcuts } from '@/hooks/useKeyboardShortcuts'
import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'
import { PageTransition } from './PageTransition'

export function Layout() {
  const location = useLocation()
  useDocumentTitle(location.pathname)
  useKeyboardShortcuts()
  const { data: stats, isRefetching, dataUpdatedAt } = useDashboardStats()
  const [sidebarOpen, setSidebarOpen] = useState(true)

  const openAlertsCount = (stats?.open_critical ?? 0) + (stats?.open_high ?? 0)
  const lastUpdated = dataUpdatedAt ? new Date(dataUpdatedAt).toISOString() : undefined

  return (
    <div className="h-screen overflow-hidden bg-background flex relative">
      {/* Ambient orbs only — no grid */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden z-0 hidden dark:block">
        <div className="absolute -top-[40%] -left-[10%] w-[70%] h-[70%] rounded-full bg-blue-900/10 blur-[120px] mix-blend-screen animate-float" />
        <div className="absolute top-[20%] -right-[20%] w-[60%] h-[60%] rounded-full bg-indigo-900/10 blur-[120px] mix-blend-screen animate-float [animation-delay:3s]" />
      </div>
      <a
        href="#main-content"
        className="absolute left-4 top-4 -translate-y-[9999px] focus:translate-y-0 z-[100] px-4 py-2 rounded-lg bg-blue-600 text-white text-sm font-medium focus:outline-none focus:ring-2 focus:ring-blue-400"
      >
        Skip to main content
      </a>
      <Sidebar
        openAlertsCount={openAlertsCount}
        openIncidentsCount={stats?.incidents_count ?? 0}
        collapsed={!sidebarOpen}
      />
      <div className="flex-1 flex flex-col min-w-0 min-h-0">
        <TopBar
          lastUpdated={lastUpdated}
          isRefetching={isRefetching}
          sidebarOpen={sidebarOpen}
          onToggleSidebar={() => setSidebarOpen((o) => !o)}
        />
        <main
          id="main-content"
          className="flex-1 min-h-0 overflow-auto p-4 lg:p-6 scrollbar-thin relative z-10"
          tabIndex={-1}
        >
          <AnimatePresence mode="wait">
            <PageTransition key={location.pathname.split('/').slice(0, 3).join('/')}>
              <Outlet />
            </PageTransition>
          </AnimatePresence>
        </main>
      </div>
    </div>
  )
}
