import { Outlet } from 'react-router-dom'
import { useDashboardStats } from '@/hooks/useDashboard'
import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'

export function Layout() {
  const { data: stats, isRefetching, dataUpdatedAt } = useDashboardStats()

  const openAlertsCount = (stats?.open_critical ?? 0) + (stats?.open_high ?? 0)
  const lastUpdated = dataUpdatedAt ? new Date(dataUpdatedAt).toISOString() : undefined

  return (
    <div className="min-h-screen bg-soc-bg flex">
      <Sidebar
        openAlertsCount={openAlertsCount}
        openIncidentsCount={stats?.incidents_count ?? 0}
      />
      <div className="flex-1 flex flex-col min-w-0">
        <TopBar
          criticalCount={stats?.open_critical ?? 0}
          highCount={stats?.open_high ?? 0}
          lastUpdated={lastUpdated}
          isRefetching={isRefetching}
        />
        <main className="flex-1 overflow-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
