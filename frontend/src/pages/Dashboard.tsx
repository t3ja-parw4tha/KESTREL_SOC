import { useDashboardStats } from '@/hooks/useDashboard'
import { StatsRow, type StatItem } from '@/components/dashboard/StatsRow'
import { SeverityChart } from '@/components/dashboard/SeverityChart'
import { VolumeChart } from '@/components/dashboard/VolumeChart'
import { RecentAlerts } from '@/components/dashboard/RecentAlerts'
import { TopIncidents } from '@/components/dashboard/TopIncidents'
import { ErrorState } from '@/components/ui/ErrorState'
import { SpinnerOverlay } from '@/components/ui/Spinner'
import { AlertTriangle, Flame, Shield, RefreshCw } from 'lucide-react'

export function Dashboard() {
  const {
    data: stats,
    isLoading,
    isError,
    refetch,
  } = useDashboardStats(30_000)

  if (isError) {
    return <ErrorState title="Failed to load dashboard" onRetry={() => refetch()} />
  }

  if (isLoading && !stats) return <SpinnerOverlay />

  const openCritical = stats?.open_critical ?? 0
  const openHigh = stats?.open_high ?? 0
  const coveragePct = stats?.coverage_pct ?? 0
  const techniquesDetected = stats?.techniques_detected ?? 0
  const totalTechniques = stats?.total_techniques ?? 58

  const statItems: StatItem[] = [
    { label: 'Total Alerts', value: stats?.total_alerts ?? 0, icon: <AlertTriangle className="w-5 h-5 text-blue-500 dark:text-blue-400" />, variant: 'blue', cardTint: 'neutral' },
    { label: 'Critical Open', value: openCritical, icon: <AlertTriangle className="w-5 h-5 text-red-500 dark:text-red-400" />, variant: 'critical', cardTint: 'danger', pulse: openCritical > 0 },
    { label: 'High Open', value: openHigh, icon: <AlertTriangle className="w-5 h-5 text-orange-500 dark:text-orange-400" />, variant: 'high', cardTint: 'warning' },
    { label: 'Active Incidents', value: stats?.incidents_count ?? 0, icon: <Flame className="w-5 h-5 text-orange-500 dark:text-orange-400" />, variant: 'high', cardTint: stats?.incidents_count ? 'warning' : 'neutral' },
    { label: 'MITRE Coverage %', value: `${coveragePct}%`, icon: <Shield className="w-5 h-5 text-emerald-500 dark:text-emerald-400" />, variant: coveragePct >= 20 ? 'green' : 'critical', cardTint: coveragePct < 20 ? 'danger' : 'neutral', subtitle: `${techniquesDetected} of ${totalTechniques} techniques detected` },
  ]

  const severityData = stats?.alerts_by_severity
    ? Object.entries(stats.alerts_by_severity).map(([name, value]) => ({ name, value })).filter((d) => d.value > 0)
    : []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold text-soc-text">
          Dashboard
        </h1>
        <button
          type="button"
          onClick={() => refetch()}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-soc-border bg-soc-surface text-soc-muted hover:text-soc-text text-sm"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>
      <StatsRow stats={statItems} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
        <SeverityChart data={severityData} />
        <VolumeChart data={stats?.volume_timeline ?? []} />
      </div>

      <RecentAlerts
        alerts={stats?.recent_alerts ?? []}
        loading={isLoading}
      />

      <TopIncidents
        incidents={stats?.incidents ?? []}
        loading={isLoading}
      />
    </div>
  )
}
