import { useDashboardStats } from '@/hooks/useDashboard'
import { useRealtimeAlerts } from '@/hooks/useRealtimeAlerts'
import { StatsRow, type StatItem } from '@/components/dashboard/StatsRow'
import { SeverityChart } from '@/components/dashboard/SeverityChart'
import { VolumeChart } from '@/components/dashboard/VolumeChart'
import { RecentAlerts } from '@/components/dashboard/RecentAlerts'
import { TopIncidents } from '@/components/dashboard/TopIncidents'
import { LiveIndicator } from '@/components/dashboard/LiveIndicator'
import { ErrorState } from '@/components/ui/ErrorState'
import { AlertTriangle, Flame, Shield } from 'lucide-react'

export function Dashboard() {
  const { status: wsStatus, reconnect } = useRealtimeAlerts()

  const {
    data: stats,
    isLoading,
    isError,
    refetch,
  } = useDashboardStats(30_000)

  if (isError) {
    return <ErrorState title="Failed to load dashboard" onRetry={() => refetch()} />
  }

  const openCritical = stats?.open_critical ?? 0
  const openHigh = stats?.open_high ?? 0
  const coveragePct = stats?.coverage_pct ?? 0
  const techniquesDetected = stats?.techniques_detected ?? 0
  const totalTechniques = stats?.total_techniques ?? 58

  const statItems: StatItem[] = [
    {
      label: 'Total Alerts',
      value: stats?.total_alerts ?? 0,
      icon: <AlertTriangle className="w-4 h-4 text-primary" />,
      variant: 'blue',
    },
    {
      label: 'Critical Open',
      value: openCritical,
      icon: <AlertTriangle className="w-4 h-4 text-severity-critical" />,
      variant: 'critical',
      pulse: openCritical > 0,
    },
    {
      label: 'High Open',
      value: openHigh,
      icon: <AlertTriangle className="w-4 h-4 text-severity-high" />,
      variant: 'high',
    },
    {
      label: 'Active Incidents',
      value: stats?.incidents_count ?? 0,
      icon: <Flame className="w-4 h-4 text-severity-high" />,
      variant: stats?.incidents_count ? 'high' : 'default',
    },
    {
      label: 'MITRE Coverage',
      value: `${coveragePct}%`,
      icon: <Shield className="w-4 h-4 text-success" />,
      variant: coveragePct >= 20 ? 'green' : 'critical',
      subtitle: `${techniquesDetected} of ${totalTechniques} techniques`,
    },
  ]

  const severityData = stats?.alerts_by_severity
    ? Object.entries(stats.alerts_by_severity)
        .map(([name, value]) => ({ name, value }))
        .filter((d) => d.value > 0)
    : []

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold tracking-tight">Dashboard</h1>
          <p className="text-xs text-muted-foreground">Security operations overview</p>
        </div>
        <LiveIndicator status={wsStatus} onReconnect={reconnect} />
      </div>

      {/* Stats */}
      <StatsRow stats={statItems} />

      {/* Charts */}
      <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
        <div className="xl:col-span-3">
          <VolumeChart data={stats?.volume_timeline ?? []} />
        </div>
        <div className="xl:col-span-2">
          <SeverityChart data={severityData} />
        </div>
      </div>

      {/* Tables */}
      <RecentAlerts
        alerts={stats?.recent_alerts ?? []}
        loading={isLoading && !stats}
      />

      <TopIncidents
        incidents={stats?.incidents ?? []}
        loading={isLoading && !stats}
      />
    </div>
  )
}
