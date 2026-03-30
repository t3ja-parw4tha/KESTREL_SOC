import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { get, post, del } from '@/api/client'
import { useDashboardStats } from '@/hooks/useDashboard'
import { useRealtimeAlerts } from '@/hooks/useRealtimeAlerts'
import { StatsRow, type StatItem } from '@/components/dashboard/StatsRow'
import { SeverityDonut } from '@/components/dashboard/SeverityDonut'
import { VolumeChart } from '@/components/dashboard/VolumeChart'
import { RecentAlerts } from '@/components/dashboard/RecentAlerts'
import { TopIncidents } from '@/components/dashboard/TopIncidents'
import { LiveIndicator } from '@/components/dashboard/LiveIndicator'
import { StatsSkeleton, ChartSkeleton, DonutSkeleton, TableSkeleton } from '@/components/ui/LoadingSkeleton'
import { ErrorBanner } from '@/components/ui/ErrorBanner'
import type { TrendPeriod } from '@/api/dashboard'
import { AlertTriangle, Flame, RefreshCw, Clock, Timer, LayoutDashboard, Plus, Trash2, Star, WifiOff, CheckCircle2 } from 'lucide-react'
import { cn } from '@/utils/cn'
import { ROUTES } from '@/utils/routes'

function relativeTime(ms: number): string {
  const diff = Date.now() - ms
  const mins = Math.floor(diff / 60_000)
  if (mins < 1) return 'just now'
  if (mins === 1) return '1 min ago'
  if (mins < 60) return `${mins} min ago`
  const hrs = Math.floor(mins / 60)
  return `${hrs}h ago`
}

const TREND_PERIODS: { value: TrendPeriod; label: string; tooltip: string }[] = [
  { value: 'day',   label: '1D', tooltip: 'Today vs yesterday' },
  { value: 'week',  label: '1W', tooltip: 'Last 7 days vs prior 7 days' },
  { value: 'month', label: '1M', tooltip: 'Last 30 days vs prior 30 days' },
]

/** Freshness indicator shown in the Dashboard header */
function FreshnessIndicator({ lagMinutes }: { lagMinutes: number | null | undefined }) {
  if (lagMinutes == null) return null
  const isStale = lagMinutes > 60
  const label = lagMinutes < 1
    ? 'Last ingest < 1 min ago'
    : lagMinutes < 60
    ? `Last ingest ${Math.round(lagMinutes)} min ago`
    : `Last ingest ${Math.round(lagMinutes / 60)}h ago`
  return (
    <span className={cn(
      'inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-full border',
      isStale
        ? 'border-amber-500/30 bg-amber-500/10 text-amber-400'
        : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
    )}>
      {isStale ? <WifiOff className="w-2.5 h-2.5" /> : <CheckCircle2 className="w-2.5 h-2.5" />}
      {label}
    </span>
  )
}

// ─── Custom Dashboard Layouts ─────────────────────────────────────────────────
interface DashboardLayout { id: number; name: string; description: string | null; widgets: unknown[]; is_default: boolean }

function CustomDashboardPanel() {
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [creating, setCreating] = useState(false)

  const { data: layouts = [] } = useQuery({
    queryKey: ['custom-dashboards'],
    queryFn: () => get<DashboardLayout[]>('/custom-dashboards'),
  })

  const createMut = useMutation({
    mutationFn: (body: object) => post<DashboardLayout>('/custom-dashboards', body),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['custom-dashboards'] }); setName(''); setCreating(false) },
  })

  const deleteMut = useMutation({
    mutationFn: (id: number) => del<void>(`/custom-dashboards/${id}`),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['custom-dashboards'] }),
  })

  if (!open) {
    return (
      <button type="button" onClick={() => setOpen(true)}
        className="w-full flex items-center justify-between px-4 py-3 rounded-xl border border-border/50 glass-card text-sm text-muted-foreground hover:text-foreground hover:border-border transition-colors">
        <span className="flex items-center gap-2"><LayoutDashboard className="w-4 h-4" /> Custom Dashboard Layouts ({layouts.length})</span>
        <Plus className="w-4 h-4" />
      </button>
    )
  }

  return (
    <div className="glass-card rounded-xl border border-border/50 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-2"><LayoutDashboard className="w-4 h-4" /> Custom Dashboard Layouts</h3>
        <button type="button" onClick={() => setOpen(false)} className="text-xs text-muted-foreground hover:text-foreground">Close</button>
      </div>

      {/* Create form */}
      {creating ? (
        <div className="flex gap-2">
          <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="Layout name"
            className="flex-1 px-3 py-2 rounded-lg border border-border bg-background text-foreground text-sm" />
          <button type="button" onClick={() => createMut.mutate({ name: name.trim(), widgets: [], is_default: false })}
            disabled={createMut.isPending || !name.trim()}
            className="px-3 py-1.5 rounded-lg bg-primary text-primary-foreground text-sm font-medium disabled:opacity-50">
            Save
          </button>
          <button type="button" onClick={() => setCreating(false)}
            className="px-3 py-1.5 rounded-lg border border-border/50 text-sm text-muted-foreground hover:text-foreground">
            Cancel
          </button>
        </div>
      ) : (
        <button type="button" onClick={() => setCreating(true)}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border/50 text-sm text-muted-foreground hover:text-foreground hover:border-border transition-colors">
          <Plus className="w-3.5 h-3.5" /> New Layout
        </button>
      )}

      {layouts.length === 0 ? (
        <p className="text-xs text-muted-foreground py-2">No saved layouts. Create one to persist your dashboard configuration.</p>
      ) : (
        <div className="space-y-1.5">
          {layouts.map((l) => (
            <div key={l.id} className="flex items-center gap-3 p-2 rounded-lg bg-muted/20">
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-foreground truncate">{l.name}</p>
                {l.description && <p className="text-xs text-muted-foreground truncate">{l.description}</p>}
                <p className="text-xs text-muted-foreground">{l.widgets.length} widgets</p>
              </div>
              {l.is_default && <Star className="w-3.5 h-3.5 text-amber-400 shrink-0" />}
              <button type="button" onClick={() => deleteMut.mutate(l.id)} disabled={deleteMut.isPending}
                className="p-1 rounded border border-border/50 text-muted-foreground hover:text-red-400 hover:border-red-500/30 transition-colors shrink-0">
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export function Dashboard() {
  const { status: wsStatus, reconnect } = useRealtimeAlerts()
  const [trendPeriod, setTrendPeriod] = useState<TrendPeriod>('day')

  const {
    data: apiStats,
    isLoading,
    isError,
    isFetching,
    dataUpdatedAt,
    refetch,
  } = useDashboardStats(30_000, trendPeriod)

  // P6-1: Never fall back to demo data — show real API data or degraded state
  const stats = apiStats

  const TREND_LABEL: Record<TrendPeriod, string> = {
    day:   'vs yesterday',
    week:  'vs last week',
    month: 'vs last month',
  }

  const statItems: StatItem[] = stats
    ? [
        {
          label: 'Total Alerts',
          value: stats.total_alerts,
          icon: <AlertTriangle className="w-4 h-4 text-primary" />,
          variant: 'blue',
          trend: stats.alerts_trend != null ? { value: stats.alerts_trend } : null,
          href: ROUTES.alerts,
        },
        {
          label: 'Critical Open',
          value: stats.open_critical,
          icon: <AlertTriangle className="w-4 h-4 text-severity-critical" />,
          variant: 'critical',
          pulse: stats.open_critical > 0,
          trend: stats.crit_trend != null ? { value: stats.crit_trend } : null,
          href: `${ROUTES.alerts}?severity=Critical&status=open`,
        },
        {
          label: 'High Open',
          value: stats.open_high,
          icon: <AlertTriangle className="w-4 h-4 text-severity-high" />,
          variant: 'high',
          trend: stats.high_trend != null ? { value: stats.high_trend } : null,
          href: `${ROUTES.alerts}?severity=High&status=open`,
        },
        {
          label: 'Active Incidents',
          value: stats.incidents_count,
          icon: <Flame className="w-4 h-4 text-severity-high" />,
          variant: stats.incidents_count ? 'high' : 'default',
          href: ROUTES.incidents,
        },
        {
          label: 'SLA Breaches',
          value: stats.sla_breach_total ?? 0,
          icon: <Clock className="w-4 h-4 text-severity-critical" />,
          variant: (stats.sla_breach_total ?? 0) > 0 ? 'critical' : 'default',
          pulse: (stats.sla_breach_total ?? 0) > 0,
          subtitle: (stats.sla_breach_total ?? 0) > 0 ? 'Open alerts past SLA' : 'All alerts within SLA',
          href: ROUTES.alerts,
        },
        {
          label: 'Avg MTTR',
          value: stats.mttr_hours != null ? `${stats.mttr_hours}h` : '—',
          icon: <Timer className="w-4 h-4 text-success" />,
          variant: 'green',
          subtitle: stats.mttr_hours != null ? 'Mean time to resolve' : 'No resolved alerts yet',
        },
      ]
    : []

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Dashboard</h1>
          <p className="text-xs text-muted-foreground">
            Security operations overview
            {dataUpdatedAt > 0 && (
              <span className="ml-1 opacity-60">· Last updated {relativeTime(dataUpdatedAt)}</span>
            )}
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Trend period selector */}
          <div className="flex items-center gap-1 glass-card rounded-lg p-1">
            {TREND_PERIODS.map((p) => (
              <button
                key={p.value}
                onClick={() => setTrendPeriod(p.value)}
                title={p.tooltip}
                className={cn(
                  'px-2.5 py-1 text-[11px] font-semibold rounded-md transition-all duration-150',
                  trendPeriod === p.value
                    ? 'gradient-primary text-white shadow-sm'
                    : 'text-muted-foreground hover:text-foreground hover:bg-muted/40'
                )}
              >
                {p.label}
              </button>
            ))}
          </div>

          {/* Trend context label */}
          <span className="text-[10px] text-muted-foreground hidden sm:block">
            Trends {TREND_LABEL[trendPeriod]}
          </span>

          {/* Refresh */}
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-border text-muted-foreground hover:text-foreground hover:bg-muted/30 transition-colors disabled:opacity-40"
          >
            <RefreshCw className={cn('h-3.5 w-3.5', isFetching && 'animate-spin')} />
            Refresh
          </button>

          <LiveIndicator status={wsStatus} onReconnect={reconnect} />
          {/* P6-2: data freshness indicator */}
          <FreshnessIndicator lagMinutes={stats?.ingest_lag_minutes} />
        </div>
      </div>

      {/* P6-1: Degraded state — no demo data, clear actionable error */}
      {isError && (
        <ErrorBanner
          message="Backend API unreachable — dashboard data unavailable. No demo data is shown. Check that the server is running, then click Retry."
          onRetry={() => refetch()}
        />
      )}

      {/* Stats */}
      {isLoading && !stats ? <StatsSkeleton /> : <StatsRow stats={statItems} />}

      {/* Charts */}
      <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
        <div className="xl:col-span-3">
          {isLoading && !stats ? <ChartSkeleton /> : <VolumeChart data={stats?.volume_timeline ?? []} />}
        </div>
        <div className="xl:col-span-2">
          {isLoading && !stats ? <DonutSkeleton /> : <SeverityDonut stats={stats} />}
        </div>
      </div>

      {/* Tables */}
      {isLoading && !stats
        ? <TableSkeleton rows={5} cols={7} />
        : <RecentAlerts alerts={stats?.recent_alerts ?? []} loading={false} />
      }

      {isLoading && !stats
        ? <TableSkeleton rows={3} cols={5} />
        : <TopIncidents incidents={stats?.incidents ?? []} loading={false} />
      }

      <CustomDashboardPanel />
    </div>
  )
}
