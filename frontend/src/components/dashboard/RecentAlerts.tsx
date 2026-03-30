import { useNavigate } from 'react-router-dom'
import { Badge } from '@/components/ui/Badge'
import { ArrowRight } from 'lucide-react'
import { cn } from '@/utils/cn'
import type { Alert } from '@/types/alert'

interface RecentAlertsProps {
  alerts: Alert[]
  loading?: boolean
}

const STATUS_LABELS: Record<string, string> = {
  open:           'Open',
  new:            'New',
  in_progress:    'In Progress',
  resolved:       'Resolved',
  closed:         'Closed',
  false_positive: 'False Positive',
}

const STATUS_COLORS: Record<string, string> = {
  open:           'bg-primary/15 text-primary border-primary/20',
  new:            'bg-primary/15 text-primary border-primary/20',
  in_progress:    'bg-severity-medium/15 text-severity-medium border-severity-medium/20',
  resolved:       'bg-success/15 text-success border-success/20',
  closed:         'bg-muted/50 text-muted-foreground border-border/30',
  false_positive: 'bg-muted/50 text-muted-foreground border-border/30',
}

function riskColor(score: number | null | undefined): string {
  if (score == null) return 'text-muted-foreground'
  if (score >= 75) return 'text-severity-critical'
  if (score >= 50) return 'text-severity-high'
  return 'text-severity-medium'
}

function verboseRelativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const secs = Math.floor(diff / 1000)
  const mins = Math.floor(secs / 60)
  const hrs  = Math.floor(mins / 60)
  const days = Math.floor(hrs / 24)
  if (secs < 60)  return 'just now'
  if (mins < 2)   return '1 minute ago'
  if (mins < 60)  return `${mins} minutes ago`
  if (hrs < 2)    return 'about 1 hour ago'
  if (hrs < 24)   return `about ${hrs} hours ago`
  if (days < 2)   return 'yesterday'
  return `${days} days ago`
}

function shortId(id: string): string {
  // Show as ALR-XXXXXXXX using first 8 hex chars
  const hex = id.replace(/-/g, '').slice(0, 6).toUpperCase()
  return `ALR-${hex}`
}

export function RecentAlerts({ alerts, loading }: RecentAlertsProps) {
  const navigate = useNavigate()

  return (
    <div className="glass-card p-5 animate-fade-in" style={{ animationDelay: '200ms' }}>
      {/* Header */}
      <div className="flex items-center justify-between mb-5">
        <div>
          <h3 className="text-sm font-semibold">Recent Alerts</h3>
          <p className="text-[10px] text-muted-foreground mt-0.5">Latest incoming security alerts</p>
        </div>
        <button
          onClick={() => navigate('/app/alerts')}
          className="flex items-center gap-1 text-[10px] text-primary hover:text-primary/80 font-medium transition-colors"
        >
          View all <ArrowRight className="h-3 w-3" />
        </button>
      </div>

      {/* Loading skeleton */}
      {loading && (
        <div className="space-y-3">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-12 rounded-lg bg-muted/30 animate-pulse" />
          ))}
        </div>
      )}

      {/* Empty */}
      {!loading && !alerts?.length && (
        <div className="py-12 text-center text-sm text-muted-foreground">
          No recent alerts
        </div>
      )}

      {/* Table */}
      {!loading && alerts?.length > 0 && (
        <div className="overflow-x-auto -mx-1">
          <table className="w-full text-xs border-collapse">
            <thead>
              <tr className="border-b border-border/30">
                <th className="pb-3 pl-1 pr-3 text-[10px] uppercase tracking-wider font-semibold text-muted-foreground whitespace-nowrap">ID</th>
                <th className="pb-3 px-3 text-[10px] uppercase tracking-wider font-semibold text-muted-foreground text-left">Alert</th>
                <th className="pb-3 px-3 text-[10px] uppercase tracking-wider font-semibold text-muted-foreground whitespace-nowrap text-left">Severity</th>
                <th className="pb-3 px-3 text-[10px] uppercase tracking-wider font-semibold text-muted-foreground whitespace-nowrap text-center">Status</th>
                <th className="pb-3 px-3 text-[10px] uppercase tracking-wider font-semibold text-muted-foreground whitespace-nowrap text-center">Source</th>
                <th className="pb-3 px-3 text-[10px] uppercase tracking-wider font-semibold text-muted-foreground whitespace-nowrap text-right">Risk</th>
                <th className="pb-3 pl-3 pr-1 text-[10px] uppercase tracking-wider font-semibold text-muted-foreground whitespace-nowrap text-right">Time</th>
              </tr>
            </thead>
            <tbody>
              {alerts.slice(0, 8).map((alert) => (
                <tr
                  key={alert.id}
                  className="border-b border-border/20 last:border-0 cursor-pointer hover:bg-primary/5 transition-colors group"
                  onClick={() => navigate(`/app/alerts/${alert.id}`)}
                >
                  {/* ID */}
                  <td className="py-3.5 pl-1 pr-3 whitespace-nowrap">
                    <span className="font-mono text-[10px] text-muted-foreground group-hover:text-foreground/60 transition-colors">
                      {shortId(alert.id)}
                    </span>
                  </td>

                  {/* Alert title */}
                  <td className="py-3.5 px-3 max-w-[200px] xl:max-w-[300px]">
                    <span
                      className="block truncate font-semibold text-foreground group-hover:text-primary transition-colors"
                      title={alert.title}
                    >
                      {alert.title}
                    </span>
                  </td>

                  {/* Severity badge */}
                  <td className="py-3.5 px-3 whitespace-nowrap">
                    <Badge severity={alert.severity} />
                  </td>

                  {/* Status badge */}
                  <td className="py-3.5 px-3 whitespace-nowrap text-center">
                    <span className={cn(
                      'inline-flex items-center px-2.5 py-0.5 rounded-full text-[10px] font-semibold border',
                      STATUS_COLORS[alert.status] ?? 'bg-muted/50 text-muted-foreground border-border/30'
                    )}>
                      {STATUS_LABELS[alert.status] ?? alert.status}
                    </span>
                  </td>

                  {/* Source */}
                  <td className="py-3.5 px-3 whitespace-nowrap text-muted-foreground capitalize text-center">
                    {alert.source}
                  </td>

                  {/* Risk score */}
                  <td className={cn(
                    'py-3.5 px-3 whitespace-nowrap text-right font-mono font-bold tabular-nums text-sm',
                    riskColor(alert.risk_score)
                  )}>
                    {alert.risk_score ?? '—'}
                  </td>

                  {/* Time */}
                  <td className="py-3.5 pl-3 pr-1 whitespace-nowrap text-right text-muted-foreground">
                    {verboseRelativeTime(alert.created_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
