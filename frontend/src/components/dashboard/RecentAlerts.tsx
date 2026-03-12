import { useNavigate } from 'react-router-dom'
import { AlertBadge } from '@/components/alerts/AlertBadge'
import { formatRelativeTime } from '@/utils/time'
import type { Alert } from '@/types/alert'
import { ArrowRight } from 'lucide-react'
import { cn } from '@/utils/cn'

interface RecentAlertsProps {
  alerts: Alert[]
  loading?: boolean
}

const statusColors: Record<string, string> = {
  new:            'bg-primary/15 text-primary',
  in_progress:    'bg-severity-medium/15 text-severity-medium',
  resolved:       'bg-success/15 text-success',
  closed:         'bg-muted text-muted-foreground',
  false_positive: 'bg-muted text-muted-foreground',
}

function riskClass(score: number | null | undefined) {
  if (score == null) return 'text-muted-foreground'
  if (score >= 75) return 'severity-critical'
  if (score >= 50) return 'severity-high'
  return 'severity-medium'
}

export function RecentAlerts({ alerts, loading }: RecentAlertsProps) {
  const navigate = useNavigate()

  return (
    <div className="glass-card p-5 animate-fade-in" style={{ animationDelay: '200ms' }}>
      <div className="flex items-center justify-between mb-4">
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

      {loading && (
        <div className="space-y-2">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-10 rounded-lg bg-muted/40 shimmer" />
          ))}
        </div>
      )}

      {!loading && !alerts?.length && (
        <div className="py-10 text-center text-sm text-muted-foreground">
          No recent alerts
        </div>
      )}

      {!loading && alerts?.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border/30">
                {['Alert', 'Severity', 'Status', 'Source', 'Risk', 'Time'].map((h, i) => (
                  <th
                    key={h}
                    className={cn(
                      'pb-2 text-[10px] uppercase tracking-wider font-semibold text-muted-foreground px-2',
                      i === 0 && 'pl-0',
                      i === 5 && 'text-right'
                    )}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {alerts.slice(0, 8).map((alert) => (
                <tr
                  key={alert.id}
                  className="border-b border-border/20 cursor-pointer hover:bg-primary/5 transition-colors"
                  onClick={() => navigate(`/app/alerts/${alert.id}`)}
                >
                  <td className="py-2.5 px-2 pl-0 font-medium max-w-[200px] truncate">
                    {alert.title}
                  </td>
                  <td className="py-2.5 px-2">
                    <AlertBadge severity={alert.severity} />
                  </td>
                  <td className="py-2.5 px-2">
                    <span
                      className={cn(
                        'inline-flex px-1.5 py-0.5 rounded-md text-[9px] font-semibold capitalize',
                        statusColors[alert.status] ?? 'bg-muted text-muted-foreground'
                      )}
                    >
                      {alert.status.replace('_', ' ')}
                    </span>
                  </td>
                  <td className="py-2.5 px-2 text-muted-foreground">{alert.source}</td>
                  <td
                    className={cn(
                      'py-2.5 px-2 font-mono font-bold tabular-nums',
                      riskClass(alert.risk_score)
                    )}
                  >
                    {alert.risk_score ?? '—'}
                  </td>
                  <td className="py-2.5 px-2 text-right text-muted-foreground">
                    {formatRelativeTime(alert.created_at)}
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
