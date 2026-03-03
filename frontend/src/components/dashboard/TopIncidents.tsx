import { useNavigate } from 'react-router-dom'
import { Card, CardHeader } from '@/components/ui/Card'
import { AlertBadge } from '@/components/alerts/AlertBadge'
import { getSeverityDot } from '@/utils/severity'
import { cn } from '@/utils/cn'
import type { Incident } from '@/types/incident'

interface TopIncidentsProps {
  incidents: Incident[]
  loading?: boolean
}

export function TopIncidents({ incidents, loading }: TopIncidentsProps) {
  const navigate = useNavigate()
  const top = incidents.slice(0, 5)

  return (
    <Card>
      <CardHeader title="Top incidents (by risk)" action={<a href="/incidents" className="text-sm text-blue-400 hover:underline">View all</a>} />
      {loading && (
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-16 rounded bg-soc-border/30 animate-pulse" />
          ))}
        </div>
      )}
      {!loading && top.length === 0 && (
        <p className="text-soc-muted text-sm py-4">No incidents</p>
      )}
      {!loading && top.length > 0 && (
        <ul className="space-y-3">
          {top.map((inc) => (
            <li
              key={inc.incident_id}
              className="flex items-center justify-between rounded-lg border border-soc-border p-3 hover:bg-soc-border/20 cursor-pointer transition-colors"
              onClick={() => navigate(`/incidents/${inc.incident_id}`)}
            >
              <div className="min-w-0 flex-1">
                <p className="font-mono text-sm text-soc-text truncate" title={inc.incident_id}>
                  {inc.incident_id.slice(0, 8)}...
                </p>
                <p className="text-xs text-soc-muted">{inc.alert_count} alerts</p>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <span className="flex items-center gap-1">
                  <span className={cn('w-2 h-2 rounded-full', getSeverityDot(inc.highest_severity))} aria-hidden />
                  <AlertBadge severity={inc.highest_severity as 'Critical' | 'High' | 'Medium' | 'Low'} />
                </span>
                <div className="w-12 h-2 rounded-full bg-soc-border overflow-hidden">
                  <div
                    className="h-full bg-orange-500 rounded-full"
                    style={{ width: `${Math.min(100, inc.max_risk_score ?? 0)}%` }}
                  />
                </div>
                <span className="text-sm font-semibold text-soc-text w-8 text-right">{inc.max_risk_score ?? 0}</span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}
