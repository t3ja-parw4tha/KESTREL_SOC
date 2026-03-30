import { useNavigate } from 'react-router-dom'
import { Card, CardHeader } from '@/components/ui/Card'
import { AlertBadge } from '@/components/alerts/AlertBadge'
import { Flame, CheckCircle2, Clock, ShieldAlert } from 'lucide-react'
import { cn } from '@/utils/cn'
import { ROUTES } from '@/utils/routes'
import type { Incident } from '@/types/incident'

interface TopIncidentsProps {
  incidents: Incident[]
  loading?: boolean
}

const STATUS_CONFIG: Record<string, { label: string; cls: string; Icon: typeof Flame }> = {
  open:         { label: 'Open',      cls: 'text-red-400 bg-red-500/10 border-red-500/20',     Icon: Flame },
  in_progress:  { label: 'Active',    cls: 'text-amber-400 bg-amber-500/10 border-amber-500/20', Icon: Clock },
  contained:    { label: 'Contained', cls: 'text-blue-400 bg-blue-500/10 border-blue-500/20',   Icon: ShieldAlert },
  resolved:     { label: 'Resolved',  cls: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20', Icon: CheckCircle2 },
}

export function TopIncidents({ incidents, loading }: TopIncidentsProps) {
  const navigate = useNavigate()
  const top = incidents.slice(0, 5)

  return (
    <Card>
      <CardHeader
        title="Top Incidents by Risk"
        action={
          <a href={ROUTES.incidents} className="text-xs text-primary hover:underline">
            View all →
          </a>
        }
      />

      {loading && (
        <div className="space-y-3">
          {[1, 2, 3].map((i) => <div key={i} className="h-16 rounded bg-muted/30 animate-pulse" />)}
        </div>
      )}

      {!loading && top.length === 0 && (
        <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
          <CheckCircle2 className="w-8 h-8 mb-2 opacity-20" />
          <p className="text-sm font-medium">No active incidents</p>
          <p className="text-xs mt-1 opacity-60">Incidents created from alerts will appear here</p>
        </div>
      )}

      {!loading && top.length > 0 && (
        <ul className="space-y-2">
          {top.map((inc) => {
            const statusKey = (inc.status ?? 'open').toLowerCase()
            const statusCfg = STATUS_CONFIG[statusKey] ?? STATUS_CONFIG['open']!
            const StatusIcon = statusCfg.Icon
            return (
              <li
                key={inc.incident_id}
                className="flex items-center gap-3 rounded-lg border border-border/50 p-3 hover:bg-muted/20 cursor-pointer transition-colors group"
                onClick={() => navigate(ROUTES.incident(inc.incident_id))}
              >
                {/* ID + status */}
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span
                      className="font-mono text-xs text-foreground bg-muted/50 px-1.5 py-0.5 rounded border border-border/40 group-hover:border-primary/30 transition-colors"
                      title={inc.incident_id}
                    >
                      {inc.incident_id.slice(0, 8).toUpperCase()}
                    </span>
                    <span className={cn('inline-flex items-center gap-1 text-[10px] font-medium px-1.5 py-0.5 rounded-full border', statusCfg.cls)}>
                      <StatusIcon className="w-2.5 h-2.5" />
                      {statusCfg.label}
                    </span>
                  </div>
                  <p className="text-xs text-muted-foreground">{inc.alert_count} alert{inc.alert_count !== 1 ? 's' : ''}</p>
                </div>

                {/* Severity + risk score */}
                <div className="flex items-center gap-2 shrink-0">
                  <AlertBadge severity={inc.highest_severity as 'Critical' | 'High' | 'Medium' | 'Low'} />
                  <div className="w-14 h-1.5 rounded-full bg-muted overflow-hidden">
                    <div
                      className={cn('h-full rounded-full', (inc.max_risk_score ?? 0) > 70 ? 'bg-red-500' : 'bg-orange-500')}
                      style={{ width: `${Math.min(100, inc.max_risk_score ?? 0)}%` }}
                    />
                  </div>
                  <span className="text-xs font-bold tabular-nums text-foreground w-6 text-right">{inc.max_risk_score ?? 0}</span>
                </div>
              </li>
            )
          })}
        </ul>
      )}
    </Card>
  )
}
