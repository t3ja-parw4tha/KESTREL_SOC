import { useNavigate } from 'react-router-dom'
import { Card } from '@/components/ui/Card'
import { AlertBadge } from '@/components/alerts/AlertBadge'
import { getSeverityDot } from '@/utils/severity'
import { cn } from '@/utils/cn'
import type { Incident } from '@/types/incident'

interface IncidentCardProps {
  incident: Incident
}

export function IncidentCard({ incident }: IncidentCardProps) {
  const navigate = useNavigate()

  return (
    <Card
      className="cursor-pointer hover:border-border transition-colors"
      onClick={() => navigate(`/app/incidents/${incident.incident_id}`)}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <p className="font-mono text-foreground truncate" title={incident.incident_id}>
            INC-{incident.incident_id.slice(0, 8)}
          </p>
          <p className="text-sm text-muted-foreground mt-1">
            {incident.alert_count} alert{incident.alert_count !== 1 ? 's' : ''}
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className={cn('w-2 h-2 rounded-full shrink-0', getSeverityDot(incident.highest_severity))} aria-hidden />
          <AlertBadge severity={incident.highest_severity as 'Critical' | 'High' | 'Medium' | 'Low'} />
        </div>
      </div>
      <div className="mt-3 flex items-center justify-between">
        <div className="w-20 h-2 rounded-full bg-muted overflow-hidden">
          <div
            className="h-full bg-orange-500 rounded-full"
            style={{ width: `${Math.min(100, incident.max_risk_score ?? 0)}%` }}
          />
        </div>
        <span className="text-lg font-semibold text-foreground">{incident.max_risk_score ?? 0}</span>
      </div>
      <button
        type="button"
        onClick={(e) => { e.stopPropagation(); navigate(`/app/incidents/${incident.incident_id}`) }}
        className="mt-3 w-full py-1.5 rounded border border-border text-foreground hover:bg-muted/30 text-sm"
      >
        Investigate
      </button>
    </Card>
  )
}
