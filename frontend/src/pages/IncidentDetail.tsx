import { useParams, useNavigate, Link } from 'react-router-dom'
import { useIncident } from '@/hooks/useIncidents'
import { Card } from '@/components/ui/Card'
import { AlertTable } from '@/components/alerts/AlertTable'
import { ArrowLeft } from 'lucide-react'
import { ErrorState } from '@/components/ui/ErrorState'
import { SpinnerOverlay } from '@/components/ui/Spinner'
import type { Alert } from '@/types/alert'
import type { IncidentDetailAlert } from '@/types/incident'

function mapToAlert(a: IncidentDetailAlert): Alert {
  return {
    id: a.id,
    title: a.title,
    source: '',
    severity: (a.severity as Alert['severity']) ?? 'Medium',
    category: '',
    status: 'open',
    assigned_to: null,
    asset_id: null,
    user_id: null,
    source_ip: null,
    dest_ip: null,
    mitre_techniques: [],
    risk_score: a.risk_score,
    risk_level: null,
    confidence: null,
    incident_group_id: null,
    ai_summary: null,
    ai_key_facts: null,
    ai_remediation: null,
    ai_next_steps: null,
    enrichment: null,
    created_at: a.created_at ?? '',
    updated_at: a.created_at ?? '',
  }
}

export function IncidentDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { data: incident, isLoading, isError } = useIncident(id)

  if (isError) return <ErrorState title="Incident not found" />
  if (isLoading || !incident) return <SpinnerOverlay />

  const alerts: Alert[] = (incident.alerts ?? []).map(mapToAlert)

  return (
    <div className="space-y-6">
      <button
        type="button"
        onClick={() => navigate(-1)}
        className="flex items-center gap-2 text-soc-muted hover:text-soc-text text-sm"
      >
        <ArrowLeft className="w-4 h-4" /> Back
      </button>
      <nav className="flex items-center gap-2 text-sm text-soc-muted">
        <Link to="/app/incidents" className="hover:text-soc-text">Incidents</Link>
        <span className="text-soc-text font-mono">{incident.incident_id}</span>
      </nav>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-soc-text font-mono">INC-{incident.incident_id.slice(0, 8)}</h1>
          <p className="text-soc-muted mt-2">{incident.alerts?.length ?? 0} alerts</p>
        </div>
      </div>
      {incident.recommended_actions?.length ? (
        <Card>
          <h3 className="text-sm font-semibold text-soc-text mb-2">Recommended actions</h3>
          <ul className="list-disc list-inside text-soc-muted text-sm space-y-1">
            {incident.recommended_actions.map((a, i) => <li key={i}>{a}</li>)}
          </ul>
        </Card>
      ) : null}
      {alerts.length > 0 && (
        <Card>
          <h3 className="text-sm font-semibold text-soc-text mb-4">Alerts in this incident</h3>
          <AlertTable alerts={alerts} total={alerts.length} />
        </Card>
      )}
      {incident.mitre_techniques?.length ? (
        <Card>
          <h3 className="text-sm font-semibold text-soc-text mb-2">MITRE techniques</h3>
          <div className="flex flex-wrap gap-2 text-sm text-soc-muted">
            {(incident.mitre_techniques as Array<{ technique_id?: string; technique_name?: string }>).map((t, i) => (
              <span key={i} className="rounded px-2 py-1 bg-soc-border">{t.technique_id ?? ''} {t.technique_name ?? ''}</span>
            ))}
          </div>
        </Card>
      ) : null}
    </div>
  )
}
