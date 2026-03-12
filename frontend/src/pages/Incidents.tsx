import { useState } from 'react'
import { useIncidents } from '@/hooks/useIncidents'
import { IncidentCard } from '@/components/incidents/IncidentCard'
import { SpinnerOverlay } from '@/components/ui/Spinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { Breadcrumb } from '@/components/ui/Breadcrumb'
import type { Incident } from '@/types/incident'

type SortBy = 'risk' | 'alerts' | 'recent'

export function Incidents() {
  const { data, isLoading, isError, refetch } = useIncidents()
  const [sortBy, setSortBy] = useState<SortBy>('risk')

  if (isError) return <ErrorState title="Failed to load incidents" onRetry={() => refetch()} />
  if (isLoading) return <SpinnerOverlay />

  const items: Incident[] = (data?.items ?? []) as Incident[]
  const sorted = [...items].sort((a, b) => {
    if (sortBy === 'risk') return (b.max_risk_score ?? 0) - (a.max_risk_score ?? 0)
    if (sortBy === 'alerts') return b.alert_count - a.alert_count
    return 0
  })

  return (
    <div className="space-y-6">
      <Breadcrumb items={[{ label: 'Home', to: '/app' }, { label: 'Incidents' }]} />
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h1 className="text-2xl font-semibold text-soc-text">Active Incidents</h1>
        <div className="flex items-center gap-2">
          <span className="text-sm text-soc-muted">Sort by</span>
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as SortBy)}
            className="rounded border border-soc-border bg-soc-bg text-soc-text px-2 py-1.5 text-sm"
          >
            <option value="risk">Risk score</option>
            <option value="alerts">Alert count</option>
            <option value="recent">Last seen</option>
          </select>
        </div>
      </div>
      <p className="text-soc-muted text-sm">{items.length} incident{items.length !== 1 ? 's' : ''}</p>
      {sorted.length === 0 ? (
        <EmptyState title="No incidents" description="Incidents are created when alerts are correlated by incident_group_id." />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {sorted.map((incident) => (
            <IncidentCard key={incident.incident_id} incident={incident} />
          ))}
        </div>
      )}
    </div>
  )
}
