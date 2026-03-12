import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, Clock, User, Search, ChevronRight, Shield, Plus } from 'lucide-react'
import { demoIncidents, incidentsApi } from '@/api/incidents'
import type { Incident } from '@/api/incidents'
import { cn } from '@/utils/cn'

const statusConfig: Record<string, { label: string; cls: string }> = {
  open: { label: 'Open', cls: 'bg-destructive/15 text-destructive border-destructive/30' },
  in_progress: { label: 'In Progress', cls: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30' },
  contained: { label: 'Contained', cls: 'bg-orange-500/15 text-orange-400 border-orange-500/30' },
  resolved: { label: 'Resolved', cls: 'bg-green-500/15 text-green-400 border-green-500/30' },
  closed: { label: 'Closed', cls: 'bg-muted/50 text-muted-foreground border-border' },
}
const severityColors: Record<string, string> = {
  critical: 'bg-severity-critical/15 text-severity-critical border-severity-critical/30',
  high: 'bg-severity-high/15 text-severity-high border-severity-high/30',
  medium: 'bg-severity-medium/15 text-severity-medium border-severity-medium/30',
  low: 'bg-severity-low/15 text-severity-low border-severity-low/30',
}

function SeverityBadge({ severity }: { severity: Incident['severity'] }) {
  return (
    <span className={cn('inline-flex items-center px-1.5 py-0.5 rounded border text-[10px] font-semibold uppercase tracking-wide', severityColors[severity])}>
      {severity}
    </span>
  )
}
const defaultStatus = { label: 'Open', cls: 'bg-destructive/15 text-destructive border-destructive/30' }
function StatusBadge({ status }: { status: Incident['status'] }) {
  const s = statusConfig[status] ?? defaultStatus
  return (
    <span className={cn('inline-flex items-center px-1.5 py-0.5 rounded border text-[10px] font-semibold', s.cls)}>
      {s.label}
    </span>
  )
}
function CardSkeleton() {
  return (
    <div className="glass-card p-4 space-y-3 animate-pulse">
      <div className="flex gap-2">
        <div className="h-4 w-16 bg-muted/50 rounded" />
        <div className="h-4 w-12 bg-muted/50 rounded" />
        <div className="h-4 w-20 bg-muted/50 rounded" />
      </div>
      <div className="h-4 w-2/3 bg-muted/50 rounded" />
      <div className="h-3 w-full bg-muted/30 rounded" />
    </div>
  )
}
function IncidentCard({ incident }: { incident: Incident }) {
  const navigate = useNavigate()
  return (
    <div
      className="glass-card-hover cursor-pointer group relative"
      onClick={() => navigate(`/app/incidents/${incident.id}`)}
      role="button"
      tabIndex={0}
      onKeyDown={e => e.key === 'Enter' && navigate(`/app/incidents/${incident.id}`)}
    >
      <div className="p-4 space-y-2">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-mono text-[10px] text-muted-foreground">{incident.id}</span>
          <SeverityBadge severity={incident.severity} />
          <StatusBadge status={incident.status} />
        </div>
        <h3 className="text-sm font-semibold text-foreground truncate pr-6">{incident.title}</h3>
        <p className="text-xs text-muted-foreground line-clamp-2">{incident.description}</p>
        <div className="flex items-center gap-4 text-[10px] text-muted-foreground flex-wrap">
          <span className="flex items-center gap-1">
            <Shield className="h-3 w-3" /> {incident.alert_count} alerts
          </span>
          <span className="flex items-center gap-1">
            <User className="h-3 w-3" /> {incident.assigned_to || 'Unassigned'}
          </span>
          <span className="flex items-center gap-1">
            <Clock className="h-3 w-3" /> {new Date(incident.updated_at).toLocaleDateString()}
          </span>
          {incident.mitre_tactics.map(t => (
            <span key={t} className="inline-flex items-center px-1.5 py-0.5 rounded bg-muted/40 text-[9px] text-muted-foreground border border-border/30">
              {t}
            </span>
          ))}
        </div>
      </div>
      <ChevronRight className="absolute right-4 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
    </div>
  )
}

export function Incidents() {
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const [severityFilter, setSeverityFilter] = useState('all')
  const { data: apiData, isLoading, isError, refetch } = useQuery({
    queryKey: ['incidents', search, statusFilter, severityFilter],
    queryFn: () => incidentsApi.list({
      search: search || undefined,
      status: statusFilter !== 'all' ? statusFilter : undefined,
      severity: severityFilter !== 'all' ? severityFilter : undefined,
    }),
    retry: 1,
    staleTime: 30_000,
  })
  const rawItems = (apiData as { items?: Incident[] } | undefined)?.items
  const incidents: Incident[] = rawItems?.length ? rawItems : demoIncidents
  const filtered = incidents.filter(inc => {
    if (search && !inc.title.toLowerCase().includes(search.toLowerCase())) return false
    if (statusFilter !== 'all' && inc.status !== statusFilter) return false
    if (severityFilter !== 'all' && inc.severity !== severityFilter) return false
    return true
  })
  const stats = {
    open: incidents.filter(i => i.status === 'open').length,
    in_progress: incidents.filter(i => i.status === 'in_progress').length,
    contained: incidents.filter(i => i.status === 'contained').length,
    resolved: incidents.filter(i => i.status === 'resolved' || i.status === 'closed').length,
  }
  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold tracking-tight text-foreground">Incidents</h1>
          <p className="text-xs text-muted-foreground">Manage and track security incidents</p>
        </div>
        <button type="button" className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg gradient-primary text-white text-xs font-medium hover:opacity-90 transition-opacity">
          <Plus className="h-3 w-3" /> New Incident
        </button>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Open', value: stats.open, color: 'text-destructive' },
          { label: 'In Progress', value: stats.in_progress, color: 'text-yellow-400' },
          { label: 'Contained', value: stats.contained, color: 'text-orange-400' },
          { label: 'Resolved / Closed', value: stats.resolved, color: 'text-green-400' },
        ].map(s => (
          <div key={s.label} className="glass-card p-3">
            <p className="text-[10px] uppercase tracking-wider text-muted-foreground">{s.label}</p>
            <p className={cn('text-2xl font-bold', s.color)}>{s.value}</p>
          </div>
        ))}
      </div>
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground pointer-events-none" />
          <input type="search" placeholder="Search incidents..." value={search} onChange={e => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg border border-border bg-muted/50 text-foreground text-xs placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/40 focus:border-primary/60 transition-all" />
        </div>
        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}
          className="h-8 px-2 pr-7 rounded-lg border border-border bg-muted/50 text-foreground text-xs focus:outline-none focus:ring-2 focus:ring-primary/40 appearance-none cursor-pointer">
          <option value="all">All Status</option>
          <option value="open">Open</option>
          <option value="in_progress">In Progress</option>
          <option value="contained">Contained</option>
          <option value="resolved">Resolved</option>
          <option value="closed">Closed</option>
        </select>
        <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}
          className="h-8 px-2 pr-7 rounded-lg border border-border bg-muted/50 text-foreground text-xs focus:outline-none focus:ring-2 focus:ring-primary/40 appearance-none cursor-pointer">
          <option value="all">All Severity</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>
      {isError && (
        <div className="flex items-center gap-3 px-4 py-3 rounded-lg bg-yellow-500/10 border border-yellow-500/30 text-xs text-yellow-400">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span className="flex-1">Could not load incidents from API — showing demo data.</span>
          <button type="button" onClick={() => refetch()} className="underline hover:no-underline">Retry</button>
        </div>
      )}
      <div className="space-y-3">
        {isLoading
          ? Array.from({ length: 4 }).map((_, i) => <CardSkeleton key={i} />)
          : <>
              {filtered.map(incident => <IncidentCard key={incident.id} incident={incident} />)}
              {filtered.length === 0 && (
                <div className="text-center py-12 text-sm text-muted-foreground">No incidents match your filters.</div>
              )}
            </>
        }
      </div>
    </div>
  )
}
