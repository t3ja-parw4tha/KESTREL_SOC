import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeft, Clock, User, Shield, Activity, Target,
  CheckCircle, Circle, ExternalLink, Download, Globe,
  Hash, Server, Monitor, Laptop, FileText, Plus,
} from 'lucide-react'
import { cn } from '@/utils/cn'
import { toast } from 'sonner'
import { incidentsApi } from '@/api/incidents'
import { useAuth } from '@/security/AuthContext'
import { generateShiftHandover } from '@/api/aiAssistant'
import {
  addIncidentEvidenceUrl,
  downloadEvidenceFile,
  listIncidentEvidence,
  uploadIncidentEvidenceFile,
} from '@/api/evidence'
import type { IncidentDetail as IncidentDetailData } from '@/api/incidents'
import { get, put } from '@/api/client'

// ─── Types ────────────────────────────────────────────────────────────────────
interface MitreTech { id: string; name: string; phase: string }
interface LinkedAlert { id: string; title: string; severity: string; status: string; source: string; created_at: string }
interface AffectedAsset { type: string; name: string; ip: string; os: string; status: string }
interface AttackerIP { ip: string; geo: string; isp: string; reputation: string; reports: number }
interface TimelineEntry { time: string; event: string; type: string; actor: string }
interface ResponseAction { id: string; label: string; completed: boolean; assignee: string | null }
interface ThreatIntel { source: string; url: string; label: string }
interface Artifact { name: string; type: string; size: string; uploaded_by: string }

interface IncidentData {
  id: string; title: string; description: string
  severity: 'critical' | 'high' | 'medium' | 'low'; status: string
  assigned_to: string | null; created_at: string; updated_at: string
  mitre_tactics: string[]; mitre_techniques: MitreTech[]
  linked_alerts: LinkedAlert[]; affected_assets: AffectedAsset[]
  attacker_ips: AttackerIP[]; timeline: TimelineEntry[]
  response_actions: ResponseAction[]; threat_intel: ThreatIntel[]; artifacts: Artifact[]
}

// ─── Map backend response to display shape ────────────────────────────────────
function mapApiToDisplay(api: IncidentDetailData): IncidentData {
  const mitreTechs: MitreTech[] = (api.mitre_techniques || []).map(t => ({
    id: t.technique_id || '',
    name: t.technique_name || t.technique_id || '',
    phase: t.tactic || t.phase || '',
  }))

  const linkedAlerts: LinkedAlert[] = (api.alerts || []).map(a => ({
    id: a.id,
    title: a.title,
    severity: a.severity,
    status: 'new',
    source: a.source || 'Unknown',
    created_at: a.created_at || new Date().toISOString(),
  }))

  const timeline: TimelineEntry[] = (api.attack_timeline || []).map(e => ({
    time: e.time || e.timestamp || new Date().toISOString(),
    event: e.event || e.title || 'Alert event',
    type: e.type || 'correlation',
    actor: e.actor || 'System',
  }))

  const responseActions: ResponseAction[] = (api.recommended_actions || []).map((label, i) => ({
    id: `ra-${i + 1}`,
    label,
    completed: false,
    assignee: null,
  }))

  // Default actions if none from AI decisions
  if (responseActions.length === 0) {
    responseActions.push(
      { id: 'ra-1', label: 'Perform initial triage and scope assessment', completed: false, assignee: null },
      { id: 'ra-2', label: 'Identify and contain affected assets', completed: false, assignee: null },
      { id: 'ra-3', label: 'Document findings and remediation steps', completed: false, assignee: null },
    )
  }

  return {
    id: api.incident_id,
    title: api.title,
    description: api.description,
    severity: (['critical', 'high', 'medium', 'low'].includes(api.severity)
      ? api.severity : 'medium') as IncidentData['severity'],
    status: api.status || 'open',
    assigned_to: api.assigned_to,
    created_at: api.created_at || new Date().toISOString(),
    updated_at: api.updated_at || new Date().toISOString(),
    mitre_tactics: api.mitre_tactics || [],
    mitre_techniques: mitreTechs,
    linked_alerts: linkedAlerts,
    affected_assets: [],
    attacker_ips: [],
    timeline,
    response_actions: responseActions,
    threat_intel: [],
    artifacts: [],
  }
}

// ─── Configs ──────────────────────────────────────────────────────────────────
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

function AssetIcon({ type }: { type: string }) {
  switch (type) {
    case 'server': return <Server className="h-4 w-4 text-muted-foreground shrink-0" />
    case 'workstation': return <Laptop className="h-4 w-4 text-muted-foreground shrink-0" />
    case 'user': return <User className="h-4 w-4 text-muted-foreground shrink-0" />
    default: return <Monitor className="h-4 w-4 text-muted-foreground shrink-0" />
  }
}

function DetailSkeleton() {
  return (
    <div className="space-y-6 animate-pulse">
      <div className="flex items-start gap-4">
        <div className="h-8 w-8 bg-muted/50 rounded-lg" />
        <div className="flex-1 space-y-2">
          <div className="flex gap-2">
            <div className="h-4 w-16 bg-muted/50 rounded" />
            <div className="h-4 w-12 bg-muted/50 rounded" />
            <div className="h-4 w-24 bg-muted/50 rounded" />
          </div>
          <div className="h-5 w-2/3 bg-muted/50 rounded" />
          <div className="h-4 w-full bg-muted/30 rounded" />
        </div>
      </div>
      <div className="h-2 bg-muted/40 rounded-full" />
      <div className="grid grid-cols-2 gap-4">
        <div className="h-40 bg-muted/30 rounded-xl" />
        <div className="h-40 bg-muted/30 rounded-xl" />
      </div>
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────
export function IncidentDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { user } = useAuth()
  const [activeTab, setActiveTab] = useState('overview')
  const [evidenceUrl, setEvidenceUrl] = useState('')
  const [evidenceNotes, setEvidenceNotes] = useState('')
  const [evidenceBusy, setEvidenceBusy] = useState(false)
  const [handoverBusy, setHandoverBusy] = useState(false)
  const [handoverText, setHandoverText] = useState('')
  const queryClient = useQueryClient()
  const isViewer = user?.role === 'viewer'

  const { data: apiData, isLoading, isError } = useQuery({
    queryKey: ['incident', id],
    queryFn: () => incidentsApi.get(id!),
    enabled: !!id,
    retry: 1,
    staleTime: 30_000,
  })

  const { data: savedActions } = useQuery({
    queryKey: ['incident-actions', id],
    queryFn: () => get<ResponseAction[]>(`/incidents/${id}/actions`),
    enabled: !!id,
    retry: 1,
    staleTime: 60_000,
  })

  const { data: incidentEvidence = [], isLoading: evidenceLoading } = useQuery({
    queryKey: ['incident-evidence', id],
    queryFn: () => listIncidentEvidence(id!),
    enabled: !!id,
    staleTime: 20_000,
  })

  const incident: IncidentData | null = apiData ? mapApiToDisplay(apiData) : null

  const [localActions, setLocalActions] = useState<ResponseAction[] | null>(null)

  // When saved actions load from backend, sync them; otherwise fall back to derived actions
  useEffect(() => {
    if (savedActions && savedActions.length > 0) {
      setLocalActions(savedActions)
    }
  }, [savedActions])

  const effectiveActions = localActions ?? incident?.response_actions ?? []

  const saveActionsMutation = useMutation({
    mutationFn: (actions: ResponseAction[]) =>
      put<ResponseAction[]>(`/incidents/${id}/actions`, { actions }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incident-actions', id] })
    },
    onError: () => toast.error('Failed to save action'),
  })

  const completedActions = effectiveActions.filter(a => a.completed).length
  const progressPercent = effectiveActions.length > 0 ? Math.round((completedActions / effectiveActions.length) * 100) : 0
  const defaultStatus = { label: 'Open', cls: 'bg-destructive/15 text-destructive border-destructive/30' }
  const status = incident ? (statusConfig[incident.status] ?? defaultStatus) : defaultStatus

  const toggleAction = (actionId: string) => {
    const updated = effectiveActions.map(a => a.id === actionId ? { ...a, completed: !a.completed } : a)
    setLocalActions(updated)
    saveActionsMutation.mutate(updated)
    toast.success('Response action updated')
  }

  const addEvidenceUrl = async () => {
    if (!id || !evidenceUrl.trim()) return
    setEvidenceBusy(true)
    try {
      await addIncidentEvidenceUrl(id, {
        url: evidenceUrl.trim(),
        notes: evidenceNotes.trim() || undefined,
      })
      setEvidenceUrl('')
      setEvidenceNotes('')
      queryClient.invalidateQueries({ queryKey: ['incident-evidence', id] })
      toast.success('Evidence URL attached')
    } catch {
      toast.error('Failed to attach evidence URL')
    } finally {
      setEvidenceBusy(false)
    }
  }

  const uploadEvidenceFile = async (file: File) => {
    if (!id) return
    setEvidenceBusy(true)
    try {
      await uploadIncidentEvidenceFile(id, file, evidenceNotes.trim() || undefined)
      setEvidenceNotes('')
      queryClient.invalidateQueries({ queryKey: ['incident-evidence', id] })
      toast.success('Artifact uploaded')
    } catch {
      toast.error('Failed to upload artifact')
    } finally {
      setEvidenceBusy(false)
    }
  }

  const runShiftHandover = async () => {
    setHandoverBusy(true)
    try {
      const result = await generateShiftHandover()
      setHandoverText(result.handover)
      toast.success('Shift handover generated')
    } catch {
      toast.error('Failed to generate shift handover')
    } finally {
      setHandoverBusy(false)
    }
  }

  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'alerts', label: `Linked Alerts (${incident?.linked_alerts.length ?? 0})` },
    { id: 'assets', label: 'Assets & IPs' },
    { id: 'response', label: 'Response Actions' },
    { id: 'timeline', label: 'Timeline' },
    { id: 'intel', label: 'Threat Intel' },
    { id: 'attribution', label: 'Threat Attribution' },
    { id: 'artifacts', label: 'Artifacts' },
  ]

  const { data: attribution } = useQuery({
    queryKey: ['threat-attribution', id],
    queryFn: async () => {
      const payload = await get<{
        actor_name?: string | null
        confidence?: number | null
        ttps_matched?: string[]
        mitre_overlap?: string[]
        summary?: string | null
        sources?: string[]
        techniques?: string[]
        candidates?: Array<{ actor: string; confidence: number; matched_ttps: string[] }>
      }>(`/threat-attribution/incidents/${id}`)

      if (Array.isArray(payload.candidates)) {
        const top = payload.candidates[0] || null
        return {
          actor_name: top?.actor ?? null,
          confidence: top?.confidence ?? null,
          ttps_matched: top?.matched_ttps ?? [],
          mitre_overlap: payload.techniques ?? [],
          summary: top ? 'Top attribution candidate based on MITRE technique overlap.' : null,
          sources: ['MITRE technique overlap'],
        }
      }

      return {
        actor_name: payload.actor_name ?? null,
        confidence: payload.confidence ?? null,
        ttps_matched: payload.ttps_matched ?? [],
        mitre_overlap: payload.mitre_overlap ?? [],
        summary: payload.summary ?? null,
        sources: payload.sources ?? [],
      }
    },
    enabled: activeTab === 'attribution',
  })

  if (isLoading) return <DetailSkeleton />

  if (!incident) {
    return (
      <div className="space-y-4 animate-fade-in">
        <button
          type="button"
          onClick={() => navigate('/app/incidents')}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-border text-xs text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
        >
          <ArrowLeft className="h-3.5 w-3.5" /> Back to Incidents
        </button>
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-400">
          {isError ? 'Could not load incident from API.' : 'Incident is unavailable.'}
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-start gap-4">
        <button type="button" onClick={() => navigate('/app/incidents')}
          className="p-2 rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent transition-colors mt-1 shrink-0">
          <ArrowLeft className="h-4 w-4" />
        </button>
        <div className="flex-1 min-w-0 space-y-2">
          <div className="flex items-center gap-3 flex-wrap">
            <span className="font-mono text-xs text-muted-foreground">{incident.id}</span>
            <span className={cn('inline-flex items-center px-1.5 py-0.5 rounded border text-[10px] font-semibold uppercase', severityColors[incident.severity])}>
              {incident.severity}
            </span>
            <span className={cn('inline-flex items-center px-1.5 py-0.5 rounded border text-[10px] font-semibold', status.cls)}>
              {status.label}
            </span>
            <span className="text-xs text-muted-foreground flex items-center gap-1">
              <Clock className="h-3 w-3" /> Created {new Date(incident.created_at).toLocaleString()}
            </span>
          </div>
          <h1 className="text-lg font-bold tracking-tight text-foreground">{incident.title}</h1>
          <p className="text-sm text-muted-foreground">{incident.description}</p>
          <div className="flex items-center gap-4 text-xs text-muted-foreground">
            {incident.assigned_to && (
              <span className="flex items-center gap-1"><User className="h-3 w-3" /> {incident.assigned_to}</span>
            )}
            <span className="flex items-center gap-1"><Shield className="h-3 w-3" /> {incident.linked_alerts.length} linked alerts</span>
            <span className="flex items-center gap-1"><Activity className="h-3 w-3" /> {completedActions}/{effectiveActions.length} actions complete</span>
          </div>
          {!isViewer && (
            <div className="mt-3 flex flex-wrap gap-2">
              <button
                type="button"
                onClick={runShiftHandover}
                disabled={handoverBusy}
                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-blue-500/30 bg-blue-500/10 text-blue-400 text-xs font-medium hover:bg-blue-500/20 disabled:opacity-40"
              >
                {handoverBusy ? 'Generating…' : 'Generate Shift Handover'}
              </button>
            </div>
          )}
        </div>
      </div>

      {handoverText && (
        <div className="glass-card p-4 space-y-2 border border-blue-500/20">
          <h3 className="text-sm font-semibold text-foreground">Shift Handover Draft</h3>
          <pre className="text-xs whitespace-pre-wrap text-foreground/90 leading-relaxed bg-muted/20 border border-border/30 rounded-lg p-3 overflow-auto max-h-72">
            {handoverText}
          </pre>
        </div>
      )}

      {/* Progress bar */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between text-xs">
          <span className="text-muted-foreground">Response Progress</span>
          <span className="font-medium text-foreground">{progressPercent}%</span>
        </div>
        <div className="h-2 w-full rounded-full bg-muted/40 overflow-hidden">
          <div className="h-full rounded-full gradient-primary transition-all duration-500" style={{ width: `${progressPercent}%` }} />
        </div>
      </div>

      <div className="h-px bg-border/40" />

      {/* Tab bar */}
      <div className="flex items-center gap-0.5 bg-muted/50 rounded-lg p-1 overflow-x-auto">
        {tabs.map(tab => (
          <button key={tab.id} type="button" onClick={() => setActiveTab(tab.id)}
            className={cn('px-3 py-1.5 rounded-md text-xs font-medium transition-all whitespace-nowrap',
              activeTab === tab.id ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground')}>
            {tab.label}
          </button>
        ))}
      </div>

      {/* ─── Overview ─── */}
      {activeTab === 'overview' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="glass-card p-4 space-y-3">
            <h3 className="text-sm font-semibold flex items-center gap-2 text-foreground">
              <Target className="h-4 w-4 text-primary" /> MITRE ATT&CK Kill Chain
            </h3>
            {incident.mitre_tactics.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {incident.mitre_tactics.map(t => (
                  <span key={t} className="inline-flex items-center px-2 py-0.5 rounded bg-muted/50 border border-border/40 text-[10px] text-muted-foreground">{t}</span>
                ))}
              </div>
            )}
            {incident.mitre_techniques.length > 0 ? (
              <div className="space-y-2">
                {incident.mitre_techniques.map(tech => (
                  <div key={tech.id} className="flex items-center gap-3 text-xs p-2 rounded-lg bg-muted/30">
                    <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/50 bg-muted/40 text-[10px] font-mono shrink-0 text-foreground">{tech.id}</span>
                    <span className="flex-1 text-foreground">{tech.name}</span>
                    <span className="text-muted-foreground text-[10px]">{tech.phase}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-muted-foreground text-center py-4">No MITRE techniques identified yet.</p>
            )}
          </div>
          <div className="glass-card p-4 space-y-3">
            <h3 className="text-sm font-semibold text-foreground">Incident Summary</h3>
            {[
              { label: 'Severity', value: incident.severity.toUpperCase() },
              { label: 'Status', value: status.label },
              { label: 'Lead Analyst', value: incident.assigned_to || 'Unassigned' },
              { label: 'Linked Alerts', value: incident.linked_alerts.length },
              { label: 'Affected Assets', value: incident.affected_assets.length },
              { label: 'Attacker IPs', value: incident.attacker_ips.length },
              { label: 'Created', value: new Date(incident.created_at).toLocaleString() },
              { label: 'Last Updated', value: new Date(incident.updated_at).toLocaleString() },
            ].map(row => (
              <div key={row.label} className="flex justify-between items-center text-xs">
                <span className="text-muted-foreground">{row.label}</span>
                <span className="font-medium text-foreground">{row.value}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ─── Linked Alerts ─── */}
      {activeTab === 'alerts' && (
        <div className="space-y-3">
          {incident.linked_alerts.length === 0
            ? <div className="text-center py-12 text-sm text-muted-foreground">No linked alerts yet.</div>
            : incident.linked_alerts.map(alert => (
                <div key={alert.id} className="glass-card-hover cursor-pointer p-4"
                  onClick={() => navigate(`/app/alerts/${alert.id}`)} role="button" tabIndex={0}
                  onKeyDown={e => e.key === 'Enter' && navigate(`/app/alerts/${alert.id}`)}>
                  <div className="flex items-center gap-3 flex-wrap">
                    <span className="font-mono text-[10px] text-muted-foreground">{alert.id}</span>
                    <span className={cn('inline-flex items-center px-1.5 py-0.5 rounded border text-[10px] font-semibold uppercase', severityColors[alert.severity] || '')}>
                      {alert.severity}
                    </span>
                    <span className="text-xs font-medium flex-1 truncate text-foreground">{alert.title}</span>
                    <span className="inline-flex items-center px-1.5 py-0.5 rounded bg-muted/40 border border-border/30 text-[10px] text-muted-foreground">{alert.source}</span>
                    <span className="text-[10px] text-muted-foreground">{new Date(alert.created_at).toLocaleString()}</span>
                  </div>
                </div>
              ))
          }
        </div>
      )}

      {/* ─── Assets & IPs ─── */}
      {activeTab === 'assets' && (
        <div className="space-y-4">
          <div className="glass-card p-4 space-y-3">
            <h3 className="text-sm font-semibold text-foreground">Affected Assets</h3>
            {incident.affected_assets.length === 0
              ? <p className="text-xs text-muted-foreground text-center py-6">No affected assets identified yet.</p>
              : <div className="space-y-2">
                  {incident.affected_assets.map((asset, i) => (
                    <div key={i} className="flex items-center gap-3 text-xs p-3 rounded-lg bg-muted/20 border border-border/30">
                      <AssetIcon type={asset.type} />
                      <span className="font-medium min-w-[120px] text-foreground">{asset.name}</span>
                      <span className="font-mono text-muted-foreground">{asset.ip}</span>
                      <span className="text-muted-foreground">{asset.os}</span>
                      <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-primary/40 text-primary bg-primary/10 text-[10px] font-semibold ml-auto">{asset.status}</span>
                    </div>
                  ))}
                </div>
            }
          </div>
          <div className="glass-card p-4 space-y-3">
            <h3 className="text-sm font-semibold flex items-center gap-2 text-foreground">
              <Globe className="h-4 w-4 text-primary" /> Attacker IPs
            </h3>
            {incident.attacker_ips.length === 0
              ? <p className="text-xs text-muted-foreground text-center py-6">No attacker IPs identified yet.</p>
              : <div className="space-y-2">
                  {incident.attacker_ips.map((ip, i) => (
                    <div key={i} className="flex items-center gap-3 text-xs p-3 rounded-lg bg-muted/20 border border-border/30">
                      <Hash className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                      <code className="font-mono text-primary min-w-[130px]">{ip.ip}</code>
                      <span className="text-muted-foreground">{ip.geo}</span>
                      <span className="text-muted-foreground">{ip.isp}</span>
                      <span className={cn('inline-flex items-center px-1.5 py-0.5 rounded border text-[10px] font-semibold ml-auto',
                        ip.reputation === 'malicious' ? 'border-destructive/40 text-destructive bg-destructive/10' : 'border-yellow-500/40 text-yellow-400 bg-yellow-500/10')}>
                        {ip.reputation}
                      </span>
                      <span className="text-[10px] text-muted-foreground">{ip.reports} reports</span>
                    </div>
                  ))}
                </div>
            }
          </div>
        </div>
      )}

      {/* ─── Response Actions ─── */}
      {activeTab === 'response' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-foreground">Response Checklist</h3>
              <p className="text-[10px] text-muted-foreground">{completedActions} of {effectiveActions.length} actions completed</p>
            </div>
            <button type="button" className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg border border-border text-foreground text-xs hover:bg-accent transition-colors">
              <Plus className="h-3 w-3" /> Add Action
            </button>
          </div>
          <div className="h-2 w-full rounded-full bg-muted/40 overflow-hidden">
            <div className="h-full rounded-full gradient-primary transition-all duration-500" style={{ width: `${progressPercent}%` }} />
          </div>
          <div className="space-y-2">
            {effectiveActions.map(action => (
              <div key={action.id} className={cn('flex items-center gap-3 p-3 rounded-lg border transition-colors',
                action.completed ? 'bg-muted/10 border-border/20' : 'bg-card/50 border-border/40')}>
                <button type="button" onClick={() => toggleAction(action.id)}
                  className={cn('h-4 w-4 rounded shrink-0 border-2 flex items-center justify-center transition-colors',
                    action.completed ? 'bg-primary border-primary' : 'border-border hover:border-primary')}
                  aria-label={action.completed ? 'Mark incomplete' : 'Mark complete'}>
                  {action.completed && <span className="text-white text-[10px] font-bold">✓</span>}
                </button>
                <span className={cn('text-xs flex-1 text-foreground', action.completed && 'line-through text-muted-foreground')}>
                  {action.label}
                </span>
                {action.assignee && (
                  <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                    <User className="h-2.5 w-2.5" /> {action.assignee}
                  </span>
                )}
                {action.completed
                  ? <CheckCircle className="h-4 w-4 text-green-400 shrink-0" />
                  : <Circle className="h-4 w-4 text-muted-foreground/30 shrink-0" />
                }
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ─── Timeline ─── */}
      {activeTab === 'timeline' && (
        <div className="glass-card p-4">
          <h3 className="text-sm font-semibold text-foreground mb-4">Incident Timeline</h3>
          {incident.timeline.length === 0
            ? <p className="text-xs text-muted-foreground text-center py-6">No timeline events yet.</p>
            : <div className="relative">
                {incident.timeline.map((entry, i) => (
                  <div key={i} className="relative flex gap-4 pb-6 last:pb-0">
                    {i < incident.timeline.length - 1 && (
                      <div className="absolute left-[11px] top-6 bottom-0 w-px bg-border" />
                    )}
                    <div className={cn('relative z-10 mt-1 h-[22px] w-[22px] shrink-0 rounded-full border-2 flex items-center justify-center',
                      entry.type === 'system' ? 'border-primary bg-primary/20' :
                      entry.type === 'correlation' ? 'border-purple-500 bg-purple-500/20' :
                      'border-green-500 bg-green-500/20')}>
                      <div className={cn('h-2 w-2 rounded-full',
                        entry.type === 'system' ? 'bg-primary' :
                        entry.type === 'correlation' ? 'bg-purple-500' : 'bg-green-500')} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium text-foreground">{entry.event}</p>
                      <p className="text-[10px] text-muted-foreground mt-0.5 flex items-center gap-2 flex-wrap">
                        <span className="flex items-center gap-1"><Clock className="h-2.5 w-2.5" /> {new Date(entry.time).toLocaleString()}</span>
                        <span className="flex items-center gap-1"><User className="h-2.5 w-2.5" /> {entry.actor}</span>
                        <span className="inline-flex items-center px-1.5 py-0.5 rounded bg-muted/40 border border-border/30 text-[9px] capitalize">{entry.type}</span>
                      </p>
                    </div>
                  </div>
                ))}
              </div>
          }
        </div>
      )}

      {/* ─── Threat Intel ─── */}
      {activeTab === 'intel' && (
        <div className="glass-card p-4 space-y-3">
          <h3 className="text-sm font-semibold flex items-center gap-2 text-foreground">
            <Globe className="h-4 w-4 text-primary" /> External Threat Intelligence
          </h3>
          {incident.threat_intel.length === 0
            ? <p className="text-xs text-muted-foreground text-center py-6">No external threat intelligence linked yet.</p>
            : <div className="space-y-2">
                {incident.threat_intel.map((intel, i) => (
                  <a key={i} href={intel.url} target="_blank" rel="noopener noreferrer"
                    className="flex items-center gap-3 text-xs p-3 rounded-lg bg-muted/20 border border-border/30 hover:bg-muted/40 transition-colors">
                    <span className="inline-flex items-center px-1.5 py-0.5 rounded bg-muted/50 border border-border/40 text-[10px] text-muted-foreground shrink-0">{intel.source}</span>
                    <span className="flex-1 text-primary truncate">{intel.label}</span>
                    <ExternalLink className="h-3 w-3 text-muted-foreground shrink-0" />
                  </a>
                ))}
              </div>
          }
        </div>
      )}

      {/* ─── Threat Attribution ─── */}
      {activeTab === 'attribution' && (
        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-foreground">Threat Actor Attribution</h3>
          {!attribution ? (
            <div className="glass-card p-6 text-center text-muted-foreground text-sm">Loading attribution data…</div>
          ) : !attribution.actor_name ? (
            <div className="glass-card p-6 text-center text-muted-foreground text-sm">No threat actor attribution available for this incident.</div>
          ) : (
            <div className="space-y-4">
              <div className="glass-card p-4 rounded-xl border border-border/50">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="text-xs text-muted-foreground uppercase tracking-wide mb-1">Attributed Actor</p>
                    <p className="text-lg font-semibold text-foreground">{attribution.actor_name}</p>
                    {attribution.summary && <p className="text-xs text-muted-foreground mt-1">{attribution.summary}</p>}
                  </div>
                  {attribution.confidence != null && (
                    <div className={cn('rounded-lg border px-3 py-2 text-center min-w-[80px]',
                      attribution.confidence >= 70 ? 'border-red-500/30 bg-red-500/10 text-red-400'
                      : attribution.confidence >= 40 ? 'border-amber-500/30 bg-amber-500/10 text-amber-400'
                      : 'border-border bg-muted/30 text-muted-foreground')}>
                      <p className="text-xs">Confidence</p>
                      <p className="text-xl font-bold">{attribution.confidence}%</p>
                    </div>
                  )}
                </div>
              </div>

              {attribution.ttps_matched.length > 0 && (
                <div className="glass-card p-4 rounded-xl border border-border/50">
                  <p className="text-xs text-muted-foreground uppercase tracking-wide mb-2">TTPs Matched</p>
                  <div className="flex flex-wrap gap-2">
                    {attribution.ttps_matched.map((ttp) => (
                      <span key={ttp} className="px-2 py-1 rounded-md bg-purple-500/10 border border-purple-500/20 text-purple-400 text-xs font-mono">{ttp}</span>
                    ))}
                  </div>
                </div>
              )}

              {attribution.mitre_overlap.length > 0 && (
                <div className="glass-card p-4 rounded-xl border border-border/50">
                  <p className="text-xs text-muted-foreground uppercase tracking-wide mb-2">MITRE ATT&CK Overlap</p>
                  <div className="flex flex-wrap gap-2">
                    {attribution.mitre_overlap.map((tech) => (
                      <span key={tech} className="px-2 py-1 rounded-md bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-mono">{tech}</span>
                    ))}
                  </div>
                </div>
              )}

              {attribution.sources.length > 0 && (
                <div className="glass-card p-4 rounded-xl border border-border/50">
                  <p className="text-xs text-muted-foreground uppercase tracking-wide mb-2">Intelligence Sources</p>
                  <div className="space-y-1">
                    {attribution.sources.map((src, i) => (
                      <p key={i} className="text-xs text-muted-foreground">• {src}</p>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ─── Artifacts ─── */}
      {activeTab === 'artifacts' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-foreground">Artifact Gallery</h3>
            {!isViewer && (
              <label className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg border border-border text-foreground text-xs hover:bg-accent transition-colors cursor-pointer">
                <Plus className="h-3 w-3" /> Upload Artifact
                <input
                  type="file"
                  className="hidden"
                  accept=".pdf,.png,.jpg,.jpeg,.txt,.log,.csv,.json,.pcap"
                  onChange={(e) => {
                    const file = e.target.files?.[0]
                    if (file) void uploadEvidenceFile(file)
                    e.target.value = ''
                  }}
                />
              </label>
            )}
          </div>
          {!isViewer && (
            <div className="glass-card p-3 space-y-2">
              <div className="flex gap-2">
                <input
                  type="url"
                  value={evidenceUrl}
                  onChange={(e) => setEvidenceUrl(e.target.value)}
                  placeholder="Attach URL evidence"
                  className="flex-1 px-3 py-2 rounded-lg border border-border bg-background text-foreground text-xs"
                />
                <button
                  type="button"
                  onClick={addEvidenceUrl}
                  disabled={evidenceBusy || !evidenceUrl.trim()}
                  className="px-3 py-2 rounded-lg border border-blue-500/30 bg-blue-500/10 text-blue-400 text-xs font-medium disabled:opacity-40"
                >
                  Add URL
                </button>
              </div>
              <input
                type="text"
                value={evidenceNotes}
                onChange={(e) => setEvidenceNotes(e.target.value)}
                placeholder="Optional notes"
                className="w-full px-3 py-2 rounded-lg border border-border bg-background text-foreground text-xs"
              />
            </div>
          )}
          {evidenceLoading
            ? <div className="text-center py-12 text-sm text-muted-foreground">Loading artifacts…</div>
            : incidentEvidence.length === 0
            ? <div className="text-center py-12 text-sm text-muted-foreground">No artifacts uploaded yet.</div>
            : <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {incidentEvidence.map((artifact) => (
                  <div key={artifact.id} className="glass-card-hover cursor-pointer p-4 flex items-center gap-3">
                    <div className="h-10 w-10 rounded-lg bg-muted/50 flex items-center justify-center shrink-0">
                      <FileText className="h-5 w-5 text-muted-foreground" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium truncate text-foreground">{artifact.name}</p>
                      <p className="text-[10px] text-muted-foreground">
                        {artifact.attachment_type.toUpperCase()} · {artifact.size_bytes ? `${(artifact.size_bytes / 1024).toFixed(1)} KB` : 'n/a'} · by {artifact.uploaded_by || 'analyst'}
                      </p>
                      {artifact.notes && <p className="text-[10px] text-muted-foreground truncate">{artifact.notes}</p>}
                    </div>
                    {artifact.attachment_type === 'file'
                      ? (
                          <button
                            type="button"
                            title="Download"
                            onClick={() => void downloadEvidenceFile(artifact.id, artifact.name)}
                            className="h-8 w-8 flex items-center justify-center rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent transition-colors shrink-0"
                          >
                            <Download className="h-3.5 w-3.5" />
                          </button>
                        )
                      : (
                          <a
                            href={artifact.external_url || '#'}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="h-8 w-8 flex items-center justify-center rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent transition-colors shrink-0"
                            title="Open URL"
                          >
                            <ExternalLink className="h-3.5 w-3.5" />
                          </a>
                        )}
                  </div>
                ))}
              </div>
          }
        </div>
      )}
    </div>
  )
}
