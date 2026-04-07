import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useAuth } from '@/security/AuthContext'
import { Plus, Trash2, Edit, Check, X, Shield, Activity, Workflow, Ban, ToggleLeft, ToggleRight, Globe, BookOpen, Hash, FlaskConical, AlertTriangle, Loader2 } from 'lucide-react'
import { Card, CardHeader } from '@/components/ui/Card'
import { Spinner } from '@/components/ui/Spinner'
import { get, post, patch, del, getToken, getCsrfToken } from '@/api/client'
import { toast } from 'sonner'
import { cn } from '@/utils/cn'

// ─── Dry-run types ────────────────────────────────────────────────────────────
interface DryRunActionItem {
  action_type: string
  risk_level: 'high' | 'medium' | 'low'
  description: string
  would_execute: boolean
}

interface DryRunResponse {
  playbook_id: string
  playbook_name: string
  action_count: number
  high_risk_count: number
  actions: DryRunActionItem[]
  requires_approval: boolean
}

// ─── Watchlist types ──────────────────────────────────────────────────────────
type IndicatorType = 'ip' | 'domain' | 'hash' | 'cidr' | 'url' | 'email'
interface WatchlistEntry {
  id: number
  indicator: string
  indicator_type: IndicatorType
  tag: string
  confidence: number
  notes: string | null
  is_active: boolean
  match_count: number
  last_matched_at: string | null
  created_at: string
}

function WatchlistSection({ isAdmin }: { isAdmin: boolean }) {
  const queryClient = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [indicator, setIndicator] = useState('')
  const [tag, setTag] = useState('')
  const [confidence, setConfidence] = useState('80')
  const [notes, setNotes] = useState('')

  const { data: entries = [], isLoading } = useQuery({
    queryKey: ['watchlist'],
    queryFn: () => get<WatchlistEntry[]>('/watchlist'),
  })

  const createMutation = useMutation({
    mutationFn: (body: object) => post<WatchlistEntry>('/watchlist', body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['watchlist'] })
      setShowCreate(false)
      setIndicator(''); setTag(''); setConfidence('80'); setNotes('')
      toast.success('Watchlist entry added')
    },
    onError: () => toast.error('Failed to add watchlist entry'),
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, is_active }: { id: number; is_active: boolean }) =>
      patch<WatchlistEntry>(`/watchlist/${id}`, { is_active }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['watchlist'] }),
    onError: () => toast.error('Failed to toggle entry'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: number) => del<void>(`/watchlist/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['watchlist'] })
      toast.success('Entry removed')
    },
    onError: () => toast.error('Failed to remove entry'),
  })

  const typeIcon = (t: IndicatorType) => {
    if (t === 'ip' || t === 'cidr') return <Globe className="w-3 h-3" />
    if (t === 'hash') return <Hash className="w-3 h-3" />
    return <Globe className="w-3 h-3" />
  }

  return (
    <div className="glass-card rounded-xl border border-border/50 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
          <Globe className="w-4 h-4 text-red-400" />
          IOC Watchlist
        </h2>
        {isAdmin && (
          <button type="button" onClick={() => setShowCreate(v => !v)}
            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border border-border text-xs text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors">
            <Plus className="w-3.5 h-3.5" /> Add IOC
          </button>
        )}
      </div>

      {showCreate && isAdmin && (
        <div className="rounded-lg border border-border/60 bg-muted/20 p-3 space-y-2">
          <input type="text" value={indicator} onChange={e => setIndicator(e.target.value)}
            placeholder="192.168.1.1 / evil.com / abc123hash" className="w-full px-3 py-1.5 rounded border border-border bg-background text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40" />
          <div className="grid grid-cols-2 gap-2">
            <input type="text" value={tag} onChange={e => setTag(e.target.value)}
              placeholder="Tag (e.g. C2, MALWARE)" className="px-3 py-1.5 rounded border border-border bg-background text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40" />
            <input type="number" value={confidence} onChange={e => setConfidence(e.target.value)}
              placeholder="Confidence 0-100" min={0} max={100} className="px-3 py-1.5 rounded border border-border bg-background text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40" />
          </div>
          <input type="text" value={notes} onChange={e => setNotes(e.target.value)}
            placeholder="Notes (optional)" className="w-full px-3 py-1.5 rounded border border-border bg-background text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40" />
          <div className="flex gap-2">
            <button type="button" disabled={!indicator.trim() || createMutation.isPending}
              onClick={() => createMutation.mutate({ indicator: indicator.trim(), tag: tag.trim() || 'WATCHLIST', confidence: Number(confidence), notes: notes.trim() || undefined })}
              className="flex-1 py-1.5 rounded-lg gradient-primary text-white text-xs font-semibold hover:opacity-90 disabled:opacity-40">
              {createMutation.isPending ? 'Adding…' : 'Add to Watchlist'}
            </button>
            <button type="button" onClick={() => setShowCreate(false)}
              className="px-3 py-1.5 rounded-lg border border-border text-xs text-muted-foreground hover:text-foreground">Cancel</button>
          </div>
        </div>
      )}

      {isLoading ? (
        <div className="flex justify-center py-4"><Spinner size="sm" /></div>
      ) : entries.length === 0 ? (
        <p className="text-xs text-muted-foreground text-center py-4">No IOC watchlist entries. Add IPs, domains, or hashes to auto-tag matching alerts.</p>
      ) : (
        <div className="space-y-1.5">
          {entries.map(entry => (
            <div key={entry.id} className={cn('flex items-center gap-2 px-3 py-2 rounded-lg border text-xs', entry.is_active ? 'border-border/40 bg-card' : 'border-border/20 bg-muted/10 opacity-60')}>
              <span className="shrink-0 text-muted-foreground">{typeIcon(entry.indicator_type)}</span>
              <span className="font-mono text-foreground flex-1 truncate">{entry.indicator}</span>
              <span className="shrink-0 px-1.5 py-0.5 rounded bg-red-500/15 border border-red-500/30 text-red-400 text-[10px] font-semibold">{entry.tag}</span>
              <span className="shrink-0 text-muted-foreground text-[10px]">{entry.confidence}%</span>
              {entry.match_count > 0 && (
                <span className="shrink-0 text-[10px] text-amber-400">{entry.match_count} hits</span>
              )}
              {isAdmin && (
                <>
                  <button type="button" onClick={() => toggleMutation.mutate({ id: entry.id, is_active: !entry.is_active })} className="shrink-0 text-muted-foreground hover:text-foreground transition-colors">
                    {entry.is_active ? <ToggleRight className="w-4 h-4 text-emerald-400" /> : <ToggleLeft className="w-4 h-4" />}
                  </button>
                  <button type="button" onClick={() => deleteMutation.mutate(entry.id)} className="shrink-0 text-muted-foreground hover:text-red-400 transition-colors">
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Playbook library types ────────────────────────────────────────────────────
interface LibraryTemplate {
  key: string
  name: string
  description: string
  trigger_type: string
  conditions: { field: string; operator: string; value: string }[]
  actions: { type: string; value: string }[]
}

const BUILTIN_TEMPLATES: LibraryTemplate[] = [
  {
    key: 'phishing_triage',
    name: 'Phishing Triage — High Confidence Mail Threat',
    description: 'Auto-tag and assign likely phishing alerts so analysts can quickly validate user impact and mailbox spread.',
    trigger_type: 'alert_created',
    conditions: [{ field: 'category', operator: 'contains', value: 'email' }, { field: 'title', operator: 'contains', value: 'phish' }],
    actions: [{ type: 'add_tag', value: 'PHISHING_TRIAGE' }, { type: 'set_status', value: 'in_progress' }, { type: 'assign_to', value: 'email-ir-queue' }],
  },
  {
    key: 'ransomware_triage',
    name: 'Ransomware Triage — Immediate Containment',
    description: 'Escalate and triage likely ransomware behaviors with high urgency to reduce dwell time and blast radius.',
    trigger_type: 'alert_created',
    conditions: [{ field: 'title', operator: 'contains', value: 'ransom' }, { field: 'severity', operator: 'equals', value: 'critical' }],
    actions: [{ type: 'add_tag', value: 'RANSOMWARE_TRIAGE' }, { type: 'set_status', value: 'in_progress' }, { type: 'set_severity', value: 'critical' }, { type: 'assign_to', value: 'containment-lead' }],
  },
  {
    key: 'bruteforce_triage',
    name: 'Brute-Force Triage — Identity Attack Pattern',
    description: 'Detect repeated identity authentication attack patterns and route to identity response queue.',
    trigger_type: 'alert_created',
    conditions: [{ field: 'category', operator: 'contains', value: 'identity' }, { field: 'title', operator: 'contains', value: 'brute' }],
    actions: [{ type: 'add_tag', value: 'BRUTEFORCE_TRIAGE' }, { type: 'set_status', value: 'in_progress' }, { type: 'assign_to', value: 'identity-ir-queue' }],
  },
]

function PlaybookLibrarySection({ onImport }: { onImport: (tpl: LibraryTemplate) => void }) {
  const [expanded, setExpanded] = useState<string | null>(null)
  return (
    <div className="glass-card rounded-xl border border-border/50 p-4 space-y-3">
      <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
        <BookOpen className="w-4 h-4 text-blue-400" />
        Playbook Library
        <span className="text-[10px] font-normal text-muted-foreground ml-1">Pre-built templates — import to activate</span>
      </h2>
      <div className="space-y-2">
        {BUILTIN_TEMPLATES.map(tpl => (
          <div key={tpl.key} className="rounded-lg border border-border/40 bg-muted/20 overflow-hidden">
            <button type="button" onClick={() => setExpanded(expanded === tpl.key ? null : tpl.key)}
              className="w-full flex items-center justify-between px-3 py-2.5 text-left hover:bg-muted/30 transition-colors">
              <div className="min-w-0">
                <p className="text-xs font-medium text-foreground truncate">{tpl.name}</p>
                <p className="text-[10px] text-muted-foreground mt-0.5 line-clamp-1">{tpl.description}</p>
              </div>
              <button type="button" onClick={e => { e.stopPropagation(); onImport(tpl) }}
                className="ml-3 shrink-0 inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border border-blue-500/30 bg-blue-500/10 text-blue-400 text-[10px] font-semibold hover:bg-blue-500/20 transition-colors">
                Import
              </button>
            </button>
            {expanded === tpl.key && (
              <div className="px-3 pb-3 grid grid-cols-1 sm:grid-cols-2 gap-2 border-t border-border/30 pt-2">
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">Conditions (ALL must match)</p>
                  {tpl.conditions.map((c, i) => (
                    <div key={i} className="text-[10px] font-mono bg-muted/30 rounded px-2 py-1 mb-1">
                      {c.field} <span className="text-muted-foreground">{c.operator}</span> <span className="text-blue-300">"{c.value}"</span>
                    </div>
                  ))}
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">Actions</p>
                  {tpl.actions.map((a, i) => (
                    <div key={i} className="text-[10px] font-mono bg-muted/30 rounded px-2 py-1 mb-1">
                      {a.type} <span className="text-muted-foreground">→</span> <span className="text-emerald-300">"{a.value}"</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Suppression types ────────────────────────────────────────────────────────
interface SuppressionCondition { field: string; operator: string; value: string }
interface SuppressionRule {
  id: number
  name: string
  description: string | null
  is_active: boolean
  conditions: SuppressionCondition[]
  expires_at: string | null
  created_by: string | null
  created_at: string
  hit_count: number
  last_hit_at: string | null
}

function SuppressionSection({ isAdmin }: { isAdmin: boolean }) {
  const queryClient = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [srName, setSrName] = useState('')
  const [srDesc, setSrDesc] = useState('')
  const [srConditions, setSrConditions] = useState<SuppressionCondition[]>([{ field: 'source', operator: 'equals', value: '' }])
  const [srExpiresHours, setSrExpiresHours] = useState<string>('')

  const { data: rules = [], isLoading } = useQuery({
    queryKey: ['suppression-rules'],
    queryFn: () => get<SuppressionRule[]>('/suppression'),
  })

  const createMutation = useMutation({
    mutationFn: (body: object) => post<SuppressionRule>('/suppression', body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['suppression-rules'] })
      setShowCreate(false)
      setSrName(''); setSrDesc(''); setSrConditions([{ field: 'source', operator: 'equals', value: '' }]); setSrExpiresHours('')
      toast.success('Suppression rule created')
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const toggleMutation = useMutation({
    mutationFn: (id: number) => post<SuppressionRule>(`/suppression/${id}/toggle`, {}),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['suppression-rules'] }),
    onError: () => toast.error('Failed to toggle rule'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: number) => del<void>(`/suppression/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['suppression-rules'] })
      toast.success('Rule deleted')
    },
    onError: () => toast.error('Failed to delete rule'),
  })

  const handleCreate = () => {
    if (!srName.trim()) return toast.error('Name is required')
    if (srConditions.some(c => !c.value.trim())) return toast.error('Condition values cannot be empty')
    createMutation.mutate({
      name: srName,
      description: srDesc || null,
      conditions: srConditions,
      expires_hours: srExpiresHours ? parseInt(srExpiresHours, 10) : null,
    })
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold flex items-center gap-2">
            <Ban className="w-5 h-5 text-yellow-400" /> Alert Suppression Rules
          </h2>
          <p className="text-muted-foreground text-sm mt-0.5">Auto-suppress noisy or known-benign alerts on ingest.</p>
        </div>
        {isAdmin && !showCreate && (
          <button onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 px-3 py-1.5 text-xs bg-yellow-500/10 border border-yellow-500/30 text-yellow-400 rounded-lg hover:bg-yellow-500/20 transition-colors">
            <Plus className="w-3 h-3" /> Add Rule
          </button>
        )}
      </div>

      {showCreate && (
        <Card className="border-yellow-500/20">
          <CardHeader title="Create Suppression Rule" />
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-muted-foreground mb-1">Name</label>
                <input type="text" value={srName} onChange={e => setSrName(e.target.value)} placeholder="e.g., Suppress port scan noise"
                  className="w-full px-3 py-2 bg-background border border-border rounded-lg text-foreground text-sm focus:outline-none focus:border-yellow-500" />
              </div>
              <div>
                <label className="block text-xs font-medium text-muted-foreground mb-1">Expires after (hours, blank = permanent)</label>
                <input type="number" value={srExpiresHours} onChange={e => setSrExpiresHours(e.target.value)} placeholder="e.g., 24"
                  className="w-full px-3 py-2 bg-background border border-border rounded-lg text-foreground text-sm focus:outline-none focus:border-yellow-500" />
              </div>
            </div>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-muted-foreground">Conditions (ALL must match)</span>
                <button onClick={() => setSrConditions([...srConditions, { field: 'source', operator: 'equals', value: '' }])}
                  className="text-xs text-yellow-400 hover:text-yellow-300 flex items-center gap-1"><Plus className="w-3 h-3" /> Add</button>
              </div>
              {srConditions.map((c, i) => (
                <div key={i} className="flex items-center gap-2">
                  <select value={c.field} onChange={e => { const n=[...srConditions]; n[i]={...n[i]!, field:e.target.value}; setSrConditions(n) }}
                    className="flex-1 px-3 py-2 bg-background border border-border rounded-lg text-foreground text-sm focus:outline-none">
                    <option value="severity">Severity</option>
                    <option value="source">Source</option>
                    <option value="category">Category</option>
                    <option value="title">Title</option>
                    <option value="source_ip">Source IP</option>
                  </select>
                  <select value={c.operator} onChange={e => { const n=[...srConditions]; n[i]={...n[i]!, operator:e.target.value}; setSrConditions(n) }}
                    className="w-32 px-3 py-2 bg-background border border-border rounded-lg text-foreground text-sm focus:outline-none">
                    <option value="equals">Equals</option>
                    <option value="not_equals">Not Equals</option>
                    <option value="contains">Contains</option>
                    <option value="not_contains">Not Contains</option>
                  </select>
                  <input type="text" value={c.value} onChange={e => { const n=[...srConditions]; n[i]={...n[i]!, value:e.target.value}; setSrConditions(n) }}
                    placeholder="Value..." className="flex-1 px-3 py-2 bg-background border border-border rounded-lg text-foreground text-sm focus:outline-none focus:border-yellow-500" />
                  <button onClick={() => setSrConditions(srConditions.filter((_, j) => j !== i))} className="p-2 text-muted-foreground hover:text-red-400">
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              ))}
            </div>
            <div className="flex justify-end gap-3 pt-2 border-t border-border">
              <button onClick={() => setShowCreate(false)} className="px-4 py-2 text-sm text-muted-foreground hover:text-foreground">Cancel</button>
              <button onClick={handleCreate} className="px-4 py-2 text-xs bg-yellow-500/10 border border-yellow-500/30 text-yellow-400 rounded-lg hover:bg-yellow-500/20">
                Create Rule
              </button>
            </div>
          </div>
        </Card>
      )}

      {isLoading ? (
        <div className="flex items-center justify-center py-8 text-muted-foreground"><Spinner /></div>
      ) : rules.length === 0 && !showCreate ? (
        <div className="text-center py-10 border border-border rounded-xl border-dashed">
          <Ban className="w-10 h-10 text-border mx-auto mb-3" />
          <p className="text-sm text-muted-foreground">No suppression rules. Add one to auto-dismiss noisy alerts.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {rules.map(rule => (
            <div key={rule.id} className={cn('glass-card p-4 flex items-start gap-4', !rule.is_active && 'opacity-50')}>
              <div className={cn('w-2 h-2 rounded-full mt-2 shrink-0', rule.is_active ? 'bg-yellow-400' : 'bg-muted')} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-sm font-medium text-foreground">{rule.name}</span>
                  {rule.expires_at && (
                    <span className="text-[10px] text-muted-foreground border border-border/50 rounded px-1.5 py-0.5">
                      Expires {new Date(rule.expires_at).toLocaleDateString()}
                    </span>
                  )}
                  <span className="text-[10px] text-muted-foreground">{rule.hit_count} hits</span>
                </div>
                <div className="flex flex-wrap gap-1.5 mt-1.5">
                  {rule.conditions.map((c, i) => (
                    <span key={i} className="inline-flex items-center px-2 py-0.5 rounded bg-muted/40 border border-border/30 text-[10px] text-muted-foreground font-mono">
                      {c.field} {c.operator} <span className="text-foreground ml-1">"{c.value}"</span>
                    </span>
                  ))}
                </div>
              </div>
              {isAdmin && (
                <div className="flex items-center gap-1 shrink-0">
                  <button onClick={() => toggleMutation.mutate(rule.id)} title={rule.is_active ? 'Disable' : 'Enable'}
                    className="p-1.5 text-muted-foreground hover:text-yellow-400 rounded">
                    {rule.is_active ? <ToggleRight className="w-4 h-4" /> : <ToggleLeft className="w-4 h-4" />}
                  </button>
                  <button onClick={() => { if (confirm('Delete this suppression rule?')) deleteMutation.mutate(rule.id) }}
                    className="p-1.5 text-muted-foreground hover:text-red-400 rounded"><Trash2 className="w-4 h-4" /></button>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

interface PlaybookCondition {
    field: string
    operator: 'equals' | 'not_equals' | 'contains' | 'not_contains'
    value: string
}

interface PlaybookAction {
    type: 'set_severity' | 'set_status' | 'add_tag' | 'assign_to'
    value: string
}

interface Playbook {
    id: number
    name: string
    description: string | null
    is_active: boolean
    trigger_type: string
    conditions: PlaybookCondition[]
    actions: PlaybookAction[]
    created_at: string
}

export function Playbooks() {
    const { user } = useAuth()
    const queryClient = useQueryClient()
    const [isEditing, setIsEditing] = useState<number | 'new' | null>(null)

    // Form State
    const [name, setName] = useState('')
    const [description, setDescription] = useState('')
    const [isActive, setIsActive] = useState(true)
    const [conditions, setConditions] = useState<PlaybookCondition[]>([{ field: 'severity', operator: 'equals', value: 'Critical' }])
    const [actions, setActions] = useState<PlaybookAction[]>([{ type: 'set_status', value: 'resolved' }])
    const [viewingPlaybook, setViewingPlaybook] = useState<Playbook | null>(null)

    // Dry-run state
    const [dryRunResult, setDryRunResult] = useState<DryRunResponse | null>(null)

    const dryRunMutation = useMutation({
        mutationFn: (id: number) => post<DryRunResponse>(`/playbooks/${id}/dry-run`),
        onSuccess: (data) => {
            setDryRunResult(data)
        },
        onError: () => toast.error('Dry-run failed'),
    })

    const apiGetPlaybooks = async () => {
        const res = await fetch('/api/v1/playbooks', {
            headers: { Authorization: `Bearer ${getToken()}` },
        })
        if (!res.ok) throw new Error('Failed to fetch playbooks')
        return res.json() as Promise<Playbook[]>
    }

    const playbooksQ = useQuery({ queryKey: ['playbooks'], queryFn: apiGetPlaybooks })

    const updateMutation = useMutation({
        mutationFn: async ({ id, data }: { id: number; data: Partial<Playbook> }) => {
            const csrf = getCsrfToken()
            const res = await fetch(`/api/v1/playbooks/${id}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${getToken()}`, ...(csrf ? { 'X-CSRF-Token': csrf } : {}) },
                body: JSON.stringify(data),
            })
            if (!res.ok) throw new Error('Update failed')
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['playbooks'] })
            toast.success('Playbook updated')
        },
        onError: () => toast.error('Failed to update playbook')
    })

    const createMutation = useMutation({
        mutationFn: async (data: Partial<Playbook>) => {
            const csrf = getCsrfToken()
            const res = await fetch('/api/v1/playbooks', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${getToken()}`, ...(csrf ? { 'X-CSRF-Token': csrf } : {}) },
                body: JSON.stringify(data),
            })
            if (!res.ok) {
                const err = await res.json().catch(() => ({}))
                throw new Error(err.detail || 'Creation failed')
            }
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['playbooks'] })
            setIsEditing(null)
            toast.success('Playbook created')
        },
        onError: (err: Error) => toast.error(err.message)
    })

    const deleteMutation = useMutation({
        mutationFn: async (id: number) => {
            const csrf = getCsrfToken()
            const res = await fetch(`/api/v1/playbooks/${id}`, {
                method: 'DELETE',
                headers: { Authorization: `Bearer ${getToken()}`, ...(csrf ? { 'X-CSRF-Token': csrf } : {}) },
            })
            if (!res.ok) throw new Error('Delete failed')
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['playbooks'] })
            toast.success('Playbook deleted')
        },
        onError: () => toast.error('Failed to delete playbook')
    })

    const handleCreateNew = () => {
        setName('')
        setDescription('')
        setIsActive(true)
        setConditions([{ field: 'severity', operator: 'equals', value: 'High' }])
        setActions([{ type: 'set_status', value: 'resolved' }])
        setIsEditing('new')
    }

    const handleEdit = (p: Playbook) => {
        setName(p.name)
        setDescription(p.description || '')
        setIsActive(p.is_active)
        setConditions(p.conditions.length ? p.conditions : [{ field: 'severity', operator: 'equals', value: 'High' }])
        setActions(p.actions.length ? p.actions : [{ type: 'set_status', value: 'resolved' }])
        setIsEditing(p.id)
    }

    const handleSave = () => {
        if (!name.trim()) return toast.error('Name is required')
        if (conditions.length === 0) return toast.error('At least one condition required')
        if (actions.length === 0) return toast.error('At least one action required')

        // validate no empty values
        if (conditions.some(c => !c.value.trim())) return toast.error('Condition values cannot be empty')
        if (actions.some(a => !a.value.trim())) return toast.error('Action values cannot be empty')

        const payload = {
            name,
            description,
            is_active: isActive,
            trigger_type: 'alert_created',
            conditions,
            actions,
        }

        if (isEditing === 'new') {
            createMutation.mutate(payload)
        } else if (typeof isEditing === 'number') {
            updateMutation.mutate({ id: isEditing, data: payload })
            setIsEditing(null)
        }
    }

    if (playbooksQ.isLoading) {
        return (
            <div className="flex h-full items-center justify-center text-muted-foreground">
                <Spinner />
            </div>
        )
    }

    const playbooks = playbooksQ.data || []
    const isAdmin = user?.role === 'admin'

    const handleImportTemplate = (tpl: LibraryTemplate) => {
      createMutation.mutate({
        name: tpl.name,
        description: tpl.description,
        trigger_type: tpl.trigger_type,
        conditions: tpl.conditions,
        actions: tpl.actions,
        is_active: true,
      } as Partial<Playbook>)
      toast.success(`Importing "${tpl.name}"…`)
    }

    return (
        <div className="space-y-6 max-w-6xl mx-auto animate-fade-in">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold flex items-center gap-2">
                        <Workflow className="w-6 h-6 text-blue-400" />
                        Automation Playbooks
                    </h2>
                    <p className="text-muted-foreground text-sm mt-1">Configure automated SOAR responses for incoming alerts.</p>
                </div>
                {isAdmin && !isEditing && (
                    <button
                        onClick={handleCreateNew}
                        className="flex items-center gap-2 px-4 py-2 gradient-primary text-white rounded-lg text-sm font-medium hover:opacity-90 transition-opacity"
                    >
                        <Plus className="w-4 h-4" />
                        Create Playbook
                    </button>
                )}
            </div>

            {isEditing && (
                <Card className="border-blue-500/30 shadow-lg shadow-blue-500/5">
                    <CardHeader title={isEditing === 'new' ? 'Create Playbook' : 'Edit Playbook'} />
                    <div className="space-y-6">
                        <div className="grid grid-cols-2 gap-4">
                            <div>
                                <label className="block text-sm font-medium text-muted-foreground mb-1">Name</label>
                                <input
                                    type="text"
                                    value={name}
                                    onChange={e => setName(e.target.value)}
                                    className="w-full px-3 py-2 bg-background border border-border rounded-lg text-foreground text-sm focus:outline-none focus:border-blue-500"
                                    placeholder="e.g., Auto-close low severity scans"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-muted-foreground mb-1">Description</label>
                                <input
                                    type="text"
                                    value={description}
                                    onChange={e => setDescription(e.target.value)}
                                    className="w-full px-3 py-2 bg-background border border-border rounded-lg text-foreground text-sm focus:outline-none focus:border-blue-500"
                                />
                            </div>
                        </div>

                        <div className="space-y-3 p-4 border border-border rounded-lg bg-background/50">
                            <div className="flex items-center justify-between">
                                <h4 className="text-sm font-medium text-foreground flex items-center gap-2">
                                    <Activity className="w-4 h-4 text-amber-500" /> IF Conditions (AND)
                                </h4>
                                <button
                                    onClick={() => setConditions([...conditions, { field: 'source', operator: 'equals', value: '' }])}
                                    className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1"
                                >
                                    <Plus className="w-3 h-3" /> Add Condition
                                </button>
                            </div>
                            {conditions.map((cond, idx) => (
                                <div key={idx} className="flex items-center gap-3">
                                    <select
                                        value={cond.field}
                                        onChange={e => {
                                            const newConds = [...conditions];
                                            newConds[idx]!.field = e.target.value;
                                            setConditions(newConds)
                                        }}
                                        className="flex-1 px-3 py-2 bg-background border border-border rounded-lg text-foreground text-sm focus:outline-none"
                                    >
                                        <option value="severity">Severity</option>
                                        <option value="source">Source</option>
                                        <option value="category">Category</option>
                                        <option value="title">Title</option>
                                        <option value="source_ip">Source IP</option>
                                    </select>
                                    <select
                                        value={cond.operator}
                                        onChange={e => {
                                            const newConds = [...conditions];
                                            newConds[idx]!.operator = e.target.value as any;
                                            setConditions(newConds)
                                        }}
                                        className="w-32 px-3 py-2 bg-background border border-border rounded-lg text-foreground text-sm focus:outline-none"
                                    >
                                        <option value="equals">Equals</option>
                                        <option value="not_equals">Not Equals</option>
                                        <option value="contains">Contains</option>
                                        <option value="not_contains">Not Contains</option>
                                    </select>
                                    <input
                                        type="text"
                                        value={cond.value}
                                        onChange={e => {
                                            const newConds = [...conditions];
                                            newConds[idx]!.value = e.target.value;
                                            setConditions(newConds)
                                        }}
                                        className="flex-1 px-3 py-2 bg-background border border-border rounded-lg text-foreground text-sm focus:outline-none focus:border-blue-500"
                                        placeholder="Value..."
                                    />
                                    <button
                                        onClick={() => setConditions(conditions.filter((_, i) => i !== idx))}
                                        className="p-2 text-muted-foreground hover:text-red-400"
                                    >
                                        <Trash2 className="w-4 h-4" />
                                    </button>
                                </div>
                            ))}
                        </div>

                        <div className="space-y-3 p-4 border border-border rounded-lg bg-background/50">
                            <div className="flex items-center justify-between">
                                <h4 className="text-sm font-medium text-foreground flex items-center gap-2">
                                    <Shield className="w-4 h-4 text-emerald-500" /> THEN Actions
                                </h4>
                                <button
                                    onClick={() => setActions([...actions, { type: 'set_status', value: '' }])}
                                    className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1"
                                >
                                    <Plus className="w-3 h-3" /> Add Action
                                </button>
                            </div>
                            {actions.map((act, idx) => (
                                <div key={idx} className="flex items-center gap-3">
                                    <select
                                        value={act.type}
                                        onChange={e => {
                                            const newActs = [...actions];
                                            newActs[idx]!.type = e.target.value as any;
                                            setActions(newActs)
                                        }}
                                        className="w-48 px-3 py-2 bg-background border border-border rounded-lg text-foreground text-sm focus:outline-none"
                                    >
                                        <option value="set_status">Set Status</option>
                                        <option value="set_severity">Set Severity</option>
                                        <option value="add_tag">Add Tag/Prefix</option>
                                        <option value="assign_to">Assign To User</option>
                                    </select>
                                    <input
                                        type="text"
                                        value={act.value}
                                        onChange={e => {
                                            const newActs = [...actions];
                                            newActs[idx]!.value = e.target.value;
                                            setActions(newActs)
                                        }}
                                        className="flex-1 px-3 py-2 bg-background border border-border rounded-lg text-foreground text-sm focus:outline-none focus:border-blue-500"
                                        placeholder="Action value..."
                                    />
                                    <button
                                        onClick={() => setActions(actions.filter((_, i) => i !== idx))}
                                        className="p-2 text-muted-foreground hover:text-red-400"
                                    >
                                        <Trash2 className="w-4 h-4" />
                                    </button>
                                </div>
                            ))}
                        </div>

                        <div className="flex items-center justify-between pt-4 border-t border-border">
                            <label className="flex items-center gap-2 cursor-pointer text-sm text-foreground">
                                <input
                                    type="checkbox"
                                    checked={isActive}
                                    onChange={e => setIsActive(e.target.checked)}
                                    className="w-4 h-4 rounded border-border text-blue-500 focus:ring-blue-500 bg-background"
                                />
                                Active Playbook
                            </label>
                            <div className="flex gap-3">
                                <button
                                    onClick={() => setIsEditing(null)}
                                    className="px-4 py-2 text-sm text-muted-foreground hover:text-foreground"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={handleSave}
                                    className="px-4 py-2 gradient-primary text-white rounded-lg text-sm font-medium hover:opacity-90 transition-opacity"
                                >
                                    Save Playbook
                                </button>
                            </div>
                        </div>
                    </div>
                </Card>
            )}

            {!isEditing && playbooks.length === 0 && (
                <div className="text-center py-16 border border-border rounded-xl border-dashed">
                    <Workflow className="w-12 h-12 text-border mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-foreground">No Playbooks</h3>
                    <p className="text-sm text-muted-foreground mt-1">Create an automation playbook to automatically triage incoming alerts.</p>
                </div>
            )}

            {!isEditing && playbooks.length > 0 && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {playbooks.map((p) => (
                        <Card
                            key={p.id}
                            className={cn("flex flex-col h-full", !p.is_active && "opacity-60", "cursor-pointer hover:border-blue-500/40")}
                            onClick={() => setViewingPlaybook(p)}
                        >
                            <div className="flex items-start justify-between mb-4">
                                <div className="flex items-center gap-2 min-w-0 flex-1">
                                    <div className={cn("w-2 h-2 rounded-full shrink-0", p.is_active ? "bg-emerald-500" : "bg-muted")}></div>
                                    <h3 className="font-semibold text-foreground truncate min-w-0" title={p.name}>{p.name}</h3>
                                </div>
                                        <div className="flex items-center gap-1 shrink-0 ml-2">
                                        <button
                                            onClick={(e) => {
                                                e.stopPropagation()
                                                dryRunMutation.mutate(p.id)
                                            }}
                                            disabled={dryRunMutation.isPending && dryRunMutation.variables === p.id}
                                            className="p-1.5 text-muted-foreground hover:bg-amber-500/10 hover:text-amber-400 rounded"
                                            title="Dry Run"
                                        >
                                            {dryRunMutation.isPending && dryRunMutation.variables === p.id
                                                ? <Loader2 className="w-4 h-4 animate-spin" />
                                                : <FlaskConical className="w-4 h-4" />}
                                        </button>
                                        {isAdmin && (
                                            <>
                                                <button
                                                    onClick={(e) => {
                                                        e.stopPropagation()
                                                        updateMutation.mutate({ id: p.id, data: { is_active: !p.is_active } })
                                                    }}
                                                    className="p-1.5 text-muted-foreground hover:bg-muted/50 hover:text-foreground rounded"
                                                    title={p.is_active ? "Disable Playbook" : "Enable Playbook"}
                                                >
                                                    {p.is_active ? <X className="w-4 h-4" /> : <Check className="w-4 h-4" />}
                                                </button>
                                                <button
                                                    onClick={(e) => {
                                                        e.stopPropagation()
                                                        handleEdit(p)
                                                    }}
                                                    className="p-1.5 text-muted-foreground hover:bg-muted/50 hover:text-foreground rounded"
                                                    title="Edit Playbook"
                                                >
                                                    <Edit className="w-4 h-4" />
                                                </button>
                                                <button
                                                    onClick={(e) => {
                                                        e.stopPropagation()
                                                        if (window.confirm('Delete this playbook?')) deleteMutation.mutate(p.id)
                                                    }}
                                                    className="p-1.5 text-muted-foreground hover:bg-red-500/10 hover:text-red-400 rounded"
                                                >
                                                    <Trash2 className="w-4 h-4" />
                                                </button>
                                            </>
                                        )}
                                    </div>
                            </div>
                            <p className="text-sm text-muted-foreground line-clamp-2 mb-4 flex-1 break-words min-w-0">
                                {p.description || 'No description provided.'}
                            </p>

                            <button
                                type="button"
                                onClick={(e) => {
                                    e.stopPropagation()
                                    setViewingPlaybook(p)
                                }}
                                className="text-xs text-blue-400 hover:text-blue-300 text-left mb-3"
                            >
                                View details
                            </button>

                            <div className="space-y-2 mt-auto pt-4 border-t border-border text-xs">
                                <div className="flex items-center justify-between text-muted-foreground">
                                    <span>Conditions</span>
                                    <span className="px-2 py-0.5 rounded bg-background border border-border">{p.conditions.length}</span>
                                </div>
                                <div className="flex items-center justify-between text-muted-foreground">
                                    <span>Actions</span>
                                    <span className="px-2 py-0.5 rounded bg-background border border-border text-blue-400">{p.actions.length}</span>
                                </div>
                            </div>
                        </Card>
                    ))}
                </div>
            )}

            {/* Suppression rules section */}
            <div className="h-px bg-border/40 my-2" />
            <SuppressionSection isAdmin={isAdmin} />

            {/* IOC Watchlist section */}
            <div className="h-px bg-border/40 my-2" />
            <WatchlistSection isAdmin={isAdmin} />

            {/* Playbook Library section */}
            <div className="h-px bg-border/40 my-2" />
            <PlaybookLibrarySection onImport={handleImportTemplate} />

            {/* Dry-run results modal */}
            {dryRunResult && (
                <div
                    className="fixed inset-0 z-[130] bg-black/60 backdrop-blur-sm flex items-center justify-center p-4"
                    onClick={() => setDryRunResult(null)}
                    role="dialog"
                    aria-modal="true"
                >
                    <div
                        className="w-full max-w-lg rounded-xl border border-border bg-card shadow-2xl p-5 space-y-4"
                        onClick={(e) => e.stopPropagation()}
                    >
                        <div className="flex items-start justify-between gap-3">
                            <div>
                                <h3 className="text-base font-semibold text-foreground flex items-center gap-2">
                                    <FlaskConical className="w-4 h-4 text-amber-400" />
                                    Dry Run — {dryRunResult.playbook_name}
                                </h3>
                                <p className="text-xs text-muted-foreground mt-0.5">
                                    {dryRunResult.action_count} action{dryRunResult.action_count !== 1 ? 's' : ''} would execute
                                    {dryRunResult.high_risk_count > 0 && (
                                        <span className="ml-1 text-red-400">· {dryRunResult.high_risk_count} high-risk</span>
                                    )}
                                </p>
                            </div>
                            <button
                                type="button"
                                onClick={() => setDryRunResult(null)}
                                className="p-1.5 rounded text-muted-foreground hover:text-foreground hover:bg-muted/40"
                                aria-label="Close"
                            >
                                <X className="w-4 h-4" />
                            </button>
                        </div>

                        {dryRunResult.requires_approval && (
                            <div className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2.5">
                                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                                <p className="text-xs text-red-300 font-medium">
                                    High-risk actions detected — approval required before live execution
                                </p>
                            </div>
                        )}

                        <div className="space-y-2">
                            {dryRunResult.actions.map((action, i) => {
                                const riskCls =
                                    action.risk_level === 'high'
                                        ? 'bg-red-500/15 border-red-500/30 text-red-400'
                                        : action.risk_level === 'medium'
                                        ? 'bg-amber-500/15 border-amber-500/30 text-amber-400'
                                        : 'bg-emerald-500/15 border-emerald-500/30 text-emerald-400'
                                return (
                                    <div key={i} className="flex items-center gap-3 rounded-lg border border-border/40 bg-muted/20 px-3 py-2">
                                        <span className={cn('shrink-0 px-2 py-0.5 rounded border text-[10px] font-semibold uppercase tracking-wide', riskCls)}>
                                            {action.risk_level}
                                        </span>
                                        <span className="text-xs font-mono text-foreground flex-1 truncate">{action.description}</span>
                                    </div>
                                )
                            })}
                            {dryRunResult.actions.length === 0 && (
                                <p className="text-xs text-muted-foreground text-center py-4">No actions configured for this playbook.</p>
                            )}
                        </div>

                        <div className="flex justify-end pt-1">
                            <button
                                type="button"
                                onClick={() => setDryRunResult(null)}
                                className="px-3 py-1.5 rounded-lg border border-border text-sm text-muted-foreground hover:text-foreground"
                            >
                                Close
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {viewingPlaybook && (
                <div
                    className="fixed inset-0 z-[130] bg-black/60 backdrop-blur-sm flex items-center justify-center p-4"
                    onClick={() => setViewingPlaybook(null)}
                    role="dialog"
                    aria-modal="true"
                >
                    <div
                        className="w-full max-w-2xl rounded-xl border border-border bg-card shadow-2xl p-5 space-y-5"
                        onClick={(e) => e.stopPropagation()}
                    >
                        <div className="flex items-start justify-between gap-3">
                            <div>
                                <h3 className="text-lg font-semibold text-foreground">{viewingPlaybook.name}</h3>
                                <p className="text-sm text-muted-foreground mt-1">
                                    {viewingPlaybook.description || 'No description provided.'}
                                </p>
                            </div>
                            <button
                                type="button"
                                onClick={() => setViewingPlaybook(null)}
                                className="p-1.5 rounded text-muted-foreground hover:text-foreground hover:bg-muted/40"
                                aria-label="Close"
                            >
                                <X className="w-4 h-4" />
                            </button>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div className="rounded-lg border border-border p-3">
                                <h4 className="text-sm font-medium text-foreground mb-2">Conditions</h4>
                                <div className="space-y-2">
                                    {viewingPlaybook.conditions.map((c, i) => (
                                        <div key={i} className="text-xs text-muted-foreground border border-border/40 rounded px-2 py-1.5">
                                            <span className="font-mono text-foreground">{c.field}</span>
                                            <span className="mx-1">{c.operator}</span>
                                            <span className="font-mono text-blue-300">"{c.value}"</span>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            <div className="rounded-lg border border-border p-3">
                                <h4 className="text-sm font-medium text-foreground mb-2">Actions</h4>
                                <div className="space-y-2">
                                    {viewingPlaybook.actions.map((a, i) => (
                                        <div key={i} className="text-xs text-muted-foreground border border-border/40 rounded px-2 py-1.5">
                                            <span className="font-mono text-foreground">{a.type}</span>
                                            <span className="mx-1">{'->'}</span>
                                            <span className="font-mono text-emerald-300">"{a.value}"</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>

                        <div className="flex justify-end pt-1">
                            <button
                                type="button"
                                onClick={() => setViewingPlaybook(null)}
                                className="px-3 py-1.5 rounded-lg border border-border text-sm text-muted-foreground hover:text-foreground"
                            >
                                Close
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    )
}
