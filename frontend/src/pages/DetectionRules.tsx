import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Shield, Plus, Play, RotateCcw, Clock, ChevronDown, ChevronRight, Pencil, Trash2 } from 'lucide-react'
import { Breadcrumb } from '@/components/ui/Breadcrumb'
import { SpinnerOverlay } from '@/components/ui/Spinner'
import { ErrorState } from '@/components/ui/ErrorState'
import { get, post, patch, del } from '@/api/client'
import { useAuth } from '@/security/AuthContext'
import { cn } from '@/utils/cn'
import { toast } from 'sonner'

// ─── Types ────────────────────────────────────────────────────────────────────
interface DetectionRule {
  id: number
  name: string
  rule_type: 'sigma' | 'custom'
  description: string | null
  severity: 'Low' | 'Medium' | 'High' | 'Critical'
  enabled: boolean
  sigma_yaml: string | null
  conditions: unknown[] | null
  created_by: string | null
  version: number
  approval_status: 'pending' | 'approved'
  has_pending_change: boolean
}

interface HistoryItem {
  id: number
  version: number | null
  action: string
  status: string
  requested_by: string | null
  approved_by: string | null
  reason: string | null
  created_at: string | null
}

const SEVERITY_COLORS: Record<string, string> = {
  Critical: 'text-red-400 bg-red-500/10 border-red-500/30',
  High: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
  Medium: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
  Low: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
}

// ─── Test panel ───────────────────────────────────────────────────────────────
function TestPanel({ rule, onClose }: { rule: DetectionRule; onClose: () => void }) {
  const [eventJson, setEventJson] = useState('{\n  "source_ip": "1.2.3.4",\n  "category": "auth"\n}')
  const [result, setResult] = useState<unknown | null>(null)
  const [testing, setTesting] = useState(false)

  const handleTest = async () => {
    setTesting(true)
    try {
      const event = JSON.parse(eventJson) as Record<string, unknown>
      const res = await post<unknown>(`/detection-rules/${rule.id}/test`, { event })
      setResult(res)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Test failed')
    } finally {
      setTesting(false)
    }
  }

  return (
    <div className="glass-card rounded-xl border border-border/50 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-sm font-medium text-foreground">Test Rule: {rule.name}</p>
        <button type="button" onClick={onClose} className="text-xs text-muted-foreground hover:text-foreground">Close</button>
      </div>
      <div>
        <p className="text-xs text-muted-foreground mb-1">Event JSON</p>
        <textarea
          value={eventJson}
          onChange={(e) => setEventJson(e.target.value)}
          rows={6}
          className="w-full px-3 py-2 rounded-lg border border-border bg-background text-foreground text-xs font-mono resize-none"
        />
      </div>
      <button type="button" onClick={handleTest} disabled={testing}
        className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-blue-500/30 bg-blue-500/10 text-blue-400 text-sm disabled:opacity-50">
        <Play className="w-3.5 h-3.5" />
        {testing ? 'Testing…' : 'Run Test'}
      </button>
      {result != null && (
        <pre className="text-xs bg-muted/30 rounded-lg p-3 overflow-auto max-h-48 whitespace-pre-wrap text-muted-foreground">
          {JSON.stringify(result, null, 2)}
        </pre>
      )}
    </div>
  )
}

// ─── History panel ────────────────────────────────────────────────────────────
function HistoryPanel({ rule, isAdmin, onClose }: { rule: DetectionRule; isAdmin: boolean; onClose: () => void }) {
  const qc = useQueryClient()
  const { data: history = [] } = useQuery({
    queryKey: ['detection-rule-history', rule.id],
    queryFn: () => get<HistoryItem[]>(`/detection-rules/${rule.id}/history`),
  })

  const rollbackMut = useMutation({
    mutationFn: (target_version: number) =>
      post<DetectionRule>(`/detection-rules/${rule.id}/rollback`, { target_version }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['detection-rules'] })
      toast.success('Rolled back')
      onClose()
    },
  })

  return (
    <div className="glass-card rounded-xl border border-border/50 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-sm font-medium text-foreground">History: {rule.name}</p>
        <button type="button" onClick={onClose} className="text-xs text-muted-foreground hover:text-foreground">Close</button>
      </div>
      {history.length === 0 ? (
        <p className="text-xs text-muted-foreground">No history available.</p>
      ) : (
        <div className="space-y-2 max-h-64 overflow-y-auto">
          {history.map((h) => (
            <div key={h.id} className="flex items-start justify-between gap-3 p-2 rounded-lg bg-muted/20">
              <div className="min-w-0">
                <p className="text-xs font-medium text-foreground">{h.action} — v{h.version ?? '?'}</p>
                <p className="text-xs text-muted-foreground">{h.requested_by ?? 'system'} · {h.created_at ? new Date(h.created_at).toLocaleString() : '—'}</p>
                {h.reason && <p className="text-xs text-muted-foreground italic">{h.reason}</p>}
              </div>
              <span className={cn('text-xs px-1.5 py-0.5 rounded border shrink-0',
                h.status === 'approved' ? 'border-emerald-500/30 text-emerald-400' : 'border-amber-500/30 text-amber-400')}>
                {h.status}
              </span>
              {isAdmin && h.version != null && h.version < rule.version && (
                <button type="button"
                  onClick={() => rollbackMut.mutate(h.version!)}
                  disabled={rollbackMut.isPending}
                  className="shrink-0 p-1 rounded border border-border/50 text-muted-foreground hover:text-amber-400 hover:border-amber-500/30">
                  <RotateCcw className="w-3 h-3" />
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Create/Edit form ─────────────────────────────────────────────────────────
function RuleForm({
  initial,
  onSave,
  onCancel,
  saving,
}: {
  initial?: Partial<DetectionRule>
  onSave: (data: object) => void
  onCancel: () => void
  saving: boolean
}) {
  const [name, setName] = useState(initial?.name ?? '')
  const [ruleType, setRuleType] = useState<'sigma' | 'custom'>(initial?.rule_type ?? 'sigma')
  const [severity, setSeverity] = useState(initial?.severity ?? 'Medium')
  const [description, setDescription] = useState(initial?.description ?? '')
  const [sigmaYaml, setSigmaYaml] = useState(initial?.sigma_yaml ?? '')
  const [conditions, setConditions] = useState(
    initial?.conditions ? JSON.stringify(initial.conditions, null, 2) : '[]'
  )

  const handleSubmit = () => {
    if (!name.trim()) { toast.error('Name required'); return }
    const body: Record<string, unknown> = { name: name.trim(), rule_type: ruleType, severity, description: description || null }
    if (ruleType === 'sigma') body.sigma_yaml = sigmaYaml
    else {
      try { body.conditions = JSON.parse(conditions) as unknown[] }
      catch { toast.error('Conditions must be valid JSON array'); return }
    }
    onSave(body)
  }

  return (
    <div className="glass-card rounded-xl border border-border/50 p-4 space-y-3">
      <p className="text-sm font-semibold text-foreground">{initial?.id ? 'Edit Rule' : 'New Detection Rule'}</p>

      <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="Rule name"
        className="w-full px-3 py-2 rounded-lg border border-border bg-background text-foreground text-sm" />

      <div className="flex gap-2">
        <div className="flex rounded-lg border border-border/50 overflow-hidden text-xs">
          {(['sigma', 'custom'] as const).map((t) => (
            <button key={t} type="button" onClick={() => setRuleType(t)}
              className={cn('px-3 py-1.5 capitalize font-medium transition-colors',
                ruleType === t ? 'gradient-primary text-white' : 'bg-card text-muted-foreground hover:bg-muted/50')}>
              {t}
            </button>
          ))}
        </div>
        <div className="flex rounded-lg border border-border/50 overflow-hidden text-xs">
          {(['Low', 'Medium', 'High', 'Critical'] as const).map((s) => (
            <button key={s} type="button" onClick={() => setSeverity(s)}
              className={cn('px-2.5 py-1.5 font-medium transition-colors',
                severity === s ? 'gradient-primary text-white' : 'bg-card text-muted-foreground hover:bg-muted/50')}>
              {s}
            </button>
          ))}
        </div>
      </div>

      <input type="text" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Description (optional)"
        className="w-full px-3 py-2 rounded-lg border border-border bg-background text-foreground text-sm" />

      {ruleType === 'sigma' ? (
        <textarea value={sigmaYaml} onChange={(e) => setSigmaYaml(e.target.value)} placeholder="Sigma YAML…" rows={8}
          className="w-full px-3 py-2 rounded-lg border border-border bg-background text-foreground text-xs font-mono resize-none" />
      ) : (
        <textarea value={conditions} onChange={(e) => setConditions(e.target.value)} placeholder='[{"field":"severity","op":"eq","value":"Critical"}]' rows={6}
          className="w-full px-3 py-2 rounded-lg border border-border bg-background text-foreground text-xs font-mono resize-none" />
      )}

      <div className="flex gap-2">
        <button type="button" onClick={handleSubmit} disabled={saving}
          className="px-3 py-1.5 rounded-lg bg-primary text-primary-foreground text-sm font-medium disabled:opacity-50">
          {saving ? 'Saving…' : 'Save Rule'}
        </button>
        <button type="button" onClick={onCancel}
          className="px-3 py-1.5 rounded-lg border border-border/50 text-sm text-muted-foreground hover:text-foreground">
          Cancel
        </button>
      </div>
    </div>
  )
}

// ─── Rule row ─────────────────────────────────────────────────────────────────
function RuleRow({ rule, isAdmin }: { rule: DetectionRule; isAdmin: boolean }) {
  const qc = useQueryClient()
  const [expanded, setExpanded] = useState(false)
  const [showTest, setShowTest] = useState(false)
  const [showHistory, setShowHistory] = useState(false)
  const [editing, setEditing] = useState(false)

  const onErr = (e: unknown) => toast.error(e instanceof Error ? e.message : 'Operation failed')

  const toggleMut = useMutation({
    mutationFn: () => patch<DetectionRule>(`/detection-rules/${rule.id}`, { enabled: !rule.enabled }),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['detection-rules'] }); toast.success(rule.enabled ? 'Rule disabled' : 'Rule enabled') },
    onError: onErr,
  })

  const deleteMut = useMutation({
    mutationFn: () => del<void>(`/detection-rules/${rule.id}`),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['detection-rules'] }); toast.success('Rule deleted') },
    onError: onErr,
  })

  const updateMut = useMutation({
    mutationFn: (data: object) => patch<DetectionRule>(`/detection-rules/${rule.id}`, data),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['detection-rules'] }); setEditing(false); toast.success('Change request submitted') },
    onError: onErr,
  })

  const approveMut = useMutation({
    mutationFn: () => post<DetectionRule>(`/detection-rules/${rule.id}/approve-change`, {}),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['detection-rules'] }); toast.success('Change approved and applied') },
    onError: onErr,
  })

  return (
    <div className="glass-card rounded-xl border border-border/50 overflow-hidden">
      <div className="flex items-center gap-3 p-3">
        <button type="button" onClick={() => setExpanded((v) => !v)} className="text-muted-foreground hover:text-foreground">
          {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </button>

        {/* Toggle enable — admin only (backend requires admin:write) */}
        {isAdmin ? (
          <button
            type="button"
            role="switch"
            aria-checked={rule.enabled}
            onClick={() => toggleMut.mutate()}
            disabled={toggleMut.isPending}
            title={rule.enabled ? 'Disable rule' : 'Enable rule'}
            className={cn(
              'relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors disabled:opacity-50',
              rule.enabled ? 'bg-emerald-500' : 'bg-muted',
            )}
          >
            <span className={cn(
              'pointer-events-none inline-block h-4 w-4 rounded-full bg-white shadow-lg ring-0 transition-transform',
              rule.enabled ? 'translate-x-4' : 'translate-x-0',
            )} />
          </button>
        ) : (
          /* Read-only indicator for non-admins */
          <div className={cn(
            'relative inline-flex h-5 w-9 shrink-0 rounded-full border-2 border-transparent',
            rule.enabled ? 'bg-emerald-500/50' : 'bg-muted/50',
          )}>
            <span className={cn(
              'pointer-events-none inline-block h-4 w-4 rounded-full bg-white/70 shadow ring-0',
              rule.enabled ? 'translate-x-4' : 'translate-x-0',
            )} />
          </div>
        )}

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="text-sm font-medium text-foreground truncate">{rule.name}</p>
            <span className={cn('text-xs px-1.5 py-0.5 rounded border', SEVERITY_COLORS[rule.severity] ?? '')}>{rule.severity}</span>
            <span className="text-xs px-1.5 py-0.5 rounded border border-border bg-muted/30 text-muted-foreground uppercase">{rule.rule_type}</span>
            {rule.has_pending_change && (
              <span className="text-xs px-1.5 py-0.5 rounded border border-amber-500/30 bg-amber-500/10 text-amber-400">pending approval</span>
            )}
          </div>
          {rule.description && <p className="text-xs text-muted-foreground mt-0.5 truncate">{rule.description}</p>}
        </div>

        <span className="text-xs text-muted-foreground shrink-0">v{rule.version}</span>

        <div className="flex items-center gap-1 shrink-0">
          {/* Test + History: all authenticated users */}
          <button type="button" onClick={() => { setShowTest((v) => !v); setShowHistory(false); setEditing(false) }}
            title="Test rule" className="p-1.5 rounded border border-border/50 text-muted-foreground hover:text-blue-400 hover:border-blue-500/30 transition-colors">
            <Play className="w-3.5 h-3.5" />
          </button>
          <button type="button" onClick={() => { setShowHistory((v) => !v); setShowTest(false); setEditing(false) }}
            title="History" className="p-1.5 rounded border border-border/50 text-muted-foreground hover:text-purple-400 hover:border-purple-500/30 transition-colors">
            <Clock className="w-3.5 h-3.5" />
          </button>

          {/* Edit, Delete, Approve: admin only (backend requires admin:write) */}
          {isAdmin && (
            <>
              <button type="button" onClick={() => { setEditing((v) => !v); setShowTest(false); setShowHistory(false) }}
                title="Edit / request change" className="p-1.5 rounded border border-border/50 text-muted-foreground hover:text-foreground hover:border-border transition-colors">
                <Pencil className="w-3.5 h-3.5" />
              </button>
              <button type="button" onClick={() => { if (confirm('Delete this rule?')) deleteMut.mutate() }}
                disabled={deleteMut.isPending} title="Delete rule"
                className="p-1.5 rounded border border-border/50 text-muted-foreground hover:text-red-400 hover:border-red-500/30 transition-colors">
                <Trash2 className="w-3.5 h-3.5" />
              </button>
              {rule.has_pending_change && (
                <button type="button" onClick={() => approveMut.mutate()} disabled={approveMut.isPending}
                  className="px-2 py-1 rounded border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 text-xs hover:bg-emerald-500/20 transition-colors disabled:opacity-50">
                  {approveMut.isPending ? '…' : 'Approve'}
                </button>
              )}
            </>
          )}
        </div>
      </div>

      {expanded && (rule.sigma_yaml || rule.conditions) && (
        <div className="border-t border-border/50 px-4 py-3">
          <pre className="text-xs text-muted-foreground bg-muted/20 rounded-lg p-3 overflow-auto max-h-48 whitespace-pre-wrap">
            {rule.sigma_yaml ?? JSON.stringify(rule.conditions, null, 2)}
          </pre>
        </div>
      )}

      {editing && (
        <div className="border-t border-border/50 p-4">
          <RuleForm initial={rule} onSave={(data) => updateMut.mutate(data)} onCancel={() => setEditing(false)} saving={updateMut.isPending} />
        </div>
      )}

      {showTest && (
        <div className="border-t border-border/50 p-4">
          <TestPanel rule={rule} onClose={() => setShowTest(false)} />
        </div>
      )}

      {showHistory && (
        <div className="border-t border-border/50 p-4">
          <HistoryPanel rule={rule} isAdmin={isAdmin} onClose={() => setShowHistory(false)} />
        </div>
      )}
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────
export function DetectionRules() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const isViewer = user?.role === 'viewer'
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [filterEnabled, setFilterEnabled] = useState<boolean | null>(null)

  const { data: rules = [], isLoading, isError, refetch } = useQuery({
    queryKey: ['detection-rules', filterEnabled],
    queryFn: () => {
      const qs = filterEnabled === null ? '' : `?enabled=${filterEnabled}`
      return get<DetectionRule[]>(`/detection-rules${qs}`)
    },
  })

  const createMut = useMutation({
    mutationFn: (data: object) => post<DetectionRule>('/detection-rules', data),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['detection-rules'] })
      setShowCreate(false)
      toast.success('Rule created')
    },
  })

  const enabled = rules.filter((r) => r.enabled).length

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <Breadcrumb items={[{ label: 'Home', to: '/app' }, { label: 'Detection Rules' }]} />
          <h1 className="text-2xl font-semibold text-foreground">Detection Rules</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Manage Sigma and custom detection rules</p>
        </div>
        <div className="flex items-center gap-2">
          {/* Filter */}
          <div className="flex rounded-lg border border-border/50 overflow-hidden text-sm">
            {([null, true, false] as const).map((v) => (
              <button key={String(v)} type="button" onClick={() => setFilterEnabled(v)}
                className={cn('px-3 py-1.5 transition-colors',
                  filterEnabled === v ? 'gradient-primary text-white font-medium' : 'bg-card text-muted-foreground hover:bg-muted/50')}>
                {v === null ? 'All' : v ? 'Enabled' : 'Disabled'}
              </button>
            ))}
          </div>
          {!isViewer && (
            <button type="button" onClick={() => setShowCreate((v) => !v)}
              className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg gradient-primary text-white text-sm font-medium">
              <Plus className="w-4 h-4" />
              New Rule
            </button>
          )}
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'Total Rules', value: rules.length },
          { label: 'Enabled', value: enabled },
          { label: 'Pending Approval', value: rules.filter((r) => r.has_pending_change).length },
        ].map(({ label, value }) => (
          <div key={label} className="glass-card rounded-xl border border-border/50 p-4">
            <p className="text-xs text-muted-foreground">{label}</p>
            <p className="text-2xl font-bold text-foreground mt-1">{value}</p>
          </div>
        ))}
      </div>

      {showCreate && (
        <RuleForm onSave={(data) => createMut.mutate(data)} onCancel={() => setShowCreate(false)} saving={createMut.isPending} />
      )}

      {isLoading && <SpinnerOverlay />}
      {isError && <ErrorState title="Failed to load detection rules" onRetry={() => void refetch()} />}

      {!isLoading && rules.length === 0 && (
        <div className="glass-card rounded-xl border border-border/50 p-10 text-center">
          <Shield className="w-12 h-12 text-muted-foreground mx-auto mb-3" />
          <p className="text-muted-foreground text-sm">No detection rules found.</p>
        </div>
      )}

      <div className="space-y-2">
        {rules.map((rule) => (
          <RuleRow key={rule.id} rule={rule} isAdmin={isAdmin} />
        ))}
      </div>
    </div>
  )
}
