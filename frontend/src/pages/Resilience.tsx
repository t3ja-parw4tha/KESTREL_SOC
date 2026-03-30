import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { get, post } from '@/api/client'
import { Beaker, KeyRound, Building2, ShieldCheck, HardDrive, BrainCircuit, Radar, CheckCircle2, Star } from 'lucide-react'
import { cn } from '@/utils/cn'
import { toast } from 'sonner'
import { useAuth } from '@/security/AuthContext'

export function Resilience() {
  const qc = useQueryClient()
  const { user: authUser } = useAuth()
  const role = (authUser as { role?: string } | null)?.role ?? 'viewer'
  const isAdmin = role === 'admin'
  const canRunPlaybooks = role === 'senior_analyst' || isAdmin
  const canReadSourceQuality = role === 'senior_analyst' || isAdmin
  const canWriteAIFeedback = role !== 'viewer'

  const [active, setActive] = useState<'qa' | 'secrets' | 'tenant' | 'approvals' | 'dr' | 'ai' | 'source'>('qa')

  // AI Governance feedback form state
  const [feedbackAlertId, setFeedbackAlertId] = useState('')
  const [feedbackRating, setFeedbackRating] = useState(3)
  const [feedbackHallucination, setFeedbackHallucination] = useState(false)
  const [feedbackComments, setFeedbackComments] = useState('')

  // Secret Rotation add-policy form state
  const [showSecretForm, setShowSecretForm] = useState(false)
  const [secretName, setSecretName] = useState('')
  const [secretProvider, setSecretProvider] = useState('env')
  const [secretRotationDays, setSecretRotationDays] = useState(90)
  const [secretOwner, setSecretOwner] = useState('')

  // Tenant Boundaries add-workspace form state
  const [showWorkspaceForm, setShowWorkspaceForm] = useState(false)
  const [workspaceOrgId, setWorkspaceOrgId] = useState('')
  const [workspaceId, setWorkspaceId] = useState('')

  // DR Drills schedule form state
  const [showDrillForm, setShowDrillForm] = useState(false)
  const [drillTarget, setDrillTarget] = useState('')
  const [drillRpo, setDrillRpo] = useState(60)
  const [drillRto, setDrillRto] = useState(120)

  // --- Detection QA ---
  const replayMut = useMutation({
    mutationFn: () => post('/resilience/detection-qa/replay', { dataset_name: 'last_30d_alerts', replay_window_days: 30 }),
    onSuccess: () => {
      toast.success('Replay gate run successfully')
      void qc.invalidateQueries({ queryKey: ['resilience-replays'] })
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Operation failed'),
  })
  const { data: replays = [] } = useQuery({
    queryKey: ['resilience-replays'],
    enabled: active === 'qa',
    queryFn: () => get<Array<{ id: string; precision_pct: number; recall_pct: number; gate_passed: boolean; created_at: string }>>('/resilience/detection-qa/replays'),
  })

  // --- Secret Rotation ---
  const { data: secretPolicies = [] } = useQuery({
    queryKey: ['resilience-secret-policies'],
    enabled: isAdmin && active === 'secrets',
    queryFn: () => get<Array<{ id: number; secret_name: string; provider: string; rotation_days: number; owner: string | null; last_rotated_at: string | null }>>('/resilience/secrets/policies'),
  })
  const { data: secretCheck } = useQuery({
    queryKey: ['resilience-secret-check'],
    enabled: isAdmin && active === 'secrets',
    queryFn: () => get<{ total: number; overdue: number; items: Array<{ secret_name: string; overdue: boolean; days_since_rotation: number | null }> }>('/resilience/secrets/rotation-check'),
  })
  const addSecretMut = useMutation({
    mutationFn: () => post('/resilience/secrets/policies', {
      secret_name: secretName.trim(),
      provider: secretProvider.trim() || 'env',
      rotation_days: secretRotationDays,
      owner: secretOwner.trim() || undefined,
    }),
    onSuccess: () => {
      toast.success('Secret rotation policy saved')
      setShowSecretForm(false)
      setSecretName('')
      setSecretProvider('env')
      setSecretRotationDays(90)
      setSecretOwner('')
      void qc.invalidateQueries({ queryKey: ['resilience-secret-policies'] })
      void qc.invalidateQueries({ queryKey: ['resilience-secret-check'] })
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Operation failed'),
  })

  // --- Tenant Boundaries ---
  const { data: workspaces = [] } = useQuery({
    queryKey: ['resilience-workspaces'],
    enabled: isAdmin && active === 'tenant',
    queryFn: () => get<Array<{ id: number; org_id: string; workspace_id: string; is_active: boolean }>>('/resilience/tenants/workspaces'),
  })
  const workspaceMut = useMutation({
    mutationFn: () => post('/resilience/tenants/workspaces', {
      org_id: workspaceOrgId.trim(),
      workspace_id: workspaceId.trim(),
      description: 'Added from UI',
      is_active: true,
    }),
    onSuccess: () => {
      toast.success('Workspace created')
      setShowWorkspaceForm(false)
      setWorkspaceOrgId('')
      setWorkspaceId('')
      void qc.invalidateQueries({ queryKey: ['resilience-workspaces'] })
      void qc.invalidateQueries({ queryKey: ['resilience-isolation'] })
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Operation failed'),
  })
  const { data: isolation } = useQuery({
    queryKey: ['resilience-isolation'],
    enabled: isAdmin && active === 'tenant',
    queryFn: () => get<{ status: string; active_workspaces: number; unique_pairs: number; cross_tenant_collision: boolean }>('/resilience/tenants/isolation-check'),
  })

  // --- Runbook Approvals ---
  const { data: approvals = [] } = useQuery({
    queryKey: ['resilience-approvals'],
    enabled: canRunPlaybooks && active === 'approvals',
    queryFn: () => get<Array<{ id: number; playbook_id: number; alert_id: string; status: string; risk_level: string; requested_by: string | null; created_at: string | null }>>('/resilience/runbook-approvals'),
  })
  const approveMut = useMutation({
    mutationFn: (id: number) => post(`/resilience/runbook-approvals/${id}/approve`, {}),
    onSuccess: () => {
      toast.success('Runbook approved')
      void qc.invalidateQueries({ queryKey: ['resilience-approvals'] })
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Operation failed'),
  })
  const executeMut = useMutation({
    mutationFn: (id: number) => post(`/resilience/runbook-approvals/${id}/execute`, {}),
    onSuccess: () => {
      toast.success('Runbook executed')
      void qc.invalidateQueries({ queryKey: ['resilience-approvals'] })
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Operation failed'),
  })

  // --- DR Drills ---
  const { data: drills = [] } = useQuery({
    queryKey: ['resilience-drills'],
    enabled: isAdmin && active === 'dr',
    queryFn: () => get<Array<{ id: number; target: string; status: string; rpo_target_minutes: number; rto_target_minutes: number; rpo_actual_minutes: number | null; rto_actual_minutes: number | null }>>('/resilience/dr/drills'),
  })
  const createDrillMut = useMutation({
    mutationFn: () => post('/resilience/dr/drills', {
      target: drillTarget.trim() || 'primary-db',
      rpo_target_minutes: drillRpo,
      rto_target_minutes: drillRto,
    }),
    onSuccess: () => {
      toast.success('Drill scheduled')
      setShowDrillForm(false)
      setDrillTarget('')
      setDrillRpo(60)
      setDrillRto(120)
      void qc.invalidateQueries({ queryKey: ['resilience-drills'] })
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Operation failed'),
  })
  const runDrillMut = useMutation({
    mutationFn: (id: number) => post(`/resilience/dr/drills/${id}/run`, {}),
    onSuccess: () => {
      toast.success('Drill run complete')
      void qc.invalidateQueries({ queryKey: ['resilience-drills'] })
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Operation failed'),
  })

  // --- AI Governance ---
  const { data: aiMetrics } = useQuery({
    queryKey: ['resilience-ai-metrics'],
    enabled: active === 'ai',
    queryFn: () => get<{ feedback_count: number; avg_rating: number; hallucination_rate: number; avg_model_confidence: number; guardrail_status: string }>('/resilience/ai-governance/metrics'),
  })
  const feedbackMut = useMutation({
    mutationFn: () => post('/resilience/ai-governance/feedback', {
      alert_id: feedbackAlertId,
      rating: feedbackRating,
      hallucination_flag: feedbackHallucination,
      comments: feedbackComments || undefined,
    }),
    onSuccess: () => {
      toast.success('Feedback submitted')
      setFeedbackAlertId('')
      setFeedbackRating(3)
      setFeedbackHallucination(false)
      setFeedbackComments('')
      void qc.invalidateQueries({ queryKey: ['resilience-ai-metrics'] })
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Operation failed'),
  })

  // --- Source Quality ---
  const { data: sourceQuality } = useQuery({
    queryKey: ['resilience-source-quality'],
    enabled: canReadSourceQuality && active === 'source',
    queryFn: () => get<{ total_sources: number; items: Array<{ source: string; alerts: number; quality_score: number; techniques_detected: number; blind_spots: string[] }> }>('/resilience/mitre/source-quality'),
  })

  const tabs = [
    { id: 'qa', label: 'Detection QA', icon: Beaker },
    { id: 'secrets', label: 'Secret Rotation', icon: KeyRound },
    { id: 'tenant', label: 'Tenant Boundaries', icon: Building2 },
    { id: 'approvals', label: 'Runbook Approvals', icon: ShieldCheck },
    { id: 'dr', label: 'DR Drills', icon: HardDrive },
    { id: 'ai', label: 'AI Governance', icon: BrainCircuit },
    { id: 'source', label: 'Source Quality', icon: Radar },
  ] as const

  return (
    <div className="space-y-5 animate-fade-in">
      <div>
        <h1 className="text-lg font-bold text-foreground">Resilience Control Plane</h1>
        <p className="text-xs text-muted-foreground">Operational resilience controls — detection QA, secret rotation, tenant isolation, runbook approvals, DR drills, AI governance, and source quality monitoring.</p>
      </div>

      <div className="flex flex-wrap gap-2">
        {tabs.map((tab) => {
          const Icon = tab.icon
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActive(tab.id)}
              className={cn('inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs transition-colors', active === tab.id ? 'gradient-primary text-white border-transparent' : 'border-border/50 text-muted-foreground hover:text-foreground')}
            >
              <Icon className="w-3.5 h-3.5" />{tab.label}
            </button>
          )
        })}
      </div>

      {/* Detection QA Tab */}
      {active === 'qa' && (
        <div className="glass-card rounded-xl border border-border/50 p-4 space-y-4">
          <div>
            <h2 className="text-sm font-semibold text-foreground">Detection Replay QA Gate</h2>
            <p className="text-xs text-muted-foreground mt-0.5">Replay historical telemetry against detection rules to validate precision and recall before promotion.</p>
          </div>
          <button
            type="button"
            onClick={() => replayMut.mutate()}
            disabled={replayMut.isPending || !isAdmin}
            className="px-3 py-1.5 rounded-lg bg-primary text-primary-foreground text-sm disabled:opacity-60"
          >
            {replayMut.isPending ? 'Running Replay…' : isAdmin ? 'Run Replay Gate' : 'Admin Required'}
          </button>
          {replays.length === 0 ? (
            <p className="text-xs text-muted-foreground py-4 text-center">No replay runs yet — trigger a replay to validate detection rules.</p>
          ) : (
            <div className="space-y-1">
              <div className="grid grid-cols-4 gap-2 px-2 py-1 text-xs font-medium text-muted-foreground">
                <span>ID</span>
                <span>Precision</span>
                <span>Recall</span>
                <span>Gate</span>
              </div>
              {replays.map((r) => (
                <div key={r.id} className="grid grid-cols-4 gap-2 text-xs border border-border/40 rounded px-2 py-1.5 items-center">
                  <span className="font-mono text-muted-foreground truncate">{r.id}</span>
                  <span>{r.precision_pct}%</span>
                  <span>{r.recall_pct}%</span>
                  <span className={r.gate_passed ? 'text-emerald-400 font-medium' : 'text-red-400 font-medium'}>{r.gate_passed ? 'PASS' : 'FAIL'}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Secret Rotation Tab */}
      {active === 'secrets' && (
        <div className="glass-card rounded-xl border border-border/50 p-4 space-y-3">
          {!isAdmin && (
            <p className="text-xs text-amber-400">Admin permission is required for secret rotation controls.</p>
          )}
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-semibold text-foreground">Rotation Compliance</p>
              <p className="text-xs text-muted-foreground">Total: {secretCheck?.total ?? 0} · Overdue: {secretCheck?.overdue ?? 0}</p>
            </div>
            <button
              type="button"
              onClick={() => setShowSecretForm((v) => !v)}
              disabled={!isAdmin}
              className="px-3 py-1.5 rounded-lg border border-border/50 text-xs text-muted-foreground hover:text-foreground"
            >
              {showSecretForm ? 'Cancel' : 'Add Policy'}
            </button>
          </div>

          {showSecretForm && (
            <div className="rounded-lg border border-border/40 bg-muted/20 p-3 space-y-2">
              <p className="text-xs font-medium text-foreground">New Secret Rotation Policy</p>
              <input
                type="text"
                value={secretName}
                onChange={(e) => setSecretName(e.target.value)}
                placeholder="Secret name"
                className="w-full px-2 py-1.5 rounded border border-border bg-background text-foreground text-xs"
              />
              <input
                type="text"
                value={secretProvider}
                onChange={(e) => setSecretProvider(e.target.value)}
                placeholder="Provider (e.g. env, vault)"
                className="w-full px-2 py-1.5 rounded border border-border bg-background text-foreground text-xs"
              />
              <div className="flex gap-2">
                <div className="flex-1">
                  <label className="text-xs text-muted-foreground">Rotation days</label>
                  <input
                    type="number"
                    min={1}
                    value={secretRotationDays}
                    onChange={(e) => setSecretRotationDays(Number(e.target.value) || 90)}
                    className="w-full px-2 py-1.5 rounded border border-border bg-background text-foreground text-xs"
                  />
                </div>
                <div className="flex-1">
                  <label className="text-xs text-muted-foreground">Owner (optional)</label>
                  <input
                    type="text"
                    value={secretOwner}
                    onChange={(e) => setSecretOwner(e.target.value)}
                    placeholder="team@example.com"
                    className="w-full px-2 py-1.5 rounded border border-border bg-background text-foreground text-xs"
                  />
                </div>
              </div>
              <button
                type="button"
                onClick={() => addSecretMut.mutate()}
                disabled={addSecretMut.isPending || !secretName.trim()}
                className="px-3 py-1 rounded border border-blue-500/30 text-blue-400 text-xs disabled:opacity-50"
              >
                {addSecretMut.isPending ? 'Saving…' : 'Save Policy'}
              </button>
            </div>
          )}

          {secretPolicies.length === 0 ? (
            <p className="text-xs text-muted-foreground py-4 text-center">No secret rotation policies configured.</p>
          ) : (
            <div className="space-y-1">
              {secretPolicies.map((item) => {
                const checkItem = secretCheck?.items.find((c) => c.secret_name === item.secret_name)
                return (
                  <div key={item.id} className="text-xs flex items-center justify-between border border-border/40 rounded px-2 py-1.5">
                    <span className="font-mono">{item.secret_name}</span>
                    <span className="text-muted-foreground">{item.provider} · {item.rotation_days}d</span>
                    <span className="text-muted-foreground">{checkItem?.days_since_rotation == null ? 'never rotated' : `${checkItem.days_since_rotation}d ago`}</span>
                    <span className={checkItem?.overdue ? 'text-red-400' : 'text-emerald-400'}>{checkItem?.overdue ? 'overdue' : 'ok'}</span>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}

      {/* Tenant Boundaries Tab */}
      {active === 'tenant' && (
        <div className="glass-card rounded-xl border border-border/50 p-4 space-y-3">
          {!isAdmin && (
            <p className="text-xs text-amber-400">Admin permission is required for tenant boundary controls.</p>
          )}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <p className="text-sm font-semibold text-foreground">Tenant Isolation</p>
              {isolation && (
                <span className={cn('text-xs px-2 py-0.5 rounded-full font-medium', isolation.cross_tenant_collision ? 'bg-amber-500/20 text-amber-400' : 'bg-emerald-500/20 text-emerald-400')}>
                  {isolation.cross_tenant_collision ? 'Collision Detected' : 'Isolated'}
                </span>
              )}
            </div>
            <button
              type="button"
              onClick={() => setShowWorkspaceForm((v) => !v)}
              disabled={!isAdmin}
              className="px-3 py-1.5 rounded-lg border border-border/50 text-xs text-muted-foreground hover:text-foreground"
            >
              {showWorkspaceForm ? 'Cancel' : 'Add Workspace'}
            </button>
          </div>

          <p className="text-xs text-muted-foreground">Status: {isolation?.status ?? 'unknown'} · Active workspaces: {isolation?.active_workspaces ?? 0}</p>

          {showWorkspaceForm && (
            <div className="rounded-lg border border-border/40 bg-muted/20 p-3 space-y-2">
              <p className="text-xs font-medium text-foreground">New Workspace</p>
              <input
                type="text"
                value={workspaceOrgId}
                onChange={(e) => setWorkspaceOrgId(e.target.value)}
                placeholder="Org ID"
                className="w-full px-2 py-1.5 rounded border border-border bg-background text-foreground text-xs"
              />
              <input
                type="text"
                value={workspaceId}
                onChange={(e) => setWorkspaceId(e.target.value)}
                placeholder="Workspace ID"
                className="w-full px-2 py-1.5 rounded border border-border bg-background text-foreground text-xs"
              />
              <button
                type="button"
                onClick={() => workspaceMut.mutate()}
                disabled={workspaceMut.isPending || !workspaceOrgId.trim() || !workspaceId.trim()}
                className="px-3 py-1 rounded border border-blue-500/30 text-blue-400 text-xs disabled:opacity-50"
              >
                {workspaceMut.isPending ? 'Creating…' : 'Create Workspace'}
              </button>
            </div>
          )}

          {workspaces.length === 0 ? (
            <p className="text-xs text-muted-foreground py-4 text-center">No workspaces configured.</p>
          ) : (
            <div className="space-y-1">
              {workspaces.map((w) => (
                <div key={w.id} className="text-xs border border-border/40 rounded px-2 py-1.5 flex items-center justify-between">
                  <span className="font-mono">{w.org_id} / {w.workspace_id}</span>
                  <span className={w.is_active ? 'text-emerald-400' : 'text-muted-foreground'}>{w.is_active ? 'active' : 'inactive'}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Runbook Approvals Tab */}
      {active === 'approvals' && (
        <div className="glass-card rounded-xl border border-border/50 p-4 space-y-2">
          {!canRunPlaybooks && (
            <p className="text-xs text-amber-400">Senior Analyst or Admin permission is required for runbook approvals.</p>
          )}
          {approvals.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 gap-2 text-muted-foreground">
              <CheckCircle2 className="w-8 h-8 text-emerald-500/60" />
              <p className="text-xs">No pending approvals.</p>
            </div>
          ) : (
            approvals.map((a) => {
              const riskColor = a.risk_level === 'high' ? 'bg-red-500/20 text-red-400' : a.risk_level === 'medium' ? 'bg-amber-500/20 text-amber-400' : 'bg-emerald-500/20 text-emerald-400'
              const createdAt = a.created_at ? new Date(a.created_at).toLocaleString() : '—'
              return (
                <div key={a.id} className="text-xs border border-border/40 rounded p-3 space-y-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-medium text-foreground">#{a.id}</span>
                    <span className="text-muted-foreground">PB {a.playbook_id}</span>
                    <span className="font-mono text-muted-foreground">{a.alert_id}</span>
                    {a.risk_level && (
                      <span className={cn('px-1.5 py-0.5 rounded-full text-xs font-medium capitalize', riskColor)}>{a.risk_level}</span>
                    )}
                    <span className="ml-auto text-muted-foreground capitalize">{a.status}</span>
                  </div>
                  <div className="flex items-center gap-4 text-muted-foreground">
                    {a.requested_by && <span>Requested by: {a.requested_by}</span>}
                    <span>{createdAt}</span>
                  </div>
                  {isAdmin && (
                    <div className="flex gap-2">
                      {a.status === 'pending' && (
                        <button
                          type="button"
                          onClick={() => approveMut.mutate(a.id)}
                          disabled={approveMut.isPending}
                          className="px-2 py-0.5 rounded border border-emerald-500/30 text-emerald-400 disabled:opacity-50"
                        >
                          Approve
                        </button>
                      )}
                      {a.status === 'approved' && (
                        <button
                          type="button"
                          onClick={() => executeMut.mutate(a.id)}
                          disabled={executeMut.isPending}
                          className="px-2 py-0.5 rounded border border-blue-500/30 text-blue-400 disabled:opacity-50"
                        >
                          Execute
                        </button>
                      )}
                    </div>
                  )}
                </div>
              )
            })
          )}
        </div>
      )}

      {/* DR Drills Tab */}
      {active === 'dr' && (
        <div className="glass-card rounded-xl border border-border/50 p-4 space-y-3">
          {!isAdmin && (
            <p className="text-xs text-amber-400">Admin permission is required for disaster recovery drills.</p>
          )}
          <div className="flex items-center justify-between">
            <p className="text-sm font-semibold text-foreground">Disaster Recovery Drills</p>
            <button
              type="button"
              onClick={() => setShowDrillForm((v) => !v)}
              disabled={!isAdmin}
              className="px-3 py-1.5 rounded-lg border border-border/50 text-xs text-muted-foreground hover:text-foreground"
            >
              {showDrillForm ? 'Cancel' : 'Schedule Drill'}
            </button>
          </div>

          {showDrillForm && (
            <div className="rounded-lg border border-border/40 bg-muted/20 p-3 space-y-2">
              <p className="text-xs font-medium text-foreground">New Drill</p>
              <input
                type="text"
                value={drillTarget}
                onChange={(e) => setDrillTarget(e.target.value)}
                placeholder="Target (e.g. primary-db)"
                className="w-full px-2 py-1.5 rounded border border-border bg-background text-foreground text-xs"
              />
              <div className="flex gap-2">
                <div className="flex-1">
                  <label className="text-xs text-muted-foreground">RPO target (min)</label>
                  <input
                    type="number"
                    min={1}
                    value={drillRpo}
                    onChange={(e) => setDrillRpo(Number(e.target.value) || 60)}
                    className="w-full px-2 py-1.5 rounded border border-border bg-background text-foreground text-xs"
                  />
                </div>
                <div className="flex-1">
                  <label className="text-xs text-muted-foreground">RTO target (min)</label>
                  <input
                    type="number"
                    min={1}
                    value={drillRto}
                    onChange={(e) => setDrillRto(Number(e.target.value) || 120)}
                    className="w-full px-2 py-1.5 rounded border border-border bg-background text-foreground text-xs"
                  />
                </div>
              </div>
              <button
                type="button"
                onClick={() => createDrillMut.mutate()}
                disabled={createDrillMut.isPending}
                className="px-3 py-1 rounded border border-blue-500/30 text-blue-400 text-xs disabled:opacity-50"
              >
                {createDrillMut.isPending ? 'Scheduling…' : 'Schedule'}
              </button>
            </div>
          )}

          {drills.length === 0 ? (
            <p className="text-xs text-muted-foreground py-4 text-center">No restore drills scheduled.</p>
          ) : (
            <div className="space-y-1">
              {drills.map((d) => {
                const passBadge = d.status === 'passed'
                  ? 'bg-emerald-500/20 text-emerald-400'
                  : d.status === 'failed'
                    ? 'bg-red-500/20 text-red-400'
                    : 'bg-muted/40 text-muted-foreground'
                return (
                  <div key={d.id} className="text-xs border border-border/40 rounded p-2 flex items-center gap-2 flex-wrap">
                    <span className="font-medium">#{d.id}</span>
                    <span>{d.target}</span>
                    <span className={cn('px-1.5 py-0.5 rounded-full text-xs font-medium capitalize', passBadge)}>{d.status}</span>
                    <span className="text-muted-foreground ml-auto">RPO {d.rpo_actual_minutes ?? '—'}/{d.rpo_target_minutes}m</span>
                    <span className="text-muted-foreground">RTO {d.rto_actual_minutes ?? '—'}/{d.rto_target_minutes}m</span>
                    {d.status === 'scheduled' && (
                      <button
                        type="button"
                        onClick={() => runDrillMut.mutate(d.id)}
                        disabled={runDrillMut.isPending}
                        className="px-2 py-0.5 rounded border border-blue-500/30 text-blue-400 disabled:opacity-50"
                      >
                        Run
                      </button>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}

      {/* AI Governance Tab */}
      {active === 'ai' && (
        <div className="glass-card rounded-xl border border-border/50 p-4 space-y-4">
          <p className="text-sm font-semibold text-foreground">AI Model Governance</p>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {/* Feedback Count */}
            <div className="rounded-lg border border-border/40 bg-muted/20 p-3 text-center">
              <p className="text-2xl font-bold text-foreground">{aiMetrics?.feedback_count ?? 0}</p>
              <p className="text-xs text-muted-foreground mt-1">Feedback Entries</p>
            </div>
            {/* Avg Rating */}
            <div className="rounded-lg border border-border/40 bg-muted/20 p-3 text-center">
              <div className="flex items-center justify-center gap-1">
                <p className="text-2xl font-bold text-foreground">{(aiMetrics?.avg_rating ?? 0).toFixed(1)}</p>
                <Star className="w-4 h-4 text-amber-400 fill-amber-400" />
              </div>
              <p className="text-xs text-muted-foreground mt-1">Avg Rating</p>
            </div>
            {/* Hallucination Rate */}
            {(() => {
              const halRate = (aiMetrics?.hallucination_rate ?? 0) * 100
              return (
                <div className="rounded-lg border border-border/40 bg-muted/20 p-3 text-center">
                  <p className={cn('text-2xl font-bold', halRate > 20 ? 'text-red-400' : 'text-foreground')}>{halRate.toFixed(1)}%</p>
                  <p className="text-xs text-muted-foreground mt-1">Hallucination Rate</p>
                </div>
              )
            })()}
            {/* Guardrail Status */}
            <div className="rounded-lg border border-border/40 bg-muted/20 p-3 text-center">
              <span className={cn('inline-block px-2 py-0.5 rounded-full text-xs font-medium capitalize mt-1', aiMetrics?.guardrail_status === 'healthy' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400')}>
                {aiMetrics?.guardrail_status ?? 'unknown'}
              </span>
              <p className="text-xs text-muted-foreground mt-1">Guardrail Status</p>
            </div>
          </div>

          <div className="rounded-lg border border-border/40 bg-muted/20 p-3 space-y-2">
            <p className="text-xs font-medium text-foreground">Submit Analyst Feedback</p>
            <input
              type="text"
              value={feedbackAlertId}
              onChange={(e) => setFeedbackAlertId(e.target.value)}
              placeholder="Alert ID"
              className="w-full px-2 py-1.5 rounded border border-border bg-background text-foreground text-xs"
            />
            <div className="flex items-center gap-2">
              <label className="text-xs text-muted-foreground">Rating</label>
              <input
                type="number"
                min={1}
                max={5}
                value={feedbackRating}
                onChange={(e) => setFeedbackRating(Number(e.target.value || 3))}
                className="w-20 px-2 py-1 rounded border border-border bg-background text-foreground text-xs"
              />
              <label className="flex items-center gap-1 text-xs text-muted-foreground">
                <input type="checkbox" checked={feedbackHallucination} onChange={(e) => setFeedbackHallucination(e.target.checked)} />
                Hallucination
              </label>
            </div>
            <input
              type="text"
              value={feedbackComments}
              onChange={(e) => setFeedbackComments(e.target.value)}
              placeholder="Comments"
              className="w-full px-2 py-1.5 rounded border border-border bg-background text-foreground text-xs"
            />
            <button
              type="button"
              onClick={() => feedbackMut.mutate()}
              disabled={feedbackMut.isPending || !feedbackAlertId.trim() || !canWriteAIFeedback}
              className="px-3 py-1 rounded border border-blue-500/30 text-blue-400 text-xs disabled:opacity-50"
            >
              {feedbackMut.isPending ? 'Submitting…' : canWriteAIFeedback ? 'Submit Feedback' : 'Write Access Required'}
            </button>
          </div>
        </div>
      )}

      {/* Source Quality Tab */}
      {active === 'source' && (
        <div className="glass-card rounded-xl border border-border/50 p-4 space-y-3">
          {!canReadSourceQuality && (
            <p className="text-xs text-amber-400">Senior Analyst or Admin permission is required for source quality insights.</p>
          )}
          <p className="text-xs text-muted-foreground">Sources analyzed: {sourceQuality?.total_sources ?? 0}</p>
          {(sourceQuality?.items ?? []).length === 0 ? (
            <p className="text-xs text-muted-foreground py-4 text-center">No source quality data available.</p>
          ) : (
            (sourceQuality?.items ?? []).map((s) => (
              <div key={s.source} className="text-xs border border-border/40 rounded p-3 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-medium text-foreground">{s.source}</span>
                  <span className="text-blue-400 font-medium">{s.quality_score}%</span>
                </div>
                {/* Quality score progress bar */}
                <div className="w-full bg-muted/40 rounded-full h-1.5">
                  <div
                    className={cn('h-1.5 rounded-full', s.quality_score >= 70 ? 'bg-emerald-500' : s.quality_score >= 40 ? 'bg-amber-500' : 'bg-red-500')}
                    style={{ width: `${Math.min(100, s.quality_score)}%` }}
                  />
                </div>
                <p className="text-muted-foreground">Alerts: {s.alerts} · Techniques: {s.techniques_detected}</p>
                {s.blind_spots.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {s.blind_spots.map((bs) => (
                      <span key={bs} className="px-1.5 py-0.5 rounded bg-muted/40 text-muted-foreground text-xs">{bs}</span>
                    ))}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}
    </div>
  )
}
