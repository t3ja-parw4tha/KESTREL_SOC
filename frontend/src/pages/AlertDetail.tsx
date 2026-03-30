import { useMemo, useState, useEffect, useCallback, useRef } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import { useAlert } from '@/hooks/useAlerts'
import { useAuth } from '@/security/AuthContext'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { triggerAI, getTimeline, updateAlertStatus, addComment, assignAlert, pickUpAlert, getAnalysts } from '@/api/alerts'
import { getAIChatHistory, sendAIChatMessage } from '@/api/aiAssistant'
import {
  addAlertEvidenceUrl,
  downloadEvidenceFile,
  listAlertEvidence,
  uploadAlertEvidenceFile,
  type EvidenceItem,
} from '@/api/evidence'
import type { TimelineItem } from '@/api/alerts'
import { incidentsApi } from '@/api/incidents'
import { get } from '@/api/client'
import { AlertBadge } from '@/components/alerts/AlertBadge'
import { MitreTags } from '@/components/alerts/MitreTags'
import { Spinner } from '@/components/ui/Spinner'
import { formatTimelineTimestamp } from '@/utils/time'
import { getRiskScoreColor } from '@/utils/severity'
import { ErrorState } from '@/components/ui/ErrorState'
import { SpinnerOverlay } from '@/components/ui/Spinner'
import {
  Sparkles, CheckCircle2, MessageSquare, FileJson, Copy,
  ChevronDown, ChevronRight, Server, User, Globe, Activity, Pencil,
  Cpu, UserPlus, X as XIcon, Clock, FileText, Bold, Italic, List,
  Paperclip, Image, Trash2, Target, AlertTriangle, Search,
  Upload, Link2, SendHorizontal, Bot, Download,
} from 'lucide-react'
import { cn } from '@/utils/cn'
import { toast } from 'sonner'
import type { Alert, Enrichment } from '@/types/alert'
import { EntityPivotPanel, type PivotEntity } from '@/components/ui/EntityPivotPanel'

// ── Observable helpers ────────────────────────────────────────────────────────
type ObservableType = 'ip' | 'user' | 'asset' | 'indicator'
interface ObservableItem { value: string; type: ObservableType; label?: string }

const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/
const IPV6_RE = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,7}:$|^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$/
function inferType(v: string): 'ip' | 'indicator' {
  return IPV4_RE.test(v.trim()) || IPV6_RE.test(v.trim()) ? 'ip' : 'indicator'
}
function collectObservables(alert: Alert): ObservableItem[] {
  const seen = new Set<string>()
  const items: ObservableItem[] = []
  const add = (value: string | null | undefined, type: ObservableType, label?: string) => {
    if (!value) return
    const v = String(value).trim()
    if (!v || seen.has(v)) return
    seen.add(v)
    items.push({ value: v, type, label })
  }
  add(alert.source_ip, 'ip', 'Source IP')
  add(alert.dest_ip, 'ip', 'Destination IP')
  add(alert.asset_id, 'asset', 'Asset')
  add(alert.user_id, 'user', 'User')
  const enr: Enrichment | null | undefined = alert.enrichment
  if (enr) {
    const iocGroup = enr.iocs ?? { ips: [], domains: [], hashes: [], cves: [] }
    ;[...iocGroup.ips, ...iocGroup.domains, ...iocGroup.hashes, ...iocGroup.cves].forEach((s) => add(s, inferType(s)))
    ;(enr.vt_results ?? []).forEach((r) => add(r.indicator, inferType(r.indicator)))
    ;(enr.abuse_results ?? []).forEach((r) => add(r.ip, 'ip'))
    ;(enr.feed_matches ?? []).forEach((m) => add(m.indicator, inferType(m.indicator)))
  }
  return items
}
function pillColor(type: ObservableType) {
  if (type === 'ip') return 'bg-blue-500/15 text-blue-400 border-blue-500/30 hover:bg-blue-500/25'
  if (type === 'user') return 'bg-purple-500/15 text-purple-400 border-purple-500/30 hover:bg-purple-500/25'
  if (type === 'asset') return 'bg-muted text-muted-foreground border-border hover:bg-muted/80'
  return 'bg-amber-500/15 text-amber-400 border-amber-500/30 hover:bg-amber-500/25'
}
function ObservablePill({ item, onCopy, onPivot }: { item: ObservableItem; onCopy: () => void; onPivot?: () => void }) {
  return (
    <span
      className={cn('inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors group', onPivot && 'cursor-pointer', pillColor(item.type))}
      title={item.label ? `${item.label}: ${item.value}${onPivot ? ' — click to pivot' : ''}` : item.value}
      onClick={onPivot}
      role={onPivot ? 'button' : undefined}
      tabIndex={onPivot ? 0 : undefined}
      onKeyDown={onPivot ? (e) => { if (e.key === 'Enter') onPivot() } : undefined}
    >
      <span className="truncate max-w-[200px]">{item.value}</span>
      <button type="button" onClick={(e) => { e.preventDefault(); e.stopPropagation(); navigator.clipboard.writeText(item.value); onCopy() }}
        className="opacity-0 group-hover:opacity-100 shrink-0 p-0.5 rounded hover:bg-black/10">
        <Copy className="w-3 h-3" />
      </button>
    </span>
  )
}

// ── Entity field — never just a dash ─────────────────────────────────────────
function EntityField({ icon: Icon, label, value, mono = false }: {
  icon: typeof Server; label: string; value: string | null | undefined; mono?: boolean
}) {
  return (
    <div className="flex items-center justify-between py-1.5 border-b border-border/20 last:border-0">
      <span className="flex items-center gap-1.5 text-xs text-muted-foreground shrink-0">
        <Icon className="w-3.5 h-3.5 shrink-0" />{label}
      </span>
      {value ? (
        <span className={cn('text-xs text-foreground max-w-[55%] truncate text-right', mono && 'font-mono bg-muted/40 px-2 py-0.5 rounded border border-border/40')} title={value}>
          {value}
        </span>
      ) : (
        <span className="text-[10px] px-2 py-0.5 rounded-full border border-border/30 bg-muted/20 text-muted-foreground/60 italic">
          not resolved
        </span>
      )}
    </div>
  )
}

// ── Alert-specific contextual actions (fallback when AI hasn't run) ───────────
function buildContextualActions(alert: Alert): string[] {
  const actions: string[] = []
  if (alert.source_ip) actions.push(`Check threat intel feeds for ${alert.source_ip} — look for prior malicious activity or known C2`)
  if (alert.dest_ip)   actions.push(`Verify ${alert.dest_ip} is an expected destination — check firewall logs for connection history`)
  if (alert.asset_id)  actions.push(`Check EDR on ${alert.asset_id} for persistence indicators, unusual processes, and lateral movement artifacts`)
  if (alert.user_id)   actions.push(`Audit recent authentication events for ${alert.user_id} — look for logins outside normal hours or geo`)
  const firstMitre = (alert.mitre_techniques ?? [])[0]
  if (firstMitre) {
    actions.push(`Review ATT&CK playbook for ${firstMitre.technique_id} (${firstMitre.technique_name}) — apply relevant detection and containment steps`)
  }
  if (alert.category)  actions.push(`Search SIEM for similar ${alert.category} events in the past 48h on other hosts`)
  if (alert.source)    actions.push(`Verify ${alert.source} rule logic hasn't triggered false positives on similar traffic recently`)
  return actions.slice(0, 5)
}

// ── Modal overlay ─────────────────────────────────────────────────────────────
function Modal({ open, onClose, title, description, children, footer, wide }: {
  open: boolean; onClose: () => void; title: string; description?: string
  children: React.ReactNode; footer: React.ReactNode; wide?: boolean
}) {
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className={cn('relative z-10 w-full glass-card rounded-xl border border-border/60 p-6 shadow-2xl animate-fade-in', wide ? 'max-w-lg' : 'max-w-md')}>
        <div className="mb-4">
          <h2 className="text-sm font-semibold text-foreground">{title}</h2>
          {description && <p className="text-xs text-muted-foreground mt-1">{description}</p>}
        </div>
        <div className="space-y-4">{children}</div>
        <div className="flex items-center justify-end gap-2 mt-5 pt-4 border-t border-border/40">{footer}</div>
      </div>
    </div>
  )
}

// ── Tabs ──────────────────────────────────────────────────────────────────────
const TABS = [
  { id: 'triage',        label: 'Triage',        icon: Activity },
  { id: 'investigation', label: 'Investigation',  icon: Search },
  { id: 'timeline',      label: 'Timeline & Raw', icon: MessageSquare },
] as const
type TabId = (typeof TABS)[number]['id']

// ── Assign control ────────────────────────────────────────────────────────────
function AssignControl({ alertId, currentAssignee, onAssigned }: {
  alertId: string; currentAssignee: string | null; onAssigned: () => void
}) {
  const { user } = useAuth()
  const [panelOpen, setPanelOpen] = useState(false)
  const [selectedUsername, setSelectedUsername] = useState('')
  const [comment, setComment] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const canPickUp = user?.role !== 'viewer'
  const canAssign = user?.role === 'senior_analyst' || user?.role === 'admin'
  const isAssignedToMe = currentAssignee === user?.username
  const isUnassigned = !currentAssignee

  const { data: analystsData } = useQuery({
    queryKey: ['analysts'],
    queryFn: getAnalysts,
    enabled: canAssign,
    staleTime: 5 * 60 * 1000,
  })
  const analysts = analystsData?.analysts ?? []

  const isPickUpViaDropdown = selectedUsername === (user?.username ?? '') && isUnassigned
  const isDropOwnViaDropdown = selectedUsername === '' && isAssignedToMe
  const commentRequired = panelOpen && selectedUsername !== (currentAssignee ?? '') && !isPickUpViaDropdown && !isDropOwnViaDropdown

  const openPanel = () => { setSelectedUsername(currentAssignee ?? ''); setComment(''); setError(''); setPanelOpen(true) }
  const closePanel = () => { setPanelOpen(false); setComment(''); setError('') }

  const handlePickUp = async () => {
    setLoading(true); setError('')
    try { await pickUpAlert(alertId); onAssigned() }
    catch (e: unknown) { setError(e instanceof Error ? e.message : 'Failed to pick up') }
    finally { setLoading(false) }
  }
  const handleDrop = async () => {
    setLoading(true); setError('')
    try { await assignAlert(alertId, null); onAssigned() }
    catch { setError('Failed to drop') }
    finally { setLoading(false) }
  }
  const handleAssign = async () => {
    if (commentRequired && !comment.trim()) { setError('A reason is required when reassigning'); return }
    setLoading(true); setError('')
    try {
      await assignAlert(alertId, selectedUsername || null, comment.trim() || undefined)
      closePanel(); onAssigned()
    } catch (e: unknown) { setError(e instanceof Error ? e.message : 'Failed to assign') }
    finally { setLoading(false) }
  }

  return (
    <div className="relative">
      <div className="flex items-center gap-1.5 flex-wrap">
        {currentAssignee && (
          <span className={cn('inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border', isAssignedToMe ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400' : 'border-blue-500/30 bg-blue-500/10 text-blue-400')}>
            <User className="w-3 h-3 shrink-0" />
            {isAssignedToMe ? `${currentAssignee} (you)` : currentAssignee}
          </span>
        )}
        {isUnassigned && canPickUp && !panelOpen && (
          <button type="button" onClick={handlePickUp} disabled={loading}
            className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium border border-blue-500/30 bg-blue-500/10 text-blue-400 hover:bg-blue-500/20 hover:border-blue-500/50 disabled:opacity-40 transition-all">
            {loading ? <span className="w-3 h-3 rounded-full border border-blue-400 border-t-transparent animate-spin" /> : <UserPlus className="w-3 h-3" />}
            Pick up
          </button>
        )}
        {isAssignedToMe && canPickUp && !panelOpen && (
          <button type="button" onClick={handleDrop} disabled={loading} title="Unassign yourself"
            className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium border border-border text-muted-foreground hover:border-red-500/30 hover:bg-red-500/10 hover:text-red-400 disabled:opacity-40 transition-all">
            <XIcon className="w-3 h-3" /> Drop
          </button>
        )}
        {canAssign && (
          <button type="button" onClick={panelOpen ? closePanel : openPanel}
            className={cn('inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium border transition-all', panelOpen ? 'border-blue-500/50 bg-blue-600/15 text-blue-300' : 'border-border text-muted-foreground hover:text-foreground hover:border-muted-foreground/50 hover:bg-muted/40')}>
            <UserPlus className="w-3 h-3" />
            {panelOpen ? 'Cancel' : isUnassigned ? 'Assign' : 'Reassign'}
          </button>
        )}
      </div>
      {error && !panelOpen && <p className="text-xs text-red-400 mt-1.5">{error}</p>}
      {panelOpen && canAssign && (
        <div className="mt-2 rounded-xl border border-border bg-card p-4 space-y-3 w-72 animate-slide-up" style={{ boxShadow: 'var(--shadow-elevated)' }}>
          <div>
            <label className="block text-[11px] font-semibold text-muted-foreground uppercase tracking-widest mb-1.5">Assign to</label>
            <select value={selectedUsername} onChange={(e) => { setSelectedUsername(e.target.value); setError('') }}
              className="w-full px-3 py-2 rounded-lg border border-border bg-background text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500 transition-all">
              <option value="">— Unassigned —</option>
              {analysts.map((a) => <option key={a.id} value={a.username}>{a.username} ({a.role.replace(/_/g, ' ')})</option>)}
            </select>
          </div>
          {commentRequired && (
            <div>
              <label className="block text-[11px] font-semibold text-muted-foreground uppercase tracking-widest mb-1.5">Reason <span className="text-red-400">*</span></label>
              <textarea value={comment} onChange={(e) => { setComment(e.target.value); setError('') }}
                placeholder="Why are you reassigning this alert?" rows={2}
                className="w-full px-3 py-2 rounded-lg border border-border bg-background text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500 transition-all resize-none" />
            </div>
          )}
          {error && <p className="text-xs text-red-400">{error}</p>}
          <div className="flex gap-2">
            <button type="button" onClick={handleAssign} disabled={loading || (commentRequired && !comment.trim())}
              className="flex-1 py-1.5 rounded-lg gradient-primary text-white text-xs font-semibold hover:opacity-90 disabled:opacity-40 transition-all active:scale-[0.98]">
              {loading ? 'Saving...' : 'Save assignment'}
            </button>
            <button type="button" onClick={closePanel}
              className="px-4 py-1.5 rounded-lg border border-border text-xs text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-all">
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────
export function AlertDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [tab, setTab] = useState<TabId>('triage')
  const [statusUpdating, setStatusUpdating] = useState(false)
  const [aiLoading, setAiLoading] = useState(false)
  const [aiError, setAiError] = useState('')
  const [comment, setComment] = useState('')
  const [commentLoading, setCommentLoading] = useState(false)
  const [whyExpanded, setWhyExpanded] = useState(false)
  const [rawExpanded, setRawExpanded] = useState(false)
  const [pivotEntity, setPivotEntity] = useState<PivotEntity | null>(null)

  // Dialogs
  const [escalateOpen, setEscalateOpen] = useState(false)
  const [escalateReason, setEscalateReason] = useState('')
  const [escalateComment, setEscalateComment] = useState('')
  const [escalateLoading, setEscalateLoading] = useState(false)

  const [incidentOpen, setIncidentOpen] = useState(false)
  const [incidentTitle, setIncidentTitle] = useState('')
  const [incidentCreating, setIncidentCreating] = useState(false)

  const [noteOpen, setNoteOpen] = useState(false)
  const [noteText, setNoteText] = useState('')
  const [noteAttachments, setNoteAttachments] = useState<{ name: string; type: string; size: string }[]>([])
  const [noteSaving, setNoteSaving] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const evidenceFileInputRef = useRef<HTMLInputElement>(null)
  const [evidenceUrl, setEvidenceUrl] = useState('')
  const [evidenceNotes, setEvidenceNotes] = useState('')
  const [evidenceBusy, setEvidenceBusy] = useState(false)
  const [chatInput, setChatInput] = useState('')
  const [chatBusy, setChatBusy] = useState(false)

  const isViewer = user?.role === 'viewer'

  const { data: alert, isLoading, isError, refetch } = useAlert(id)
  const { data: timelineData } = useQuery({
    queryKey: ['alert', 'timeline', id],
    queryFn: () => getTimeline(id!),
    enabled: !!id,
  })
  const timelineItems = timelineData?.items ?? []
  const { data: alertAttribution } = useQuery({
    queryKey: ['threat-attribution', 'alert', id],
    queryFn: () =>
      get<{
        candidates: Array<{ actor: string; confidence: number; matched_ttps: string[] }>
        techniques: string[]
      }>(`/threat-attribution/alerts/${id}`),
    enabled: !!id,
  })
  const { data: evidenceData, refetch: refetchEvidence, isLoading: evidenceLoading } = useQuery({
    queryKey: ['alert', 'evidence', id],
    queryFn: () => listAlertEvidence(id!),
    enabled: !!id,
  })
  const evidenceItems = evidenceData ?? []

  const { data: chatData, refetch: refetchChat, isLoading: chatLoading } = useQuery({
    queryKey: ['alert', 'assistant-chat', id],
    queryFn: () => getAIChatHistory('alert', id!),
    enabled: !!id,
  })
  const chatItems = chatData ?? []
  const timelineCount = timelineItems.length
  const analystNotes = timelineItems.filter((e) => e.action === 'comment')

  const observables = useMemo(() => (alert ? collectObservables(alert) : []), [alert])

  const handleRunAI = useCallback(async () => {
    if (!id) return
    setAiLoading(true); setAiError('')
    try { await triggerAI(id); await refetch() }
    catch { setAiError('AI analysis failed. Check Settings to configure an AI provider.') }
    finally { setAiLoading(false) }
  }, [id, refetch])

  // Auto-trigger AI on Triage tab load if no summary yet
  useEffect(() => {
    if (tab === 'triage' && !isViewer && alert && !alert.ai_summary && !aiLoading && !aiError) {
      handleRunAI()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, alert])

  if (isError) return <ErrorState title="Alert not found" message="The alert may have been removed." onRetry={() => refetch()} />
  if (isLoading || !alert) return <SpinnerOverlay />

  const decision = alert.decision
  const decisionActions = decision?.recommended_actions?.items ?? []
  const explanation = decision?.explanation?.items ?? []
  const enrichment = alert.enrichment

  // Recommended actions: prefer AI-specific ones, fall back to contextual
  const aiRemediationActions: string[] = Array.isArray((alert.ai_remediation as { actions?: string[] })?.actions)
    ? (alert.ai_remediation as { actions: string[] }).actions
    : []
  const aiNextSteps: string[] = Array.isArray((alert.ai_next_steps as { recommendations?: string[] })?.recommendations)
    ? (alert.ai_next_steps as { recommendations: string[] }).recommendations
    : []
  const primaryActions = aiRemediationActions.length > 0
    ? aiRemediationActions
    : aiNextSteps.length > 0
      ? aiNextSteps
      : decisionActions.length > 0
        ? decisionActions
        : buildContextualActions(alert)

  const handleStatusChange = async (newStatus: Alert['status']) => {
    if (!id) return
    setStatusUpdating(true)
    try { await updateAlertStatus(id, newStatus); refetch() }
    finally { setStatusUpdating(false) }
  }

  const handleAddComment = async () => {
    if (!id || !comment.trim()) return
    setCommentLoading(true)
    try {
      await addComment(id, comment.trim())
      setComment('')
      refetch()
      queryClient.invalidateQueries({ queryKey: ['alert', 'timeline', id] })
    } finally { setCommentLoading(false) }
  }

  // Dialog handlers
  const handleEscalate = async () => {
    if (!escalateReason.trim()) { toast.error('Please select a reason'); return }
    if (!escalateComment.trim()) { toast.error('Please provide context for the escalation'); return }
    if (!id) return
    setEscalateLoading(true)
    try {
      const label = ESCALATE_REASONS.find((r) => r.value === escalateReason)?.label ?? escalateReason
      await addComment(id, `[ESCALATION] ${label}: ${escalateComment}`)
      await queryClient.invalidateQueries({ queryKey: ['alert', 'timeline', id] })
      toast.warning('Alert escalated and logged to timeline')
      setEscalateOpen(false); setEscalateReason(''); setEscalateComment('')
    } catch { toast.error('Failed to log escalation') }
    finally { setEscalateLoading(false) }
  }

  const handleCreateIncident = async () => {
    if (!incidentTitle.trim()) { toast.error('Please enter an incident title'); return }
    if (!id) return
    setIncidentCreating(true)
    try {
      const incident = await incidentsApi.create({
        title: incidentTitle.trim(),
        severity: alert.severity as 'critical' | 'high' | 'medium' | 'low',
        status: 'open',
        description: `Created from alert: ${alert.title}`,
      })
      toast.success(`Incident ${incident.id} created`)
      setIncidentOpen(false); setIncidentTitle('')
      navigate(`/app/incidents/${incident.id}`)
    } catch { toast.error('Failed to create incident') }
    finally { setIncidentCreating(false) }
  }

  const handleSaveNote = async () => {
    if (!noteText.trim()) { toast.error('Please enter a note'); return }
    if (!id) return
    setNoteSaving(true)
    try {
      await addComment(id, noteText.trim())
      await queryClient.invalidateQueries({ queryKey: ['alert', 'timeline', id] })
      toast.success('Note added')
      setNoteOpen(false); setNoteText(''); setNoteAttachments([])
    } catch { toast.error('Failed to save note') }
    finally { setNoteSaving(false) }
  }

  const handleAddEvidenceUrl = async () => {
    if (!id || !evidenceUrl.trim()) return
    setEvidenceBusy(true)
    try {
      await addAlertEvidenceUrl(id, { url: evidenceUrl.trim(), notes: evidenceNotes.trim() || undefined })
      setEvidenceUrl('')
      setEvidenceNotes('')
      await refetchEvidence()
      toast.success('Evidence URL attached')
    } catch {
      toast.error('Failed to attach evidence URL')
    } finally {
      setEvidenceBusy(false)
    }
  }

  const handleUploadEvidenceFile = async (file: File) => {
    if (!id) return
    setEvidenceBusy(true)
    try {
      await uploadAlertEvidenceFile(id, file, evidenceNotes.trim() || undefined)
      setEvidenceNotes('')
      await refetchEvidence()
      toast.success('Evidence file uploaded')
    } catch {
      toast.error('Failed to upload evidence file')
    } finally {
      setEvidenceBusy(false)
    }
  }

  const handleSendChat = async () => {
    if (!id || !chatInput.trim()) return
    const msg = chatInput.trim()
    setChatBusy(true)
    setChatInput('')
    try {
      await sendAIChatMessage({ context_type: 'alert', context_id: id, message: msg })
      await refetchChat()
    } catch {
      toast.error('Failed to send AI chat message')
      setChatInput(msg)
    } finally {
      setChatBusy(false)
    }
  }

  const handleDownloadEvidence = async (item: EvidenceItem) => {
    try {
      await downloadEvidenceFile(item.id, item.name)
    } catch {
      toast.error('Failed to download evidence file')
    }
  }

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files; if (!files) return
    setNoteAttachments((prev) => [...prev, ...Array.from(files).map((f) => ({
      name: f.name,
      type: f.name.split('.').pop()?.toLowerCase() || 'file',
      size: f.size < 1048576 ? `${(f.size / 1024).toFixed(1)} KB` : `${(f.size / 1048576).toFixed(1)} MB`,
    }))])
    e.target.value = ''
  }

  const isRuleBasedAI = !!(alert.ai_summary?.startsWith('Summary for alert:') || alert.ai_summary?.includes('Rule-based'))

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Breadcrumb */}
      <nav className="flex items-center gap-2 text-sm text-muted-foreground flex-wrap">
        <Link to="/app/alerts" className="hover:text-foreground">Alerts</Link>
        {alert.incident_group_id && (
          <>
            <ChevronDown className="w-4 h-4 rotate-[-90deg]" />
            <Link to={`/app/incidents/${alert.incident_group_id}`} className="hover:text-foreground text-amber-400 hover:text-amber-300" title="View incident">
              Incident
            </Link>
          </>
        )}
        <ChevronDown className="w-4 h-4 rotate-[-90deg]" />
        <span className="text-foreground truncate max-w-[200px]">{alert.title}</span>
      </nav>

      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <h1 className="text-2xl font-semibold text-foreground break-words">{alert.title}</h1>
          <div className="flex flex-wrap items-center gap-2 mt-2">
            <AlertBadge severity={alert.severity} />
            {/* Risk score bar */}
            <div className="flex items-center gap-1.5">
              <div className="w-20 h-1.5 rounded-full bg-muted overflow-hidden">
                <div
                  className={cn('h-full rounded-full', (alert.risk_score ?? 0) > 75 ? 'bg-red-500' : (alert.risk_score ?? 0) > 50 ? 'bg-orange-500' : 'bg-blue-500')}
                  style={{ width: `${Math.min(100, alert.risk_score ?? 0)}%` }}
                />
              </div>
              <span className={cn('text-sm font-bold tabular-nums', getRiskScoreColor(alert.risk_score))}>{alert.risk_score ?? 0}</span>
            </div>
            {isViewer ? (
              <span className="px-2 py-0.5 rounded border border-border text-xs text-muted-foreground capitalize">{alert.status?.replace('_', ' ')}</span>
            ) : (
              <select value={alert.status} onChange={(e) => handleStatusChange(e.target.value as Alert['status'])} disabled={statusUpdating}
                className="rounded border border-border bg-background text-foreground px-2 py-1 text-sm">
                <option value="open">Open</option>
                <option value="in_progress">In Progress</option>
                <option value="resolved">Resolved</option>
                <option value="false_positive">False Positive</option>
              </select>
            )}
            {!isViewer && id && <AssignControl alertId={id} currentAssignee={alert.assigned_to} onAssigned={refetch} />}
            {isViewer && alert.assigned_to && <span className="text-muted-foreground text-sm">Assigned: {alert.assigned_to}</span>}
          </div>
        </div>

        {/* Action bar */}
        {!isViewer && (
          <div className="flex flex-wrap gap-2">
            <button type="button" onClick={() => handleStatusChange('resolved')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 text-sm font-medium transition-colors">
              <CheckCircle2 className="w-4 h-4" /> Mark Resolved
            </button>
            <button type="button" onClick={() => setEscalateOpen(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-amber-500/30 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 text-sm font-medium transition-colors">
              <AlertTriangle className="w-4 h-4" /> Escalate
            </button>
            <button type="button" onClick={() => setIncidentOpen(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border text-muted-foreground hover:text-foreground hover:bg-muted/30 text-sm font-medium transition-colors">
              <Activity className="w-4 h-4" /> Create Incident
            </button>
            <button type="button" onClick={() => setNoteOpen(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border text-muted-foreground hover:text-foreground hover:bg-muted/30 text-sm font-medium transition-colors">
              <FileText className="w-4 h-4" /> Add Note
            </button>
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="border-b border-border overflow-x-auto">
        <nav className="flex gap-1 min-w-max">
          {TABS.map(({ id: t, label, icon: Icon }) => (
            <button key={t} type="button" onClick={() => setTab(t)}
              className={cn('flex items-center gap-2 py-2 px-4 text-sm font-medium border-b-2 transition-colors',
                tab === t ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground')}>
              <Icon className="w-4 h-4" /> {label}
              {t === 'timeline' && timelineCount > 0 && (
                <span className="ml-1 min-w-[1.25rem] rounded-full bg-muted px-1.5 py-0.5 text-xs font-medium text-muted-foreground">{timelineCount}</span>
              )}
            </button>
          ))}
        </nav>
      </div>

      {/* ── TRIAGE TAB ── merged Overview + AI ───────────────────────────────── */}
      {tab === 'triage' && (
        <div className="space-y-5">
          {/* Top row: entities + decision + AI summary */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">

            {/* Entities */}
            <div className="glass-card rounded-xl border border-border/50 p-4">
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Entities</h3>
              <div className="divide-y divide-border/20">
                <EntityField icon={Server} label="Asset"     value={alert.asset_id}  mono />
                <EntityField icon={User}   label="User"      value={alert.user_id}   mono />
                <EntityField icon={Globe}  label="Source IP" value={alert.source_ip} mono />
                <EntityField icon={Globe}  label="Dest IP"   value={alert.dest_ip}   mono />
                <EntityField icon={FileJson} label="Source"  value={alert.source} />
                <EntityField icon={Target} label="Category"  value={alert.category} />
              </div>
            </div>

            {/* Decision engine */}
            <div className="glass-card rounded-xl border border-border/50 p-4 space-y-3">
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Decision Engine</h3>
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Risk score</span>
                <span className={cn('font-bold text-base tabular-nums', getRiskScoreColor(decision?.risk_score ?? null))}>
                  {decision?.risk_score ?? alert.risk_score ?? '—'}
                  <span className="text-xs text-muted-foreground font-normal ml-0.5">/100</span>
                </span>
              </div>
              {(decision?.risk_level ?? alert.risk_level) && (
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Risk level</span>
                  <span className="font-medium text-foreground capitalize">{decision?.risk_level ?? alert.risk_level}</span>
                </div>
              )}
              {decision?.confidence != null && (
                <div>
                  <div className="flex items-center justify-between text-sm mb-1.5">
                    <span className="text-muted-foreground">Confidence</span>
                    <span className="font-medium text-foreground">{Math.round(decision.confidence * 100)}%</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-muted overflow-hidden">
                    <div className={cn('h-full rounded-full', decision.confidence > 0.7 ? 'bg-emerald-500' : decision.confidence > 0.4 ? 'bg-amber-500' : 'bg-red-500')}
                      style={{ width: `${Math.min(100, Math.round(decision.confidence * 100))}%` }} />
                  </div>
                </div>
              )}
              {decision?.correlation_rule_triggered && (
                <div>
                  <span className="text-muted-foreground text-xs">Triggered rule</span>
                  <p className="text-xs font-medium text-blue-400 mt-0.5">{decision.correlation_rule_triggered}</p>
                </div>
              )}
              {explanation.length > 0 && (
                <div className="border-t border-border/30 pt-3">
                  <button type="button" onClick={() => setWhyExpanded((e) => !e)}
                    className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors w-full">
                    {whyExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                    Why this score?
                  </button>
                  {whyExpanded && (
                    <ul className="mt-2 space-y-1 pl-5 list-disc">
                      {explanation.map((e, i) => <li key={i} className="text-xs text-muted-foreground">{e}</li>)}
                    </ul>
                  )}
                </div>
              )}
            </div>

            {/* AI Summary */}
            <div className="glass-card rounded-xl border border-border/50 p-4">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                  <Sparkles className="w-3.5 h-3.5 text-yellow-400" /> AI Analysis
                </h3>
                {!isViewer && (
                  <button type="button" onClick={handleRunAI} disabled={aiLoading}
                    className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[10px] font-medium bg-primary/10 text-primary hover:bg-primary/20 transition-colors disabled:opacity-40">
                    {aiLoading ? <span className="w-3 h-3 rounded-full border border-primary border-t-transparent animate-spin" /> : <Sparkles className="w-3 h-3" />}
                    {alert.ai_summary ? 'Re-run' : 'Run AI'}
                  </button>
                )}
              </div>

              {aiLoading && (
                <div className="flex items-center gap-2 text-xs text-muted-foreground py-4">
                  <Spinner size="sm" /> Analyzing alert…
                </div>
              )}
              {aiError && (
                <p className="text-xs text-red-400 p-2 rounded bg-red-500/10 border border-red-500/20">
                  {aiError} <a href="/app/settings" className="text-blue-400 underline ml-1">Configure →</a>
                </p>
              )}
              {!alert.ai_summary && !aiLoading && !aiError && (
                <p className="text-xs text-muted-foreground py-4 text-center">{isViewer ? 'No AI analysis yet.' : 'Queuing analysis…'}</p>
              )}
              {alert.ai_summary && !aiLoading && (
                <div className="space-y-2">
                  {isRuleBasedAI && (
                    <p className="text-[10px] text-amber-400 flex items-start gap-1">
                      <span className="shrink-0 mt-0.5">⚠</span>
                      Rule-based summary — <Link to="/app/settings" className="underline">add an AI key</Link> for full analysis.
                    </p>
                  )}
                  <p className="text-xs text-foreground/90 leading-relaxed whitespace-pre-wrap">{alert.ai_summary}</p>
                </div>
              )}
            </div>
          </div>

          {/* Recommended actions — alert-specific */}
          <div className="glass-card rounded-xl border border-border/50 p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                {aiRemediationActions.length > 0 ? 'AI Recommended Actions' : aiNextSteps.length > 0 ? 'AI Next Steps' : 'Triage Actions'}
              </h3>
              {aiRemediationActions.length === 0 && aiNextSteps.length === 0 && !alert.ai_summary && !isViewer && (
                <span className="text-[10px] text-muted-foreground italic">Generated from alert context</span>
              )}
            </div>
            {primaryActions.length === 0 ? (
              <p className="text-xs text-muted-foreground">No actions available.</p>
            ) : (
              <ol className="space-y-2">
                {primaryActions.map((a, i) => (
                  <li key={i} className="flex items-start gap-3 text-sm">
                    <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-primary/15 text-primary text-[10px] font-bold">
                      {i + 1}
                    </span>
                    <span className="text-foreground/90 leading-relaxed text-xs">{a}</span>
                  </li>
                ))}
              </ol>
            )}
          </div>

          {/* AI Key Facts (if available) */}
          {alert.ai_key_facts && Object.keys(alert.ai_key_facts as Record<string, unknown>).length > 0 && (
            <div className="glass-card rounded-xl border border-border/50 p-4">
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">AI Key Facts</h3>
              <dl className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                {Object.entries(alert.ai_key_facts as Record<string, unknown>).map(([k, v]) => (
                  <div key={k} className="bg-muted/30 rounded-lg p-2.5">
                    <dt className="text-[10px] text-muted-foreground uppercase tracking-wide mb-0.5 capitalize">{k.replace(/_/g, ' ')}</dt>
                    <dd className="text-xs font-medium text-foreground">{String(v)}</dd>
                  </div>
                ))}
              </dl>
            </div>
          )}

          {/* Analyst Notes */}
          <div className="glass-card rounded-xl border border-border/50 p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                <MessageSquare className="w-3.5 h-3.5 text-primary" /> Analyst Notes
                {analystNotes.length > 0 && (
                  <span className="px-1.5 py-0.5 rounded-full bg-muted text-[10px] font-medium text-muted-foreground">{analystNotes.length}</span>
                )}
              </h3>
              {!isViewer && (
                <button type="button" onClick={() => setNoteOpen(true)}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border border-border text-[10px] font-medium text-muted-foreground hover:text-foreground hover:bg-muted/30 transition-colors">
                  <FileText className="w-3 h-3" /> Add Note
                </button>
              )}
            </div>
            {analystNotes.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-6 text-muted-foreground">
                <MessageSquare className="w-7 h-7 mb-2 opacity-20" />
                <p className="text-xs">No analyst notes yet</p>
              </div>
            ) : (
              <div className="space-y-3">
                {analystNotes.map((note, i) => {
                  const content = typeof note.details?.text === 'string' ? note.details.text
                    : typeof note.details?.content === 'string' ? note.details.content
                    : JSON.stringify(note.details ?? '')
                  return (
                    <div key={i} className="rounded-lg border border-border/40 bg-muted/20 p-3.5">
                      <div className="flex items-center gap-2 mb-2">
                        <div className="h-5 w-5 rounded-full bg-primary/15 flex items-center justify-center shrink-0">
                          <User className="h-2.5 w-2.5 text-primary" />
                        </div>
                        <span className="text-xs font-semibold">{note.analyst ?? 'Analyst'}</span>
                        <span className="text-[10px] text-muted-foreground flex items-center gap-0.5">
                          <Clock className="h-2.5 w-2.5" /> {formatTimelineTimestamp(note.timestamp)}
                        </span>
                      </div>
                      <p className="text-xs leading-relaxed text-foreground/90 whitespace-pre-wrap">{content}</p>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── INVESTIGATION TAB ── merged Enrichment + MITRE ───────────────────── */}
      {tab === 'investigation' && (
        <div className="space-y-5">
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
            <div className="glass-card rounded-xl border border-border/50 p-4 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                  <Bot className="w-3.5 h-3.5 text-primary" /> Analyst AI Chat
                </h3>
              </div>
              <div className="rounded-lg border border-border/40 bg-muted/20 p-3 h-56 overflow-auto space-y-2">
                {chatLoading ? (
                  <p className="text-xs text-muted-foreground">Loading chat…</p>
                ) : chatItems.length === 0 ? (
                  <p className="text-xs text-muted-foreground">No context messages yet.</p>
                ) : (
                  chatItems.map((m) => (
                    <div key={m.id} className={cn('rounded-md px-2.5 py-2 text-xs', m.role === 'assistant' ? 'bg-primary/10 border border-primary/20' : 'bg-muted border border-border/40')}>
                      <p className="text-[10px] text-muted-foreground mb-1 uppercase tracking-wide">{m.role === 'assistant' ? 'AI Assistant' : (m.analyst || 'Analyst')}</p>
                      <p className="text-foreground whitespace-pre-wrap leading-relaxed">{m.message}</p>
                    </div>
                  ))
                )}
              </div>
              {!isViewer && (
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={chatInput}
                    onChange={(e) => setChatInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleSendChat()}
                    placeholder="Ask AI to evaluate this alert context…"
                    className="flex-1 px-3 py-2 rounded-lg border border-border bg-background text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40"
                  />
                  <button
                    type="button"
                    onClick={handleSendChat}
                    disabled={chatBusy || !chatInput.trim()}
                    className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg border border-primary/30 bg-primary/10 text-primary text-xs font-semibold hover:bg-primary/20 disabled:opacity-40"
                  >
                    <SendHorizontal className="w-3.5 h-3.5" /> Send
                  </button>
                </div>
              )}
            </div>

            <div className="glass-card rounded-xl border border-border/50 p-4 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                  <Paperclip className="w-3.5 h-3.5 text-primary" /> Evidence Attachments
                </h3>
                {!isViewer && (
                  <button
                    type="button"
                    onClick={() => evidenceFileInputRef.current?.click()}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border border-border text-[10px] text-muted-foreground hover:text-foreground hover:bg-muted/30"
                  >
                    <Upload className="w-3 h-3" /> Upload
                  </button>
                )}
              </div>

              {!isViewer && (
                <div className="space-y-2">
                  <div className="flex gap-2">
                    <input
                      type="url"
                      value={evidenceUrl}
                      onChange={(e) => setEvidenceUrl(e.target.value)}
                      placeholder="https://intel-source.example/report"
                      className="flex-1 px-3 py-2 rounded-lg border border-border bg-background text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40"
                    />
                    <button
                      type="button"
                      onClick={handleAddEvidenceUrl}
                      disabled={evidenceBusy || !evidenceUrl.trim()}
                      className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg border border-blue-500/30 bg-blue-500/10 text-blue-400 text-xs font-semibold hover:bg-blue-500/20 disabled:opacity-40"
                    >
                      <Link2 className="w-3.5 h-3.5" /> Add URL
                    </button>
                  </div>
                  <input
                    type="text"
                    value={evidenceNotes}
                    onChange={(e) => setEvidenceNotes(e.target.value)}
                    placeholder="Optional notes for evidence"
                    className="w-full px-3 py-2 rounded-lg border border-border bg-background text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40"
                  />
                  <input
                    ref={evidenceFileInputRef}
                    type="file"
                    className="hidden"
                    accept=".pdf,.png,.jpg,.jpeg,.txt,.log,.csv,.json,.pcap"
                    onChange={(e) => {
                      const f = e.target.files?.[0]
                      if (f) void handleUploadEvidenceFile(f)
                      e.target.value = ''
                    }}
                  />
                </div>
              )}

              <div className="rounded-lg border border-border/40 bg-muted/20 p-2.5 max-h-56 overflow-auto space-y-2">
                {evidenceLoading ? (
                  <p className="text-xs text-muted-foreground">Loading evidence…</p>
                ) : evidenceItems.length === 0 ? (
                  <p className="text-xs text-muted-foreground">No evidence attached yet.</p>
                ) : (
                  evidenceItems.map((ev) => (
                    <div key={ev.id} className="rounded-md border border-border/40 bg-card/60 px-2.5 py-2 text-xs">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-medium text-foreground truncate">{ev.name}</span>
                        {ev.attachment_type === 'file' ? (
                          <button type="button" onClick={() => handleDownloadEvidence(ev)} className="inline-flex items-center gap-1 text-[10px] text-blue-400 hover:underline">
                            <Download className="w-3 h-3" /> Download
                          </button>
                        ) : (
                          <a href={ev.external_url || '#'} target="_blank" rel="noopener noreferrer" className="text-[10px] text-blue-400 hover:underline">Open</a>
                        )}
                      </div>
                      <p className="text-[10px] text-muted-foreground mt-1">
                        {ev.attachment_type.toUpperCase()} {ev.size_bytes ? `- ${(ev.size_bytes / 1024).toFixed(1)} KB` : ''}
                      </p>
                      {ev.notes && <p className="text-[10px] text-foreground/80 mt-1 whitespace-pre-wrap">{ev.notes}</p>}
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Observables */}
          <div className="glass-card rounded-xl border border-border/50 p-4">
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Observables</h3>
            {observables.length === 0 ? (
              <p className="text-muted-foreground text-sm">No observables extracted.</p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {observables.map((obs, i) => (
                  <ObservablePill key={`${obs.value}-${i}`} item={obs} onCopy={() => toast.success('Copied')}
                    onPivot={() => setPivotEntity({ type: obs.type, value: obs.value, label: obs.label })} />
                ))}
              </div>
            )}
          </div>

          {/* AI Intelligence signals — FP score, cluster, watchlist tags */}
          {enrichment && (enrichment.fp_classifier || enrichment.ai_cluster || (enrichment.watchlist_tags ?? []).length > 0) && (
            <div className="glass-card rounded-xl border border-border/50 p-4">
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3 flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-yellow-400" /> AI Intelligence Signals
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {enrichment.fp_classifier && (
                  <div className={cn('rounded-lg border p-3', enrichment.fp_classifier.candidate ? 'border-amber-500/30 bg-amber-500/10' : 'border-border/40 bg-muted/20')}>
                    <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">FP Confidence</p>
                    <div className="flex items-end gap-2 mb-1.5">
                      <span className={cn('text-2xl font-bold tabular-nums', enrichment.fp_classifier.candidate ? 'text-amber-400' : enrichment.fp_classifier.score > 60 ? 'text-orange-400' : 'text-foreground')}>
                        {enrichment.fp_classifier.score}
                      </span>
                      <span className="text-xs text-muted-foreground mb-0.5">/100</span>
                    </div>
                    {enrichment.fp_classifier.candidate && (
                      <span className="inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded border border-amber-500/40 bg-amber-500/20 text-amber-400">
                        ⚠ FP Candidate
                      </span>
                    )}
                    {enrichment.fp_classifier.reasons.length > 0 && (
                      <ul className="mt-2 space-y-0.5">
                        {enrichment.fp_classifier.reasons.slice(0, 3).map((r, i) => (
                          <li key={i} className="text-[10px] text-muted-foreground">• {r}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
                {enrichment.ai_cluster && (
                  <div className="rounded-lg border border-border/40 bg-muted/20 p-3">
                    <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">Investigation Cluster</p>
                    <p className="text-xs font-mono text-foreground break-all">{enrichment.ai_cluster}</p>
                    <p className="text-[10px] text-muted-foreground mt-1">Semantically grouped with similar alerts</p>
                  </div>
                )}
                {(enrichment.watchlist_tags ?? []).length > 0 && (
                  <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3">
                    <p className="text-[10px] uppercase tracking-wider text-red-400 mb-1.5">Watchlist Matches</p>
                    <div className="flex flex-wrap gap-1">
                      {(enrichment.watchlist_tags ?? []).map((tag, i) => (
                        <span key={i} className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold bg-red-500/20 border border-red-500/40 text-red-400">
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {alertAttribution && (
            <div className="glass-card rounded-xl border border-border/50 p-4">
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Threat Actor Attribution</h3>
              {alertAttribution.candidates.length === 0 ? (
                <p className="text-xs text-muted-foreground">No threat actor attribution match for this alert yet.</p>
              ) : (
                <div className="space-y-2">
                  {alertAttribution.candidates.slice(0, 3).map((candidate, i) => (
                    <div key={`${candidate.actor}-${i}`} className="rounded-lg border border-border/40 bg-muted/20 p-3">
                      <div className="flex items-center justify-between gap-2">
                        <p className="text-sm font-medium text-foreground">{candidate.actor}</p>
                        <span className="text-xs px-2 py-0.5 rounded border border-red-500/30 bg-red-500/10 text-red-400 font-semibold">
                          {candidate.confidence}%
                        </span>
                      </div>
                      {candidate.matched_ttps.length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-1">
                          {candidate.matched_ttps.slice(0, 8).map((ttp) => (
                            <span key={ttp} className="inline-flex items-center px-1.5 py-0.5 rounded bg-muted/40 border border-border/30 text-[10px] font-mono text-muted-foreground">
                              {ttp}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            {/* MITRE ATT&CK */}
            <div className="glass-card rounded-xl border border-border/50 p-4">
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3 flex items-center gap-1.5">
                <Target className="w-3.5 h-3.5 text-primary" /> MITRE ATT&CK
              </h3>
              {(alert.mitre_techniques ?? []).length === 0 ? (
                <p className="text-muted-foreground text-sm">No MITRE techniques mapped.</p>
              ) : (
                <div className="space-y-2">
                  {(alert.mitre_techniques ?? []).map((t, i) => (
                    <div key={i} className="flex items-center gap-2 p-2.5 rounded-lg bg-muted/30 border border-border/30">
                      <div>
                        <div className="flex items-center gap-2 mb-0.5">
                          <MitreTags techniques={[t]} />
                          <span className="text-xs font-medium text-foreground">{t.technique_name}</span>
                        </div>
                        {t.tactic && <span className="text-[10px] text-muted-foreground capitalize">{t.tactic}</span>}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* IOCs */}
            <div className="glass-card rounded-xl border border-border/50 p-4">
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">IOC Breakdown</h3>
              {!enrichment ? (
                <p className="text-muted-foreground text-sm">No enrichment data available.</p>
              ) : (
                <div className="space-y-3">
                  {(['ips', 'domains', 'hashes', 'cves'] as const).map((kind) => {
                    const items = enrichment.iocs?.[kind] ?? []
                    if (items.length === 0) return null
                    return (
                      <div key={kind}>
                        <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium mb-1.5">{kind}</p>
                        <div className="flex flex-wrap gap-1.5">
                          {items.map((ioc, i) => (
                            <span key={i} className="rounded-md px-2 py-0.5 text-xs font-mono bg-muted/50 text-muted-foreground border border-border/30">{ioc}</span>
                          ))}
                        </div>
                      </div>
                    )
                  })}
                  {!enrichment.iocs && <p className="text-muted-foreground text-xs">No IOC data.</p>}
                </div>
              )}
            </div>
          </div>

          {/* VirusTotal */}
          {(enrichment?.vt_results ?? []).length > 0 && (
            <div className="glass-card rounded-xl border border-border/50 p-4">
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">VirusTotal</h3>
              <div className="space-y-3">
                {(enrichment?.vt_results ?? []).map((r, i) => (
                  <div key={i} className="p-3 rounded-lg border border-border/40 bg-muted/20">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-mono text-foreground">{r.indicator}</span>
                      {r.permalink && <a href={r.permalink} target="_blank" rel="noopener noreferrer" className="text-[10px] text-blue-400 hover:underline">Report →</a>}
                    </div>
                    <div className="h-1.5 rounded-full bg-muted overflow-hidden mb-1">
                      <div className={cn('h-full rounded-full', (r.malicious_count ?? 0) > 0 ? 'bg-red-500' : 'bg-emerald-500')}
                        style={{ width: `${(r.detection_ratio ?? 0) * 100}%` }} />
                    </div>
                    <p className="text-[10px] text-muted-foreground">
                      {r.malicious_count ?? 0} malicious / {r.total_engines ?? 0} engines
                      {(r.malicious_count ?? 0) > 0 && <span className="ml-2 text-red-400 font-medium">DETECTED</span>}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* AbuseIPDB + Feed matches */}
          {((enrichment?.abuse_results ?? []).length > 0 || (enrichment?.feed_matches ?? []).length > 0) && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
              {(enrichment?.abuse_results ?? []).length > 0 && (
                <div className="glass-card rounded-xl border border-border/50 p-4">
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">AbuseIPDB</h3>
                  <div className="space-y-2">
                    {(enrichment?.abuse_results ?? []).map((r, i) => (
                      <div key={i} className="text-xs grid grid-cols-2 gap-1 p-2.5 rounded-lg bg-muted/30 border border-border/30">
                        <span className="text-muted-foreground">IP</span><span className="font-mono text-foreground text-right">{r.ip}</span>
                        <span className="text-muted-foreground">Abuse score</span><span className={cn('font-medium text-right', (r.abuse_score ?? 0) > 50 ? 'text-red-400' : 'text-foreground')}>{r.abuse_score ?? '—'}</span>
                        <span className="text-muted-foreground">ISP</span><span className="text-foreground text-right truncate">{r.isp ?? '—'}</span>
                        <span className="text-muted-foreground">Country</span><span className="text-foreground text-right">{r.country_code ?? '—'}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {(enrichment?.feed_matches ?? []).length > 0 && (
                <div className="glass-card rounded-xl border border-border/50 p-4">
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Threat Feed Matches</h3>
                  <div className="space-y-1.5">
                    {(enrichment?.feed_matches ?? []).map((m, i) => (
                      <div key={i} className="flex items-center justify-between text-xs p-2 rounded-lg bg-muted/30 border border-border/30">
                        <span className="text-muted-foreground">{m.feed_name}</span>
                        <span className="font-mono text-foreground">{m.indicator}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── TIMELINE & RAW TAB ───────────────────────────────────────────────── */}
      {tab === 'timeline' && id && (
        <div className="space-y-5">
          <TimelineTab
            alertId={id}
            comment={comment}
            setComment={setComment}
            commentLoading={commentLoading}
            onAddComment={handleAddComment}
            readOnly={isViewer}
          />

          {/* Raw log — collapsible */}
          <div className="glass-card rounded-xl border border-border/50 overflow-hidden">
            <button type="button" onClick={() => setRawExpanded((e) => !e)}
              className="w-full flex items-center justify-between px-4 py-3 text-xs font-semibold text-muted-foreground hover:text-foreground transition-colors">
              <span className="flex items-center gap-2"><FileJson className="w-3.5 h-3.5" /> Raw Log</span>
              {rawExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
            </button>
            {rawExpanded && (
              <div className="border-t border-border/40">
                <div className="px-4 py-2 border-b border-border/30">
                  <button type="button" onClick={() => { navigator.clipboard.writeText(JSON.stringify(alert.raw ?? {}, null, 2)); toast.success('Copied') }}
                    className="inline-flex items-center gap-1 px-2 py-1 rounded border border-border text-muted-foreground hover:text-foreground text-xs">
                    <Copy className="w-3.5 h-3.5" /> Copy
                  </button>
                </div>
                <pre className="text-xs text-muted-foreground overflow-auto max-h-[500px] bg-muted/20 p-4 leading-relaxed">
                  {JSON.stringify(alert.raw ?? {}, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── ESCALATE DIALOG ──────────────────────────────────────────────────── */}
      <Modal open={escalateOpen} onClose={() => { setEscalateOpen(false); setEscalateReason(''); setEscalateComment('') }}
        title="Escalate Alert"
        description="Select a reason and provide context. This will be logged in the alert timeline."
        footer={
          <>
            <button type="button" onClick={() => { setEscalateOpen(false); setEscalateReason(''); setEscalateComment('') }}
              className="px-4 py-1.5 rounded-lg border border-border text-xs text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-all">Cancel</button>
            <button type="button" onClick={handleEscalate} disabled={escalateLoading}
              className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-lg gradient-primary text-white text-xs font-semibold hover:opacity-90 disabled:opacity-40 transition-all">
              <AlertTriangle className="w-3 h-3" /> {escalateLoading ? 'Logging…' : 'Confirm Escalation'}
            </button>
          </>
        }>
        <div className="space-y-2">
          <label className="block text-[11px] font-semibold text-muted-foreground uppercase tracking-widest">Reason <span className="text-red-400">*</span></label>
          <select value={escalateReason} onChange={(e) => setEscalateReason(e.target.value)}
            className="w-full px-3 py-2 rounded-lg border border-border bg-background text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500 transition-all">
            <option value="">Select a reason…</option>
            {ESCALATE_REASONS.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
          </select>
        </div>
        <div className="space-y-2">
          <label className="block text-[11px] font-semibold text-muted-foreground uppercase tracking-widest">Comments <span className="text-red-400">*</span></label>
          <textarea value={escalateComment} onChange={(e) => setEscalateComment(e.target.value)}
            placeholder="Explain why this alert needs to be escalated…" rows={4}
            className="w-full px-3 py-2 rounded-lg border border-border bg-background text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500 transition-all resize-none" />
          <p className="text-[10px] text-muted-foreground">Minimum detail required. This will be logged in the timeline.</p>
        </div>
      </Modal>

      {/* ── CREATE INCIDENT DIALOG ───────────────────────────────────────────── */}
      <Modal open={incidentOpen} onClose={() => { setIncidentOpen(false); setIncidentTitle('') }}
        title="Create Incident from Alert"
        description={`Creates a new incident linked to: ${alert.title}`}
        footer={
          <>
            <button type="button" onClick={() => { setIncidentOpen(false); setIncidentTitle('') }}
              className="px-4 py-1.5 rounded-lg border border-border text-xs text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-all">Cancel</button>
            <button type="button" onClick={handleCreateIncident} disabled={incidentCreating || !incidentTitle.trim()}
              className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-lg gradient-primary text-white text-xs font-semibold hover:opacity-90 disabled:opacity-40 transition-all">
              <Activity className="w-3 h-3" /> {incidentCreating ? 'Creating…' : 'Create Incident'}
            </button>
          </>
        }>
        <div className="space-y-2">
          <label className="block text-[11px] font-semibold text-muted-foreground uppercase tracking-widest">Incident Title</label>
          <input type="text" value={incidentTitle} onChange={(e) => setIncidentTitle(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleCreateIncident()}
            placeholder={`e.g. ${alert.title.slice(0, 50)} Investigation`}
            className="w-full px-3 py-2 rounded-lg border border-border bg-background text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500 transition-all" />
        </div>
      </Modal>

      {/* ── ADD NOTE DIALOG ──────────────────────────────────────────────────── */}
      <Modal open={noteOpen} wide onClose={() => { setNoteOpen(false); setNoteText(''); setNoteAttachments([]) }}
        title="Add Analyst Note"
        description="Notes appear in the Triage tab and Timeline."
        footer={
          <>
            <button type="button" onClick={() => { setNoteOpen(false); setNoteText(''); setNoteAttachments([]) }}
              className="px-4 py-1.5 rounded-lg border border-border text-xs text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-all">Cancel</button>
            <button type="button" onClick={handleSaveNote} disabled={noteSaving || !noteText.trim()}
              className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-lg gradient-primary text-white text-xs font-semibold hover:opacity-90 disabled:opacity-40 transition-all">
              <FileText className="w-3 h-3" /> {noteSaving ? 'Saving…' : 'Save Note'}
            </button>
          </>
        }>
        {/* Toolbar */}
        <div className="flex items-center gap-0.5 border-b border-border/40 pb-2">
          {[{ Icon: Bold, title: 'Bold' }, { Icon: Italic, title: 'Italic' }, { Icon: List, title: 'List' }].map(({ Icon, title }) => (
            <button key={title} type="button" title={title}
              className="p-1.5 rounded hover:bg-muted/50 text-muted-foreground hover:text-foreground transition-colors">
              <Icon className="w-3.5 h-3.5" />
            </button>
          ))}
          <div className="w-px h-4 bg-border/50 mx-1" />
          {[{ Icon: Paperclip, title: 'Attach file' }, { Icon: Image, title: 'Attach image' }].map(({ Icon, title }) => (
            <button key={title} type="button" title={title} onClick={() => fileInputRef.current?.click()}
              className="p-1.5 rounded hover:bg-muted/50 text-muted-foreground hover:text-foreground transition-colors">
              <Icon className="w-3.5 h-3.5" />
            </button>
          ))}
          <input ref={fileInputRef} type="file" multiple className="hidden" onChange={handleFileSelect}
            accept=".pdf,.png,.jpg,.jpeg,.txt,.log,.csv,.json,.pcap" />
        </div>
        <textarea value={noteText} onChange={(e) => setNoteText(e.target.value)}
          placeholder="Enter your analysis notes… (supports markdown)" rows={6}
          className="w-full px-3 py-2 rounded-lg border border-border bg-background text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500 transition-all resize-none" />
        {noteAttachments.length > 0 && (
          <div className="space-y-1.5">
            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">Attachments</p>
            {noteAttachments.map((att, i) => (
              <div key={i} className="flex items-center gap-2 text-xs bg-muted/30 rounded-md px-3 py-1.5">
                <Paperclip className="h-3 w-3 text-muted-foreground shrink-0" />
                <span className="truncate flex-1">{att.name}</span>
                <span className="text-muted-foreground text-[10px] shrink-0">{att.size}</span>
                <button type="button" onClick={() => setNoteAttachments((prev) => prev.filter((_, idx) => idx !== i))}
                  className="text-muted-foreground hover:text-red-400 transition-colors"><Trash2 className="h-3 w-3" /></button>
              </div>
            ))}
          </div>
        )}
      </Modal>

      {/* ── ENTITY PIVOT PANEL ────────────────────────────────────────────────── */}
      <EntityPivotPanel entity={pivotEntity} onClose={() => setPivotEntity(null)} />
    </div>
  )
}

// ── Constants ─────────────────────────────────────────────────────────────────
const ESCALATE_REASONS = [
  { value: 'confirmed_threat',    label: 'Confirmed Threat Activity' },
  { value: 'high_impact',         label: 'High Business Impact' },
  { value: 'active_exploitation', label: 'Active Exploitation Detected' },
  { value: 'data_exfiltration',   label: 'Potential Data Exfiltration' },
  { value: 'lateral_movement',    label: 'Lateral Movement Observed' },
  { value: 'executive_request',   label: 'Executive/Management Request' },
  { value: 'other',               label: 'Other' },
]

// ── Timeline section ──────────────────────────────────────────────────────────
const TIMELINE_CONFIG: Record<string, { label: string; Icon: typeof MessageSquare; borderClass: string }> = {
  comment:       { label: 'Comment',      Icon: MessageSquare, borderClass: 'border-l-blue-500' },
  alert_updated: { label: 'Alert updated', Icon: Pencil,       borderClass: 'border-l-amber-500' },
  decision:      { label: 'Decision',     Icon: Cpu,          borderClass: 'border-l-purple-500' },
  request:       { label: 'Request',      Icon: Globe,        borderClass: 'border-l-border' },
}
function getTimelineCfg(action: string) {
  return TIMELINE_CONFIG[action] ?? { label: action, Icon: Activity, borderClass: 'border-l-border' }
}

function TimelineEntryCard({ entry }: { entry: TimelineItem }) {
  const { label, Icon, borderClass } = getTimelineCfg(entry.action)
  const details = entry.details && Object.keys(entry.details).length > 0 ? entry.details : null
  return (
    <div className={cn('glass-card rounded-xl border border-l-4 p-3', borderClass)}>
      <div className="flex items-start gap-3">
        <div className="mt-0.5 shrink-0 rounded bg-card p-1.5"><Icon className="h-4 w-4 text-muted-foreground" /></div>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-foreground">{label}</p>
          <p className="text-xs text-muted-foreground mt-0.5">{entry.analyst ?? 'System'} · {formatTimelineTimestamp(entry.timestamp)}</p>
          {details && (
            <div className="mt-2 rounded border border-border bg-card px-2.5 py-2 text-xs">
              <dl className="space-y-1">
                {Object.entries(details).map(([k, v]) => (
                  <div key={k} className="flex gap-2">
                    <dt className="shrink-0 text-muted-foreground">{k}:</dt>
                    <dd className="text-foreground break-all">{typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v)}</dd>
                  </div>
                ))}
              </dl>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function TimelineTab({ alertId, comment, setComment, commentLoading, onAddComment, readOnly = false }: {
  alertId: string; comment: string; setComment: (v: string) => void
  commentLoading: boolean; onAddComment: () => void; readOnly?: boolean
}) {
  const { data, isLoading } = useQuery({
    queryKey: ['alert', 'timeline', alertId],
    queryFn: () => getTimeline(alertId),
    enabled: !!alertId,
  })
  const timeline = data?.items ?? []
  if (isLoading) return <div className="glass-card rounded-xl border border-border/50 p-8 text-center"><Spinner size="md" /></div>
  return (
    <div className="glass-card rounded-xl border border-border/50 p-4 space-y-4">
      <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Alert Timeline</h3>
      {timeline.length === 0 ? (
        <p className="text-muted-foreground text-sm">No timeline events.</p>
      ) : (
        <div className="space-y-3">
          {timeline.map((e, i) => <TimelineEntryCard key={`${e.timestamp}-${i}`} entry={e} />)}
        </div>
      )}
      {!readOnly && (
        <div className="border-t border-border/40 pt-4">
          <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">Quick note</p>
          <div className="flex gap-2">
            <input type="text" value={comment} onChange={(e) => setComment(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && onAddComment()}
              placeholder="Investigation note…"
              className="flex-1 px-3 py-1.5 rounded border border-border bg-background text-foreground text-sm focus:outline-none focus:border-blue-500" />
            <button onClick={onAddComment} disabled={commentLoading || !comment.trim()}
              className="px-3 py-1.5 rounded-lg gradient-primary text-white text-sm hover:opacity-90 disabled:opacity-50">
              {commentLoading ? '…' : 'Add'}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
