import { useMemo, useState, useEffect, useCallback } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useAlert } from '@/hooks/useAlerts'
import { useAuth } from '@/security/AuthContext'
import { useQuery } from '@tanstack/react-query'
import { triggerAI, getTimeline, updateAlertStatus, addComment, assignAlert, pickUpAlert, getAnalysts } from '@/api/alerts'
import type { TimelineItem } from '@/api/alerts'
import { Card } from '@/components/ui/Card'
import { AlertBadge } from '@/components/alerts/AlertBadge'
import { MitreTags } from '@/components/alerts/MitreTags'
import { Spinner } from '@/components/ui/Spinner'
import { formatTimelineTimestamp } from '@/utils/time'
import { getRiskScoreColor } from '@/utils/severity'
import { ErrorState } from '@/components/ui/ErrorState'
import { SpinnerOverlay } from '@/components/ui/Spinner'
import {
  Sparkles,
  Shield,
  CheckCircle2,
  MessageSquare,
  FileJson,
  Copy,
  ChevronDown,
  ChevronRight,
  Server,
  User,
  Globe,
  Activity,
  Pencil,
  Cpu,
  UserPlus,
  X as XIcon,
} from 'lucide-react'
import { cn } from '@/utils/cn'
import { toast } from 'sonner'
import type { Alert, Enrichment } from '@/types/alert'

/** Observable type for pill color: IP=blue, user=purple, asset=gray, indicator=amber (domain/hash). */
type ObservableType = 'ip' | 'user' | 'asset' | 'indicator'

interface ObservableItem {
  value: string
  type: ObservableType
  label?: string
}

const IPV4_REGEX = /^(?:\d{1,3}\.){3}\d{1,3}$/
const IPV6_REGEX = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,7}:$|^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$/
/** MD5=32, SHA1=40, SHA256=64 hex chars. */
function looksLikeHash(s: string): boolean {
  const trimmed = s.trim()
  if (trimmed.length !== 32 && trimmed.length !== 40 && trimmed.length !== 64) return false
  return /^[0-9a-fA-F]+$/.test(trimmed)
}

function inferIndicatorType(value: string): 'ip' | 'indicator' {
  const v = value.trim()
  if (IPV4_REGEX.test(v) || IPV6_REGEX.test(v)) return 'ip'
  if (looksLikeHash(v)) return 'indicator'
  return 'indicator' // domain or other
}

function collectObservables(alert: Alert): ObservableItem[] {
  const seen = new Set<string>()
  const add = (value: string | null | undefined, type: ObservableType, label?: string) => {
    if (value == null || value === '') return
    const v = String(value).trim()
    if (!v || seen.has(v)) return
    seen.add(v)
    items.push({ value: v, type, label })
  }
  const items: ObservableItem[] = []

  add(alert.source_ip, 'ip', 'Source IP')
  add(alert.dest_ip, 'ip', 'Destination IP')
  add(alert.asset_id, 'asset', 'Asset')
  add(alert.user_id, 'user', 'User')

  const enr: Enrichment | null | undefined = alert.enrichment
  if (enr) {
    // iocs is an object with ips/domains/hashes/cves arrays written by the backend pipeline
    const iocGroup = enr.iocs ?? { ips: [], domains: [], hashes: [], cves: [] }
      ;[...iocGroup.ips, ...iocGroup.domains, ...iocGroup.hashes, ...iocGroup.cves].forEach((s) => {
        add(s, inferIndicatorType(s))
      })
      ; (enr.vt_results ?? []).forEach((r) => add(r.indicator, inferIndicatorType(r.indicator)))
      ; (enr.abuse_results ?? []).forEach((r) => add(r.ip, 'ip'))
      ; (enr.feed_matches ?? []).forEach((m) => add(m.indicator, inferIndicatorType(m.indicator)))
  }
  return items
}

function observablePillColor(type: ObservableType): string {
  switch (type) {
    case 'ip':
      return 'bg-blue-500/15 text-blue-400 border-blue-500/30 hover:bg-blue-500/25'
    case 'user':
      return 'bg-purple-500/15 text-purple-400 border-purple-500/30 hover:bg-purple-500/25'
    case 'asset':
      return 'bg-soc-border text-soc-muted border-soc-border hover:bg-soc-border/80'
    default:
      return 'bg-amber-500/15 text-amber-400 border-amber-500/30 hover:bg-amber-500/25'
  }
}

function ObservablePill({ item, onCopy }: { item: ObservableItem; onCopy: () => void }) {
  const handleCopy = () => {
    navigator.clipboard.writeText(item.value)
    onCopy()
  }
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors group',
        observablePillColor(item.type)
      )}
      title={item.label ? `${item.label}: ${item.value}` : item.value}
    >
      <span className="truncate max-w-[200px]">{item.value}</span>
      <button
        type="button"
        onClick={(e) => {
          e.preventDefault()
          e.stopPropagation()
          handleCopy()
        }}
        className="opacity-0 group-hover:opacity-100 focus:opacity-100 shrink-0 p-0.5 rounded hover:bg-black/10 focus:outline-none"
        aria-label={`Copy ${item.value}`}
      >
        <Copy className="w-3 h-3" />
      </button>
    </span>
  )
}

const TABS = [
  { id: 'overview', label: 'Overview', icon: Activity },
  { id: 'ai', label: 'AI Analysis', icon: Sparkles },
  { id: 'enrichment', label: 'Enrichment', icon: Shield },
  { id: 'mitre', label: 'MITRE', icon: Shield },
  { id: 'timeline', label: 'Timeline', icon: MessageSquare },
  { id: 'raw', label: 'Raw Log', icon: FileJson },
] as const

type TabId = (typeof TABS)[number]['id']

// ── Assign control ────────────────────────────────────────────────────────────
// State machine:
//   unassigned  → "Pick up" (analyst+) | "Assign ▾" dropdown (senior+)
//   assigned=me → green badge + "Drop" (analyst+) | "Reassign ▾" (senior+)
//   assigned≠me → blue badge | "Reassign ▾" (senior+) | read-only (analyst)
function AssignControl({
  alertId,
  currentAssignee,
  onAssigned,
}: {
  alertId: string
  currentAssignee: string | null
  onAssigned: () => void
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

  // Fetch analyst list — only needed for the dropdown (senior+ only)
  const { data: analystsData } = useQuery({
    queryKey: ['analysts'],
    queryFn: getAnalysts,
    enabled: canAssign,
    staleTime: 5 * 60 * 1000,
  })
  const analysts = analystsData?.analysts ?? []

  // Comment is mandatory when changing to a DIFFERENT user — not for pick-up or drop-own
  const isPickUpViaDropdown = selectedUsername === (user?.username ?? '') && isUnassigned
  const isDropOwnViaDropdown = selectedUsername === '' && isAssignedToMe
  const commentRequired = panelOpen
    && selectedUsername !== (currentAssignee ?? '')
    && !isPickUpViaDropdown
    && !isDropOwnViaDropdown

  const openPanel = () => {
    setSelectedUsername(currentAssignee ?? '')
    setComment('')
    setError('')
    setPanelOpen(true)
  }

  const closePanel = () => {
    setPanelOpen(false)
    setComment('')
    setError('')
  }

  const handlePickUp = async () => {
    setLoading(true)
    setError('')
    try {
      await pickUpAlert(alertId)
      onAssigned()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to pick up alert')
    } finally {
      setLoading(false)
    }
  }

  const handleDrop = async () => {
    setLoading(true)
    setError('')
    try {
      await assignAlert(alertId, null)
      onAssigned()
    } catch {
      setError('Failed to drop alert')
    } finally {
      setLoading(false)
    }
  }

  const handleAssign = async () => {
    if (commentRequired && !comment.trim()) {
      setError('A reason is required when reassigning')
      return
    }
    setLoading(true)
    setError('')
    try {
      const newAssignee = selectedUsername || null
      await assignAlert(alertId, newAssignee, comment.trim() || undefined)
      closePanel()
      onAssigned()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to assign')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="relative">
      <div className="flex items-center gap-1.5 flex-wrap">
        {/* Current assignee badge */}
        {currentAssignee && (
          <span className={cn(
            'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border',
            isAssignedToMe
              ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
              : 'border-blue-500/30 bg-blue-500/10 text-blue-400'
          )}>
            <User className="w-3 h-3 shrink-0" />
            {isAssignedToMe ? `${currentAssignee} (you)` : currentAssignee}
          </span>
        )}

        {/* Pick up */}
        {isUnassigned && canPickUp && !panelOpen && (
          <button
            type="button"
            onClick={handlePickUp}
            disabled={loading}
            className={cn(
              'inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium border transition-all duration-150',
              'border-blue-500/30 bg-blue-500/10 text-blue-400',
              'hover:bg-blue-500/20 hover:border-blue-500/50',
              'disabled:opacity-40 disabled:cursor-not-allowed'
            )}
          >
            {loading ? <span className="w-3 h-3 rounded-full border border-blue-400 border-t-transparent animate-spin" /> : <UserPlus className="w-3 h-3" />}
            Pick up
          </button>
        )}

        {/* Drop */}
        {isAssignedToMe && canPickUp && !panelOpen && (
          <button
            type="button"
            onClick={handleDrop}
            disabled={loading}
            title="Unassign yourself"
            className={cn(
              'inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium border transition-all duration-150',
              'border-soc-border text-soc-muted',
              'hover:border-red-500/30 hover:bg-red-500/10 hover:text-red-400',
              'disabled:opacity-40 disabled:cursor-not-allowed'
            )}
          >
            <XIcon className="w-3 h-3" />
            Drop
          </button>
        )}

        {/* Assign / Reassign toggle */}
        {canAssign && (
          <button
            type="button"
            onClick={panelOpen ? closePanel : openPanel}
            className={cn(
              'inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium border transition-all duration-150',
              panelOpen
                ? 'border-blue-500/50 bg-blue-600/15 text-blue-300'
                : 'border-soc-border text-soc-muted hover:text-soc-text hover:border-soc-muted/50 hover:bg-soc-border/40'
            )}
          >
            <UserPlus className="w-3 h-3" />
            {panelOpen ? 'Cancel' : isUnassigned ? 'Assign' : 'Reassign'}
          </button>
        )}
      </div>

      {/* Error (pick-up / drop errors) */}
      {error && !panelOpen && (
        <p className="text-xs text-red-400 mt-1.5 leading-snug">{error}</p>
      )}

      {/* Assignment panel — appears below as inline card */}
      {panelOpen && canAssign && (
        <div className="mt-2 rounded-xl border border-soc-border bg-soc-surface p-4 space-y-3 w-72 animate-slide-up"
             style={{ boxShadow: 'var(--shadow-elevated)' }}>
          <div>
            <label className="block text-[11px] font-semibold text-soc-muted uppercase tracking-widest mb-1.5">
              Assign to
            </label>
            <select
              value={selectedUsername}
              onChange={(e) => { setSelectedUsername(e.target.value); setError('') }}
              className="w-full px-3 py-2 rounded-lg border border-soc-border bg-soc-bg text-soc-text text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500 transition-all"
            >
              <option value="">— Unassigned —</option>
              {analysts.map((a) => (
                <option key={a.id} value={a.username}>
                  {a.username} ({a.role.replace(/_/g, ' ')})
                </option>
              ))}
            </select>
          </div>

          {commentRequired && (
            <div>
              <label className="block text-[11px] font-semibold text-soc-muted uppercase tracking-widest mb-1.5">
                Reason <span className="text-red-400">*</span>
              </label>
              <textarea
                value={comment}
                onChange={(e) => { setComment(e.target.value); setError('') }}
                placeholder="Why are you reassigning this alert?"
                rows={2}
                className="w-full px-3 py-2 rounded-lg border border-soc-border bg-soc-bg text-soc-text text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500 transition-all resize-none"
              />
            </div>
          )}

          {error && <p className="text-xs text-red-400 leading-snug">{error}</p>}

          <div className="flex gap-2 pt-0.5">
            <button
              type="button"
              onClick={handleAssign}
              disabled={loading || (commentRequired && !comment.trim())}
              className="flex-1 py-1.5 rounded-lg bg-blue-600 text-white text-xs font-semibold hover:bg-blue-500 disabled:opacity-40 disabled:cursor-not-allowed transition-all active:scale-[0.98]"
              style={{ boxShadow: '0 1px 2px rgba(0,0,0,0.2), inset 0 1px 0 rgba(255,255,255,0.1)' }}
            >
              {loading ? 'Saving...' : 'Save assignment'}
            </button>
            <button
              type="button"
              onClick={closePanel}
              className="px-4 py-1.5 rounded-lg border border-soc-border text-xs text-soc-muted hover:text-soc-text hover:bg-soc-border/40 transition-all"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

export function AlertDetail() {
  const { id } = useParams<{ id: string }>()
  const { user } = useAuth()
  const [tab, setTab] = useState<TabId>('overview')
  const [statusUpdating, setStatusUpdating] = useState(false)
  const [aiLoading, setAiLoading] = useState(false)
  const [aiError, setAiError] = useState('')
  const [comment, setComment] = useState('')
  const [commentLoading, setCommentLoading] = useState(false)
  const [overviewWhyExpanded, setOverviewWhyExpanded] = useState(false)

  // Role-based capability flags
  const isViewer = user?.role === 'viewer'

  const { data: alert, isLoading, isError, refetch } = useAlert(id)
  const { data: timelineData } = useQuery({
    queryKey: ['alert', 'timeline', id],
    queryFn: () => getTimeline(id!),
    enabled: !!id,
  })
  const timelineCount = timelineData?.items?.length ?? 0

  // ALL hooks and derived functions that call hooks must appear before any early returns
  const observables = useMemo(() => (alert ? collectObservables(alert) : []), [alert])

  const handleRunAI = useCallback(async () => {
    if (!id) return
    setAiLoading(true)
    setAiError('')
    try {
      await triggerAI(id)
      await refetch()
    } catch (e) {
      setAiError('AI analysis failed. Check Settings to configure an AI provider.')
    } finally {
      setAiLoading(false)
    }
  }, [id, refetch])

  // Auto-trigger AI analysis when opening the AI tab if no summary exists yet
  // Must be before early returns — guarded with `alert &&` since alert may be undefined during load
  useEffect(() => {
    if (tab === 'ai' && !isViewer && alert && !alert.ai_summary && !aiLoading && !aiError) {
      handleRunAI()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, alert])

  if (isError) return <ErrorState title="Alert not found" message="The alert may have been removed." onRetry={() => refetch()} />
  if (isLoading || !alert) return <SpinnerOverlay />

  const decision = alert.decision
  const recommendedActions = decision?.recommended_actions?.items ?? []
  const explanation = decision?.explanation?.items ?? []
  const enrichment = alert.enrichment

  const handleStatusChange = async (newStatus: Alert['status']) => {
    if (!id) return
    setStatusUpdating(true)
    try {
      await updateAlertStatus(id, newStatus)
      refetch()
    } finally {
      setStatusUpdating(false)
    }
  }

  const handleCopyRaw = () => {
    if (alert.raw) {
      navigator.clipboard.writeText(JSON.stringify(alert.raw, null, 2))
      toast.success('Copied to clipboard')
    }
  }

  const handleAddComment = async () => {
    if (!id || !comment.trim()) return
    setCommentLoading(true)
    try {
      await addComment(id, comment.trim())
      setComment('')
      refetch()
    } finally {
      setCommentLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <nav className="flex items-center gap-2 text-sm text-soc-muted flex-wrap">
        <Link to="/app/alerts" className="hover:text-soc-text">Alerts</Link>
        {alert.incident_group_id && (
          <>
            <ChevronDown className="w-4 h-4 rotate-[-90deg]" />
            <Link
              to={`/app/incidents/${alert.incident_group_id}`}
              className="hover:text-soc-text text-amber-400 hover:text-amber-300"
              title="View incident"
            >
              Incident
            </Link>
          </>
        )}
        <ChevronDown className="w-4 h-4 rotate-[-90deg]" />
        <span className="text-soc-text truncate max-w-[200px]">{alert.title}</span>
      </nav>

      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <h1 className="text-2xl font-semibold text-soc-text break-words">{alert.title}</h1>
          <div className="flex flex-wrap items-center gap-2 mt-2">
            <AlertBadge severity={alert.severity} />
            <div className="w-24 h-2 rounded-full bg-soc-border overflow-hidden">
              <div
                className={cn('h-full rounded-full', (alert.risk_score ?? 0) > 75 ? 'bg-red-500' : (alert.risk_score ?? 0) > 50 ? 'bg-orange-500' : 'bg-blue-500')}
                style={{ width: `${Math.min(100, alert.risk_score ?? 0)}%` }}
              />
            </div>
            <span className={cn('text-sm font-medium', getRiskScoreColor(alert.risk_score))}>{alert.risk_score ?? 0}</span>
            {isViewer ? (
              <span className="px-2 py-0.5 rounded border border-soc-border text-xs text-soc-muted">
                {alert.status?.replace('_', ' ')}
              </span>
            ) : (
              <select
                value={alert.status}
                onChange={(e) => handleStatusChange(e.target.value as Alert['status'])}
                disabled={statusUpdating}
                className="rounded border border-soc-border bg-soc-bg text-soc-text px-2 py-1 text-sm"
              >
                <option value="open">Open</option>
                <option value="in_progress">In Progress</option>
                <option value="resolved">Resolved</option>
                <option value="false_positive">False Positive</option>
              </select>
            )}
            {/* AssignControl is always rendered; it manages its own visibility per role */}
            {!isViewer && id && (
              <AssignControl alertId={id} currentAssignee={alert.assigned_to} onAssigned={refetch} />
            )}
            {isViewer && alert.assigned_to && (
              <span className="text-soc-muted text-sm">Assigned: {alert.assigned_to}</span>
            )}
          </div>
        </div>
        {!isViewer && (
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => handleStatusChange('resolved')}
              className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 text-sm"
            >
              <CheckCircle2 className="w-4 h-4" /> Mark Resolved
            </button>
          </div>
        )}
      </div>

      <div className="border-b border-soc-border overflow-x-auto">
        <nav className="flex gap-1 min-w-max">
          {TABS.map(({ id: t, label, icon: Icon }) => (
            <button
              key={t}
              type="button"
              onClick={() => setTab(t)}
              className={cn(
                'flex items-center gap-2 py-2 px-3 text-sm font-medium border-b-2 transition-colors',
                tab === t ? 'border-blue-500 text-soc-text' : 'border-transparent text-soc-muted hover:text-soc-text'
              )}
            >
              <Icon className="w-4 h-4" /> {label}
              {t === 'timeline' && timelineCount > 0 && (
                <span className="ml-1 min-w-[1.25rem] rounded-full bg-soc-border px-1.5 py-0.5 text-xs font-medium text-soc-muted">
                  {timelineCount}
                </span>
              )}
            </button>
          ))}
        </nav>
      </div>

      <div className="rounded-lg border border-soc-border bg-soc-surface p-4 min-h-[200px]">
        {tab === 'overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div>
              <h3 className="text-sm font-semibold text-soc-text mb-2">Key facts</h3>
              <ul className="list-disc list-inside text-soc-muted text-sm space-y-1">
                {recommendedActions.slice(0, 5).map((a, i) => (
                  <li key={i}>{a}</li>
                ))}
                {recommendedActions.length === 0 && <li>No key facts</li>}
              </ul>
              <h3 className="text-sm font-semibold text-soc-text mt-4 mb-2">Affected</h3>
              <div className="space-y-2 text-sm">
                <div className="flex items-center gap-2 text-soc-muted"><Server className="w-4 h-4" /> Asset: {alert.asset_id ?? '—'}</div>
                <div className="flex items-center gap-2 text-soc-muted"><User className="w-4 h-4" /> User: {alert.user_id ?? '—'}</div>
                <div className="flex items-center gap-2 text-soc-muted"><Globe className="w-4 h-4" /> Source IP: {alert.source_ip ?? '—'}</div>
                <div className="flex items-center gap-2 text-soc-muted"><Globe className="w-4 h-4" /> Dest IP: {alert.dest_ip ?? '—'}</div>
              </div>
            </div>
            <div>
              <h3 className="text-sm font-semibold text-soc-text mb-2">Decision engine</h3>
              <div className="rounded-lg border border-soc-border bg-soc-bg p-3 space-y-3 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-soc-muted">Risk score:</span>
                  <span className={cn('font-medium', getRiskScoreColor(decision?.risk_score ?? null))}>
                    {decision?.risk_score ?? '—'}
                  </span>
                  {decision?.risk_level && (
                    <span className="text-soc-muted">({decision.risk_level})</span>
                  )}
                </div>
                {decision?.confidence != null && (
                  <div>
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <span className="text-soc-muted">Confidence</span>
                      <span className="font-medium text-soc-text">
                        {Math.round(decision.confidence * 100)}%
                      </span>
                    </div>
                    <div className="h-2 rounded-full bg-soc-border overflow-hidden">
                      <div
                        className={cn(
                          'h-full rounded-full transition-colors',
                          decision.confidence > 0.7 ? 'bg-emerald-500' : decision.confidence > 0.4 ? 'bg-amber-500' : 'bg-red-500'
                        )}
                        style={{ width: `${Math.min(100, Math.round(decision.confidence * 100))}%` }}
                      />
                    </div>
                  </div>
                )}
                {decision?.correlation_rule_triggered && (
                  <div className="flex items-center gap-2">
                    <span className="inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium bg-blue-500/20 text-blue-400 border border-blue-500/30">
                      Triggered: {decision.correlation_rule_triggered}
                    </span>
                  </div>
                )}
                {explanation.length > 0 && (
                  <div className="border-t border-soc-border pt-3">
                    <button
                      type="button"
                      onClick={() => setOverviewWhyExpanded((e) => !e)}
                      className="flex items-center gap-2 w-full text-left text-soc-text hover:text-soc-muted transition-colors"
                    >
                      {overviewWhyExpanded ? (
                        <ChevronDown className="w-4 h-4 shrink-0" />
                      ) : (
                        <ChevronRight className="w-4 h-4 shrink-0" />
                      )}
                      <span className="font-medium">Why this score?</span>
                    </button>
                    {overviewWhyExpanded && (
                      <ul className="list-disc list-inside text-soc-muted mt-2 pl-6 space-y-1">
                        {explanation.map((e, i) => (
                          <li key={i}>{e}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
              </div>

              <h3 className="text-sm font-semibold text-soc-text mt-4 mb-2">Recommended actions</h3>
              <div className="rounded-lg border border-soc-border bg-soc-bg p-3">
                {recommendedActions.length === 0 ? (
                  <p className="text-soc-muted text-sm">None</p>
                ) : (
                  <ol className="space-y-2 list-none">
                    {recommendedActions.map((a, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-soc-text">
                        <span
                          className="mt-0.5 w-4 h-4 shrink-0 rounded border border-soc-border bg-soc-surface"
                          aria-hidden
                        />
                        <span className="text-soc-muted">
                          <span className="font-medium text-soc-text">{i + 1}.</span> {a}
                        </span>
                      </li>
                    ))}
                  </ol>
                )}
              </div>
            </div>
          </div>
        )}

        {tab === 'ai' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-soc-text">
                AI Triage Analysis
              </h3>
              {!isViewer && (
                <button
                  type="button"
                  onClick={handleRunAI}
                  disabled={aiLoading}
                  className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-soc-border bg-soc-surface text-soc-text hover:bg-soc-border/30 disabled:opacity-50 text-sm"
                >
                  {aiLoading ? <Spinner size="sm" /> : <Sparkles className="w-4 h-4 text-yellow-400" />}
                  {alert.ai_summary ? 'Re-run Analysis' : 'Run AI Analysis'}
                </button>
              )}
            </div>

            {aiError && (
              <p className="text-red-400 text-sm p-2 rounded bg-red-500/10 border border-red-500/20">
                {aiError}
                <a href="/app/settings" className="ml-2 text-blue-400 underline">
                  Configure AI →
                </a>
              </p>
            )}

            {!alert.ai_summary && !aiLoading && !aiError && (
              <div className="rounded-lg border border-soc-border bg-soc-surface/50 p-6 text-center">
                <Sparkles className="w-8 h-8 text-soc-muted mx-auto mb-2" />
                <p className="text-soc-muted text-sm">
                  {isViewer ? 'No AI analysis has been run yet.' : 'Starting AI analysis…'}
                </p>
              </div>
            )}

            {aiLoading && (
              <div className="rounded-lg border border-soc-border bg-soc-surface/50 p-6 text-center">
                <Spinner size="md" />
                <p className="text-soc-muted text-sm mt-2">Analyzing alert...</p>
              </div>
            )}

            {alert.ai_summary && !aiLoading && (
              <div className="space-y-4">
                <div className="rounded-lg border border-soc-border bg-soc-surface p-4">
                  <h4 className="text-xs font-semibold text-soc-muted uppercase tracking-wide mb-2">
                    Summary
                  </h4>
                  <p className="text-soc-text text-sm leading-relaxed whitespace-pre-wrap">
                    {alert.ai_summary}
                  </p>
                </div>

                {(alert.ai_summary?.startsWith('Summary for alert:') || alert.ai_summary?.includes('Rule-based')) && (
                  <p className="text-xs text-amber-400 mt-2 flex items-center gap-1.5">
                    <span>⚠</span>
                    <span>
                      This is a <strong>rule-based summary</strong> — no AI provider is configured.{' '}
                      <Link to="/app/settings" className="underline hover:text-amber-300">
                        Add an AI key in Settings
                      </Link>{' '}
                      to get full contextual analysis.
                    </span>
                  </p>
                )}

                {alert.ai_key_facts && Object.keys(alert.ai_key_facts as Record<string, unknown>).length > 0 && (
                  <div className="rounded-lg border border-soc-border bg-soc-surface p-4">
                    <h4 className="text-xs font-semibold text-soc-muted uppercase tracking-wide mb-2">
                      Key Facts
                    </h4>
                    <dl className="grid grid-cols-2 gap-2">
                      {Object.entries(alert.ai_key_facts as Record<string, unknown>).map(([k, v]) => (
                        <div key={k}>
                          <dt className="text-xs text-soc-muted capitalize">{k}</dt>
                          <dd className="text-sm text-soc-text">{String(v)}</dd>
                        </div>
                      ))}
                    </dl>
                  </div>
                )}

                {alert.ai_remediation && (
                  <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-4">
                    <h4 className="text-xs font-semibold text-amber-400 uppercase tracking-wide mb-2">
                      Remediation
                    </h4>
                    {Array.isArray((alert.ai_remediation as { actions?: string[] })?.actions) ? (
                      <ul className="space-y-1">
                        {((alert.ai_remediation as { actions: string[] }).actions).map((a, i) => (
                          <li key={i} className="text-sm text-soc-text flex gap-2">
                            <span className="text-amber-400 shrink-0">→</span>
                            {a}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-sm text-soc-text">{JSON.stringify(alert.ai_remediation)}</p>
                    )}
                  </div>
                )}

                {alert.ai_next_steps && (
                  <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-4">
                    <h4 className="text-xs font-semibold text-blue-400 uppercase tracking-wide mb-2">
                      Next Steps
                    </h4>
                    {Array.isArray((alert.ai_next_steps as { recommendations?: string[] })?.recommendations) ? (
                      <ul className="space-y-1">
                        {((alert.ai_next_steps as { recommendations: string[] }).recommendations).map((r, i) => (
                          <li key={i} className="text-sm text-soc-text flex gap-2">
                            <span className="text-blue-400 shrink-0">{i + 1}.</span>
                            {r}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-sm text-soc-text">{JSON.stringify(alert.ai_next_steps)}</p>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {tab === 'enrichment' && (
          <div className="space-y-4">
            <div className="rounded-lg border border-soc-border bg-soc-bg p-4">
              <h3 className="text-sm font-semibold text-soc-text mb-3">Observables</h3>
              {observables.length === 0 ? (
                <p className="text-soc-muted text-sm">No observables found.</p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {observables.map((obs, i) => (
                    <ObservablePill key={`${obs.value}-${i}`} item={obs} onCopy={() => toast.success('Copied to clipboard')} />
                  ))}
                </div>
              )}
            </div>

            <h3 className="text-sm font-semibold text-soc-text">IOCs found</h3>
            <div className="flex flex-wrap gap-2">
              {!enrichment && <p className="text-soc-muted text-sm">No enrichment data.</p>}
              {enrichment && [
                ...(enrichment.iocs?.ips ?? []),
                ...(enrichment.iocs?.domains ?? []),
                ...(enrichment.iocs?.hashes ?? []),
                ...(enrichment.iocs?.cves ?? []),
              ].map((ioc, i) => (
                <span key={i} className="rounded px-2 py-1 text-xs bg-soc-border text-soc-muted">{ioc}</span>
              ))}
            </div>
            <h3 className="text-sm font-semibold text-soc-text mt-4">VirusTotal</h3>
            <div className="space-y-2 text-sm">
              {(enrichment?.vt_results ?? []).map((r, i) => (
                <div key={i} className="rounded border border-soc-border p-2">
                  <span className="text-soc-text">{r.indicator}</span>
                  <div className="mt-1 h-2 rounded-full bg-soc-border overflow-hidden">
                    <div className={cn('h-full', (r.malicious_count ?? 0) > 0 ? 'bg-red-500' : 'bg-soc-muted')} style={{ width: `${(r.detection_ratio ?? 0) * 100}%` }} />
                  </div>
                  <p className="text-soc-muted text-xs">Malicious: {r.malicious_count ?? 0} / Total: {r.total_engines ?? 0}</p>
                  {r.permalink && <a href={r.permalink} target="_blank" rel="noopener noreferrer" className="text-blue-400 text-xs">Report</a>}
                </div>
              ))}
              {(enrichment?.vt_results ?? []).length === 0 && <p className="text-soc-muted">No VT results.</p>}
            </div>
            <h3 className="text-sm font-semibold text-soc-text mt-4">AbuseIPDB</h3>
            <div className="space-y-2 text-sm text-soc-muted">
              {(enrichment?.abuse_results ?? []).map((r, i) => (
                <div key={i}>IP: {r.ip} — Score: {r.abuse_score} — ISP: {r.isp ?? '—'} — Country: {r.country_code ?? '—'}</div>
              ))}
              {(enrichment?.abuse_results ?? []).length === 0 && <p>No AbuseIPDB results.</p>}
            </div>
            <h3 className="text-sm font-semibold text-soc-text mt-4">Feed matches</h3>
            <div className="text-sm text-soc-muted">
              {(enrichment?.feed_matches ?? []).length === 0 && <p>None.</p>}
              {(enrichment?.feed_matches ?? []).map((m, i) => <p key={i}>{m.feed_name}: {m.indicator}</p>)}
            </div>
          </div>
        )}

        {tab === 'mitre' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {(alert.mitre_techniques ?? []).map((t, i) => (
              <Card key={i} className="p-3">
                <span className="text-xs text-soc-muted">{t.tactic}</span>
                <div className="flex items-center gap-2 mt-1">
                  <MitreTags techniques={[t]} />
                  <span className="text-soc-text font-medium">{t.technique_name}</span>
                </div>
              </Card>
            ))}
            {(alert.mitre_techniques ?? []).length === 0 && <p className="text-soc-muted text-sm">No MITRE techniques.</p>}
          </div>
        )}

        {tab === 'timeline' && id && (
          <TimelineTab
            alertId={id}
            comment={comment}
            setComment={setComment}
            commentLoading={commentLoading}
            onAddComment={handleAddComment}
            readOnly={isViewer}
          />
        )}

        {tab === 'raw' && (
          <div>
            <button type="button" onClick={handleCopyRaw} className="mb-2 inline-flex items-center gap-1 px-2 py-1 rounded border border-soc-border text-soc-muted hover:text-soc-text text-sm">
              <Copy className="w-4 h-4" /> Copy
            </button>
            <pre className="text-xs text-soc-muted overflow-auto max-h-[400px] bg-soc-bg p-3 rounded border border-soc-border">
              {JSON.stringify(alert.raw ?? {}, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  )
}

const TIMELINE_ACTION_CONFIG: Record<
  string,
  { label: string; Icon: typeof MessageSquare; borderClass: string }
> = {
  comment: { label: 'Comment', Icon: MessageSquare, borderClass: 'border-l-blue-500' },
  alert_updated: { label: 'Alert updated', Icon: Pencil, borderClass: 'border-l-amber-500' },
  decision: { label: 'Decision', Icon: Cpu, borderClass: 'border-l-purple-500' },
  request: { label: 'Request', Icon: Globe, borderClass: 'border-l-soc-border' },
}

function getTimelineActionConfig(action: string) {
  return TIMELINE_ACTION_CONFIG[action] ?? {
    label: action,
    Icon: Activity,
    borderClass: 'border-l-soc-border',
  }
}

function TimelineEntryCard({ entry }: { entry: TimelineItem }) {
  const { label, Icon, borderClass } = getTimelineActionConfig(entry.action)
  const details = entry.details && Object.keys(entry.details).length > 0 ? entry.details : null
  return (
    <div
      className={cn(
        'rounded-lg border border-soc-border border-l-4 bg-soc-bg p-3',
        borderClass
      )}
    >
      <div className="flex items-start gap-3">
        <div className="mt-0.5 shrink-0 rounded bg-soc-surface p-1.5">
          <Icon className="h-4 w-4 text-soc-muted" />
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-soc-text">{label}</p>
          <p className="text-xs text-soc-muted mt-0.5">
            {entry.analyst ?? 'System'} · {formatTimelineTimestamp(entry.timestamp)}
          </p>
          {details && (
            <div className="mt-2 rounded border border-soc-border bg-soc-surface px-2.5 py-2 text-xs">
              <dl className="space-y-1">
                {Object.entries(details).map(([k, v]) => (
                  <div key={k} className="flex gap-2">
                    <dt className="shrink-0 text-soc-muted">{k}:</dt>
                    <dd className="text-soc-text break-all">
                      {typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v)}
                    </dd>
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

function TimelineTab({
  alertId,
  comment,
  setComment,
  commentLoading,
  onAddComment,
  readOnly = false,
}: {
  alertId: string
  comment: string
  setComment: (value: string) => void
  commentLoading: boolean
  onAddComment: () => void
  readOnly?: boolean
}) {
  const { data, isLoading } = useQuery({
    queryKey: ['alert', 'timeline', alertId],
    queryFn: () => getTimeline(alertId),
    enabled: !!alertId,
  })
  const timeline = data?.items ?? []
  if (isLoading) return <Spinner size="md" />
  return (
    <div className="space-y-4">
      {timeline.length === 0 ? (
        <p className="text-soc-muted text-sm">No timeline events.</p>
      ) : (
        <div className="space-y-3">
          {timeline.map((e, i) => (
            <TimelineEntryCard key={`${e.timestamp}-${i}`} entry={e} />
          ))}
        </div>
      )}
      {!readOnly && (
        <div className="mt-4 border-t border-soc-border pt-4">
          <p className="text-xs text-soc-muted mb-2">Add note</p>
          <div className="flex gap-2">
            <input
              type="text"
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && onAddComment()}
              placeholder="Investigation note..."
              className="flex-1 px-3 py-1.5 rounded border border-soc-border 
                   bg-soc-bg text-soc-text text-sm focus:outline-none 
                   focus:border-blue-500"
            />
            <button
              onClick={onAddComment}
              disabled={commentLoading || !comment.trim()}
              className="px-3 py-1.5 rounded bg-blue-600 text-white
                   text-sm hover:bg-blue-700 disabled:opacity-50"
            >
              {commentLoading ? '...' : 'Add'}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

