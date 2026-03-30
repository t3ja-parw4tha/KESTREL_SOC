import { useState, useCallback, useEffect } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Inbox, AlertTriangle, RefreshCw, Keyboard, ChevronDown, ChevronRight, Users2 } from 'lucide-react'
import { get } from '@/api/client'
import { useAlerts } from '@/hooks/useAlerts'
import { useAuth } from '@/security/AuthContext'
import { AlertTable } from '@/components/alerts/AlertTable'
import { AlertFilters } from '@/components/alerts/AlertFilters'
import { bulkPatchAlerts, patchAlert, type BulkPatchBody } from '@/api/alerts'
import { toast } from 'sonner'
import { cn } from '@/utils/cn'
import type { Alert } from '@/types/alert'

interface PendingBulk { payload: BulkPatchBody; count: number }

function bulkMessage(payload: BulkPatchBody, count: number): string {
  const n = `${count} alert${count > 1 ? 's' : ''}`
  if (payload.status === 'false_positive') return `Mark ${n} as false positive? This cannot be easily undone.`
  if (payload.assigned_to) return `Assign ${n} to ${payload.assigned_to}?`
  if (payload.status) return `Update ${n} to "${payload.status.replace('_', ' ')}"?`
  return `Update ${n}?`
}

function csvField(value: string | number | null | undefined): string {
  const s = String(value ?? '')
  return s.includes(',') || s.includes('\n') || s.includes('"') ? `"${s.replace(/"/g, '""')}"` : s
}

function exportAlertsCSV(alerts: Alert[]) {
  const headers = ['ID', 'Title', 'Source', 'Severity', 'Status', 'Category', 'Risk Score', 'Assigned To', 'Created At']
  const rows = alerts.map((a) => [
    csvField(a.id), csvField(a.title), csvField(a.source), csvField(a.severity),
    csvField(a.status), csvField(a.category), csvField(a.risk_score),
    csvField(a.assigned_to), csvField(a.created_at),
  ])
  const csv = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n')
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `soc-alerts-${new Date().toISOString().slice(0, 10)}.csv`
  document.body.appendChild(link)
  link.click()
  setTimeout(() => { document.body.removeChild(link); URL.revokeObjectURL(url) }, 100)
}

const PAGE_SIZE = 20
type SortKey = 'severity' | 'risk_score' | 'created_at'
type QueueMode = 'all' | 'mine'

// ─── Queue Ops Panel (P6-3) ───────────────────────────────────────────────────
interface QueueStats {
  total_open: number
  unassigned_count: number
  workload: Array<{ analyst: string; count: number }>
  stale_assignments: Array<{ analyst: string; stale_count: number }>
  queue_by_severity: Record<string, number>
}

function QueueOpsPanel() {
  const [open, setOpen] = useState(false)
  const { data } = useQuery({
    queryKey: ['alerts-queue-stats'],
    queryFn: () => get<QueueStats>('/alerts/queue/stats'),
    refetchInterval: 60_000,
    enabled: open,
  })

  const SEVERITY_COLORS: Record<string, string> = {
    Critical: 'text-red-400', High: 'text-orange-400', Medium: 'text-amber-400', Low: 'text-blue-400',
  }

  return (
    <div className="glass-card rounded-xl border border-border/50 overflow-hidden">
      <button type="button" onClick={() => setOpen(v => !v)}
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-muted/20 transition-colors">
        <Users2 className="w-4 h-4 text-muted-foreground" />
        <span className="text-sm font-medium text-foreground flex-1 text-left">Queue Operations</span>
        {data && (
          <span className="text-xs text-muted-foreground mr-2">
            {data.total_open} open · {data.unassigned_count} unassigned
            {data.stale_assignments.length > 0 && <span className="text-amber-400 ml-2">⚠ {data.stale_assignments.length} stale</span>}
          </span>
        )}
        {open ? <ChevronDown className="w-4 h-4 text-muted-foreground" /> : <ChevronRight className="w-4 h-4 text-muted-foreground" />}
      </button>
      {open && data && (
        <div className="border-t border-border/50 p-4 grid grid-cols-1 sm:grid-cols-3 gap-4">
          {/* Severity breakdown */}
          <div>
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-2">Queue by Severity</p>
            <div className="space-y-1">
              {Object.entries(data.queue_by_severity).map(([sev, cnt]) => (
                <div key={sev} className="flex items-center justify-between text-xs">
                  <span className={cn('font-medium', SEVERITY_COLORS[sev] ?? 'text-muted-foreground')}>{sev}</span>
                  <span className="text-foreground font-mono">{cnt}</span>
                </div>
              ))}
              {Object.keys(data.queue_by_severity).length === 0 && <p className="text-xs text-muted-foreground">Queue empty</p>}
            </div>
          </div>
          {/* Analyst workload */}
          <div>
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-2">Analyst Workload</p>
            <div className="space-y-1.5">
              {data.workload.slice(0, 6).map(({ analyst, count }) => {
                const max = Math.max(...data.workload.map(w => w.count), 1)
                return (
                  <div key={analyst} className="flex items-center gap-2 text-xs">
                    <span className="text-muted-foreground truncate w-28" title={analyst}>{analyst}</span>
                    <div className="flex-1 h-1.5 rounded-full bg-muted overflow-hidden">
                      <div className="h-full rounded-full bg-blue-500" style={{ width: `${Math.round((count / max) * 100)}%` }} />
                    </div>
                    <span className="font-mono text-foreground w-4 text-right">{count}</span>
                  </div>
                )
              })}
              {data.workload.length === 0 && <p className="text-xs text-muted-foreground">No assigned alerts</p>}
            </div>
          </div>
          {/* Stale assignments */}
          <div>
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-2">Stale (&gt;24h no update)</p>
            {data.stale_assignments.length === 0 ? (
              <p className="text-xs text-emerald-400">No stale assignments</p>
            ) : (
              <div className="space-y-1">
                {data.stale_assignments.map(({ analyst, stale_count }) => (
                  <div key={analyst} className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground truncate w-28" title={analyst}>{analyst}</span>
                    <span className="text-amber-400 font-mono">{stale_count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

export function Alerts() {
  const [searchParams, setSearchParams] = useSearchParams()
  const navigate = useNavigate()
  const { user } = useAuth()
  const [queueMode, setQueueMode] = useState<QueueMode>('all')
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [bulkLoading, setBulkLoading] = useState(false)
  const [pendingBulk, setPendingBulk] = useState<PendingBulk | null>(null)
  const [sortKey, setSortKey] = useState<SortKey>('created_at')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')
  const [triageMode, setTriageMode] = useState(false)
  const [triageIdx, setTriageIdx] = useState(0)

  const page     = Math.max(1, parseInt(searchParams.get('page') ?? '1', 10))
  const severity = searchParams.get('severity') ?? undefined
  const status   = searchParams.get('status') ?? undefined
  const source   = searchParams.get('source') ?? ''
  const category = searchParams.get('category') ?? ''
  const search   = searchParams.get('search') ?? ''
  const dateFrom = searchParams.get('date_from') ?? undefined
  const dateTo   = searchParams.get('date_to') ?? undefined

  // Clear selection whenever filter params change (#3)
  useEffect(() => {
    setSelectedIds(new Set())
  }, [severity, status, source, category, search, queueMode, dateFrom, dateTo])

  const { data, isLoading, isFetching, refetch } = useAlerts({
    page,
    limit: PAGE_SIZE,
    severity: severity || undefined,
    status: status || undefined,
    source: source || undefined,
    category: category || undefined,
    search: search || undefined,
    date_from: dateFrom || undefined,
    date_to: dateTo || undefined,
    assigned_to: queueMode === 'mine' ? (user?.username ?? undefined) : undefined,
    sort_by: sortKey,
    sort_dir: sortDir,
  })

  const alerts = data?.alerts ?? []

  // ─── Keyboard triage mode ─────────────────────────────────────────────────
  useEffect(() => {
    if (!triageMode) return
    const handler = (e: KeyboardEvent) => {
      // Don't fire when typing in inputs
      const tag = (e.target as HTMLElement)?.tagName
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return

      const current = alerts[triageIdx]
      if (e.key === 'j' || e.key === 'ArrowDown') {
        e.preventDefault()
        setTriageIdx(i => Math.min(i + 1, alerts.length - 1))
      } else if (e.key === 'k' || e.key === 'ArrowUp') {
        e.preventDefault()
        setTriageIdx(i => Math.max(i - 1, 0))
      } else if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault()
        if (current) navigate(`/app/alerts/${current.id}`)
      } else if (e.key === 'a' && current) {
        e.preventDefault()
        if (user?.username) {
          patchAlert(current.id, { assigned_to: user.username }).then(() => toast.success(`Assigned ${current.id} to you`))
        }
      } else if (e.key === 'r' && current) {
        e.preventDefault()
        patchAlert(current.id, { status: 'resolved' }).then(() => toast.success(`Resolved ${current.id}`))
      } else if (e.key === 'Escape') {
        setTriageMode(false)
        toast.info('Triage mode off')
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [triageMode, triageIdx, alerts, navigate, user])

  const setPage = useCallback((p: number) => {
    setSearchParams((prev) => { const next = new URLSearchParams(prev); next.set('page', String(p)); return next })
  }, [setSearchParams])

  const handleQueueSwitch = useCallback((mode: QueueMode) => {
    setQueueMode(mode)
    setSearchParams((prev) => { const next = new URLSearchParams(prev); next.set('page', '1'); return next })
  }, [setSearchParams])

  const handleSort = useCallback((key: SortKey) => {
    setSortKey(key)
    setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    setSearchParams((prev) => { const next = new URLSearchParams(prev); next.set('page', '1'); return next })
  }, [setSearchParams])

  const executeBulk = useCallback(async (payload: BulkPatchBody) => {
    setBulkLoading(true)
    setPendingBulk(null)
    try {
      const res = await bulkPatchAlerts({
        alert_ids: payload.alert_ids,
        status: payload.status,
        assigned_to: payload.assigned_to ?? undefined,
        assign_comment: payload.assign_comment,
      })
      toast.success(`Updated ${res.updated} alert(s)`)
      if (res.failed > 0) toast.warning(`${res.failed} alert(s) could not be updated`)
      setSelectedIds(new Set())
      refetch()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Bulk update failed')
    } finally {
      setBulkLoading(false)
    }
  }, [refetch])

  const handleBulkAction = useCallback((_action: 'status' | 'assign_me' | 'false_positive', payload: BulkPatchBody) => {
    if (!payload.alert_ids.length) return
    setPendingBulk({ payload, count: payload.alert_ids.length })
  }, [])

  return (
    <div className="space-y-4">
      {/* P6-3: Queue operations panel */}
      <QueueOpsPanel />

      {/* Bulk confirmation bar */}
      {pendingBulk && (
        <div className="flex flex-wrap items-center gap-3 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
          <span className="text-sm text-amber-200 flex-1">{bulkMessage(pendingBulk.payload, pendingBulk.count)}</span>
          <button type="button" onClick={() => executeBulk(pendingBulk.payload)}
            className="px-3 py-1.5 rounded bg-amber-500 text-black text-sm font-medium hover:bg-amber-400">
            Confirm
          </button>
          <button type="button" onClick={() => setPendingBulk(null)}
            className="px-3 py-1.5 rounded border border-border text-muted-foreground text-sm hover:text-foreground">
            Cancel
          </button>
        </div>
      )}

      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-lg font-bold tracking-tight">Alerts</h1>
          <p className="text-xs text-muted-foreground">
            Monitor and manage security alerts across all sources
          </p>
        </div>
        <div className="flex items-center gap-2">
          {/* Triage mode toggle */}
          <button type="button" onClick={() => { setTriageMode(v => !v); if (!triageMode) toast.info('Triage mode: j/k navigate, a assign, r resolve, Esc exit') }}
            title="Quick triage mode (keyboard)"
            className={cn('inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors',
              triageMode ? 'border-primary bg-primary/10 text-primary' : 'border-border bg-card text-muted-foreground hover:text-foreground')}>
            <Keyboard className="w-3.5 h-3.5" /> Triage
          </button>

          {/* Queue toggle */}
          <div className="flex rounded-lg overflow-hidden border border-border text-sm">
            <button type="button" onClick={() => handleQueueSwitch('all')}
              className={cn('px-4 py-1.5 transition-colors text-xs font-medium',
                queueMode === 'all' ? 'gradient-primary text-primary-foreground' : 'bg-card text-muted-foreground hover:text-foreground')}>
              All Alerts
            </button>
            <button type="button" onClick={() => handleQueueSwitch('mine')}
              className={cn('px-4 py-1.5 flex items-center gap-1.5 transition-colors text-xs font-medium',
                queueMode === 'mine' ? 'gradient-primary text-primary-foreground' : 'bg-card text-muted-foreground hover:text-foreground')}>
              <Inbox className="w-3.5 h-3.5" />
              My Queue
              {queueMode === 'mine' && (data?.total ?? 0) > 0 && (
                <span className="min-w-[18px] px-1 rounded-full text-xs font-medium bg-black/20 text-white">
                  {(data?.total ?? 0) > 99 ? '99+' : data?.total}
                </span>
              )}
            </button>
          </div>
        </div>
      </div>

      {queueMode === 'mine' && data?.total === 0 && !isLoading && (
        <div className="glass-card rounded-xl p-6 text-center">
          <Inbox className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
          <p className="font-medium">Your queue is empty</p>
          <p className="text-sm text-muted-foreground mt-1">
            No alerts are assigned to <strong>{user?.username}</strong>.
          </p>
        </div>
      )}

      <AlertFilters
        severity={severity}
        status={status}
        source={source}
        category={category}
        search={search}
        dateFrom={dateFrom}
        dateTo={dateTo}
        onExport={alerts.length > 0 ? () => exportAlertsCSV(alerts) : undefined}
        onRefresh={refetch}
      />

      {/* Triage mode banner */}
      {triageMode && (
        <div className="flex items-center gap-3 px-4 py-2 rounded-lg bg-primary/10 border border-primary/30 text-xs text-primary">
          <Keyboard className="w-3.5 h-3.5 shrink-0" />
          <span>Triage mode active — <kbd className="px-1 py-0.5 rounded bg-primary/20 font-mono">j/k</kbd> navigate · <kbd className="px-1 py-0.5 rounded bg-primary/20 font-mono">a</kbd> assign to me · <kbd className="px-1 py-0.5 rounded bg-primary/20 font-mono">r</kbd> resolve · <kbd className="px-1 py-0.5 rounded bg-primary/20 font-mono">Enter</kbd> open · <kbd className="px-1 py-0.5 rounded bg-primary/20 font-mono">Esc</kbd> exit</span>
          <span className="ml-auto font-semibold">Row {triageIdx + 1}/{alerts.length}</span>
        </div>
      )}

      {/* Table with isFetching overlay (#15) */}
      <div className="relative">
        {isFetching && !isLoading && (
          <div className="absolute inset-0 z-10 flex items-center justify-center rounded-xl bg-background/40 backdrop-blur-[2px]">
            <div className="flex items-center gap-2 text-xs text-muted-foreground bg-card border border-border rounded-full px-3 py-1.5 shadow">
              <RefreshCw className="w-3 h-3 animate-spin" /> Updating…
            </div>
          </div>
        )}
        <AlertTable
          alerts={alerts}
          total={data?.total ?? 0}
          loading={isLoading || bulkLoading}
          page={page}
          pageSize={PAGE_SIZE}
          onPageChange={setPage}
          sortKey={sortKey}
          sortDir={sortDir}
          onSort={handleSort}
          selectedIds={selectedIds}
          onSelectionChange={setSelectedIds}
          onBulkAction={handleBulkAction}
          currentUsername={user?.username}
          focusedAlertId={triageMode ? (alerts[triageIdx]?.id ?? null) : null}
        />
      </div>
    </div>
  )
}
