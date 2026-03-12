import { useState, useCallback, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Inbox, AlertTriangle, Download } from 'lucide-react'
import { useAlerts } from '@/hooks/useAlerts'
import { useAuth } from '@/security/AuthContext'
import { AlertTable } from '@/components/alerts/AlertTable'
import { AlertFilters } from '@/components/alerts/AlertFilters'
import { bulkPatchAlerts, type BulkPatchBody } from '@/api/alerts'
import { toast } from 'sonner'
import { cn } from '@/utils/cn'
import type { Alert } from '@/types/alert'

/** Pending bulk action — message is derived at render, not stored */
interface PendingBulk {
  payload: BulkPatchBody
  count: number
}

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
    csvField(a.id),
    csvField(a.title),
    csvField(a.source),
    csvField(a.severity),
    csvField(a.status),
    csvField(a.category),
    csvField(a.risk_score),
    csvField(a.assigned_to),
    csvField(a.created_at),
  ])
  const csv = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n')
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `kestrel-alerts-${new Date().toISOString().slice(0, 10)}.csv`
  document.body.appendChild(link)
  link.click()
  setTimeout(() => {
    document.body.removeChild(link)
    URL.revokeObjectURL(url)
  }, 100)
}

const PAGE_SIZE = 20
type SortKey = 'severity' | 'risk_score' | 'created_at'
type QueueMode = 'all' | 'mine'

export function Alerts() {
  const [searchParams, setSearchParams] = useSearchParams()
  const { user } = useAuth()
  const [queueMode, setQueueMode] = useState<QueueMode>('all')
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [bulkLoading, setBulkLoading] = useState(false)
  const [pendingBulk, setPendingBulk] = useState<PendingBulk | null>(null)

  const page = Math.max(1, parseInt(searchParams.get('page') ?? '1', 10))
  const severity = searchParams.get('severity') ?? undefined
  const status = searchParams.get('status') ?? undefined
  const source = searchParams.get('source') ?? ''
  const category = searchParams.get('category') ?? ''
  const search = searchParams.get('search') ?? ''

  const [sortKey, setSortKey] = useState<SortKey>('created_at')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')

  const { data, isLoading, refetch } = useAlerts({
    page,
    limit: PAGE_SIZE,
    severity: severity || undefined,
    status: status || undefined,
    source: source || undefined,
    category: category || undefined,
    search: search || undefined,
    assigned_to: queueMode === 'mine' ? (user?.username ?? undefined) : undefined,
  })

  const setPage = useCallback(
    (p: number) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev)
        next.set('page', String(p))
        return next
      })
    },
    [setSearchParams]
  )

  const handleQueueSwitch = useCallback((mode: QueueMode) => {
    setQueueMode(mode)
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      next.set('page', '1')
      return next
    })
  }, [setSearchParams])

  const handleSort = useCallback((key: SortKey) => {
    setSortKey(key)
    setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
  }, [])

  const executeBulk = useCallback(
    async (payload: BulkPatchBody) => {
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
    },
    [refetch]
  )

  const handleBulkAction = useCallback(
    (_action: 'status' | 'assign_me' | 'false_positive', payload: BulkPatchBody) => {
      if (!payload.alert_ids.length) return
      setPendingBulk({ payload, count: payload.alert_ids.length })
    },
    []
  )

  const sortedAlerts = useMemo(() => {
    const items = [...(data?.alerts ?? [])]
    return items.sort((a, b) => {
      if (sortKey === 'severity') {
        const order = { Critical: 0, High: 1, Medium: 2, Low: 3 }
        const aVal = order[a.severity as keyof typeof order] ?? 4
        const bVal = order[b.severity as keyof typeof order] ?? 4
        return sortDir === 'asc' ? aVal - bVal : bVal - aVal
      }
      if (sortKey === 'risk_score') {
        const aVal = a.risk_score ?? 0
        const bVal = b.risk_score ?? 0
        return sortDir === 'asc' ? aVal - bVal : bVal - aVal
      }
      const aDate = a.created_at ?? ''
      const bDate = b.created_at ?? ''
      return sortDir === 'asc' ? aDate.localeCompare(bDate) : bDate.localeCompare(aDate)
    })
  }, [data?.alerts, sortKey, sortDir])

  return (
    <div className="space-y-4">
      {/* Inline bulk action confirmation bar */}
      {pendingBulk && (
        <div className="flex flex-wrap items-center gap-3 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
          <span className="text-sm text-amber-200 flex-1">{bulkMessage(pendingBulk.payload, pendingBulk.count)}</span>
          <button
            type="button"
            onClick={() => executeBulk(pendingBulk.payload)}
            className="px-3 py-1.5 rounded bg-amber-500 text-black text-sm font-medium hover:bg-amber-400"
          >
            Confirm
          </button>
          <button
            type="button"
            onClick={() => setPendingBulk(null)}
            className="px-3 py-1.5 rounded border border-soc-border text-soc-muted text-sm hover:text-soc-text"
          >
            Cancel
          </button>
        </div>
      )}

      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <h1 className="text-2xl font-semibold text-soc-text">Alerts</h1>
        <div className="flex items-center gap-2">
          {/* Export CSV */}
          {sortedAlerts.length > 0 && (
            <button
              type="button"
              onClick={() => exportAlertsCSV(sortedAlerts)}
              title="Export current page as CSV"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-soc-border bg-soc-surface text-soc-muted hover:text-soc-text text-sm transition-colors"
            >
              <Download className="w-4 h-4" />
              <span className="hidden sm:inline">Export CSV</span>
            </button>
          )}
          {/* My Queue / All Alerts toggle */}
          <div className="flex rounded-lg border border-soc-border overflow-hidden text-sm self-start sm:self-auto">
          <button
            type="button"
            onClick={() => handleQueueSwitch('all')}
            className={cn(
              'px-4 py-1.5 transition-colors',
              queueMode === 'all'
                ? 'bg-blue-600 text-soc-bg dark:text-white'
                : 'bg-soc-surface text-soc-muted hover:text-soc-text'
            )}
          >
            All Alerts
          </button>
          <button
            type="button"
            onClick={() => handleQueueSwitch('mine')}
            className={cn(
              'px-4 py-1.5 flex items-center gap-1.5 transition-colors',
              queueMode === 'mine'
                ? 'bg-blue-600 text-soc-bg dark:text-white'
                : 'bg-soc-surface text-soc-muted hover:text-soc-text'
            )}
          >
            <Inbox className="w-3.5 h-3.5" />
            My Queue
            {queueMode === 'mine' && (data?.total ?? 0) > 0 && (
              <span className="min-w-[18px] px-1 rounded-full text-xs font-medium bg-black/20 dark:bg-white/20 text-soc-bg dark:text-white">
                {(data?.total ?? 0) > 99 ? '99+' : data?.total}
              </span>
            )}
          </button>
          </div>
        </div>
      </div>

      {queueMode === 'mine' && data?.total === 0 && !isLoading && (
        <div className="rounded-lg border border-soc-border bg-soc-surface p-6 text-center">
          <Inbox className="w-8 h-8 text-soc-muted mx-auto mb-2" />
          <p className="text-soc-text font-medium">Your queue is empty</p>
          <p className="text-sm text-soc-muted mt-1">
            No alerts are assigned to <strong>{user?.username}</strong>. A senior analyst or admin can assign alerts to you.
          </p>
        </div>
      )}

      <AlertFilters
        severity={severity}
        status={status}
        source={source}
        category={category}
        search={search}
      />
      <AlertTable
        alerts={sortedAlerts}
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
      />
    </div>
  )
}
