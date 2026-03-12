import { useNavigate } from 'react-router-dom'
import {
  Table,
  TableHead,
  TableBody,
  TableRow,
  TableHeader,
  TableCell,
} from '@/components/ui/Table'
import { AlertBadge } from './AlertBadge'
import { MitreTags } from './MitreTags'
import { Badge } from '@/components/ui/Badge'
import { formatRelativeTime } from '@/utils/time'
import { getRiskScoreColor } from '@/utils/severity'
import { EmptyState } from '@/components/ui/EmptyState'
import { ChevronUp, ChevronDown } from 'lucide-react'
import { cn } from '@/utils/cn'
import type { Alert } from '@/types/alert'

type SortKey = 'severity' | 'risk_score' | 'created_at'
type SortDir = 'asc' | 'desc'

interface AlertTableProps {
  alerts: Alert[]
  total?: number
  loading?: boolean
  page?: number
  pageSize?: number
  onPageChange?: (page: number) => void
  sortKey?: SortKey
  sortDir?: SortDir
  onSort?: (key: SortKey) => void
  /** Bulk selection and actions */
  selectedIds?: Set<string>
  onSelectionChange?: (ids: Set<string>) => void
  onBulkAction?: (action: 'status' | 'assign_me' | 'false_positive', payload: { alert_ids: string[]; status?: string; assigned_to?: string | null; assign_comment?: string }) => void
  currentUsername?: string | null
}

const SEVERITY_ORDER: Record<string, number> = { Critical: 4, High: 3, Medium: 2, Low: 1 }

function sortAlerts(alerts: Alert[], sortKey: SortKey, sortDir: SortDir): Alert[] {
  const arr = [...alerts]
  arr.sort((a, b) => {
    let cmp = 0
    if (sortKey === 'severity') {
      cmp = (SEVERITY_ORDER[a.severity] ?? 0) - (SEVERITY_ORDER[b.severity] ?? 0)
    } else if (sortKey === 'risk_score') {
      cmp = (a.risk_score ?? 0) - (b.risk_score ?? 0)
    } else {
      cmp = (a.created_at || '').localeCompare(b.created_at || '')
    }
    return sortDir === 'asc' ? cmp : -cmp
  })
  return arr
}

function TableSkeleton() {
  return (
    <div className="space-y-2">
      {[1, 2, 3, 4, 5, 6, 7, 8].map((i) => (
        <div key={i} className="h-12 rounded bg-soc-border/30 animate-pulse" />
      ))}
    </div>
  )
}

export function AlertTable({
  alerts,
  total = 0,
  loading,
  page = 1,
  pageSize = 20,
  onPageChange,
  sortKey = 'created_at',
  sortDir = 'desc',
  onSort,
  selectedIds = new Set(),
  onSelectionChange,
  onBulkAction,
  currentUsername,
}: AlertTableProps) {
  const navigate = useNavigate()
  const sorted = sortAlerts(alerts, sortKey, sortDir)
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const hasSelection = selectedIds.size > 0
  const pageIds = sorted.map((a) => a.id)
  const allOnPageSelected = pageIds.length > 0 && pageIds.every((id) => selectedIds.has(id))

  const toggleSelect = (id: string) => {
    if (!onSelectionChange) return
    const next = new Set(selectedIds)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    onSelectionChange(next)
  }
  const toggleSelectAllOnPage = () => {
    if (!onSelectionChange) return
    if (allOnPageSelected) {
      const next = new Set(selectedIds)
      pageIds.forEach((id) => next.delete(id))
      onSelectionChange(next)
    } else {
      const next = new Set(selectedIds)
      pageIds.forEach((id) => next.add(id))
      onSelectionChange(next)
    }
  }
  const handleBulkStatus = (status: string) => {
    if (!onBulkAction || !hasSelection) return
    onBulkAction('status', { alert_ids: Array.from(selectedIds), status })
  }
  const handleBulkAssignMe = () => {
    if (!onBulkAction || !hasSelection || !currentUsername) return
    onBulkAction('assign_me', { alert_ids: Array.from(selectedIds), assigned_to: currentUsername })
  }
  const handleBulkFalsePositive = () => {
    if (!onBulkAction || !hasSelection) return
    onBulkAction('false_positive', { alert_ids: Array.from(selectedIds), status: 'false_positive' })
  }

  const SortIcon = ({ column }: { column: SortKey }) => {
    if (sortKey !== column) return null
    return sortDir === 'asc' ? <ChevronUp className="w-4 h-4 inline" /> : <ChevronDown className="w-4 h-4 inline" /> 
  }

  if (loading) return <TableSkeleton />
  if (!alerts.length) {
    return (
      <EmptyState
        title="No alerts match filters"
        description="Try adjusting severity, status, or search."
      />
    )
  }

  return (
    <div className="space-y-4">
      {hasSelection && onBulkAction && (
        <div className="flex flex-wrap items-center gap-2 p-3 rounded-lg border border-soc-border bg-soc-surface">
          <span className="text-sm text-soc-muted">{selectedIds.size} selected</span>
          <button
            type="button"
            onClick={() => handleBulkStatus('in_progress')}
            className="px-3 py-1.5 text-sm rounded border border-soc-border bg-soc-bg text-soc-text hover:bg-soc-border/50"
          >
            Set In Progress
          </button>
          <button
            type="button"
            onClick={() => handleBulkStatus('resolved')}
            className="px-3 py-1.5 text-sm rounded border border-soc-border bg-soc-bg text-soc-text hover:bg-soc-border/50"
          >
            Resolve
          </button>
          <button
            type="button"
            onClick={handleBulkFalsePositive}
            className="px-3 py-1.5 text-sm rounded border border-soc-border bg-soc-bg text-soc-text hover:bg-soc-border/50"
          >
            Mark False Positive
          </button>
          {currentUsername && (
            <button
              type="button"
              onClick={handleBulkAssignMe}
              className="px-3 py-1.5 text-sm rounded border border-blue-500/50 bg-blue-500/10 text-blue-400 hover:bg-blue-500/20"
            >
              Assign to me
            </button>
          )}
          <button
            type="button"
            onClick={() => onSelectionChange?.(new Set())}
            className="px-3 py-1.5 text-sm rounded border border-soc-border text-soc-muted hover:text-soc-text"
          >
            Clear selection
          </button>
        </div>
      )}
      <Table>
        <TableHead>
          <TableRow>
            {onSelectionChange && (
              <TableHeader className="w-10">
                <input
                  type="checkbox"
                  checked={allOnPageSelected}
                  onChange={toggleSelectAllOnPage}
                  onClick={(e) => e.stopPropagation()}
                  aria-label="Select all on page"
                  className="rounded border-soc-border"
                />
              </TableHeader>
            )}
            <TableHeader>
              <button type="button" onClick={() => onSort?.('severity')} className="flex items-center gap-1 hover:text-soc-text">
                Severity <SortIcon column="severity" />
              </button>
            </TableHeader>
            <TableHeader>Title</TableHeader>
            <TableHeader>Source</TableHeader>
            <TableHeader>Category</TableHeader>
            <TableHeader>MITRE</TableHeader>
            <TableHeader>
              <button type="button" onClick={() => onSort?.('risk_score')} className="flex items-center gap-1 hover:text-soc-text">
                Risk <SortIcon column="risk_score" />
              </button>
            </TableHeader>
            <TableHeader>Status</TableHeader>
            <TableHeader>Assigned</TableHeader>
            <TableHeader>
              <button type="button" onClick={() => onSort?.('created_at')} className="flex items-center gap-1 hover:text-soc-text">
                Time <SortIcon column="created_at" />
              </button>
            </TableHeader>
          </TableRow>
        </TableHead>
        <TableBody>
          {sorted.map((alert) => (
            <TableRow
              key={alert.id}
              onClick={() => navigate(`/app/alerts/${alert.id}`)}
              className="cursor-pointer hover:bg-soc-border/30"
            >
              {onSelectionChange && (
                <TableCell onClick={(e) => e.stopPropagation()}>
                  <input
                    type="checkbox"
                    checked={selectedIds.has(alert.id)}
                    onChange={() => toggleSelect(alert.id)}
                    aria-label={`Select ${alert.id}`}
                    className="rounded border-soc-border"
                  />
                </TableCell>
              )}
              <TableCell>
                <AlertBadge severity={alert.severity} />
              </TableCell>
              <TableCell className="font-medium max-w-[220px] truncate" title={alert.title}>{alert.title}</TableCell>
              <TableCell className="text-soc-muted">{alert.source}</TableCell>
              <TableCell className="text-soc-muted">{alert.category}</TableCell>
              <TableCell>
                {alert.mitre_techniques?.length ? (
                  <MitreTags techniques={alert.mitre_techniques} />
                ) : (
                  <span className="text-soc-muted">—</span>
                )}
              </TableCell>
              <TableCell>
                <span className={cn('font-medium', getRiskScoreColor(alert.risk_score))}>
                  {alert.risk_score ?? '—'}
                </span>
              </TableCell>
              <TableCell>
                <Badge status={alert.status}>{alert.status?.replace('_', ' ')}</Badge>
              </TableCell>
              <TableCell className="text-soc-muted">{alert.assigned_to ?? '—'}</TableCell>
              <TableCell className="text-soc-muted">{formatRelativeTime(alert.created_at)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {total > pageSize && onPageChange && (
        <div className="flex justify-between items-center text-sm text-soc-muted">
          <span>
            {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, total)} of {total}
          </span>
          <div className="flex gap-2">
            <button
              type="button"
              disabled={page <= 1}
              onClick={() => onPageChange(page - 1)}
              className="px-3 py-1.5 rounded border border-soc-border disabled:opacity-50 hover:bg-soc-border/30 text-soc-text"
            >
              Previous
            </button>
            <button
              type="button"
              disabled={page >= totalPages}
              onClick={() => onPageChange(page + 1)}
              className="px-3 py-1.5 rounded border border-soc-border disabled:opacity-50 hover:bg-soc-border/30 text-soc-text"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
