import { useNavigate } from 'react-router-dom'
import { AlertBadge } from './AlertBadge'
import { formatRelativeTime, getSlaStatus } from '@/utils/time'
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
  selectedIds?: Set<string>
  onSelectionChange?: (ids: Set<string>) => void
  onBulkAction?: (action: 'status' | 'assign_me' | 'false_positive', payload: { alert_ids: string[]; status?: string; assigned_to?: string | null; assign_comment?: string }) => void
  currentUsername?: string | null
  focusedAlertId?: string | null
}

const STATUS_COLORS: Record<string, string> = {
  open:           'bg-primary/15 text-primary',
  new:            'bg-primary/15 text-primary',
  in_progress:    'bg-amber-500/15 text-amber-400',
  resolved:       'bg-emerald-500/15 text-emerald-400',
  false_positive: 'bg-muted text-muted-foreground',
  closed:         'bg-muted text-muted-foreground',
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
    <div className="glass-card overflow-hidden rounded-xl">
      {[1, 2, 3, 4, 5, 6].map((i) => (
        <div key={i} className="h-[52px] border-b border-border/30 bg-muted/10 animate-pulse" />
      ))}
    </div>
  )
}

function Checkbox({ checked, indeterminate, onChange, label }: {
  checked: boolean; indeterminate?: boolean; onChange: () => void; label: string
}) {
  return (
    <button
      type="button"
      onClick={(e) => { e.stopPropagation(); onChange() }}
      aria-label={label}
      className={cn(
        'w-4 h-4 rounded border flex items-center justify-center shrink-0 transition-all',
        checked || indeterminate
          ? 'border-primary bg-primary'
          : 'border-border/60 bg-transparent hover:border-primary/60'
      )}
    >
      {indeterminate && !checked && (
        <span className="block w-2 h-0.5 bg-white rounded" />
      )}
      {checked && (
        <svg className="w-2.5 h-2.5 text-white" viewBox="0 0 10 8" fill="none">
          <path d="M1 4l3 3 5-6" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      )}
    </button>
  )
}

const thCls = 'px-3 py-3 text-left text-[11px] font-semibold text-muted-foreground uppercase tracking-wider'
const tdCls = 'px-3 py-3 text-sm'

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
  focusedAlertId = null,
}: AlertTableProps) {
  const navigate = useNavigate()
  const sorted = sortAlerts(alerts, sortKey, sortDir)
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const hasSelection = selectedIds.size > 0
  const pageIds = sorted.map((a) => a.id)
  const allSelected = pageIds.length > 0 && pageIds.every((id) => selectedIds.has(id))
  const someSelected = !allSelected && pageIds.some((id) => selectedIds.has(id))

  const toggle = (id: string) => {
    if (!onSelectionChange) return
    const next = new Set(selectedIds)
    next.has(id) ? next.delete(id) : next.add(id)
    onSelectionChange(next)
  }

  const toggleAll = () => {
    if (!onSelectionChange) return
    if (allSelected) {
      const next = new Set(selectedIds)
      pageIds.forEach((id) => next.delete(id))
      onSelectionChange(next)
    } else {
      const next = new Set(selectedIds)
      pageIds.forEach((id) => next.add(id))
      onSelectionChange(next)
    }
  }

  const SortIcon = ({ col }: { col: SortKey }) => {
    if (sortKey !== col) return null
    return sortDir === 'asc'
      ? <ChevronUp className="w-3 h-3 inline ml-0.5" />
      : <ChevronDown className="w-3 h-3 inline ml-0.5" />
  }

  if (loading) return <TableSkeleton />

  return (
    <div className="space-y-4">
      {/* Bulk action bar */}
      {hasSelection && onBulkAction && (
        <div className="flex flex-wrap items-center gap-2 px-3 py-2 rounded-lg border border-border/50 bg-card/80 text-xs">
          <span className="text-muted-foreground">{selectedIds.size} selected</span>
          <button type="button" onClick={() => onBulkAction('status', { alert_ids: Array.from(selectedIds), status: 'in_progress' })}
            className="px-2.5 py-1 rounded border border-border bg-background hover:bg-muted/50 text-foreground">Set In Progress</button>
          <button type="button" onClick={() => onBulkAction('status', { alert_ids: Array.from(selectedIds), status: 'resolved' })}
            className="px-2.5 py-1 rounded border border-border bg-background hover:bg-muted/50 text-foreground">Resolve</button>
          <button type="button" onClick={() => onBulkAction('false_positive', { alert_ids: Array.from(selectedIds), status: 'false_positive' })}
            className="px-2.5 py-1 rounded border border-border bg-background hover:bg-muted/50 text-foreground">False Positive</button>
          {currentUsername && (
            <button type="button" onClick={() => onBulkAction('assign_me', { alert_ids: Array.from(selectedIds), assigned_to: currentUsername })}
              className="px-2.5 py-1 rounded border border-blue-500/40 bg-blue-500/10 text-blue-400 hover:bg-blue-500/20">Assign to me</button>
          )}
          <button type="button" onClick={() => onSelectionChange?.(new Set())}
            className="px-2.5 py-1 rounded border border-border text-muted-foreground hover:text-foreground ml-auto">Clear</button>
        </div>
      )}

      {/* Table */}
      <div className="glass-card overflow-hidden">
        {alerts.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-14 text-muted-foreground">
            <p className="text-sm">No alerts match your filters</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border/50 hover:bg-transparent">
                  {onSelectionChange && (
                    <th className="px-3 py-3 w-10">
                      <Checkbox checked={allSelected} indeterminate={someSelected} onChange={toggleAll} label="Select all" />
                    </th>
                  )}
                  <th className={thCls}>ID</th>
                  <th className={thCls}>Alert</th>
                  <th className={cn(thCls, 'cursor-pointer select-none')} onClick={() => onSort?.('severity')}>
                    Severity <SortIcon col="severity" />
                  </th>
                  <th className={thCls}>Status</th>
                  <th className={thCls}>Source</th>
                  <th className={thCls}>MITRE</th>
                  <th className={cn(thCls, 'cursor-pointer select-none text-right')} onClick={() => onSort?.('risk_score')}>
                    Risk <SortIcon col="risk_score" />
                  </th>
                  <th className={cn(thCls, 'text-right')}>SLA</th>
                  <th className={cn(thCls, 'cursor-pointer select-none text-right')} onClick={() => onSort?.('created_at')}>
                    Time <SortIcon col="created_at" />
                  </th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((alert) => (
                  <tr
                    key={alert.id}
                    onClick={() => navigate(`/app/alerts/${alert.id}`)}
                    className={cn(
                      'border-b border-border/30 cursor-pointer hover:bg-muted/30 transition-colors',
                      focusedAlertId === alert.id && 'bg-primary/10 border-l-2 border-l-primary'
                    )}
                  >
                    {onSelectionChange && (
                      <td className={cn(tdCls, 'w-10')}>
                        <Checkbox checked={selectedIds.has(alert.id)} onChange={() => toggle(alert.id)} label={`Select ${alert.id}`} />
                      </td>
                    )}
                    <td className={cn(tdCls, 'font-mono text-xs text-muted-foreground whitespace-nowrap')}>
                      {alert.id?.slice(0, 8) ?? '—'}
                    </td>
                    <td className={cn(tdCls, 'font-medium max-w-[260px] text-xs')} title={alert.title}>
                      <div className="flex items-center gap-1.5 min-w-0">
                        <span className="truncate">{alert.title}</span>
                        {alert.false_positive_candidate && (
                          <span
                            className="shrink-0 inline-flex items-center px-1.5 py-0.5 rounded-full bg-amber-500/15 border border-amber-500/30 text-[9px] font-semibold text-amber-300 tabular-nums"
                            title={`AI FP score ${alert.false_positive_score ?? 'n/a'}`}
                          >
                            FP {alert.false_positive_score ?? ''}
                          </span>
                        )}
                        {(alert.enrichment?.duplicate_count ?? 0) > 1 && (
                          <span className="shrink-0 inline-flex items-center px-1.5 py-0.5 rounded-full bg-muted/60 border border-border/50 text-[9px] font-semibold text-muted-foreground tabular-nums"
                            title={`${alert.enrichment!.duplicate_count} duplicate events`}>
                            ×{alert.enrichment!.duplicate_count}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className={tdCls}>
                      <AlertBadge severity={alert.severity} />
                    </td>
                    <td className={tdCls}>
                      <span className={cn(
                        'inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium capitalize',
                        STATUS_COLORS[alert.status] ?? 'bg-muted text-muted-foreground'
                      )}>
                        {alert.status?.replace(/_/g, ' ')}
                      </span>
                    </td>
                    <td className={cn(tdCls, 'text-xs text-muted-foreground')}>{alert.source}</td>
                    <td className={tdCls}>
                      <span className="font-mono text-[10px] text-muted-foreground">
                        {(typeof alert.mitre_techniques?.[0] === 'string'
                          ? alert.mitre_techniques[0]
                          : (alert.mitre_techniques?.[0] as { id?: string })?.id) ?? '—'}
                      </span>
                    </td>
                    <td className={cn(tdCls, 'text-xs text-right font-mono font-semibold tabular-nums')}>
                      {alert.risk_score ?? '—'}
                    </td>
                    <td className={cn(tdCls, 'text-xs text-right whitespace-nowrap')}>
                      {(() => {
                        const sla = getSlaStatus(alert.created_at, alert.severity, alert.status)
                        if (!sla) return <span className="text-muted-foreground/40">—</span>
                        return (
                          <span className={cn(
                            'inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-medium tabular-nums',
                            sla.breached
                              ? 'bg-destructive/15 text-destructive border border-destructive/30'
                              : sla.elapsedHours / sla.thresholdHours > 0.75
                              ? 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30'
                              : 'bg-muted/40 text-muted-foreground border border-border/30'
                          )}>
                            {sla.label}
                          </span>
                        )
                      })()}
                    </td>
                    <td className={cn(tdCls, 'text-xs text-right text-muted-foreground whitespace-nowrap')}>
                      {formatRelativeTime(alert.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>
          Showing <span className="text-foreground font-medium">{sorted.length}</span> of{' '}
          <span className="text-foreground font-medium">{total}</span> alerts
        </span>
        <div className="flex items-center gap-4">
          <span>{selectedIds.size} selected</span>
          {total > pageSize && onPageChange && (
            <div className="flex items-center gap-2">
              <button type="button" disabled={page <= 1} onClick={() => onPageChange(page - 1)}
                className="px-2.5 py-1 rounded border border-border disabled:opacity-40 hover:bg-muted/50 transition-colors">
                Previous
              </button>
              <span className="tabular-nums">{page} / {totalPages}</span>
              <button type="button" disabled={page >= totalPages} onClick={() => onPageChange(page + 1)}
                className="px-2.5 py-1 rounded border border-border disabled:opacity-40 hover:bg-muted/50 transition-colors">
                Next
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
