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
}: AlertTableProps) {
  const navigate = useNavigate()
  const sorted = sortAlerts(alerts, sortKey, sortDir)
  const totalPages = Math.max(1, Math.ceil(total / pageSize))

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
      <Table>
        <TableHead>
          <TableRow>
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
              onClick={() => navigate(`/alerts/${alert.id}`)}
              className="cursor-pointer hover:bg-soc-border/30"
            >
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
