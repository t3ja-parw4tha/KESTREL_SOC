import { useSearchParams } from 'react-router-dom'
import { cn } from '@/utils/cn'
import type { Alert } from '@/types/alert'

const SEVERITIES: Alert['severity'][] = ['Critical', 'High', 'Medium', 'Low']
const STATUSES: Alert['status'][] = ['open', 'in_progress', 'resolved', 'false_positive']

interface AlertFiltersProps {
  severity?: string | null
  status?: string | null
  source?: string
  category?: string
  search?: string
  onSeverityChange?: (v: string | null) => void
  onStatusChange?: (v: string | null) => void
  onSourceChange?: (v: string) => void
  onCategoryChange?: (v: string) => void
  onSearchChange?: (v: string) => void
  className?: string
}

export function AlertFilters({
  severity = null,
  status = null,
  source = '',
  category = '',
  search = '',
  onSeverityChange,
  onStatusChange,
  onSourceChange,
  onCategoryChange,
  onSearchChange,
  className,
}: AlertFiltersProps) {
  const [, setSearchParams] = useSearchParams()

  const updateParams = (updates: Record<string, string | null>) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      Object.entries(updates).forEach(([k, v]) => {
        if (v == null || v === '') next.delete(k)
        else next.set(k, v)
      })
      next.set('page', '1')
      return next
    })
  }

  return (
    <div className={cn('flex flex-wrap items-center gap-4 p-4 rounded-lg border border-soc-border bg-soc-surface', className)}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm text-soc-muted">Severity</span>
        <select
          value={severity ?? ''}
          onChange={(e) => {
            const v = e.target.value || null
            onSeverityChange?.(v)
            updateParams({ severity: v })
          }}
          className="rounded border border-soc-border bg-soc-bg text-soc-text px-2 py-1.5 text-sm min-w-[100px]"
        >
          <option value="">All</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm text-soc-muted">Status</span>
        <select
          value={status ?? ''}
          onChange={(e) => {
            const v = e.target.value || null
            onStatusChange?.(v)
            updateParams({ status: v })
          }}
          className="rounded border border-soc-border bg-soc-bg text-soc-text px-2 py-1.5 text-sm min-w-[120px]"
        >
          <option value="">All</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>{s.replace('_', ' ')}</option>
          ))}
        </select>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm text-soc-muted">Source</span>
        <input
          type="text"
          value={source}
          onChange={(e) => {
            onSourceChange?.(e.target.value)
            updateParams({ source: e.target.value || null })
          }}
          placeholder="Filter by source"
          className="rounded border border-soc-border bg-soc-bg text-soc-text px-2 py-1.5 text-sm w-40"
        />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm text-soc-muted">Category</span>
        <input
          type="text"
          value={category}
          onChange={(e) => {
            onCategoryChange?.(e.target.value)
            updateParams({ category: e.target.value || null })
          }}
          placeholder="Filter by category"
          className="rounded border border-soc-border bg-soc-bg text-soc-text px-2 py-1.5 text-sm w-40"
        />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm text-soc-muted">Search</span>
        <input
          type="search"
          value={search}
          onChange={(e) => {
            onSearchChange?.(e.target.value)
            updateParams({ search: e.target.value || null })
          }}
          placeholder="Search title"
          className="rounded border border-soc-border bg-soc-bg text-soc-text px-2 py-1.5 text-sm w-48"
        />
      </div>
    </div>
  )
}
