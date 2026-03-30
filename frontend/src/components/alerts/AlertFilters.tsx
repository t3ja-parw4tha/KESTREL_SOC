import { useState, useEffect, useRef } from 'react'
import { Search, Download, RefreshCw, Calendar } from 'lucide-react'
import { useSearchParams } from 'react-router-dom'
import { cn } from '@/utils/cn'
import type { Alert } from '@/types/alert'

const SEVERITIES: Alert['severity'][] = ['Critical', 'High', 'Medium', 'Low']
const STATUSES: Alert['status'][] = ['open', 'in_progress', 'resolved', 'false_positive']

const QUICK_RANGES = [
  { label: '1h', hours: 1 },
  { label: '6h', hours: 6 },
  { label: '24h', hours: 24 },
  { label: '7d', hours: 168 },
  { label: '30d', hours: 720 },
]

interface AlertFiltersProps {
  severity?: string | null
  status?: string | null
  source?: string
  category?: string
  search?: string
  dateFrom?: string | null
  dateTo?: string | null
  onExport?: () => void
  onRefresh?: () => void
  className?: string
}

const selectCls =
  'h-9 rounded-lg border border-border/50 bg-muted/50 text-foreground px-2.5 text-xs focus:outline-none focus:ring-1 focus:ring-primary/50 transition-colors cursor-pointer'

export function AlertFilters({
  severity = null,
  status = null,
  search = '',
  dateFrom = null,
  dateTo = null,
  onExport,
  onRefresh,
  className,
}: AlertFiltersProps) {
  const [, setSearchParams] = useSearchParams()
  const [showDatePicker, setShowDatePicker] = useState(false)

  // Local search state — debounced before hitting URL/API
  const [localSearch, setLocalSearch] = useState(search)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Keep local state in sync when URL param changes externally (e.g. clear button)
  useEffect(() => { setLocalSearch(search) }, [search])

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

  const handleSearchChange = (value: string) => {
    setLocalSearch(value)
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => {
      updateParams({ search: value || null })
    }, 300)
  }

  const applyQuickRange = (hours: number) => {
    const to = new Date()
    const from = new Date(to.getTime() - hours * 60 * 60 * 1000)
    updateParams({
      date_from: from.toISOString(),
      date_to: to.toISOString(),
    })
  }

  const clearDateRange = () => updateParams({ date_from: null, date_to: null })
  const hasDateFilter = !!(dateFrom || dateTo)

  return (
    <div className={cn('flex flex-col gap-3', className)}>
      {/* Search — debounced 300ms */}
      <div className="relative flex-1">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground pointer-events-none" />
        <input
          type="search"
          value={localSearch}
          onChange={(e) => handleSearchChange(e.target.value)}
          placeholder="Search alerts..."
          className="w-full h-9 pl-9 pr-3 rounded-lg border border-border/50 bg-muted/50 text-foreground placeholder:text-muted-foreground text-sm focus:outline-none focus:ring-1 focus:ring-primary/50 transition-colors"
        />
      </div>

      {/* Severity */}
      <select
        value={severity ?? 'all'}
        onChange={(e) => updateParams({ severity: e.target.value === 'all' ? null : e.target.value })}
        className={cn(selectCls, 'w-[140px]')}
      >
        <option value="all">All Severity</option>
        {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
      </select>

      {/* Status */}
      <select
        value={status ?? 'all'}
        onChange={(e) => updateParams({ status: e.target.value === 'all' ? null : e.target.value })}
        className={cn(selectCls, 'w-[140px]')}
      >
        <option value="all">All Status</option>
        {STATUSES.map((s) => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
      </select>

      {/* Actions */}
      <div className="flex gap-2">
        <button type="button" onClick={() => setShowDatePicker(v => !v)}
          className={cn(
            'inline-flex items-center gap-1.5 h-9 px-3 rounded-lg border text-xs transition-colors',
            hasDateFilter
              ? 'border-primary/50 bg-primary/10 text-primary'
              : 'border-border/50 bg-card text-muted-foreground hover:text-foreground'
          )}>
          <Calendar className="h-3.5 w-3.5" />
          {hasDateFilter ? 'Date filter active' : 'Date range'}
        </button>
        {onExport && (
          <button type="button" onClick={onExport}
            className="inline-flex items-center gap-1.5 h-9 px-3 rounded-lg border border-border/50 bg-card text-muted-foreground hover:text-foreground text-xs transition-colors">
            <Download className="h-3.5 w-3.5" /> Export
          </button>
        )}
        {onRefresh && (
          <button type="button" onClick={onRefresh}
            className="inline-flex items-center gap-1.5 h-9 px-3 rounded-lg border border-border/50 bg-card text-muted-foreground hover:text-foreground text-xs transition-colors">
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </button>
        )}
      </div>

      {/* Date range panel */}
      {showDatePicker && (
        <div className="flex flex-wrap items-center gap-3 px-4 py-3 rounded-lg border border-border/50 bg-card/80">
          <span className="text-xs text-muted-foreground font-medium shrink-0">Quick:</span>
          {QUICK_RANGES.map(r => (
            <button key={r.label} type="button" onClick={() => { applyQuickRange(r.hours); setShowDatePicker(false) }}
              className="inline-flex items-center px-2.5 py-1 rounded border border-border/50 bg-background text-xs text-foreground hover:border-primary/50 hover:text-primary transition-colors">
              Last {r.label}
            </button>
          ))}
          <span className="text-border/50">|</span>
          <div className="flex items-center gap-2">
            <input type="datetime-local" value={dateFrom ? dateFrom.slice(0, 16) : ''}
              onChange={e => updateParams({ date_from: e.target.value ? new Date(e.target.value).toISOString() : null })}
              className="h-8 px-2 rounded-lg border border-border/50 bg-background text-foreground text-xs focus:outline-none focus:ring-1 focus:ring-primary/50" />
            <span className="text-xs text-muted-foreground">to</span>
            <input type="datetime-local" value={dateTo ? dateTo.slice(0, 16) : ''}
              onChange={e => updateParams({ date_to: e.target.value ? new Date(e.target.value).toISOString() : null })}
              className="h-8 px-2 rounded-lg border border-border/50 bg-background text-foreground text-xs focus:outline-none focus:ring-1 focus:ring-primary/50" />
          </div>
          {hasDateFilter && (
            <button type="button" onClick={() => { clearDateRange(); setShowDatePicker(false) }}
              className="text-xs text-muted-foreground hover:text-foreground underline">Clear</button>
          )}
        </div>
      )}
    </div>
  )
}
