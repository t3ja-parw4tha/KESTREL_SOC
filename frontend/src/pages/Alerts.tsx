import { useState, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useAlerts } from '@/hooks/useAlerts'
import { AlertTable } from '@/components/alerts/AlertTable'
import { AlertFilters } from '@/components/alerts/AlertFilters'
const PAGE_SIZE = 20
type SortKey = 'severity' | 'risk_score' | 'created_at'

export function Alerts() {
  const [searchParams, setSearchParams] = useSearchParams()
  const page = Math.max(1, parseInt(searchParams.get('page') ?? '1', 10))
  const severity = searchParams.get('severity') ?? undefined
  const status = searchParams.get('status') ?? undefined
  const source = searchParams.get('source') ?? ''
  const category = searchParams.get('category') ?? ''
  const search = searchParams.get('search') ?? ''

  const [sortKey, setSortKey] = useState<SortKey>('created_at')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')

  const { data, isLoading } = useAlerts({
    page,
    limit: PAGE_SIZE,
    severity: severity || undefined,
    status: status || undefined,
    source: source || undefined,
    category: category || undefined,
    search: search || undefined,
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

  const handleSort = useCallback((key: SortKey) => {
    setSortKey(key)
    setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
  }, [])

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <h1 className="text-2xl font-semibold text-soc-text">Alerts</h1>
      </div>
      <AlertFilters
        severity={severity}
        status={status}
        source={source}
        category={category}
        search={search}
      />
      <AlertTable
        alerts={data?.alerts ?? []}
        total={data?.total ?? 0}
        loading={isLoading}
        page={page}
        pageSize={PAGE_SIZE}
        onPageChange={setPage}
        sortKey={sortKey}
        sortDir={sortDir}
        onSort={handleSort}
      />
    </div>
  )
}
