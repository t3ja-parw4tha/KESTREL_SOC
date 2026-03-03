import { useState, useCallback, useMemo } from 'react'
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
        alerts={sortedAlerts}
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
