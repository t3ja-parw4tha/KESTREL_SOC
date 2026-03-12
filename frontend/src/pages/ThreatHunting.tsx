import { useState, useCallback, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { Search, Bookmark, BookmarkCheck, X, SlidersHorizontal, Clock, CalendarDays } from 'lucide-react'
import { toDateInput } from '@/utils/time'
import { getAlerts } from '@/api/alerts'
import type { AlertFiltersParams } from '@/types/alert'
import { AlertTable } from '@/components/alerts/AlertTable'
import { SpinnerOverlay } from '@/components/ui/Spinner'
import { cn } from '@/utils/cn'
import { toast } from 'sonner'

// ── Saved searches (localStorage) ────────────────────────────────────────────
interface SavedSearch {
  id: string
  name: string
  params: HuntParams
  savedAt: string
}

const LS_KEY = 'kestrel_hunt_saved'

function loadSaved(): SavedSearch[] {
  try {
    return JSON.parse(localStorage.getItem(LS_KEY) ?? '[]')
  } catch {
    return []
  }
}

function persistSaved(searches: SavedSearch[]) {
  try {
    localStorage.setItem(LS_KEY, JSON.stringify(searches))
  } catch { /* ignore quota errors */ }
}

// ── Hunt filter params ────────────────────────────────────────────────────────
interface HuntParams {
  search: string
  severity: string
  source: string
  category: string
  status: string
  source_ip: string
  date_from: string
  date_to: string
}

const EMPTY: HuntParams = {
  search: '',
  severity: '',
  source: '',
  category: '',
  status: '',
  source_ip: '',
  date_from: '',
  date_to: '',
}

function paramsToQuery(p: HuntParams): AlertFiltersParams {
  const q: AlertFiltersParams = {}
  if (p.search) q.search = p.search
  if (p.severity) q.severity = p.severity
  if (p.source) q.source = p.source
  if (p.category) q.category = p.category
  if (p.status) q.status = p.status
  if (p.date_from) q.date_from = p.date_from
  if (p.date_to) q.date_to = p.date_to
  return q
}

function isParamsEmpty(p: HuntParams): boolean {
  return Object.values(p).every((v) => !v.trim())
}

const DATE_PRESETS = [
  { label: 'Today', daysBack: 0 },
  { label: 'Last 7d', daysBack: 7 },
  { label: 'Last 30d', daysBack: 30 },
  { label: 'Last 90d', daysBack: 90 },
].map(({ label, daysBack }) => ({
  label,
  apply: () => {
    const now = new Date()
    const from = new Date(now)
    from.setDate(from.getDate() - daysBack)
    return { date_from: toDateInput(from), date_to: toDateInput(now) }
  },
}))

// ── Filter row component ──────────────────────────────────────────────────────
function FilterRow({
  label, children,
}: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <label className="text-xs text-soc-muted">{label}</label>
      {children}
    </div>
  )
}

const INPUT_CLS = 'w-full px-2.5 py-1.5 rounded border border-soc-border bg-soc-bg text-soc-text text-sm focus:outline-none focus:border-blue-500'
const SELECT_CLS = `${INPUT_CLS} appearance-none`

// ── Main page ─────────────────────────────────────────────────────────────────
export function ThreatHunting() {
  const [searchParams] = useSearchParams()

  // Seed search from URL ?search= (e.g. from TopBar search redirect)
  const [params, setParams] = useState<HuntParams>(() => ({
    ...EMPTY,
    search: searchParams.get('search') ?? '',
  }))
  const [submitted, setSubmitted] = useState(() => !!searchParams.get('search'))
  const [page, setPage] = useState(1)
  const [showFilters, setShowFilters] = useState(false)
  const [saved, setSaved] = useState<SavedSearch[]>(loadSaved)
  const [saveNameInput, setSaveNameInput] = useState('')
  const [showSaveInput, setShowSaveInput] = useState(false)

  // Re-seed when URL param changes (e.g. TopBar search)
  useEffect(() => {
    const q = searchParams.get('search')
    if (q) {
      setParams((p) => ({ ...p, search: q }))
      setSubmitted(true)
    }
  }, [searchParams])

  const queryParams = { ...paramsToQuery(params), page, limit: 25 }

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['hunt', queryParams],
    queryFn: () => getAlerts(queryParams),
    enabled: submitted,
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setPage(1)
    setSubmitted(true)
    refetch()
  }

  const handleClear = () => {
    setParams(EMPTY)
    setSubmitted(false)
    setPage(1)
  }

  const handleSave = useCallback(() => {
    const name = saveNameInput.trim()
    if (!name) return
    const newSearch: SavedSearch = {
      id: Date.now().toString(),
      name,
      params,
      savedAt: new Date().toISOString(),
    }
    const next = [newSearch, ...saved].slice(0, 10) // keep max 10
    setSaved(next)
    persistSaved(next)
    setSaveNameInput('')
    setShowSaveInput(false)
    toast.success(`Search "${name}" saved`)
  }, [saveNameInput, params, saved])

  const handleDeleteSaved = (id: string) => {
    const next = saved.filter((s) => s.id !== id)
    setSaved(next)
    persistSaved(next)
  }

  const handleLoadSaved = (s: SavedSearch) => {
    setParams(s.params)
    setPage(1)
    setSubmitted(true)
    toast.info(`Loaded "${s.name}"`)
  }

  const hasFilters = !isParamsEmpty(params)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-semibold text-soc-text">Threat Hunting</h1>
        <p className="text-sm text-soc-muted mt-0.5">
          Search and pivot across alerts. Add filters to narrow indicators of compromise.
        </p>
      </div>

      {/* Search form */}
      <form onSubmit={handleSubmit} className="space-y-3">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-soc-muted pointer-events-none" />
            <input
              type="search"
              placeholder="Search alert titles, IPs, indicators..."
              value={params.search}
              onChange={(e) => setParams((p) => ({ ...p, search: e.target.value }))}
              className="w-full pl-9 pr-3 py-2 rounded-lg border border-soc-border bg-soc-bg text-soc-text text-sm placeholder:text-soc-muted focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          <button
            type="button"
            onClick={() => setShowFilters((v) => !v)}
            className={cn(
              'inline-flex items-center gap-2 px-3 py-2 rounded-lg border text-sm transition-colors',
              showFilters
                ? 'border-blue-500 bg-blue-500/10 text-blue-400'
                : 'border-soc-border bg-soc-surface text-soc-muted hover:text-soc-text'
            )}
            title="Toggle advanced filters"
          >
            <SlidersHorizontal className="w-4 h-4" />
            Filters
            {hasFilters && (
              <span className="w-2 h-2 rounded-full bg-blue-500 shrink-0" />
            )}
          </button>
          <button
            type="submit"
            className="px-4 py-2 rounded-lg bg-blue-600 text-white text-sm font-medium hover:bg-blue-700 transition-colors"
          >
            Hunt
          </button>
          {(hasFilters || submitted) && (
            <button
              type="button"
              onClick={handleClear}
              className="px-3 py-2 rounded-lg border border-soc-border text-soc-muted hover:text-soc-text text-sm transition-colors"
              title="Clear all filters"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>

        {/* Advanced filters */}
        {showFilters && (
          <div className="space-y-3">
          <div className="rounded-lg border border-soc-border bg-soc-surface p-4 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            <FilterRow label="Severity">
              <select
                value={params.severity}
                onChange={(e) => setParams((p) => ({ ...p, severity: e.target.value }))}
                className={SELECT_CLS}
              >
                <option value="">Any</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </FilterRow>
            <FilterRow label="Status">
              <select
                value={params.status}
                onChange={(e) => setParams((p) => ({ ...p, status: e.target.value }))}
                className={SELECT_CLS}
              >
                <option value="">Any</option>
                <option value="open">Open</option>
                <option value="in_progress">In Progress</option>
                <option value="resolved">Resolved</option>
                <option value="false_positive">False Positive</option>
              </select>
            </FilterRow>
            <FilterRow label="Source">
              <input
                type="text"
                placeholder="e.g. suricata"
                value={params.source}
                onChange={(e) => setParams((p) => ({ ...p, source: e.target.value }))}
                className={INPUT_CLS}
              />
            </FilterRow>
            <FilterRow label="Category">
              <input
                type="text"
                placeholder="e.g. brute_force"
                value={params.category}
                onChange={(e) => setParams((p) => ({ ...p, category: e.target.value }))}
                className={INPUT_CLS}
              />
            </FilterRow>
            <FilterRow label="Date from">
              <input
                type="date"
                value={params.date_from}
                onChange={(e) => setParams((p) => ({ ...p, date_from: e.target.value }))}
                className={INPUT_CLS}
              />
            </FilterRow>
            <FilterRow label="Date to">
              <input
                type="date"
                value={params.date_to}
                onChange={(e) => setParams((p) => ({ ...p, date_to: e.target.value }))}
                className={INPUT_CLS}
              />
            </FilterRow>
          </div>
          {/* Quick date presets */}
          <div className="flex items-center gap-2 flex-wrap pt-1">
            <span className="text-xs text-soc-muted flex items-center gap-1">
              <CalendarDays className="w-3.5 h-3.5" /> Quick:
            </span>
            {DATE_PRESETS.map((preset) => (
              <button
                key={preset.label}
                type="button"
                onClick={() => setParams((p) => ({ ...p, ...preset.apply() }))}
                className="px-2.5 py-1 rounded-full border border-soc-border bg-soc-bg text-xs text-soc-muted hover:text-soc-text hover:border-blue-500/50 transition-colors"
              >
                {preset.label}
              </button>
            ))}
            {(params.date_from || params.date_to) && (
              <button
                type="button"
                onClick={() => setParams((p) => ({ ...p, date_from: '', date_to: '' }))}
                className="px-2.5 py-1 rounded-full border border-red-500/30 bg-red-500/5 text-xs text-red-400 hover:text-red-300 transition-colors"
              >
                Clear dates
              </button>
            )}
          </div>
          </div>
        )}

        {/* Save search bar */}
        {submitted && hasFilters && (
          <div className="flex items-center gap-2">
            {showSaveInput ? (
              <>
                <input
                  type="text"
                  placeholder="Name this search..."
                  value={saveNameInput}
                  onChange={(e) => setSaveNameInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleSave()}
                  className="flex-1 max-w-xs px-3 py-1.5 rounded border border-soc-border bg-soc-bg text-soc-text text-sm focus:outline-none focus:border-blue-500"
                  autoFocus
                />
                <button
                  type="button"
                  onClick={handleSave}
                  disabled={!saveNameInput.trim()}
                  className="px-3 py-1.5 rounded bg-blue-600 text-white text-sm hover:bg-blue-700 disabled:opacity-50"
                >
                  Save
                </button>
                <button
                  type="button"
                  onClick={() => setShowSaveInput(false)}
                  className="px-3 py-1.5 rounded border border-soc-border text-soc-muted text-sm hover:text-soc-text"
                >
                  Cancel
                </button>
              </>
            ) : (
              <button
                type="button"
                onClick={() => setShowSaveInput(true)}
                className="inline-flex items-center gap-1.5 text-xs text-soc-muted hover:text-soc-text"
              >
                <Bookmark className="w-3.5 h-3.5" />
                Save this search
              </button>
            )}
          </div>
        )}
      </form>

      {/* Saved searches */}
      {saved.length > 0 && (
        <div className="flex flex-wrap gap-2 items-center">
          <span className="text-xs text-soc-muted flex items-center gap-1">
            <Clock className="w-3.5 h-3.5" /> Saved:
          </span>
          {saved.map((s) => (
            <span
              key={s.id}
              className="group inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-soc-border bg-soc-surface text-xs text-soc-muted hover:text-soc-text cursor-pointer"
            >
              <BookmarkCheck className="w-3 h-3 text-blue-400 shrink-0" />
              <button
                type="button"
                onClick={() => handleLoadSaved(s)}
                className="max-w-[120px] truncate"
                title={s.name}
              >
                {s.name}
              </button>
              <button
                type="button"
                onClick={() => handleDeleteSaved(s.id)}
                className="opacity-0 group-hover:opacity-100 text-soc-muted hover:text-red-400 transition-opacity"
                aria-label={`Delete "${s.name}"`}
              >
                <X className="w-3 h-3" />
              </button>
            </span>
          ))}
        </div>
      )}

      {/* Results */}
      {!submitted && (
        <div className="rounded-lg border border-soc-border bg-soc-surface p-10 text-center">
          <Search className="w-10 h-10 text-soc-muted mx-auto mb-3" />
          <p className="text-soc-text font-medium">Enter a search query to start hunting</p>
          <p className="text-soc-muted text-sm mt-1">
            Search by title, IP address, category, or use the advanced filters to pivot on an indicator.
          </p>
        </div>
      )}

      {submitted && isLoading && <SpinnerOverlay />}

      {submitted && isError && (
        <div className="rounded-lg border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-400">
          Failed to execute hunt query. Try adjusting your filters.
        </div>
      )}

      {submitted && data && (
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <p className="text-sm text-soc-muted">
              {data.total === 0
                ? 'No results'
                : `${data.total} result${data.total === 1 ? '' : 's'}`}
            </p>
          </div>
          <AlertTable
            alerts={data.alerts}
            total={data.total}
            loading={isLoading}
            page={page}
            pageSize={25}
            onPageChange={setPage}
          />
        </div>
      )}
    </div>
  )
}
