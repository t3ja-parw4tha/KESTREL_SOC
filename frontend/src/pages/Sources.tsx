import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { get } from '@/api/client'
import { SourceLogo } from '@/components/sources/SourceLogo'
import { SourceDocPanel } from '@/components/sources/SourceDocPanel'
import { SetupGuideModal } from '@/components/sources/SetupGuideModal'
import { SOURCE_CATALOG, type SourceEntry, type SourceType } from '@/data/sourcesCatalog'
import {
  Plus, RefreshCw, Search, Terminal, AlertTriangle,
  Activity, Clock, ArrowRight, BookOpen, X,
} from 'lucide-react'
import { toast } from 'sonner'
import { cn } from '@/utils/cn'
import { useNavigate } from 'react-router-dom'

// ── Types ─────────────────────────────────────────────────────────────────────
interface ApiSource {
  id: string
  status: 'connected' | 'not_configured' | 'push_ready'
  events_today?: number
  total_alerts?: number
  last_seen?: string | null
}

interface SourceHealthSnapshot {
  source_id: string
  is_stale: boolean
  error_rate_pct: number
  freshness_seconds: number | null
  error_budget_remaining_pct: number | null
}

interface SourceHealthResponse {
  sources: SourceHealthSnapshot[]
}

type HealthStatus = 'healthy' | 'degraded' | 'stale' | 'unknown'

function deriveHealthStatus(h: SourceHealthSnapshot): HealthStatus {
  if (h.is_stale) return 'stale'
  if (h.error_rate_pct > 10) return 'degraded'
  return 'healthy'
}

const HEALTH_DOT: Record<HealthStatus, string> = {
  healthy:  'bg-emerald-400',
  degraded: 'bg-amber-400',
  stale:    'bg-red-500',
  unknown:  'bg-muted-foreground/30',
}

const HEALTH_TITLE: Record<HealthStatus, string> = {
  healthy:  'Healthy',
  degraded: 'Degraded — elevated error rate',
  stale:    'Stale — no recent data',
  unknown:  'Health unknown',
}

// ── Status config ─────────────────────────────────────────────────────────────
const STATUS_CFG = {
  connected: {
    label: 'Active',
    dotCls: 'bg-emerald-400 animate-pulse',
    badgeCls: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/25',
    cardBorder: 'border-emerald-500/20 hover:border-emerald-500/35',
  },
  not_configured: {
    label: 'Not Configured',
    dotCls: 'bg-muted-foreground/40',
    badgeCls: 'bg-muted text-muted-foreground border-border/50',
    cardBorder: 'border-border/40 hover:border-border/70',
  },
  push_ready: {
    label: 'Push Ready',
    dotCls: 'bg-blue-400',
    badgeCls: 'bg-blue-500/15 text-blue-400 border-blue-500/25',
    cardBorder: 'border-blue-500/20 hover:border-blue-500/35',
  },
} as const

// ── Type badge colors ─────────────────────────────────────────────────────────
const TYPE_BADGE: Record<SourceType, string> = {
  SIEM:          'bg-violet-500/10 text-violet-400',
  Cloud:         'bg-sky-500/10 text-sky-400',
  EDR:           'bg-red-500/10 text-red-400',
  Identity:      'bg-blue-500/10 text-blue-400',
  Network:       'bg-cyan-500/10 text-cyan-400',
  Email:         'bg-emerald-500/10 text-emerald-400',
  Enrichment:    'bg-amber-500/10 text-amber-400',
  'IDS/IPS':     'bg-orange-500/10 text-orange-400',
  OS:            'bg-slate-500/10 text-slate-400',
  Vulnerability: 'bg-rose-500/10 text-rose-400',
}

function relTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const m = Math.floor((Date.now() - new Date(iso).getTime()) / 60_000)
  if (m < 1) return 'Just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

function fmtNum(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`
  return String(n)
}

// ── curlExample ────────────────────────────────────────────────────────────────
const CURL_EXAMPLE = `curl -X POST https://your-soc.example.com/api/v1/ingest/alerts \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "title": "Suspicious login attempt",
    "severity": "high",
    "source": "custom_siem",
    "raw_log": {"ip": "10.0.0.1", "user": "admin"}
  }'`

// ── SourceCard ────────────────────────────────────────────────────────────────
function SourceCard({
  entry,
  apiData,
  healthStatus,
  onConfigure,
  onSetupGuide,
  onViewDocs,
}: {
  entry: SourceEntry
  apiData?: ApiSource
  healthStatus?: HealthStatus
  onConfigure: (id: string) => void
  onSetupGuide: (id: string) => void
  onViewDocs: (id: string) => void
}) {
  const status = apiData?.status ?? (entry.push ? 'push_ready' : 'not_configured')
  const cfg = STATUS_CFG[status]
  const eventsToday = apiData?.events_today
  const lastSeen = apiData?.last_seen

  return (
    <div className={cn(
      'glass-card rounded-xl border p-4 flex flex-col gap-3 transition-all duration-200 group',
      cfg.cardBorder
    )}>
      {/* Top row: logo + name + status */}
      <div className="flex items-start gap-3">
        {/* Logo */}
        <div
          className="w-11 h-11 rounded-xl flex items-center justify-center shrink-0 shadow-sm"
          style={{ backgroundColor: entry.logoBg }}
        >
          <SourceLogo sourceId={entry.id} size={26} />
        </div>

        {/* Name + badges */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <h3 className="text-sm font-semibold text-foreground leading-tight truncate">{entry.name}</h3>
            {healthStatus && healthStatus !== 'unknown' && (
              <span
                title={HEALTH_TITLE[healthStatus]}
                className={cn('w-2 h-2 rounded-full shrink-0', HEALTH_DOT[healthStatus],
                  healthStatus === 'healthy' && 'animate-pulse'
                )}
              />
            )}
          </div>
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className={cn('text-[9px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded-md', TYPE_BADGE[entry.type])}>
              {entry.type}
            </span>
            <span className={cn('inline-flex items-center gap-1 text-[9px] font-semibold px-1.5 py-0.5 rounded-full border', cfg.badgeCls)}>
              <span className={cn('w-1.5 h-1.5 rounded-full', cfg.dotCls)} />
              {cfg.label}
            </span>
          </div>
        </div>
      </div>

      {/* Description */}
      <p className="text-xs text-muted-foreground leading-relaxed line-clamp-2 flex-1">
        {entry.description}
      </p>

      {/* Stats row */}
      <div className="flex items-center justify-between text-[10px] text-muted-foreground border-t border-border/30 pt-2.5">
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1">
            <Activity className="w-3 h-3 shrink-0" />
            {eventsToday !== undefined
              ? <><span className="text-foreground font-medium">{fmtNum(eventsToday)}</span> today</>
              : <span className="italic opacity-50">no data</span>
            }
          </span>
          {lastSeen && (
            <span className="flex items-center gap-1">
              <Clock className="w-3 h-3 shrink-0" />
              {relTime(lastSeen)}
            </span>
          )}
        </div>
        {/* Docs link */}
        <button
          type="button"
          onClick={() => onViewDocs(entry.id)}
          className="flex items-center gap-0.5 text-primary/60 hover:text-primary transition-colors"
          title="View documentation"
        >
          <BookOpen className="w-3 h-3" />
        </button>
      </div>

      {/* Action */}
      <div className="flex gap-2">
        {entry.push ? (
          <button
            type="button"
            onClick={() => onSetupGuide(entry.id)}
            className="flex-1 flex items-center justify-center gap-1.5 py-1.5 rounded-lg text-xs font-medium border border-blue-500/30 bg-blue-500/10 text-blue-400 hover:bg-blue-500/20 transition-colors"
          >
            <Terminal className="w-3 h-3" /> Setup Guide
          </button>
        ) : status === 'connected' ? (
          <button
            type="button"
            onClick={() => onConfigure(entry.id)}
            className="flex-1 flex items-center justify-center gap-1.5 py-1.5 rounded-lg text-xs font-medium border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 transition-colors"
          >
            <ArrowRight className="w-3 h-3" /> Manage
          </button>
        ) : (
          <button
            type="button"
            onClick={() => onConfigure(entry.id)}
            className="flex-1 flex items-center justify-center gap-1.5 py-1.5 rounded-lg text-xs font-medium border border-border/60 text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
          >
            Configure <ArrowRight className="w-3 h-3" />
          </button>
        )}
        <button
          type="button"
          onClick={() => onViewDocs(entry.id)}
          className="px-2.5 py-1.5 rounded-lg text-xs border border-border/40 text-muted-foreground hover:text-foreground hover:bg-muted/30 transition-colors"
          title="Documentation"
        >
          <BookOpen className="w-3 h-3" />
        </button>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export function Sources() {
  const navigate = useNavigate()
  const [searchQuery, setSearchQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [showApiModal, setShowApiModal] = useState(false)
  const [setupGuideId, setSetupGuideId] = useState<string | null>(null)
  const [docsPanelId, setDocsPanelId] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const { data, isError, isLoading, refetch, dataUpdatedAt } = useQuery({
    queryKey: ['sources'],
    queryFn: () => get<{ items: ApiSource[] }>('/sources'),
    retry: 1,
    staleTime: 30_000,
    refetchInterval: 30_000,
  })

  // Health data — gracefully degraded if API unavailable
  const { data: healthData } = useQuery({
    queryKey: ['sources-health'],
    queryFn: () => get<SourceHealthResponse>('/sources/health'),
    retry: 1,
    staleTime: 60_000,
    refetchInterval: 60_000,
  })

  const healthMap = useMemo(() => {
    const m: Record<string, HealthStatus> = {}
    for (const s of healthData?.sources ?? []) {
      m[s.source_id] = deriveHealthStatus(s)
    }
    return m
  }, [healthData])

  const apiMap = useMemo(() => {
    const m: Record<string, ApiSource> = {}
    for (const s of data?.items ?? []) m[s.id] = s
    return m
  }, [data])

  const isDemo = (data?.items ?? []).length === 0

  // Merge API status into catalog
  const enriched = useMemo(() =>
    SOURCE_CATALOG.map((e) => ({
      entry: e,
      apiData: apiMap[e.id],
      status: apiMap[e.id]?.status ?? (e.push ? 'push_ready' : 'not_configured'),
    })),
    [apiMap]
  )

  const connected  = enriched.filter((s) => s.status === 'connected').length
  const pushReady  = enriched.filter((s) => s.status === 'push_ready').length
  const configured = connected

  const uniqueTypes = ['all', ...Array.from(new Set(SOURCE_CATALOG.map((s) => s.type))).sort()]

  const filtered = useMemo(() => {
    const q = searchQuery.toLowerCase()
    return enriched.filter(({ entry, status }) => {
      const matchSearch = !q ||
        entry.name.toLowerCase().includes(q) ||
        entry.type.toLowerCase().includes(q) ||
        entry.description.toLowerCase().includes(q) ||
        entry.helpTags.some((t) => t.includes(q))
      const matchType   = typeFilter   === 'all' || entry.type === typeFilter
      const matchStatus = statusFilter === 'all' || status === statusFilter
      return matchSearch && matchType && matchStatus
    })
  }, [enriched, searchQuery, typeFilter, statusFilter])

  const copyText = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    toast.success('Copied')
    setTimeout(() => setCopied(false), 2000)
  }

  // If docs panel is open, render it full-width
  if (docsPanelId) {
    return (
      <div className="animate-fade-in">
        <SourceDocPanel
          sourceId={docsPanelId}
          onBack={() => setDocsPanelId(null)}
        />
      </div>
    )
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* ── Header ── */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold tracking-tight">Data Sources</h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            {configured} active · {pushReady} push ready · {SOURCE_CATALOG.length} total integrations
            {dataUpdatedAt > 0 && (
              <span className="ml-2 opacity-40">· refreshed {relTime(new Date(dataUpdatedAt).toISOString())}</span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            disabled={isLoading}
            className="p-2 rounded-lg border border-border/50 text-muted-foreground hover:text-foreground hover:bg-muted/30 transition-colors disabled:opacity-40"
          >
            <RefreshCw className={cn('h-3.5 w-3.5', isLoading && 'animate-spin')} />
          </button>
          <button
            onClick={() => setShowApiModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-border/50 text-muted-foreground hover:text-foreground hover:bg-muted/30 transition-colors"
          >
            <Terminal className="h-3.5 w-3.5" /> API Ingest
          </button>
          <button
            onClick={() => navigate('/app/settings')}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg gradient-primary text-white"
          >
            <Plus className="h-3.5 w-3.5" /> Configure Source
          </button>
        </div>
      </div>

      {/* Demo / error notice */}
      {isError && (
        <div className="flex items-center gap-2 text-xs text-amber-400 bg-amber-400/10 border border-amber-400/20 rounded-lg px-3 py-2.5">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
          API unavailable — showing source catalog. Configure credentials in{' '}
          <a href="/app/settings" className="underline">Settings</a>.
        </div>
      )}

      {/* ── Stats strip ── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Active', value: connected,                  cls: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/20' },
          { label: 'Push Ready', value: pushReady,              cls: 'text-blue-400',    bg: 'bg-blue-500/10 border-blue-500/20' },
          { label: 'Not Configured', value: SOURCE_CATALOG.length - connected - pushReady, cls: 'text-muted-foreground', bg: 'bg-muted/20 border-border/30' },
          { label: 'Total Integrations', value: SOURCE_CATALOG.length, cls: 'text-foreground', bg: 'bg-muted/20 border-border/30' },
        ].map(({ label, value, cls, bg }) => (
          <div key={label} className={cn('rounded-xl border px-4 py-3', bg)}>
            <p className={cn('text-2xl font-bold tabular-nums', cls)}>{value}</p>
            <p className="text-[10px] text-muted-foreground mt-0.5">{label}</p>
          </div>
        ))}
      </div>

      {/* ── Filters ── */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground pointer-events-none" />
          <input
            placeholder="Search integrations…"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full h-9 pl-9 pr-3 text-sm rounded-lg border border-border/50 bg-muted/30 text-foreground focus:outline-none focus:border-primary transition-colors"
          />
        </div>
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="h-9 rounded-lg border border-border/50 bg-muted/30 text-foreground text-xs px-2.5 focus:outline-none focus:border-primary cursor-pointer"
        >
          {uniqueTypes.map((t) => <option key={t} value={t}>{t === 'all' ? 'All Categories' : t}</option>)}
        </select>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="h-9 rounded-lg border border-border/50 bg-muted/30 text-foreground text-xs px-2.5 focus:outline-none focus:border-primary cursor-pointer"
        >
          <option value="all">All Status</option>
          <option value="connected">Active</option>
          <option value="not_configured">Not Configured</option>
          <option value="push_ready">Push Ready</option>
        </select>
        {(searchQuery || typeFilter !== 'all' || statusFilter !== 'all') && (
          <button
            type="button"
            onClick={() => { setSearchQuery(''); setTypeFilter('all'); setStatusFilter('all') }}
            className="h-9 px-3 rounded-lg border border-border/50 text-xs text-muted-foreground hover:text-foreground flex items-center gap-1.5 transition-colors"
          >
            <X className="w-3 h-3" /> Clear
          </button>
        )}
        <span className="text-xs text-muted-foreground ml-auto hidden sm:block">
          {filtered.length} of {SOURCE_CATALOG.length}
        </span>
      </div>

      {/* ── Category groups → 3-col grid ── */}
      {filtered.length === 0 ? (
        <div className="text-center py-16 text-sm text-muted-foreground">
          No sources match your search.
        </div>
      ) : typeFilter !== 'all' ? (
        // Single filtered type — flat grid
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filtered.map(({ entry, apiData }) => (
            <SourceCard
              key={entry.id}
              entry={entry}
              apiData={apiData}
              healthStatus={healthMap[entry.id]}
              onConfigure={() => navigate('/app/settings')}
              onSetupGuide={(id) => setSetupGuideId(id)}
              onViewDocs={(id) => setDocsPanelId(id)}
            />
          ))}
        </div>
      ) : (
        // Grouped by category
        <div className="space-y-8">
          {Array.from(new Set(filtered.map((s) => s.entry.type))).map((type) => {
            const group = filtered.filter((s) => s.entry.type === type)
            return (
              <div key={type}>
                <div className="flex items-center gap-3 mb-4">
                  <span className={cn('text-[10px] font-bold uppercase tracking-widest px-2.5 py-1 rounded-lg', TYPE_BADGE[type as SourceType])}>
                    {type}
                  </span>
                  <span className="text-xs text-muted-foreground">{group.length} source{group.length !== 1 ? 's' : ''}</span>
                  <div className="flex-1 h-px bg-border/30" />
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {group.map(({ entry, apiData }) => (
                    <SourceCard
                      key={entry.id}
                      entry={entry}
                      apiData={apiData}
                      healthStatus={healthMap[entry.id]}
                      onConfigure={() => navigate('/app/settings')}
                      onSetupGuide={(id) => setSetupGuideId(id)}
                      onViewDocs={(id) => setDocsPanelId(id)}
                    />
                  ))}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* ── Setup Guide Modal ── */}
      {setupGuideId && (
        <SetupGuideModal sourceId={setupGuideId} onClose={() => setSetupGuideId(null)} />
      )}

      {/* ── API Ingest Modal ── */}
      {showApiModal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
          onClick={(e) => e.target === e.currentTarget && setShowApiModal(false)}
        >
          <div className="glass-card-elevated rounded-2xl shadow-2xl p-6 max-w-lg w-full mx-4 animate-fade-in">
            <div className="flex items-center gap-2 mb-5">
              <Terminal className="h-4 w-4 text-primary" />
              <h2 className="text-sm font-bold">Push Alerts via REST API</h2>
              <button type="button" onClick={() => setShowApiModal(false)} className="ml-auto text-muted-foreground hover:text-foreground text-xl leading-none">×</button>
            </div>
            <div className="space-y-4 text-xs">
              <div>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium mb-2">Endpoint</p>
                <div className="flex items-center gap-2">
                  <code className="flex-1 bg-muted rounded-lg px-3 py-2 font-mono">POST /api/v1/ingest/alerts</code>
                  <button onClick={() => copyText('/api/v1/ingest/alerts')} className="p-2 rounded-lg border border-border text-muted-foreground hover:text-foreground transition-colors">
                    {copied ? '✓' : <span className="text-xs">Copy</span>}
                  </button>
                </div>
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium mb-2">Example</p>
                <div className="relative">
                  <pre className="bg-muted rounded-lg p-3 font-mono text-xs overflow-x-auto leading-relaxed">{CURL_EXAMPLE}</pre>
                  <button onClick={() => copyText(CURL_EXAMPLE)} className="absolute top-2 right-2 px-2 py-1 text-[10px] rounded border border-border bg-muted/80 text-muted-foreground hover:text-foreground transition-colors">
                    Copy
                  </button>
                </div>
              </div>
              {isDemo && (
                <div className="flex items-center gap-2 text-amber-400 bg-amber-400/10 border border-amber-400/20 rounded-lg px-3 py-2">
                  <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                  Set your API key in Settings before using this endpoint.
                </div>
              )}
            </div>
            <div className="flex justify-end mt-5 pt-4 border-t border-border/40">
              <button onClick={() => setShowApiModal(false)} className="px-3 py-1.5 text-xs rounded-lg border border-border text-muted-foreground hover:text-foreground transition-colors">Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default Sources
