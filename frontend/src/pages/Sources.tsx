import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { get } from '@/api/client'
import { SetupGuideModal } from '@/components/sources/SetupGuideModal'
import {
  Database, Plus, Activity, RefreshCw, Search, Copy, Check,
  Eye, EyeOff, Terminal, ExternalLink,
} from 'lucide-react'
import { toast } from 'sonner'
import { useAuth } from '@/security/AuthContext'

const TEST_PASSED_KEY = 'kestrel_source_tested_'
const SOURCES_REQUIRING_TEST = ['sentinel', 'guardduty', 'virustotal', 'abuseipdb']

function getTestPassed(sourceId: string): boolean {
  try {
    return localStorage.getItem(TEST_PASSED_KEY + sourceId) === '1'
  } catch {
    return false
  }
}

function displayStatus(
  apiStatus: 'connected' | 'not_configured' | 'push_ready',
  sourceId: string
): 'connected' | 'not_configured' | 'push_ready' {
  if (apiStatus !== 'connected' || !SOURCES_REQUIRING_TEST.includes(sourceId)) {
    return apiStatus
  }
  return getTestPassed(sourceId) ? 'connected' : 'not_configured'
}

interface Source {
  id: string
  name: string
  type: string
  status: 'connected' | 'not_configured' | 'push_ready'
  description: string
  push: boolean
  eventsPerDay?: string
  lastSync?: string
}

const STATUS_CONFIG = {
  connected: {
    label: 'Connected',
    dot: 'bg-green-400 animate-pulse',
    text: 'text-green-400',
    border: 'border-green-500/20',
    bg: 'bg-green-500/5',
    badge: 'bg-green-500/15 text-green-400 border-green-500/30',
  },
  not_configured: {
    label: 'Not Configured',
    dot: 'bg-gray-500',
    text: 'text-muted-foreground',
    border: 'border-border/30',
    bg: 'bg-muted/20',
    badge: 'bg-muted text-muted-foreground border-border',
  },
  push_ready: {
    label: 'Push Ready',
    dot: 'bg-blue-400',
    text: 'text-blue-400',
    border: 'border-blue-500/20',
    bg: 'bg-blue-500/5',
    badge: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  },
}

const TYPE_COLORS: Record<string, string> = {
  SIEM: 'bg-purple-500/10 text-purple-400',
  Cloud: 'bg-orange-500/10 text-orange-400',
  Enrichment: 'bg-teal-500/10 text-teal-400',
  'IDS/IPS': 'bg-red-500/10 text-red-400',
  OS: 'bg-blue-500/10 text-blue-400',
  EDR: 'bg-yellow-500/10 text-yellow-400',
  Identity: 'bg-indigo-500/10 text-indigo-400',
  Network: 'bg-cyan-500/10 text-cyan-400',
  Email: 'bg-pink-500/10 text-pink-400',
}

const curlExample = `curl -X POST /api/v1/ingest/alerts \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "title": "Suspicious login attempt",
    "severity": "high",
    "source": "custom_siem",
    "raw_log": {"ip": "10.0.0.1"}
  }'`

// Demo data shown when API has no sources
const demoSources: Source[] = [
  { id: 'azure-ad', name: 'Azure Active Directory', type: 'Identity', status: 'connected', description: 'Identity and access events from Azure AD.', push: false, eventsPerDay: '45,200', lastSync: '5m ago' },
  { id: 'crowdstrike', name: 'CrowdStrike Falcon', type: 'EDR', status: 'connected', description: 'Endpoint detection and response telemetry.', push: false, eventsPerDay: '128,400', lastSync: '1m ago' },
  { id: 'palo-alto', name: 'Palo Alto Firewall', type: 'Network', status: 'connected', description: 'Network traffic and threat logs.', push: false, eventsPerDay: '892,000', lastSync: '2m ago' },
  { id: 'microsoft-365', name: 'Microsoft 365', type: 'Email', status: 'not_configured', description: 'Email security and collaboration events.', push: false, eventsPerDay: '23,100', lastSync: '45m ago' },
  { id: 'aws-cloudtrail', name: 'AWS CloudTrail', type: 'Cloud', status: 'connected', description: 'AWS API activity and account events.', push: false, eventsPerDay: '67,800', lastSync: '10m ago' },
  { id: 'sentinel', name: 'Microsoft Sentinel', type: 'SIEM', status: 'not_configured', description: 'Cloud-native SIEM and SOAR platform.', push: false },
  { id: 'guardduty', name: 'AWS GuardDuty', type: 'Cloud', status: 'not_configured', description: 'Threat detection service for AWS.', push: false },
  { id: 'syslog', name: 'Syslog Push', type: 'OS', status: 'push_ready', description: 'Receive events via syslog push from any source.', push: true },
]

export function Sources() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const [setupGuideSourceId, setSetupGuideSourceId] = useState<string | null>(null)
  const [showApiModal, setShowApiModal] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [apiKeyRevealed, setApiKeyRevealed] = useState(false)
  const [copied, setCopied] = useState<string | null>(null)

  const { data, isError } = useQuery({
    queryKey: ['sources'],
    queryFn: () => get<{ items: Source[]; configured_count: number }>('/sources'),
    retry: 1,
    staleTime: 60_000,
  })

  const rawItems = data?.items ?? []
  const items = rawItems.length > 0
    ? rawItems.map((s) => ({ ...s, status: displayStatus(s.status, s.id) }))
    : demoSources

  const configured = items.filter((s) => s.status === 'connected').length

  const filtered = items.filter(
    (s) =>
      s.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.type.toLowerCase().includes(searchQuery.toLowerCase())
  )

  const copyText = (text: string, label: string) => {
    navigator.clipboard.writeText(text)
    setCopied(label)
    toast.success(`${label} copied`)
    setTimeout(() => setCopied(null), 2000)
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold tracking-tight flex items-center gap-2">
            <Database className="h-5 w-5 text-primary" /> Data Sources
          </h1>
          <p className="text-xs text-muted-foreground">{configured}/{items.length} sources connected</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowApiModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-border text-muted-foreground hover:text-foreground hover:bg-muted/30 transition-colors"
          >
            <Terminal className="h-3.5 w-3.5" /> API Ingest
          </button>
          <button
            onClick={() => toast.info('Add Source wizard coming soon')}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg gradient-primary text-primary-foreground"
          >
            <Plus className="h-3.5 w-3.5" /> Add Source
          </button>
        </div>
      </div>

      {isError && (
        <div className="flex items-center gap-2 text-xs text-amber-400 bg-amber-400/10 border border-amber-400/20 rounded-lg px-3 py-2">
          <ExternalLink className="h-3.5 w-3.5 shrink-0" />
          API unavailable — showing demo source data.
          <a href="/app/settings" className="underline ml-auto">Configure in Settings →</a>
        </div>
      )}

      {/* Search + stats bar */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <input
            placeholder="Search sources..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full h-8 pl-9 pr-3 text-xs rounded-lg border border-border bg-muted/30 text-foreground focus:outline-none focus:border-primary transition-colors"
          />
        </div>
        <div className="glass-card rounded-lg px-3 py-1.5 text-xs text-muted-foreground">
          <span className="text-foreground font-semibold">{configured}</span> connected ·{' '}
          <span className="text-blue-400">{items.filter((s) => s.push).length}</span> push ready
        </div>
      </div>

      {/* Source Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filtered.map((source) => {
          const cfg = STATUS_CONFIG[source.status]
          const typeCls = TYPE_COLORS[source.type] ?? 'bg-muted text-muted-foreground'
          return (
            <div
              key={source.id}
              className={`glass-card-hover rounded-xl p-4 border ${cfg.border} ${cfg.bg} transition-all`}
            >
              <div className="flex items-start gap-3">
                <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
                  <Database className="h-5 w-5 text-primary" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2 mb-0.5">
                    <h3 className="text-sm font-semibold truncate">{source.name}</h3>
                    <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded border ${cfg.badge} shrink-0`}>
                      {cfg.label}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 mb-2">
                    <span className={`text-[9px] font-medium px-1.5 py-0.5 rounded ${typeCls}`}>{source.type}</span>
                  </div>
                  <p className="text-xs text-muted-foreground">{source.description}</p>
                </div>
              </div>

              {(source.eventsPerDay || source.lastSync || source.status === 'not_configured' || source.push) && (
                <div className="flex items-center justify-between mt-3 pt-3 border-t border-border/30">
                  {source.eventsPerDay ? (
                    <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
                      <Activity className="h-3 w-3" />
                      {source.eventsPerDay} events/day
                    </div>
                  ) : (
                    <div />
                  )}
                  <div className="flex items-center gap-2">
                    {source.lastSync && (
                      <span className="text-[10px] text-muted-foreground">Last sync: {source.lastSync}</span>
                    )}
                    {source.status === 'not_configured' && !source.push && (
                      <a
                        href="/app/settings#sources"
                        className="text-[10px] text-blue-400 hover:underline"
                      >
                        Configure →
                      </a>
                    )}
                    {source.push && (
                      <button
                        type="button"
                        onClick={() => setSetupGuideSourceId(source.id)}
                        className="text-[10px] text-blue-400 hover:underline"
                      >
                        View Setup Guide →
                      </button>
                    )}
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>

      {filtered.length === 0 && (
        <div className="text-center py-12 text-sm text-muted-foreground">
          No sources match your search.
        </div>
      )}

      {/* Setup Guide Modal */}
      {setupGuideSourceId && (
        <SetupGuideModal
          sourceId={setupGuideSourceId}
          onClose={() => setSetupGuideSourceId(null)}
        />
      )}

      {/* API Ingest Modal */}
      {showApiModal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
          onClick={(e) => e.target === e.currentTarget && setShowApiModal(false)}
          role="dialog"
          aria-modal="true"
        >
          <div className="glass-card-elevated rounded-2xl shadow-2xl shadow-black/40 p-6 max-w-lg w-full mx-4">
            <div className="flex items-center gap-2 mb-4">
              <Terminal className="h-4 w-4 text-primary" />
              <h2 className="text-sm font-bold">Push Alerts via REST API</h2>
              <button
                type="button"
                onClick={() => setShowApiModal(false)}
                className="ml-auto text-muted-foreground hover:text-foreground text-xl leading-none"
              >
                ×
              </button>
            </div>

            <div className="space-y-4">
              {/* Endpoint */}
              <div>
                <label className="block text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5">Endpoint</label>
                <div className="flex items-center gap-2">
                  <div className="flex-1 rounded-lg bg-muted px-3 py-2 font-mono text-xs">
                    POST /api/v1/ingest/alerts
                  </div>
                  <button
                    onClick={() => copyText('/api/v1/ingest/alerts', 'Endpoint')}
                    className="flex items-center gap-1 px-2 py-2 text-xs rounded-lg border border-border text-muted-foreground hover:text-foreground hover:bg-muted/30 transition-colors"
                  >
                    {copied === 'Endpoint' ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                  </button>
                </div>
              </div>

              {/* API Key */}
              <div>
                <label className="block text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5">API Key</label>
                <div className="flex items-center gap-2">
                  <div className="flex-1 rounded-lg bg-muted px-3 py-2 font-mono text-xs">
                    {apiKeyRevealed ? 'SOC-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6' : 'SOC-xxxx····xxxx'}
                  </div>
                  <button
                    onClick={() => setApiKeyRevealed(!apiKeyRevealed)}
                    className="p-2 text-xs rounded-lg border border-border text-muted-foreground hover:text-foreground hover:bg-muted/30 transition-colors"
                  >
                    {apiKeyRevealed ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                  </button>
                  <button
                    onClick={() => copyText('SOC-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6', 'API Key')}
                    className="p-2 text-xs rounded-lg border border-border text-muted-foreground hover:text-foreground hover:bg-muted/30 transition-colors"
                  >
                    {copied === 'API Key' ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                  </button>
                  {isAdmin && (
                    <button
                      onClick={() => toast.success('API key regenerated')}
                      className="p-2 text-xs rounded-lg border border-border text-destructive hover:bg-destructive/10 transition-colors"
                    >
                      <RefreshCw className="h-3 w-3" />
                    </button>
                  )}
                </div>
              </div>

              {/* Example */}
              <div>
                <label className="block text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5">cURL Example</label>
                <div className="relative">
                  <pre className="rounded-lg bg-muted p-4 text-xs font-mono overflow-x-auto max-h-[200px]">
                    {curlExample}
                  </pre>
                  <button
                    onClick={() => copyText(curlExample, 'cURL')}
                    className="absolute top-2 right-2 flex items-center gap-1 px-2 py-1 text-[10px] rounded border border-border bg-muted/80 text-muted-foreground hover:text-foreground transition-colors"
                  >
                    {copied === 'cURL' ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                    {copied === 'cURL' ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>
            </div>

            <div className="flex justify-end mt-5 pt-4 border-t border-border/50">
              <button
                type="button"
                onClick={() => setShowApiModal(false)}
                className="px-3 py-1.5 text-xs font-medium rounded-lg border border-border text-muted-foreground hover:text-foreground hover:bg-muted/30 transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default Sources
