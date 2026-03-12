import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { get } from '@/api/client'
import { SpinnerOverlay } from '@/components/ui/Spinner'
import { ErrorState } from '@/components/ui/ErrorState'
import { SetupGuideModal } from '@/components/sources/SetupGuideModal'

const TEST_PASSED_KEY = 'kestrel_source_tested_'
const SOURCES_REQUIRING_TEST = ['sentinel', 'guardduty', 'virustotal', 'abuseipdb']

function getTestPassed(sourceId: string): boolean {
  try {
    return localStorage.getItem(TEST_PASSED_KEY + sourceId) === '1'
  } catch {
    return false
  }
}

/** Only show Connected when credentials exist AND Test Connection has passed (same as Settings). */
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
}

const STATUS_CONFIG = {
  connected: {
    label: 'Connected',
    dot: 'bg-green-400 animate-pulse',
    text: 'text-green-400',
    border: 'border-green-500/20',
    bg: 'bg-green-500/5',
  },
  not_configured: {
    label: 'Not Configured',
    dot: 'bg-gray-500',
    text: 'text-soc-muted',
    border: 'border-soc-border',
    bg: 'bg-soc-surface',
  },
  push_ready: {
    label: 'Push Ready',
    dot: 'bg-blue-400',
    text: 'text-blue-400',
    border: 'border-blue-500/20',
    bg: 'bg-blue-500/5',
  },
}

const TYPE_COLORS: Record<string, string> = {
  SIEM: 'bg-purple-500/10 text-purple-400',
  Cloud: 'bg-orange-500/10 text-orange-400',
  Enrichment: 'bg-teal-500/10 text-teal-400',
  'IDS/IPS': 'bg-red-500/10 text-red-400',
  OS: 'bg-blue-500/10 text-blue-400',
  EDR: 'bg-yellow-500/10 text-yellow-400',
}

export function Sources() {
  const [setupGuideSourceId, setSetupGuideSourceId] = useState<string | null>(null)
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['sources'],
    queryFn: () => get<{ items: Source[]; configured_count: number }>('/sources'),
  })

  if (isError) return <ErrorState title="Failed to load sources" onRetry={() => refetch()} />
  if (isLoading) return <SpinnerOverlay />

  const rawItems = data?.items ?? []
  const items = rawItems.map((s) => ({ ...s, status: displayStatus(s.status, s.id) }))
  const configured = items.filter((s) => s.status === 'connected').length

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold text-soc-text">
          Connected Sources
        </h1>
        <a
          href="/app/settings"
          className="text-sm text-blue-400 hover:underline"
        >
          Configure in Settings →
        </a>
      </div>

      <div className="p-4 rounded-lg border border-soc-border bg-soc-surface">
        <p className="text-sm text-soc-muted">
          <span className={configured === 0 ? 'text-amber-400 font-semibold' : 'text-soc-text font-semibold'}>
            {configured}
          </span>
          {' '}of{' '}
          <span className={configured === 0 ? 'text-amber-400 font-semibold' : 'text-soc-text font-semibold'}>
            4
          </span>
          {' '}sources connected
          {' · '}
          <span className="text-blue-400">
            {items.filter((s) => s.push).length} push sources ready to receive
          </span>
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {items.map((source) => {
          const cfg = STATUS_CONFIG[source.status]
          return (
            <div
              key={source.id}
              className={`rounded-lg border p-4 ${cfg.border} ${cfg.bg}`}
            >
              <div className="flex items-start justify-between mb-2">
                <div className="flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full shrink-0 ${cfg.dot}`} />
                  <h3 className="text-sm font-semibold text-soc-text">
                    {source.name}
                  </h3>
                </div>
                <div className="flex items-center gap-2">
                  <span
                    className={`text-xs px-2 py-0.5 rounded-full 
                    ${TYPE_COLORS[source.type] ?? 'bg-soc-border text-soc-muted'}`}
                  >
                    {source.type}
                  </span>
                  <span className={`text-xs ${cfg.text}`}>
                    {cfg.label}
                  </span>
                </div>
              </div>
              <p className="text-xs text-soc-muted">{source.description}</p>
              {source.status === 'not_configured' && !source.push && (
                <a
                  href="/app/settings#sources"
                  className="text-xs text-blue-400 hover:underline mt-2 inline-block"
                >
                  Configure →
                </a>
              )}
              {source.push && (
                <button
                  type="button"
                  onClick={() => setSetupGuideSourceId(source.id)}
                  className="text-xs text-blue-400 hover:underline mt-2 inline-block"
                >
                  View Setup Guide →
                </button>
              )}
            </div>
          )
        })}
      </div>

      {setupGuideSourceId && (
        <SetupGuideModal
          sourceId={setupGuideSourceId}
          onClose={() => setSetupGuideSourceId(null)}
        />
      )}
    </div>
  )
}
