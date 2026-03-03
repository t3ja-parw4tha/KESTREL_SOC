import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useAlert } from '@/hooks/useAlerts'
import { useQuery } from '@tanstack/react-query'
import { triggerAI, getTimeline, updateAlertStatus } from '@/api/alerts'
import { Card } from '@/components/ui/Card'
import { AlertBadge } from '@/components/alerts/AlertBadge'
import { MitreTags } from '@/components/alerts/MitreTags'
import { Spinner } from '@/components/ui/Spinner'
import { formatDateTime } from '@/utils/time'
import { getRiskScoreColor } from '@/utils/severity'
import { ErrorState } from '@/components/ui/ErrorState'
import { SpinnerOverlay } from '@/components/ui/Spinner'
import {
  Sparkles,
  Shield,
  CheckCircle2,
  MessageSquare,
  FileJson,
  Copy,
  ChevronDown,
  Server,
  User,
  Globe,
  Activity,
} from 'lucide-react'
import { cn } from '@/utils/cn'
import type { Alert } from '@/types/alert'

const TABS = [
  { id: 'overview', label: 'Overview', icon: Activity },
  { id: 'ai', label: 'AI Analysis', icon: Sparkles },
  { id: 'enrichment', label: 'Enrichment', icon: Shield },
  { id: 'mitre', label: 'MITRE', icon: Shield },
  { id: 'timeline', label: 'Timeline', icon: MessageSquare },
  { id: 'raw', label: 'Raw Log', icon: FileJson },
] as const

type TabId = (typeof TABS)[number]['id']

export function AlertDetail() {
  const { id } = useParams<{ id: string }>()
  const [tab, setTab] = useState<TabId>('overview')
  const [statusUpdating, setStatusUpdating] = useState(false)
  const [aiLoading, setAiLoading] = useState(false)

  const { data: alert, isLoading, isError, refetch } = useAlert(id)

  if (isError) return <ErrorState title="Alert not found" message="The alert may have been removed." onRetry={() => refetch()} />
  if (isLoading || !alert) return <SpinnerOverlay />

  const decision = alert.decision
  const recommendedActions = decision?.recommended_actions?.items ?? []
  const explanation = decision?.explanation?.items ?? []
  const enrichment = alert.enrichment

  const handleStatusChange = async (newStatus: Alert['status']) => {
    if (!id) return
    setStatusUpdating(true)
    try {
      await updateAlertStatus(id, newStatus)
      refetch()
    } finally {
      setStatusUpdating(false)
    }
  }

  const handleRunAI = async () => {
    if (!id) return
    setAiLoading(true)
    try {
      await triggerAI(id)
      await refetch()
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('AI triage failed:', e)
    } finally {
      setAiLoading(false)
    }
  }

  const handleCopyRaw = () => {
    if (alert.raw) {
      navigator.clipboard.writeText(JSON.stringify(alert.raw, null, 2))
    }
  }

  return (
    <div className="space-y-6">
      <nav className="flex items-center gap-2 text-sm text-soc-muted">
        <Link to="/alerts" className="hover:text-soc-text">Alerts</Link>
        <ChevronDown className="w-4 h-4 rotate-[-90deg]" />
        <span className="text-soc-text truncate max-w-[200px]">{alert.title}</span>
      </nav>

      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <h1 className="text-2xl font-semibold text-soc-text break-words">{alert.title}</h1>
          <div className="flex flex-wrap items-center gap-2 mt-2">
            <AlertBadge severity={alert.severity} />
            <div className="w-24 h-2 rounded-full bg-soc-border overflow-hidden">
              <div
                className={cn('h-full rounded-full', (alert.risk_score ?? 0) > 75 ? 'bg-red-500' : (alert.risk_score ?? 0) > 50 ? 'bg-orange-500' : 'bg-blue-500')}
                style={{ width: `${Math.min(100, alert.risk_score ?? 0)}%` }}
              />
            </div>
            <span className={cn('text-sm font-medium', getRiskScoreColor(alert.risk_score))}>{alert.risk_score ?? 0}</span>
            <select
              value={alert.status}
              onChange={(e) => handleStatusChange(e.target.value as Alert['status'])}
              disabled={statusUpdating}
              className="rounded border border-soc-border bg-soc-bg text-soc-text px-2 py-1 text-sm"
            >
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="resolved">Resolved</option>
              <option value="false_positive">False Positive</option>
            </select>
            {alert.assigned_to && <span className="text-soc-muted text-sm">Assigned: {alert.assigned_to}</span>}
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={handleRunAI}
            disabled={aiLoading}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-soc-border bg-soc-surface text-soc-text hover:bg-soc-border/30 disabled:opacity-50 text-sm"
          >
            {aiLoading ? <Spinner size="sm" /> : <Sparkles className="w-4 h-4" />}
            Run AI Analysis
          </button>
          <button
            type="button"
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-soc-border bg-soc-surface text-soc-text hover:bg-soc-border/30 text-sm"
          >
            Run Decision Engine
          </button>
          <button
            type="button"
            onClick={() => handleStatusChange('resolved')}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 text-sm"
          >
            <CheckCircle2 className="w-4 h-4" /> Mark Resolved
          </button>
        </div>
      </div>

      <div className="border-b border-soc-border">
        <nav className="flex gap-1">
          {TABS.map(({ id: t, label, icon: Icon }) => (
            <button
              key={t}
              type="button"
              onClick={() => setTab(t)}
              className={cn(
                'flex items-center gap-2 py-2 px-3 text-sm font-medium border-b-2 transition-colors',
                tab === t ? 'border-blue-500 text-soc-text' : 'border-transparent text-soc-muted hover:text-soc-text'
              )}
            >
              <Icon className="w-4 h-4" /> {label}
            </button>
          ))}
        </nav>
      </div>

      <div className="rounded-lg border border-soc-border bg-soc-surface p-4 min-h-[200px]">
        {tab === 'overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div>
              <h3 className="text-sm font-semibold text-soc-text mb-2">Key facts</h3>
              <ul className="list-disc list-inside text-soc-muted text-sm space-y-1">
                {recommendedActions.slice(0, 5).map((a, i) => (
                  <li key={i}>{a}</li>
                ))}
                {recommendedActions.length === 0 && <li>No key facts</li>}
              </ul>
              <h3 className="text-sm font-semibold text-soc-text mt-4 mb-2">Affected</h3>
              <div className="space-y-2 text-sm">
                <div className="flex items-center gap-2 text-soc-muted"><Server className="w-4 h-4" /> Asset: {alert.asset_id ?? '—'}</div>
                <div className="flex items-center gap-2 text-soc-muted"><User className="w-4 h-4" /> User: {alert.user_id ?? '—'}</div>
                <div className="flex items-center gap-2 text-soc-muted"><Globe className="w-4 h-4" /> Source IP: {alert.source_ip ?? '—'}</div>
                <div className="flex items-center gap-2 text-soc-muted"><Globe className="w-4 h-4" /> Dest IP: {alert.dest_ip ?? '—'}</div>
              </div>
            </div>
            <div>
              <h3 className="text-sm font-semibold text-soc-text mb-2">Recommended actions</h3>
              <ol className="list-decimal list-inside text-soc-muted text-sm space-y-1">
                {recommendedActions.map((a, i) => (
                  <li key={i}>{a}</li>
                ))}
                {recommendedActions.length === 0 && <li>None</li>}
              </ol>
              <h3 className="text-sm font-semibold text-soc-text mt-4 mb-2">Decision engine</h3>
              <div className="space-y-1 text-sm text-soc-muted">
                <p>Risk score: {decision?.risk_score ?? '—'}</p>
                <p>Confidence: {decision?.confidence != null ? `${Math.round(decision.confidence * 100)}%` : '—'}</p>
                {explanation.length > 0 && (
                  <ul className="list-disc list-inside mt-2">{explanation.map((e, i) => <li key={i}>{e}</li>)}</ul>
                )}
              </div>
            </div>
          </div>
        )}

        {tab === 'ai' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-soc-text">
                AI Triage Analysis
              </h3>
              <button
                type="button"
                onClick={handleRunAI}
                disabled={aiLoading}
                className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-soc-border bg-soc-surface text-soc-text hover:bg-soc-border/30 disabled:opacity-50 text-sm"
              >
                {aiLoading ? <Spinner size="sm" /> : <Sparkles className="w-4 h-4 text-yellow-400" />}
                {alert.ai_summary ? 'Re-run Analysis' : 'Run AI Analysis'}
              </button>
            </div>

            {!alert.ai_summary && !aiLoading && (
              <div className="rounded-lg border border-soc-border bg-soc-surface/50 p-6 text-center">
                <Sparkles className="w-8 h-8 text-soc-muted mx-auto mb-2" />
                <p className="text-soc-muted text-sm">
                  No AI analysis yet. Click "Run AI Analysis" to generate triage.
                </p>
              </div>
            )}

            {aiLoading && (
              <div className="rounded-lg border border-soc-border bg-soc-surface/50 p-6 text-center">
                <Spinner size="md" />
                <p className="text-soc-muted text-sm mt-2">Analyzing alert...</p>
              </div>
            )}

            {alert.ai_summary && !aiLoading && (
              <div className="space-y-4">
                <div className="rounded-lg border border-soc-border bg-soc-surface p-4">
                  <h4 className="text-xs font-semibold text-soc-muted uppercase tracking-wide mb-2">
                    Summary
                  </h4>
                  <p className="text-soc-text text-sm leading-relaxed whitespace-pre-wrap">
                    {alert.ai_summary}
                  </p>
                </div>

                {alert.ai_key_facts && Object.keys(alert.ai_key_facts as Record<string, unknown>).length > 0 && (
                  <div className="rounded-lg border border-soc-border bg-soc-surface p-4">
                    <h4 className="text-xs font-semibold text-soc-muted uppercase tracking-wide mb-2">
                      Key Facts
                    </h4>
                    <dl className="grid grid-cols-2 gap-2">
                      {Object.entries(alert.ai_key_facts as Record<string, unknown>).map(([k, v]) => (
                        <div key={k}>
                          <dt className="text-xs text-soc-muted capitalize">{k}</dt>
                          <dd className="text-sm text-soc-text">{String(v)}</dd>
                        </div>
                      ))}
                    </dl>
                  </div>
                )}

                {alert.ai_remediation && (
                  <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-4">
                    <h4 className="text-xs font-semibold text-amber-400 uppercase tracking-wide mb-2">
                      Remediation
                    </h4>
                    {Array.isArray((alert.ai_remediation as { actions?: string[] })?.actions) ? (
                      <ul className="space-y-1">
                        {((alert.ai_remediation as { actions: string[] }).actions).map((a, i) => (
                          <li key={i} className="text-sm text-soc-text flex gap-2">
                            <span className="text-amber-400 shrink-0">→</span>
                            {a}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-sm text-soc-text">{JSON.stringify(alert.ai_remediation)}</p>
                    )}
                  </div>
                )}

                {alert.ai_next_steps && (
                  <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-4">
                    <h4 className="text-xs font-semibold text-blue-400 uppercase tracking-wide mb-2">
                      Next Steps
                    </h4>
                    {Array.isArray((alert.ai_next_steps as { recommendations?: string[] })?.recommendations) ? (
                      <ul className="space-y-1">
                        {((alert.ai_next_steps as { recommendations: string[] }).recommendations).map((r, i) => (
                          <li key={i} className="text-sm text-soc-text flex gap-2">
                            <span className="text-blue-400 shrink-0">{i + 1}.</span>
                            {r}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-sm text-soc-text">{JSON.stringify(alert.ai_next_steps)}</p>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {tab === 'enrichment' && (
          <div className="space-y-4">
            <h3 className="text-sm font-semibold text-soc-text">IOCs found</h3>
            <div className="flex flex-wrap gap-2">
              {(enrichment?.iocs_found ?? []).length === 0 && !enrichment && <p className="text-soc-muted text-sm">No enrichment data.</p>}
              {(enrichment?.iocs_found ?? []).map((ioc, i) => (
                <span key={i} className="rounded px-2 py-1 text-xs bg-soc-border text-soc-muted">{ioc}</span>
              ))}
            </div>
            <h3 className="text-sm font-semibold text-soc-text mt-4">VirusTotal</h3>
            <div className="space-y-2 text-sm">
              {(enrichment?.vt_results ?? []).map((r, i) => (
                <div key={i} className="rounded border border-soc-border p-2">
                  <span className="text-soc-text">{r.indicator}</span>
                  <div className="mt-1 h-2 rounded-full bg-soc-border overflow-hidden">
                    <div className={cn('h-full', (r.malicious_count ?? 0) > 0 ? 'bg-red-500' : 'bg-soc-muted')} style={{ width: `${(r.detection_ratio ?? 0) * 100}%` }} />
                  </div>
                  <p className="text-soc-muted text-xs">Malicious: {r.malicious_count ?? 0} / Total: {r.total_engines ?? 0}</p>
                  {r.permalink && <a href={r.permalink} target="_blank" rel="noopener noreferrer" className="text-blue-400 text-xs">Report</a>}
                </div>
              ))}
              {(enrichment?.vt_results ?? []).length === 0 && <p className="text-soc-muted">No VT results.</p>}
            </div>
            <h3 className="text-sm font-semibold text-soc-text mt-4">AbuseIPDB</h3>
            <div className="space-y-2 text-sm text-soc-muted">
              {(enrichment?.abuse_results ?? []).map((r, i) => (
                <div key={i}>IP: {r.ip} — Score: {r.abuse_score} — ISP: {r.isp ?? '—'} — Country: {r.country_code ?? '—'}</div>
              ))}
              {(enrichment?.abuse_results ?? []).length === 0 && <p>No AbuseIPDB results.</p>}
            </div>
            <h3 className="text-sm font-semibold text-soc-text mt-4">Feed matches</h3>
            <div className="text-sm text-soc-muted">
              {(enrichment?.feed_matches ?? []).length === 0 && <p>None.</p>}
              {(enrichment?.feed_matches ?? []).map((m, i) => <p key={i}>{m.feed_name}: {m.indicator}</p>)}
            </div>
          </div>
        )}

        {tab === 'mitre' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {(alert.mitre_techniques ?? []).map((t, i) => (
              <Card key={i} className="p-3">
                <span className="text-xs text-soc-muted">{t.tactic}</span>
                <div className="flex items-center gap-2 mt-1">
                  <MitreTags techniques={[t]} />
                  <span className="text-soc-text font-medium">{t.technique_name}</span>
                </div>
              </Card>
            ))}
            {(alert.mitre_techniques ?? []).length === 0 && <p className="text-soc-muted text-sm">No MITRE techniques.</p>}
          </div>
        )}

        {tab === 'timeline' && id && <TimelineTab alertId={id} />}

        {tab === 'raw' && (
          <div>
            <button type="button" onClick={handleCopyRaw} className="mb-2 inline-flex items-center gap-1 px-2 py-1 rounded border border-soc-border text-soc-muted hover:text-soc-text text-sm">
              <Copy className="w-4 h-4" /> Copy
            </button>
            <pre className="text-xs text-soc-muted overflow-auto max-h-[400px] bg-soc-bg p-3 rounded border border-soc-border">
              {JSON.stringify(alert.raw ?? {}, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  )
}

function TimelineTab({ alertId }: { alertId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ['alert', 'timeline', alertId],
    queryFn: () => getTimeline(alertId),
    enabled: !!alertId,
  })
  const timeline = data?.items ?? []
  if (isLoading) return <Spinner size="md" />
  return (
    <div className="space-y-3">
      {timeline.map((e, i) => (
        <div key={i} className="flex gap-3">
          <div className="w-2 h-2 rounded-full bg-soc-border mt-1.5 shrink-0" />
          <div>
            <p className="text-sm text-soc-text">{e.action}</p>
            <p className="text-xs text-soc-muted">{formatDateTime(e.timestamp)} {e.analyst && `· ${e.analyst}`}</p>
          </div>
        </div>
      ))}
      {timeline.length === 0 && <p className="text-soc-muted text-sm">No timeline events.</p>}
    </div>
  )
}

