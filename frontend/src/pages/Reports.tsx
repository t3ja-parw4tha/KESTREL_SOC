import { useState } from 'react'
import { createPortal } from 'react-dom'
import { useQuery } from '@tanstack/react-query'
import { Breadcrumb } from '@/components/ui/Breadcrumb'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
  LineChart, Line,
} from 'recharts'
import {
  Printer, TrendingUp, TrendingDown, Minus, Target, Users,
  Shield, AlertTriangle, CheckCircle2, XCircle, ChevronDown, ChevronRight, Lock,
} from 'lucide-react'
import { getReportSummary, getAnalystActivity, type ReportSummary, type AnalystActivity } from '@/api/reports'
import { useAuth } from '@/security/AuthContext'
import type { User } from '@/security/AuthContext'
import { fetchMitreCoverage } from '@/api/mitre'
import type { MitreCoverageResponse } from '@/types/mitre'
import { SpinnerOverlay } from '@/components/ui/Spinner'
import { ErrorState } from '@/components/ui/ErrorState'
import { cn } from '@/utils/cn'

type DayRange = 7 | 30 | 90
type Tab = 'summary' | 'coverage' | 'analysts'

const CHART_STYLE = {
  backgroundColor: 'var(--soc-tooltip-bg)',
  border: '1px solid var(--soc-tooltip-border)',
  borderRadius: '8px',
  color: 'var(--soc-tooltip-text)',
  fontSize: '12px',
}

const SEVERITY_COLORS: Record<string, string> = {
  Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#3b82f6',
}

// ── KPI card ──────────────────────────────────────────────────────────────────
function KpiCard({
  label, value, sub, trend, danger, icon: Icon,
}: {
  label: string; value: string | number; sub?: string
  trend?: number | null; danger?: boolean; icon?: React.ElementType
}) {
  return (
    <div className={cn('rounded-lg border bg-soc-surface p-4', danger ? 'border-red-500/30 bg-red-500/5' : 'border-soc-border')}>
      <div className="flex items-center justify-between mb-2">
        <p className="text-xs text-soc-muted">{label}</p>
        {Icon && <Icon className="w-4 h-4 text-soc-muted/60" />}
      </div>
      <p className={cn('text-2xl font-bold', danger ? 'text-red-400' : 'text-soc-text')}>{value}</p>
      {sub && <p className="text-xs text-soc-muted mt-0.5">{sub}</p>}
      {trend != null && (
        <p className={cn('text-xs mt-1.5 flex items-center gap-1',
          trend > 0 ? 'text-red-400' : trend < 0 ? 'text-emerald-400' : 'text-soc-muted')}>
          {trend > 0 ? <TrendingUp className="w-3 h-3" /> : trend < 0 ? <TrendingDown className="w-3 h-3" /> : <Minus className="w-3 h-3" />}
          {Math.abs(Math.round(trend))}% vs prev period
        </p>
      )}
    </div>
  )
}

function SectionHeading({ children }: { children: React.ReactNode }) {
  return <h2 className="text-sm font-semibold text-soc-text mb-3">{children}</h2>
}

// ── Summary tab ───────────────────────────────────────────────────────────────
function SummaryTab({ data, days }: { data: ReportSummary; days: number }) {
  const severityData = Object.entries(data.alerts_by_severity)
    .map(([name, value]) => ({ name, value })).filter((d) => d.value > 0)
  const chartData = data.volume_timeline.map((d) => ({
    ...d,
    label: new Date(`${d.date}T00:00:00`).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
  }))
  const xInterval = days <= 7 ? 0 : days <= 30 ? 3 : 9

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="rounded-lg border border-soc-border bg-soc-surface p-4">
          <SectionHeading>Alert Volume ({days} days)</SectionHeading>
          <div className="h-[220px]">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--soc-chart-grid)" />
                <XAxis dataKey="label" stroke="var(--soc-muted)" fontSize={10} tick={{ fill: 'var(--soc-muted)' }} interval={xInterval} />
                <YAxis stroke="var(--soc-muted)" fontSize={10} tick={{ fill: 'var(--soc-muted)' }} allowDecimals={false} width={28} />
                <Tooltip contentStyle={CHART_STYLE} formatter={(v: number) => [v, 'Alerts']} />
                <Line type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="rounded-lg border border-soc-border bg-soc-surface p-4">
          <SectionHeading>Alerts by Severity</SectionHeading>
          {severityData.length === 0 ? (
            <div className="h-[220px] flex items-center justify-center text-soc-muted text-sm">No data</div>
          ) : (
            <div className="h-[220px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={severityData} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--soc-chart-grid)" />
                  <XAxis dataKey="name" fontSize={11} tick={{ fill: 'var(--soc-muted)' }} />
                  <YAxis fontSize={11} tick={{ fill: 'var(--soc-muted)' }} allowDecimals={false} width={28} />
                  <Tooltip contentStyle={CHART_STYLE} />
                  <Bar dataKey="value" name="Alerts" radius={[4, 4, 0, 0]}>
                    {severityData.map((entry) => (
                      <rect key={entry.name} fill={SEVERITY_COLORS[entry.name] ?? '#6b7280'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="rounded-lg border border-soc-border bg-soc-surface p-4">
          <SectionHeading>Top Alert Sources</SectionHeading>
          {data.top_sources.length === 0 ? <p className="text-soc-muted text-sm py-4">No data</p> : (
            <div className="space-y-2">
              {data.top_sources.map(({ source, count }) => {
                const max = Math.max(...data.top_sources.map((s) => s.count), 1)
                return (
                  <div key={source} className="flex items-center gap-3">
                    <span className="text-sm text-soc-muted w-28 truncate" title={source}>{source}</span>
                    <div className="flex-1 h-2 rounded-full bg-soc-border overflow-hidden">
                      <div className="h-full rounded-full bg-blue-500" style={{ width: `${Math.round((count / max) * 100)}%` }} />
                    </div>
                    <span className="text-sm font-medium text-soc-text w-8 text-right">{count}</span>
                  </div>
                )
              })}
            </div>
          )}
        </div>
        <div className="rounded-lg border border-soc-border bg-soc-surface p-4">
          <SectionHeading>Top MITRE Tactics Triggered</SectionHeading>
          {data.top_tactics.length === 0 ? <p className="text-soc-muted text-sm py-4">No MITRE mappings</p> : (
            <div className="space-y-2">
              {data.top_tactics.map(({ tactic, count }) => {
                const max = Math.max(...data.top_tactics.map((t) => t.count), 1)
                return (
                  <div key={tactic} className="flex items-center gap-3">
                    <span className="text-sm text-soc-muted flex-1 truncate" title={tactic}>{tactic}</span>
                    <div className="w-32 h-2 rounded-full bg-soc-border overflow-hidden">
                      <div className="h-full rounded-full bg-orange-500" style={{ width: `${Math.round((count / max) * 100)}%` }} />
                    </div>
                    <span className="text-sm font-medium text-soc-text w-8 text-right">{count}</span>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Coverage tab ──────────────────────────────────────────────────────────────
function CoverageTab({ data }: { data: MitreCoverageResponse }) {
  const [gapsOpen, setGapsOpen] = useState(false)
  const techniques = data.techniques ?? []
  const tactics = data.tactics ?? []
  const tacticStats = tactics.map((tac) => {
    const tacTechniques = techniques.filter((t) => t.tactic_id === tac.id)
    const detected = tacTechniques.filter((t) => (t.alert_count ?? 0) > 0).length
    const total = tacTechniques.length
    return { id: tac.id, name: tac.name, detected, total, pct: total ? Math.round((detected / total) * 100) : 0 }
  }).filter((t) => t.total > 0)
  const gaps = techniques.filter((t) => (t.alert_count ?? 0) === 0)
  const summary = data.summary ?? {}
  const coveragePct = summary.coverage_percentage ?? 0

  return (
    <div className="space-y-6">
      <div className="rounded-lg border border-soc-border bg-soc-surface p-6 flex flex-wrap items-center gap-8">
        <div className="text-center">
          <p className="text-4xl font-bold text-soc-text">{coveragePct}%</p>
          <p className="text-xs text-soc-muted mt-1">Overall Coverage</p>
        </div>
        <div className="flex-1 min-w-[200px]">
          <div className="h-3 rounded-full bg-soc-border overflow-hidden">
            <div className={cn('h-full rounded-full transition-all', coveragePct >= 50 ? 'bg-emerald-500' : coveragePct >= 20 ? 'bg-amber-500' : 'bg-red-500')} style={{ width: `${coveragePct}%` }} />
          </div>
          <div className="flex justify-between mt-1.5 text-xs text-soc-muted">
            <span>{summary.techniques_detected ?? 0} techniques detected</span>
            <span>{summary.total_techniques ?? 0} total</span>
          </div>
        </div>
        <div className="text-center"><p className="text-2xl font-bold text-soc-text">{summary.tactics_covered ?? 0}</p><p className="text-xs text-soc-muted mt-1">Tactics covered</p></div>
        <div className="text-center"><p className="text-2xl font-bold text-red-400">{gaps.length}</p><p className="text-xs text-soc-muted mt-1">Detection gaps</p></div>
      </div>
      <div className="rounded-lg border border-soc-border bg-soc-surface overflow-hidden">
        <table className="w-full text-sm">
          <thead><tr className="border-b border-soc-border">
            <th className="text-left px-4 py-2.5 text-xs font-medium text-soc-muted uppercase tracking-wide">Tactic</th>
            <th className="text-right px-4 py-2.5 text-xs font-medium text-soc-muted uppercase tracking-wide">Detected</th>
            <th className="text-right px-4 py-2.5 text-xs font-medium text-soc-muted uppercase tracking-wide">Total</th>
            <th className="px-4 py-2.5 text-xs font-medium text-soc-muted uppercase tracking-wide">Coverage</th>
          </tr></thead>
          <tbody className="divide-y divide-soc-border">
            {tacticStats.map((t) => (
              <tr key={t.id} className="hover:bg-soc-border/20">
                <td className="px-4 py-2.5 font-medium text-soc-text">{t.name}</td>
                <td className="px-4 py-2.5 text-right text-soc-text">{t.detected}</td>
                <td className="px-4 py-2.5 text-right text-soc-muted">{t.total}</td>
                <td className="px-4 py-2.5">
                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-1.5 rounded-full bg-soc-border overflow-hidden">
                      <div className={cn('h-full rounded-full', t.pct >= 50 ? 'bg-emerald-500' : t.pct >= 20 ? 'bg-amber-500' : 'bg-red-500')} style={{ width: `${t.pct}%` }} />
                    </div>
                    <span className="text-xs text-soc-muted w-8 text-right">{t.pct}%</span>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {gaps.length > 0 && (
        <div className="rounded-lg border border-red-500/20 bg-red-500/5">
          <button type="button" onClick={() => setGapsOpen((o) => !o)} className="w-full flex items-center justify-between px-4 py-3 text-sm font-medium text-red-400">
            <span className="flex items-center gap-2"><XCircle className="w-4 h-4" />{gaps.length} techniques with no detection</span>
            {gapsOpen ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
          </button>
          {gapsOpen && (
            <div className="border-t border-red-500/20 px-4 pb-4 pt-3 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
              {gaps.map((t) => (
                <div key={t.id} className="flex items-start gap-2 text-xs text-soc-muted">
                  <span className="shrink-0 font-mono text-red-400">{t.id}</span>
                  <span className="truncate" title={t.name}>{t.name}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Analyst Activity tab ──────────────────────────────────────────────────────
function AnalystTab({ analysts, days }: { analysts: Array<{ analyst: string; alerts_triaged: number; comments_added: number }>; days: number }) {
  if (analysts.length === 0) {
    return (
      <div className="rounded-lg border border-soc-border bg-soc-surface p-8 text-center">
        <Users className="w-10 h-10 text-soc-muted mx-auto mb-2" />
        <p className="text-soc-muted text-sm">No analyst activity in the last {days} days.</p>
      </div>
    )
  }
  const maxTriaged = Math.max(...analysts.map((a) => a.alerts_triaged), 1)
  return (
    <div className="rounded-lg border border-soc-border bg-soc-surface overflow-hidden">
      <table className="w-full text-sm">
        <thead><tr className="border-b border-soc-border">
          <th className="text-left px-4 py-2.5 text-xs font-medium text-soc-muted uppercase tracking-wide">Analyst ID</th>
          <th className="text-right px-4 py-2.5 text-xs font-medium text-soc-muted uppercase tracking-wide">Triaged</th>
          <th className="text-right px-4 py-2.5 text-xs font-medium text-soc-muted uppercase tracking-wide">Comments</th>
          <th className="text-right px-4 py-2.5 text-xs font-medium text-soc-muted uppercase tracking-wide">Total</th>
          <th className="px-4 py-2.5 text-xs font-medium text-soc-muted uppercase tracking-wide">Activity</th>
        </tr></thead>
        <tbody className="divide-y divide-soc-border">
          {analysts.map((a) => (
            <tr key={a.analyst} className="hover:bg-soc-border/20">
              <td className="px-4 py-2.5 font-mono text-soc-text text-xs">{a.analyst}</td>
              <td className="px-4 py-2.5 text-right font-medium text-soc-text">{a.alerts_triaged}</td>
              <td className="px-4 py-2.5 text-right text-soc-muted">{a.comments_added}</td>
              <td className="px-4 py-2.5 text-right text-soc-text">{a.alerts_triaged + a.comments_added}</td>
              <td className="px-4 py-2.5">
                <div className="h-1.5 rounded-full bg-soc-border overflow-hidden">
                  <div className="h-full rounded-full bg-blue-500" style={{ width: `${Math.round((a.alerts_triaged / maxTriaged) * 100)}%` }} />
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ── Print Report (hidden on screen, full business report layout for print/PDF) ─
function PrintReport({
  summary, coverage, activity, user, days,
}: {
  summary: ReportSummary
  coverage: MitreCoverageResponse | undefined
  activity: AnalystActivity | undefined
  user: User | null
  days: number
}) {
  const generatedAt = new Date().toLocaleString('en-US', { dateStyle: 'long', timeStyle: 'short' })
  const periodLabel = `Last ${days} days (ending ${new Date().toLocaleDateString('en-US', { dateStyle: 'long' })})`
  const severityTotal = Object.values(summary.alerts_by_severity).reduce((a, b) => a + b, 0)
  const fpRate = summary.total_alerts ? Math.round((summary.false_positives / summary.total_alerts) * 100) : 0
  const prevChange = summary.prev_total_alerts > 0
    ? ((summary.total_alerts - summary.prev_total_alerts) / summary.prev_total_alerts * 100).toFixed(1)
    : null

  const tactics = coverage?.tactics ?? []
  const techniques = coverage?.techniques ?? []
  const tacticStats = tactics.map((tac) => {
    const tacTechs = techniques.filter((t) => t.tactic_id === tac.id)
    const detected = tacTechs.filter((t) => (t.alert_count ?? 0) > 0).length
    const total = tacTechs.length
    return { name: tac.name, detected, total, pct: total ? Math.round((detected / total) * 100) : 0 }
  }).filter((t) => t.total > 0)

  const coverageSummary = coverage?.summary ?? {}

  return (
    <div className="kestrel-report">
      {/* ── Cover header ── */}
      <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: '16pt', borderBottom: '2pt solid #1e3a5f' }}>
        <tbody>
          <tr>
            <td style={{ paddingBottom: '8pt', verticalAlign: 'bottom' }}>
              <div style={{ fontSize: '22pt', fontWeight: 700, color: '#1e3a5f', letterSpacing: '-0.5pt' }}>KESTREL</div>
              <div style={{ fontSize: '10pt', color: '#64748b', marginTop: '2pt' }}>Security Operations Platform</div>
            </td>
            <td style={{ textAlign: 'right', paddingBottom: '8pt', verticalAlign: 'bottom' }}>
              <div style={{ fontSize: '14pt', fontWeight: 700, color: '#0f172a' }}>SECURITY OPERATIONS REPORT</div>
              <div style={{ fontSize: '9pt', color: '#64748b', marginTop: '3pt' }}>{periodLabel}</div>
              <div style={{ fontSize: '9pt', color: '#64748b' }}>Generated: {generatedAt}</div>
              <div style={{ fontSize: '9pt', color: '#64748b' }}>Prepared by: {user?.username ?? 'system'} ({user?.role?.replace('_', ' ') ?? 'admin'})</div>
              <div style={{ display: 'inline-block', marginTop: '4pt', padding: '2pt 8pt', background: '#1e3a5f', color: '#fff', fontSize: '8pt', fontWeight: 600, borderRadius: '2pt' }}>
                CONFIDENTIAL
              </div>
            </td>
          </tr>
        </tbody>
      </table>

      {/* ── Executive KPI summary ── */}
      <h2>Executive Summary</h2>
      <table>
        <thead>
          <tr>
            <th>Metric</th>
            <th className="right">Value</th>
            <th>Notes</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Total Alerts</td>
            <td className="right"><strong>{summary.total_alerts.toLocaleString()}</strong></td>
            <td>{prevChange != null ? `${Number(prevChange) >= 0 ? '↑' : '↓'} ${Math.abs(Number(prevChange))}% vs previous ${days}d` : 'No comparison data'}</td>
          </tr>
          <tr>
            <td>Resolved</td>
            <td className="right"><strong>{summary.resolved_pct}%</strong></td>
            <td>{summary.resolved.toLocaleString()} alerts closed in this period</td>
          </tr>
          <tr>
            <td>Open Critical Alerts</td>
            <td className="right" style={{ color: summary.open_critical > 0 ? '#dc2626' : '#16a34a' }}>
              <strong>{summary.open_critical}</strong>
            </td>
            <td>{summary.open_critical > 0 ? 'Requires immediate attention' : 'None outstanding'}</td>
          </tr>
          <tr>
            <td>False Positives</td>
            <td className="right"><strong>{summary.false_positives.toLocaleString()}</strong></td>
            <td>{fpRate}% false-positive rate</td>
          </tr>
          <tr>
            <td>Active Incidents</td>
            <td className="right"><strong>{summary.incidents_count}</strong></td>
            <td>Correlated alert groups</td>
          </tr>
          <tr>
            <td>MITRE ATT&CK Coverage</td>
            <td className="right"><strong>{summary.coverage_pct}%</strong></td>
            <td>{summary.techniques_detected} of {summary.total_techniques} techniques detected (all-time)</td>
          </tr>
        </tbody>
      </table>

      {/* ── Alerts by severity ── */}
      <h2>Alert Breakdown by Severity</h2>
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th className="right">Count</th>
            <th className="right">Share</th>
            <th>Visual</th>
          </tr>
        </thead>
        <tbody>
          {(['Critical', 'High', 'Medium', 'Low'] as const).map((sev) => {
            const count = summary.alerts_by_severity[sev] ?? 0
            const pct = severityTotal ? Math.round((count / severityTotal) * 100) : 0
            const barColor = sev === 'Critical' ? 'red' : sev === 'High' ? 'amber' : sev === 'Medium' ? 'amber' : undefined
            return (
              <tr key={sev}>
                <td><span className={`rpt-badge rpt-badge-${sev.toLowerCase()}`}>{sev}</span></td>
                <td className="right"><strong>{count.toLocaleString()}</strong></td>
                <td className="right">{pct}%</td>
                <td>
                  <div className="rpt-bar-container">
                    <div className="rpt-bar-track">
                      <div className={`rpt-bar-fill${barColor ? ` ${barColor}` : ''}`} style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                </td>
              </tr>
            )
          })}
          <tr style={{ fontWeight: 600 }}>
            <td>Total</td>
            <td className="right">{severityTotal.toLocaleString()}</td>
            <td className="right">100%</td>
            <td />
          </tr>
        </tbody>
      </table>

      {/* ── Top sources ── */}
      {summary.top_sources.length > 0 && (
        <>
          <h2>Top Alert Sources</h2>
          <table>
            <thead><tr><th>Source</th><th className="right">Alerts</th><th>Share</th></tr></thead>
            <tbody>
              {summary.top_sources.map(({ source, count }) => {
                const total = summary.top_sources.reduce((a, s) => a + s.count, 0)
                const pct = total ? Math.round((count / total) * 100) : 0
                return (
                  <tr key={source}>
                    <td>{source}</td>
                    <td className="right"><strong>{count.toLocaleString()}</strong></td>
                    <td>
                      <div className="rpt-bar-container">
                        <div className="rpt-bar-track" style={{ maxWidth: '120pt' }}>
                          <div className="rpt-bar-fill" style={{ width: `${pct}%` }} />
                        </div>
                        <span style={{ fontSize: '8pt', color: '#64748b' }}>{pct}%</span>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </>
      )}

      {/* ── Daily volume ── */}
      <h2>Daily Alert Volume</h2>
      <table>
        <thead><tr><th>Date</th><th className="right">Alerts</th></tr></thead>
        <tbody>
          {summary.volume_timeline.filter((d) => d.count > 0 || summary.volume_timeline.indexOf(d) % 3 === 0).map((d) => (
            <tr key={d.date}>
              <td>{new Date(`${d.date}T00:00:00`).toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' })}</td>
              <td className="right">{d.count}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {/* ── Top MITRE tactics ── */}
      {summary.top_tactics.length > 0 && (
        <>
          <h2>Top MITRE ATT&CK Tactics Triggered</h2>
          <table>
            <thead><tr><th>Tactic</th><th className="right">Alert Count</th></tr></thead>
            <tbody>
              {summary.top_tactics.map(({ tactic, count }) => (
                <tr key={tactic}><td>{tactic}</td><td className="right"><strong>{count}</strong></td></tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {/* ── MITRE ATT&CK coverage ── */}
      {tacticStats.length > 0 && (
        <div className="rpt-page-break">
          <h2>MITRE ATT&CK Detection Coverage</h2>
          <p style={{ fontSize: '9pt', color: '#64748b', marginBottom: '8pt' }}>
            Overall coverage: <strong>{coverageSummary.coverage_percentage ?? 0}%</strong> — {coverageSummary.techniques_detected ?? 0} of {coverageSummary.total_techniques ?? 0} techniques detected across {coverageSummary.tactics_covered ?? 0} tactics.
          </p>
          <table>
            <thead>
              <tr>
                <th>Tactic</th>
                <th className="right">Detected</th>
                <th className="right">Total Techniques</th>
                <th className="right">Coverage</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {tacticStats.map((t) => (
                <tr key={t.name}>
                  <td>{t.name}</td>
                  <td className="right">{t.detected}</td>
                  <td className="right">{t.total}</td>
                  <td className="right"><strong>{t.pct}%</strong></td>
                  <td>
                    <div className="rpt-bar-container">
                      <div className="rpt-bar-track" style={{ maxWidth: '80pt' }}>
                        <div className={`rpt-bar-fill ${t.pct >= 50 ? 'green' : t.pct >= 20 ? 'amber' : 'red'}`} style={{ width: `${t.pct}%` }} />
                      </div>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* ── Analyst Activity (admin-only, only included when available) ── */}
      {activity && activity.analysts.length > 0 && (
        <div className="rpt-avoid-break">
          <h2>Analyst Activity</h2>
          <p style={{ fontSize: '9pt', color: '#64748b', marginBottom: '8pt' }}>
            Actions logged in the last {days} days. Triaged = status changes; Comments = investigation notes added.
          </p>
          <table>
            <thead>
              <tr>
                <th>Analyst ID</th>
                <th className="right">Alerts Triaged</th>
                <th className="right">Comments Added</th>
                <th className="right">Total Actions</th>
              </tr>
            </thead>
            <tbody>
              {activity.analysts.map((a) => (
                <tr key={a.analyst}>
                  <td style={{ fontFamily: 'monospace' }}>{a.analyst}</td>
                  <td className="right">{a.alerts_triaged}</td>
                  <td className="right">{a.comments_added}</td>
                  <td className="right"><strong>{a.alerts_triaged + a.comments_added}</strong></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* ── Footer ── */}
      <div style={{
        marginTop: '24pt', paddingTop: '8pt',
        borderTop: '1pt solid #cbd5e1',
        fontSize: '8pt', color: '#94a3b8',
        display: 'flex', justifyContent: 'space-between',
      }}>
        <span>KESTREL Security Operations Platform — CONFIDENTIAL</span>
        <span>Generated {generatedAt} · {user?.username ?? 'system'}</span>
      </div>
    </div>
  )
}

// ── Main Reports page ─────────────────────────────────────────────────────────
export function Reports() {
  const [days, setDays] = useState<DayRange>(30)
  const [tab, setTab] = useState<Tab>('summary')
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'

  // Always fetch summary; fetch coverage and activity up-front so they're
  // ready both for the interactive tabs and for the print/export layout.
  const summaryQ = useQuery({
    queryKey: ['reports', 'summary', days],
    queryFn: () => getReportSummary(days),
  })

  const coverageQ = useQuery({
    queryKey: ['mitre', 'coverage'],
    queryFn: fetchMitreCoverage,
  })

  const activityQ = useQuery({
    queryKey: ['reports', 'analyst-activity', days],
    queryFn: () => getAnalystActivity(days),
    enabled: isAdmin,  // Only admin has audit:read
  })

  const s = summaryQ.data
  const alertTrend = s && s.prev_total_alerts > 0
    ? ((s.total_alerts - s.prev_total_alerts) / s.prev_total_alerts) * 100
    : null

  const TABS: Array<{ id: Tab; label: string; icon: React.ElementType }> = [
    { id: 'summary', label: 'Executive Summary', icon: TrendingUp },
    { id: 'coverage', label: 'Detection Coverage', icon: Target },
    ...(isAdmin ? [{ id: 'analysts' as Tab, label: 'Analyst Activity', icon: Users }] : []),
  ]

  const allLoaded = summaryQ.isFetched && coverageQ.isFetched && (!isAdmin || activityQ.isFetched)

  const handleExport = () => {
    if (!allLoaded) return
    // Programmatically toggle: hide app, show print report, print, then restore
    const root = document.getElementById('root')
    const printEl = document.getElementById('kestrel-print-report')
    if (root) root.style.display = 'none'
    if (printEl) printEl.style.display = 'block'
    window.print()
    if (root) root.style.display = ''
    if (printEl) printEl.style.display = 'none'
  }

  return (
    <>
      {/* Print report rendered via portal directly on <body>, outside Layout */}
      {s && createPortal(
        <div id="kestrel-print-report" style={{ display: 'none' }}>
          <PrintReport
            summary={s}
            coverage={coverageQ.data}
            activity={isAdmin ? activityQ.data : undefined}
            user={user}
            days={days}
          />
        </div>,
        document.body
      )}

      {/* ── Interactive screen view ── */}
      <div id="kestrel-screen-report" className="space-y-6">
        {/* Header */}
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <Breadcrumb items={[{ label: 'Home', to: '/app' }, { label: 'Reports' }]} />
            <h1 className="text-2xl font-semibold text-soc-text">Reports</h1>
            <p className="text-sm text-soc-muted mt-0.5">Platform analytics and detection coverage</p>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex rounded-lg border border-soc-border overflow-hidden text-sm">
              {([7, 30, 90] as DayRange[]).map((d) => (
                <button
                  key={d}
                  type="button"
                  onClick={() => setDays(d)}
                  className={cn(
                    'px-3 py-1.5 transition-colors',
                    days === d ? 'bg-blue-600 text-white' : 'bg-soc-surface text-soc-muted hover:text-soc-text'
                  )}
                >
                  {d}d
                </button>
              ))}
            </div>
            {/* Export — admin only */}
            {isAdmin ? (
              <button
                type="button"
                onClick={handleExport}
                disabled={!allLoaded}
                title={!allLoaded ? 'Loading report data…' : 'Export as PDF via browser print dialog'}
                className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-soc-border bg-soc-surface text-soc-muted hover:text-soc-text text-sm transition-colors disabled:opacity-50 disabled:cursor-wait"
              >
                <Printer className="w-4 h-4" />
                {!allLoaded ? 'Loading…' : 'Export PDF'}
              </button>
            ) : (
              <div
                title="Only admins can export reports"
                className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-soc-border bg-soc-surface text-soc-muted/40 text-sm cursor-not-allowed select-none"
              >
                <Lock className="w-4 h-4" />
                Export PDF
              </div>
            )}
          </div>
        </div>

        {/* KPI row */}
        {summaryQ.isLoading && !s && <SpinnerOverlay />}
        {summaryQ.isError && <ErrorState title="Failed to load report" onRetry={() => summaryQ.refetch()} />}
        {s && (
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
            <KpiCard label="Total Alerts" value={s.total_alerts} trend={alertTrend} icon={AlertTriangle} />
            <KpiCard label="Resolved" value={`${s.resolved_pct}%`} sub={`${s.resolved} of ${s.total_alerts}`} icon={CheckCircle2} />
            <KpiCard label="Open Critical" value={s.open_critical} danger={s.open_critical > 0} icon={AlertTriangle} />
            <KpiCard label="False Positives" value={s.false_positives}
              sub={s.total_alerts ? `${Math.round((s.false_positives / s.total_alerts) * 100)}% FP rate` : undefined}
              icon={XCircle} />
            <KpiCard label="MITRE Coverage" value={`${s.coverage_pct}%`}
              sub={`${s.techniques_detected}/${s.total_techniques} techniques`} icon={Shield} />
          </div>
        )}

        {/* Tabs */}
        <div className="border-b border-soc-border">
          <nav className="flex gap-1">
            {TABS.map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                type="button"
                onClick={() => setTab(id)}
                className={cn(
                  'flex items-center gap-2 py-2.5 px-3 text-sm font-medium border-b-2 transition-colors',
                  tab === id ? 'border-blue-500 text-soc-text' : 'border-transparent text-soc-muted hover:text-soc-text'
                )}
              >
                <Icon className="w-4 h-4" />
                {label}
              </button>
            ))}
          </nav>
        </div>

        {/* Tab content */}
        {tab === 'summary' && s && <SummaryTab data={s} days={days} />}
        {tab === 'coverage' && (
          coverageQ.isLoading ? <SpinnerOverlay /> :
            coverageQ.isError ? <ErrorState title="Failed to load coverage" onRetry={() => coverageQ.refetch()} /> :
              coverageQ.data ? <CoverageTab data={coverageQ.data as MitreCoverageResponse} /> : null
        )}
        {tab === 'analysts' && isAdmin && (
          activityQ.isLoading ? <SpinnerOverlay /> :
            activityQ.isError ? <ErrorState title="Failed to load analyst activity" onRetry={() => activityQ.refetch()} /> :
              activityQ.data ? <AnalystTab analysts={activityQ.data.analysts} days={days} /> : null
        )}
      </div>
    </>
  )
}
