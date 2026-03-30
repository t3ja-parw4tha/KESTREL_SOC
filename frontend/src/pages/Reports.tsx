import { useState } from 'react'
import { createPortal } from 'react-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Breadcrumb } from '@/components/ui/Breadcrumb'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
  AreaChart, Area, Cell,
} from 'recharts'
import {
  Printer, TrendingUp, TrendingDown, Minus, Target, Users,
  Shield, AlertTriangle, CheckCircle2, XCircle, ChevronDown, ChevronRight, Lock,
  FileCheck, Calendar, Play, Trash2,
} from 'lucide-react'
import { get, post, del } from '@/api/client'
import { getReportSummary, getAnalystActivity, type ReportSummary, type AnalystActivity } from '@/api/reports'
import { useAuth } from '@/security/AuthContext'
import type { User } from '@/security/AuthContext'
import { fetchMitreCoverage } from '@/api/mitre'
import type { MitreCoverageResponse } from '@/types/mitre'
import { SpinnerOverlay } from '@/components/ui/Spinner'
import { ErrorState } from '@/components/ui/ErrorState'
import { cn } from '@/utils/cn'

type DayRange = 7 | 30 | 90
type Tab = 'summary' | 'coverage' | 'analysts' | 'compliance' | 'scheduled'

const CHART_TOOLTIP_STYLE = {
  backgroundColor: 'hsl(var(--card))',
  border: '1px solid hsl(var(--border))',
  borderRadius: '8px',
  color: 'hsl(var(--foreground))',
  fontSize: '12px',
}

const SEVERITY_COLORS: Record<string, string> = {
  Critical: 'hsl(var(--severity-critical))',
  High:     'hsl(var(--severity-high))',
  Medium:   'hsl(var(--severity-medium))',
  Low:      'hsl(var(--severity-low))',
}

// ── KPI card ──────────────────────────────────────────────────────────────────
function KpiCard({
  label, value, sub, trend, danger, icon: Icon,
}: {
  label: string; value: string | number; sub?: string
  trend?: number | null; danger?: boolean; icon?: React.ElementType
}) {
  return (
    <div className={cn(
      'glass-card p-4 rounded-xl border transition-all duration-200',
      danger
        ? 'border-red-500/30 bg-red-500/5'
        : 'border-border/50 hover:border-border'
    )}>
      <div className="flex items-center justify-between mb-2">
        <p className="text-xs text-muted-foreground">{label}</p>
        {Icon && <Icon className={cn('w-4 h-4', danger ? 'text-red-400' : 'text-muted-foreground/60')} />}
      </div>
      <p className={cn('text-2xl font-bold', danger ? 'text-red-400' : 'text-foreground')}>{value}</p>
      {sub && <p className="text-xs text-muted-foreground mt-0.5">{sub}</p>}
      {trend != null && (
        <p className={cn('text-xs mt-1.5 flex items-center gap-1',
          trend > 0 ? 'text-red-400' : trend < 0 ? 'text-emerald-400' : 'text-muted-foreground')}>
          {trend > 0 ? <TrendingUp className="w-3 h-3" /> : trend < 0 ? <TrendingDown className="w-3 h-3" /> : <Minus className="w-3 h-3" />}
          {Math.abs(Math.round(trend))}% vs prev period
        </p>
      )}
    </div>
  )
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
        {/* Alert Volume — AreaChart with gradient */}
        <div className="glass-card rounded-xl border border-border/50 p-5">
          <h3 className="text-sm font-semibold text-foreground mb-4">Alert Volume ({days} days)</h3>
          <div className="h-[220px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
                <defs>
                  <linearGradient id="volumeGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border)/0.5)" />
                <XAxis dataKey="label" stroke="hsl(var(--muted-foreground))" fontSize={10} tick={{ fill: 'hsl(var(--muted-foreground))' }} interval={xInterval} />
                <YAxis stroke="hsl(var(--muted-foreground))" fontSize={10} tick={{ fill: 'hsl(var(--muted-foreground))' }} allowDecimals={false} width={28} />
                <Tooltip contentStyle={CHART_TOOLTIP_STYLE} formatter={(v: number) => [v, 'Alerts']} />
                <Area type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={2} fill="url(#volumeGradient)" dot={false} activeDot={{ r: 4 }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Alerts by Severity — horizontal bar */}
        <div className="glass-card rounded-xl border border-border/50 p-5">
          <h3 className="text-sm font-semibold text-foreground mb-4">Alerts by Severity</h3>
          {severityData.length === 0 ? (
            <div className="h-[220px] flex items-center justify-center text-muted-foreground text-sm">No data</div>
          ) : (
            <div className="h-[220px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={severityData} layout="vertical" margin={{ top: 5, right: 30, left: 10, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border)/0.5)" horizontal={false} />
                  <XAxis type="number" fontSize={10} tick={{ fill: 'hsl(var(--muted-foreground))' }} allowDecimals={false} />
                  <YAxis dataKey="name" type="category" fontSize={11} tick={{ fill: 'hsl(var(--muted-foreground))' }} width={56} />
                  <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                  <Bar dataKey="value" name="Alerts" radius={[0, 4, 4, 0]}>
                    {severityData.map((entry) => (
                      <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] ?? '#6b7280'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Sources */}
        <div className="glass-card rounded-xl border border-border/50 p-5">
          <h3 className="text-sm font-semibold text-foreground mb-4">Top Alert Sources</h3>
          {data.top_sources.length === 0 ? (
            <p className="text-muted-foreground text-sm py-4">No data</p>
          ) : (
            <div className="space-y-3">
              {data.top_sources.map(({ source, count }) => {
                const max = Math.max(...data.top_sources.map((s) => s.count), 1)
                return (
                  <div key={source} className="flex items-center gap-3">
                    <span className="text-sm text-muted-foreground w-28 truncate" title={source}>{source}</span>
                    <div className="flex-1 h-2 rounded-full bg-muted overflow-hidden">
                      <div className="h-full rounded-full bg-blue-500 transition-all duration-500" style={{ width: `${Math.round((count / max) * 100)}%` }} />
                    </div>
                    <span className="text-sm font-medium text-foreground w-8 text-right">{count}</span>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Top MITRE Tactics */}
        <div className="glass-card rounded-xl border border-border/50 p-5">
          <h3 className="text-sm font-semibold text-foreground mb-4">Top MITRE Tactics Triggered</h3>
          {data.top_tactics.length === 0 ? (
            <p className="text-muted-foreground text-sm py-4">No MITRE mappings</p>
          ) : (
            <div className="space-y-3">
              {data.top_tactics.map(({ tactic, count }) => {
                const max = Math.max(...data.top_tactics.map((t) => t.count), 1)
                return (
                  <div key={tactic} className="flex items-center gap-3">
                    <span className="text-sm text-muted-foreground flex-1 truncate" title={tactic}>{tactic}</span>
                    <div className="w-32 h-2 rounded-full bg-muted overflow-hidden">
                      <div className="h-full rounded-full bg-orange-500 transition-all duration-500" style={{ width: `${Math.round((count / max) * 100)}%` }} />
                    </div>
                    <span className="text-sm font-medium text-foreground w-8 text-right">{count}</span>
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
      <div className="glass-card rounded-xl border border-border/50 p-6 flex flex-wrap items-center gap-8">
        <div className="text-center">
          <p className="text-4xl font-bold text-foreground">{coveragePct}%</p>
          <p className="text-xs text-muted-foreground mt-1">Overall Coverage</p>
        </div>
        <div className="flex-1 min-w-[200px]">
          <div className="h-3 rounded-full bg-muted overflow-hidden">
            <div className={cn('h-full rounded-full transition-all duration-700', coveragePct >= 50 ? 'bg-emerald-500' : coveragePct >= 20 ? 'bg-amber-500' : 'bg-red-500')} style={{ width: `${coveragePct}%` }} />
          </div>
          <div className="flex justify-between mt-1.5 text-xs text-muted-foreground">
            <span>{summary.techniques_detected ?? 0} techniques detected</span>
            <span>{summary.total_techniques ?? 0} total</span>
          </div>
        </div>
        <div className="text-center"><p className="text-2xl font-bold text-foreground">{summary.tactics_covered ?? 0}</p><p className="text-xs text-muted-foreground mt-1">Tactics covered</p></div>
        <div className="text-center"><p className="text-2xl font-bold text-red-400">{gaps.length}</p><p className="text-xs text-muted-foreground mt-1">Detection gaps</p></div>
      </div>

      <div className="glass-card rounded-xl border border-border/50 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border/50 bg-muted/30">
              <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wide">Tactic</th>
              <th className="text-right px-4 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wide">Detected</th>
              <th className="text-right px-4 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wide">Total</th>
              <th className="px-4 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wide">Coverage</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/50">
            {tacticStats.map((t) => (
              <tr key={t.id} className="hover:bg-muted/20 transition-colors">
                <td className="px-4 py-2.5 font-medium text-foreground">{t.name}</td>
                <td className="px-4 py-2.5 text-right text-foreground">{t.detected}</td>
                <td className="px-4 py-2.5 text-right text-muted-foreground">{t.total}</td>
                <td className="px-4 py-2.5">
                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-1.5 rounded-full bg-muted overflow-hidden">
                      <div className={cn('h-full rounded-full', t.pct >= 50 ? 'bg-emerald-500' : t.pct >= 20 ? 'bg-amber-500' : 'bg-red-500')} style={{ width: `${t.pct}%` }} />
                    </div>
                    <span className="text-xs text-muted-foreground w-8 text-right">{t.pct}%</span>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {gaps.length > 0 && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 overflow-hidden">
          <button type="button" onClick={() => setGapsOpen((o) => !o)} className="w-full flex items-center justify-between px-4 py-3 text-sm font-medium text-red-400 hover:bg-red-500/10 transition-colors">
            <span className="flex items-center gap-2"><XCircle className="w-4 h-4" />{gaps.length} techniques with no detection</span>
            {gapsOpen ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
          </button>
          {gapsOpen && (
            <div className="border-t border-red-500/20 px-4 pb-4 pt-3 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
              {gaps.map((t) => (
                <div key={t.id} className="flex items-start gap-2 text-xs text-muted-foreground">
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
      <div className="glass-card rounded-xl border border-border/50 p-8 text-center">
        <Users className="w-10 h-10 text-muted-foreground mx-auto mb-2" />
        <p className="text-muted-foreground text-sm">No analyst activity in the last {days} days.</p>
      </div>
    )
  }
  const maxTriaged = Math.max(...analysts.map((a) => a.alerts_triaged), 1)
  return (
    <div className="glass-card rounded-xl border border-border/50 overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border/50 bg-muted/30">
            <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wide">Analyst ID</th>
            <th className="text-right px-4 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wide">Triaged</th>
            <th className="text-right px-4 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wide">Comments</th>
            <th className="text-right px-4 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wide">Total</th>
            <th className="px-4 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wide">Activity</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border/50">
          {analysts.map((a) => (
            <tr key={a.analyst} className="hover:bg-muted/20 transition-colors">
              <td className="px-4 py-2.5 font-mono text-foreground text-xs">{a.analyst}</td>
              <td className="px-4 py-2.5 text-right font-medium text-foreground">{a.alerts_triaged}</td>
              <td className="px-4 py-2.5 text-right text-muted-foreground">{a.comments_added}</td>
              <td className="px-4 py-2.5 text-right text-foreground">{a.alerts_triaged + a.comments_added}</td>
              <td className="px-4 py-2.5">
                <div className="h-1.5 rounded-full bg-muted overflow-hidden">
                  <div className="h-full rounded-full bg-blue-500 transition-all duration-500" style={{ width: `${Math.round((a.alerts_triaged / maxTriaged) * 100)}%` }} />
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ── Compliance tab ────────────────────────────────────────────────────────────
const FRAMEWORKS = ['soc2', 'iso27001', 'pci-dss'] as const
type Framework = typeof FRAMEWORKS[number]

function ComplianceTab({ days }: { days: number }) {
  const [framework, setFramework] = useState<Framework>('soc2')
  const [report, setReport] = useState<Record<string, unknown> | null>(null)
  const [generating, setGenerating] = useState(false)
  const [downloading, setDownloading] = useState(false)

  const handleGenerate = async () => {
    setGenerating(true)
    try {
      const data = await get<Record<string, unknown>>(`/compliance/reports/generate?framework=${framework}&days=${days}`)
      setReport(data)
    } catch {
      // handled by global error toast
    } finally {
      setGenerating(false)
    }
  }

  const handleExport = async () => {
    setDownloading(true)
    try {
      const url = `/api/compliance/reports/export?framework=${framework}&days=${days}`
      const a = document.createElement('a')
      a.href = url
      a.download = `compliance_${framework}_${days}d.zip`
      a.click()
    } finally {
      setDownloading(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="glass-card rounded-xl border border-border/50 p-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex rounded-lg border border-border/50 overflow-hidden text-sm">
            {FRAMEWORKS.map((fw) => (
              <button
                key={fw}
                type="button"
                onClick={() => { setFramework(fw); setReport(null) }}
                className={cn('px-3 py-1.5 transition-colors uppercase text-xs font-medium',
                  framework === fw ? 'gradient-primary text-white' : 'bg-card text-muted-foreground hover:bg-muted/50')}
              >
                {fw}
              </button>
            ))}
          </div>
          <button
            type="button"
            onClick={handleGenerate}
            disabled={generating}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 text-sm hover:bg-emerald-500/20 disabled:opacity-50 transition-colors"
          >
            <FileCheck className="w-4 h-4" />
            {generating ? 'Generating…' : 'Generate Report'}
          </button>
          {report && (
            <button
              type="button"
              onClick={handleExport}
              disabled={downloading}
              className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-blue-500/30 bg-blue-500/10 text-blue-400 text-sm hover:bg-blue-500/20 disabled:opacity-50 transition-colors"
            >
              <Printer className="w-4 h-4" />
              {downloading ? 'Downloading…' : 'Export Bundle (.zip)'}
            </button>
          )}
        </div>
      </div>

      {report && (
        <div className="glass-card rounded-xl border border-border/50 p-4 space-y-3">
          <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide">{framework.toUpperCase()} Compliance Report — Last {days} days</h3>
          <pre className="text-xs text-muted-foreground bg-muted/30 rounded-lg p-3 overflow-auto max-h-[480px] whitespace-pre-wrap">
            {JSON.stringify(report, null, 2)}
          </pre>
        </div>
      )}

      {!report && !generating && (
        <div className="glass-card rounded-xl border border-border/50 p-8 text-center">
          <FileCheck className="w-10 h-10 text-muted-foreground mx-auto mb-2" />
          <p className="text-sm text-muted-foreground">Select a framework and click Generate Report to view compliance status.</p>
        </div>
      )}
    </div>
  )
}

// ── Scheduled tab ─────────────────────────────────────────────────────────────
interface ScheduledReport {
  id: number
  name: string
  framework: string
  cadence: string
  recipients: string[]
  delivery_format: string
  is_active: boolean
  next_run_at: string | null
  last_run_at: string | null
}

function ScheduledTab() {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [framework, setFramework] = useState<Framework>('soc2')
  const [cadence, setCadence] = useState<'daily' | 'weekly'>('weekly')
  const [recipients, setRecipients] = useState('')
  const [showForm, setShowForm] = useState(false)

  const { data: schedules = [], isLoading } = useQuery({
    queryKey: ['scheduled-reports'],
    queryFn: () => get<ScheduledReport[]>('/scheduled-reports'),
  })

  const createMutation = useMutation({
    mutationFn: (body: object) => post<ScheduledReport>('/scheduled-reports', body),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['scheduled-reports'] }); setShowForm(false); setName(''); setRecipients('') },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: number) => del<void>(`/scheduled-reports/${id}`),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['scheduled-reports'] }),
  })

  const runMutation = useMutation({
    mutationFn: (id: number) => post<void>(`/scheduled-reports/${id}/run`, {}),
  })

  const handleCreate = () => {
    if (!name.trim() || !recipients.trim()) return
    createMutation.mutate({
      name: name.trim(),
      framework,
      cadence,
      recipients: recipients.split(',').map((r) => r.trim()).filter(Boolean),
    })
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-foreground">Scheduled Compliance Reports</h3>
        <button
          type="button"
          onClick={() => setShowForm((v) => !v)}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-border/50 text-sm text-muted-foreground hover:text-foreground hover:border-border transition-colors"
        >
          <Calendar className="w-4 h-4" />
          New Schedule
        </button>
      </div>

      {showForm && (
        <div className="glass-card rounded-xl border border-border/50 p-4 space-y-3">
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">New Scheduled Report</p>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Schedule name"
            className="w-full px-3 py-2 rounded-lg border border-border bg-background text-foreground text-sm"
          />
          <div className="flex gap-2">
            <div className="flex rounded-lg border border-border/50 overflow-hidden text-xs">
              {FRAMEWORKS.map((fw) => (
                <button key={fw} type="button" onClick={() => setFramework(fw)}
                  className={cn('px-2.5 py-1.5 uppercase font-medium transition-colors',
                    framework === fw ? 'gradient-primary text-white' : 'bg-card text-muted-foreground hover:bg-muted/50')}>
                  {fw}
                </button>
              ))}
            </div>
            <div className="flex rounded-lg border border-border/50 overflow-hidden text-xs">
              {(['daily', 'weekly'] as const).map((c) => (
                <button key={c} type="button" onClick={() => setCadence(c)}
                  className={cn('px-2.5 py-1.5 capitalize font-medium transition-colors',
                    cadence === c ? 'gradient-primary text-white' : 'bg-card text-muted-foreground hover:bg-muted/50')}>
                  {c}
                </button>
              ))}
            </div>
          </div>
          <input
            type="text"
            value={recipients}
            onChange={(e) => setRecipients(e.target.value)}
            placeholder="Recipients (comma-separated emails)"
            className="w-full px-3 py-2 rounded-lg border border-border bg-background text-foreground text-sm"
          />
          <div className="flex gap-2">
            <button type="button" onClick={handleCreate} disabled={createMutation.isPending || !name.trim() || !recipients.trim()}
              className="px-3 py-1.5 rounded-lg bg-primary text-primary-foreground text-sm font-medium disabled:opacity-50">
              {createMutation.isPending ? 'Saving…' : 'Save Schedule'}
            </button>
            <button type="button" onClick={() => setShowForm(false)}
              className="px-3 py-1.5 rounded-lg border border-border/50 text-sm text-muted-foreground hover:text-foreground">
              Cancel
            </button>
          </div>
        </div>
      )}

      {isLoading ? (
        <div className="glass-card p-8 text-center text-muted-foreground text-sm">Loading schedules…</div>
      ) : schedules.length === 0 ? (
        <div className="glass-card rounded-xl border border-border/50 p-8 text-center">
          <Calendar className="w-10 h-10 text-muted-foreground mx-auto mb-2" />
          <p className="text-sm text-muted-foreground">No scheduled reports yet. Create one above.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {schedules.map((s) => (
            <div key={s.id} className="glass-card rounded-xl border border-border/50 p-4 flex items-center gap-4">
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-foreground truncate">{s.name}</p>
                <p className="text-xs text-muted-foreground mt-0.5">
                  {s.framework.toUpperCase()} · {s.cadence} · {s.recipients.join(', ')}
                </p>
                {s.next_run_at && (
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Next run: {new Date(s.next_run_at).toLocaleString()}
                  </p>
                )}
              </div>
              <span className={cn('text-xs px-2 py-0.5 rounded-full border',
                s.is_active ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400' : 'border-border bg-muted/30 text-muted-foreground')}>
                {s.is_active ? 'Active' : 'Paused'}
              </span>
              <button type="button" title="Run now"
                onClick={() => runMutation.mutate(s.id)}
                disabled={runMutation.isPending}
                className="p-1.5 rounded-lg border border-border/50 text-muted-foreground hover:text-blue-400 hover:border-blue-500/30 transition-colors">
                <Play className="w-3.5 h-3.5" />
              </button>
              <button type="button" title="Delete"
                onClick={() => deleteMutation.mutate(s.id)}
                disabled={deleteMutation.isPending}
                className="p-1.5 rounded-lg border border-border/50 text-muted-foreground hover:text-red-400 hover:border-red-500/30 transition-colors">
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          ))}
        </div>
      )}
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
            <td>MITRE ATT&amp;CK Coverage</td>
            <td className="right"><strong>{summary.coverage_pct}%</strong></td>
            <td>{summary.techniques_detected} of {summary.total_techniques} techniques detected (all-time)</td>
          </tr>
        </tbody>
      </table>

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

      {summary.top_tactics.length > 0 && (
        <>
          <h2>Top MITRE ATT&amp;CK Tactics Triggered</h2>
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

      {tacticStats.length > 0 && (
        <div className="rpt-page-break">
          <h2>MITRE ATT&amp;CK Detection Coverage</h2>
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
    enabled: isAdmin,
  })

  const s = summaryQ.data
  const alertTrend = s && s.prev_total_alerts > 0
    ? ((s.total_alerts - s.prev_total_alerts) / s.prev_total_alerts) * 100
    : null

  const TABS: Array<{ id: Tab; label: string; icon: React.ElementType }> = [
    { id: 'summary', label: 'Executive Summary', icon: TrendingUp },
    { id: 'coverage', label: 'Detection Coverage', icon: Target },
    { id: 'compliance', label: 'Compliance', icon: FileCheck },
    { id: 'scheduled', label: 'Scheduled Reports', icon: Calendar },
    ...(isAdmin ? [{ id: 'analysts' as Tab, label: 'Analyst Activity', icon: Users }] : []),
  ]

  const allLoaded = summaryQ.isFetched && coverageQ.isFetched && (!isAdmin || activityQ.isFetched)

  const handleExport = () => {
    if (!allLoaded) return
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

      <div className="space-y-6 animate-fade-in">
        {/* Header */}
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <Breadcrumb items={[{ label: 'Home', to: '/app' }, { label: 'Reports' }]} />
            <h1 className="text-2xl font-semibold text-foreground">Reports</h1>
            <p className="text-sm text-muted-foreground mt-0.5">Platform analytics and detection coverage</p>
          </div>
          <div className="flex items-center gap-2">
            {/* Day range selector */}
            <div className="flex rounded-lg border border-border/50 overflow-hidden text-sm">
              {([7, 30, 90] as DayRange[]).map((d) => (
                <button
                  key={d}
                  type="button"
                  onClick={() => setDays(d)}
                  className={cn(
                    'px-3 py-1.5 transition-all duration-200',
                    days === d
                      ? 'gradient-primary text-white font-medium'
                      : 'bg-card text-muted-foreground hover:text-foreground hover:bg-muted/50'
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
                className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-border/50 bg-card text-muted-foreground hover:text-foreground hover:border-border text-sm transition-all duration-200 disabled:opacity-50 disabled:cursor-wait"
              >
                <Printer className="w-4 h-4" />
                {!allLoaded ? 'Loading…' : 'Export PDF'}
              </button>
            ) : (
              <div
                title="Only admins can export reports"
                className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-border/50 bg-card text-muted-foreground/40 text-sm cursor-not-allowed select-none"
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
        <div className="border-b border-border/50">
          <nav className="flex gap-1">
            {TABS.map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                type="button"
                onClick={() => setTab(id)}
                className={cn(
                  'flex items-center gap-2 py-2.5 px-3 text-sm font-medium border-b-2 -mb-px transition-all duration-200',
                  tab === id
                    ? 'border-primary text-foreground'
                    : 'border-transparent text-muted-foreground hover:text-foreground hover:border-border'
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
        {tab === 'compliance' && <ComplianceTab days={days} />}
        {tab === 'scheduled' && <ScheduledTab />}
      </div>
    </>
  )
}
