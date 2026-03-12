import { useState, useMemo } from 'react'
import { useMitreCoverage } from '@/hooks/useMitre'
import { CoverageHeatmap } from '@/components/mitre/CoverageHeatmap'
import { ErrorState } from '@/components/ui/ErrorState'
import { SpinnerOverlay } from '@/components/ui/Spinner'
import { toast } from 'sonner'
import type { MitreTechnique } from '@/types/mitre'

/* ── High-priority techniques used for gap analysis ──────────────────── */
const HIGH_PRIORITY_TECHNIQUES = [
  { id: 'T1078', name: 'Valid Accounts', tactic: 'Initial Access' },
  { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
  { id: 'T1003', name: 'Credential Dumping', tactic: 'Credential Access' },
  { id: 'T1059', name: 'Command and Scripting', tactic: 'Execution' },
  { id: 'T1053', name: 'Scheduled Task', tactic: 'Persistence' },
  { id: 'T1055', name: 'Process Injection', tactic: 'Defense Evasion' },
  { id: 'T1071', name: 'Application Layer Protocol', tactic: 'C2' },
  { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact' },
  { id: 'T1190', name: 'Exploit Public Application', tactic: 'Initial Access' },
  { id: 'T1133', name: 'External Remote Services', tactic: 'Initial Access' },
]

type GapTechnique = { id: string; name: string; tactic: string }

/* ═══════════════════════════════════════════════════════════════════════
   Coverage Ring — animated SVG ring showing coverage percentage
   ═══════════════════════════════════════════════════════════════════════ */
function CoverageRing({ percentage }: { percentage: number }) {
  const radius = 38
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (percentage / 100) * circumference
  const color =
    percentage >= 60 ? '#10b981' : percentage >= 30 ? '#f59e0b' : '#ef4444'

  return (
    <div className="relative flex items-center justify-center">
      <svg width="96" height="96" className="-rotate-90">
        <circle
          cx="48" cy="48" r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth="6"
          className="text-soc-border"
        />
        <circle
          cx="48" cy="48" r={radius}
          fill="none"
          stroke={color}
          strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className="transition-all duration-1000 ease-out"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-xl font-bold text-soc-text tabular-nums">{percentage}%</span>
        <span className="text-[9px] text-soc-muted uppercase tracking-widest">coverage</span>
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════════════
   Stat Card — single metric display
   ═══════════════════════════════════════════════════════════════════════ */
function StatCard({ label, value, total, accent }: { label: string; value: number; total: number; accent: string }) {
  const pct = total > 0 ? Math.round((value / total) * 100) : 0
  return (
    <div className="rounded-xl border border-soc-border bg-soc-surface/60 backdrop-blur-sm p-4 flex-1 min-w-[140px]">
      <p className="text-[10px] text-soc-muted uppercase tracking-wider font-semibold mb-2">{label}</p>
      <p className="text-2xl font-bold text-soc-text tabular-nums">
        {value}<span className="text-sm text-soc-muted font-medium"> / {total}</span>
      </p>
      <div className="mt-2 h-1.5 rounded-full bg-soc-border overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ease-out ${accent}`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════════════
   Technique Detail Modal
   ═══════════════════════════════════════════════════════════════════════ */
function TechniqueModal({
  technique,
  onClose,
}: {
  technique: MitreTechnique
  onClose: () => void
}) {
  const count = technique.alert_count ?? 0
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-in fade-in duration-150"
      onClick={(e) => e.target === e.currentTarget && onClose()}
      role="dialog"
      aria-modal="true"
      aria-labelledby="tech-modal-title"
    >
      <div className="bg-soc-surface border border-soc-border rounded-2xl shadow-2xl shadow-black/40 p-6 max-w-md w-full mx-4 animate-in zoom-in-95 duration-200">
        {/* Header */}
        <div className="flex items-start justify-between gap-4 mb-4">
          <div>
            <span className="inline-block text-xs font-mono font-bold px-2 py-0.5 rounded bg-blue-500/15 text-blue-400 mb-2">
              {technique.id}
            </span>
            <h2 id="tech-modal-title" className="text-lg font-bold text-soc-text leading-snug">
              {technique.name}
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-soc-muted hover:text-soc-text transition-colors text-xl leading-none mt-1"
            aria-label="Close"
          >
            ×
          </button>
        </div>

        {/* Stats row */}
        <div className="flex gap-3 mb-4">
          <div className="flex-1 rounded-lg border border-soc-border bg-soc-bg p-3 text-center">
            <p className="text-2xl font-bold tabular-nums text-soc-text">{count}</p>
            <p className="text-[10px] text-soc-muted uppercase tracking-wide">Alerts</p>
          </div>
          <div className="flex-1 rounded-lg border border-soc-border bg-soc-bg p-3 text-center">
            <p className="text-sm font-semibold text-soc-text">{technique.tactic_name ?? '—'}</p>
            <p className="text-[10px] text-soc-muted uppercase tracking-wide">Tactic</p>
          </div>
          <div className="flex-1 rounded-lg border border-soc-border bg-soc-bg p-3 text-center">
            <p className="text-sm font-semibold text-soc-text capitalize">{count > 0 ? (count > 10 ? 'Hot' : count > 3 ? 'Warm' : 'Low') : 'None'}</p>
            <p className="text-[10px] text-soc-muted uppercase tracking-wide">Activity</p>
          </div>
        </div>

        {/* Description */}
        {technique.description && (
          <div className="mb-4">
            <h3 className="text-xs font-semibold text-soc-muted uppercase tracking-wide mb-1">Description</h3>
            <p className="text-sm text-soc-text leading-relaxed">{technique.description}</p>
          </div>
        )}

        {/* Footer */}
        <div className="flex justify-end pt-2 border-t border-soc-border">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-sm font-medium rounded-lg border border-soc-border bg-soc-bg text-soc-text hover:bg-soc-border/50 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════════════
   Create Rule Modal
   ═══════════════════════════════════════════════════════════════════════ */
const SEVERITIES = ['Critical', 'High', 'Medium', 'Low'] as const

function CreateRuleModal({
  technique,
  onClose,
  onSave,
}: {
  technique: GapTechnique
  onClose: () => void
  onSave: () => void
}) {
  const [ruleName, setRuleName] = useState(`Detect ${technique.name}`)
  const [description, setDescription] = useState('')
  const [severity, setSeverity] = useState<string>('High')

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-in fade-in duration-150"
      onClick={(e) => e.target === e.currentTarget && onClose()}
      role="dialog"
      aria-modal="true"
      aria-labelledby="create-rule-title"
    >
      <div className="bg-soc-surface border border-soc-border rounded-2xl shadow-2xl shadow-black/40 p-6 max-w-lg w-full mx-4 animate-in zoom-in-95 duration-200">
        <h2 id="create-rule-title" className="text-lg font-bold text-soc-text mb-5">
          New Detection Rule
          <span className="block text-xs font-normal text-soc-muted mt-1">
            {technique.id} — {technique.name}
          </span>
        </h2>

        <div className="space-y-4">
          <div>
            <label className="block text-[10px] font-semibold text-soc-muted uppercase tracking-wide mb-1.5">Rule Name</label>
            <input
              type="text"
              value={ruleName}
              onChange={(e) => setRuleName(e.target.value)}
              className="w-full rounded-lg border border-soc-border bg-soc-bg text-soc-text px-3 py-2 text-sm focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-colors"
            />
          </div>
          <div>
            <label className="block text-[10px] font-semibold text-soc-muted uppercase tracking-wide mb-1.5">Description</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
              placeholder="Describe what this rule should detect..."
              className="w-full rounded-lg border border-soc-border bg-soc-bg text-soc-text px-3 py-2 text-sm focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 resize-y transition-colors"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-[10px] font-semibold text-soc-muted uppercase tracking-wide mb-1.5">Severity</label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
                className="w-full rounded-lg border border-soc-border bg-soc-bg text-soc-text px-3 py-2 text-sm focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-colors"
              >
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-[10px] font-semibold text-soc-muted uppercase tracking-wide mb-1.5">Tactic</label>
              <p className="text-sm text-soc-text rounded-lg border border-soc-border bg-soc-bg px-3 py-2">
                {technique.tactic}
              </p>
            </div>
          </div>
        </div>

        <div className="flex gap-2 justify-end mt-6 pt-4 border-t border-soc-border">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-sm rounded-lg border border-soc-border bg-soc-bg text-soc-text hover:bg-soc-border/50 font-medium transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onSave}
            className="px-4 py-2 text-sm rounded-lg bg-blue-600 text-soc-bg dark:text-white hover:bg-blue-500 font-medium shadow-lg shadow-blue-600/20 transition-all"
          >
            Save as Draft
          </button>
        </div>
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════════════
   Main Page
   ═══════════════════════════════════════════════════════════════════════ */
export function MitreCoverage() {
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechnique | null>(null)
  const [ruleModalTechnique, setRuleModalTechnique] = useState<GapTechnique | null>(null)

  const { data, isLoading, isError, refetch } = useMitreCoverage()

  const computedStats = useMemo(() => {
    if (!data) return null
    const techniques = data.techniques ?? []
    const summary = data.summary ?? {}
    const techniquesDetected = summary.techniques_detected ?? techniques.filter((t) => (t.alert_count ?? 0) > 0).length
    const totalTechniques = summary.total_techniques ?? techniques.length
    const tacticsCovered = summary.tactics_covered ?? new Set(techniques.filter((t) => (t.alert_count ?? 0) > 0).map((t) => t.tactic_id)).size
    const coveragePct = summary.coverage_percentage ?? (totalTechniques ? Math.round((techniquesDetected / totalTechniques) * 1000) / 10 : 0)
    const detectedIds = new Set(techniques.filter((t) => (t.alert_count ?? 0) > 0).map((t) => t.id))
    const gaps = HIGH_PRIORITY_TECHNIQUES.filter((t) => !detectedIds.has(t.id))
    return { techniquesDetected, totalTechniques, tacticsCovered, coveragePct, gaps }
  }, [data])

  if (isError) return <ErrorState title="Failed to load MITRE coverage" onRetry={() => refetch()} />
  if (isLoading || !data || !computedStats) return <SpinnerOverlay />

  const { techniquesDetected, totalTechniques, tacticsCovered, coveragePct, gaps } = computedStats
  const tactics = data.tactics ?? []
  const techniques = data.techniques ?? []

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* ── Page Title ─────────────────────────────────────────────────── */}
      <div>
        <h1 className="text-2xl font-bold text-soc-text">MITRE ATT&CK Coverage</h1>
        <p className="text-sm text-soc-muted mt-0.5">Detection coverage mapped to the MITRE ATT&CK Enterprise framework</p>
      </div>

      {/* ── Stats Bar ──────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-4 p-5 rounded-2xl border border-soc-border bg-gradient-to-br from-soc-surface via-soc-surface to-blue-500/5">
        <CoverageRing percentage={coveragePct} />
        <div className="flex-1 flex flex-wrap gap-3 min-w-0">
          <StatCard
            label="Techniques Detected"
            value={techniquesDetected}
            total={totalTechniques}
            accent="bg-emerald-500"
          />
          <StatCard
            label="Tactics Covered"
            value={tacticsCovered}
            total={12}
            accent="bg-blue-500"
          />
          <StatCard
            label="Detection Gaps"
            value={gaps.length}
            total={HIGH_PRIORITY_TECHNIQUES.length}
            accent="bg-red-500"
          />
        </div>
      </div>

      {/* ── Heatmap Matrix ─────────────────────────────────────────────── */}
      <CoverageHeatmap
        tactics={tactics}
        techniques={techniques}
        onTechniqueClick={(t) => setSelectedTechnique(t)}
      />

      {/* ── Detection Gaps ─────────────────────────────────────────────── */}
      <div className="rounded-2xl border border-soc-border bg-soc-surface/60 backdrop-blur-sm p-5">
        <div className="flex items-center gap-3 mb-4">
          <div className="h-8 w-1 rounded-full bg-red-500" />
          <div>
            <h2 className="text-sm font-bold text-soc-text">Detection Gaps</h2>
            <p className="text-[11px] text-soc-muted">
              High-priority techniques with no current detections
            </p>
          </div>
        </div>
        {gaps.length === 0 ? (
          <div className="flex items-center gap-2 py-4 px-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20">
            <span className="text-emerald-400 text-lg">✓</span>
            <p className="text-sm text-emerald-400 font-medium">
              All high-priority techniques are covered
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {gaps.map((t) => (
              <div
                key={t.id}
                className="group rounded-xl border border-red-500/20 bg-red-500/5 p-4 hover:border-red-500/40 hover:bg-red-500/10 transition-all duration-200 hover:shadow-lg hover:shadow-red-500/5"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-mono font-bold text-red-400">{t.id}</span>
                  <span className="text-[10px] text-soc-muted font-medium px-2 py-0.5 rounded-full bg-soc-border/50">
                    {t.tactic}
                  </span>
                </div>
                <p className="text-sm font-medium text-soc-text mb-1">{t.name}</p>
                <p className="text-[10px] text-red-400/80 mb-3 flex items-center gap-1">
                  <span className="h-1.5 w-1.5 rounded-full bg-red-400 animate-pulse" />
                  No detections
                </p>
                <button
                  type="button"
                  onClick={() => setRuleModalTechnique(t)}
                  className="w-full py-2 px-3 rounded-lg border border-soc-border bg-soc-bg text-soc-text hover:bg-soc-border/50 hover:border-soc-border text-xs font-semibold transition-all group-hover:border-red-500/30 group-hover:text-red-400"
                >
                  Create Detection Rule
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── Modals ─────────────────────────────────────────────────────── */}
      {selectedTechnique && (
        <TechniqueModal
          technique={selectedTechnique}
          onClose={() => setSelectedTechnique(null)}
        />
      )}

      {ruleModalTechnique && (
        <CreateRuleModal
          key={ruleModalTechnique.id}
          technique={ruleModalTechnique}
          onClose={() => setRuleModalTechnique(null)}
          onSave={() => {
            toast.success('Detection rule saved as draft')
            setRuleModalTechnique(null)
          }}
        />
      )}
    </div>
  )
}
