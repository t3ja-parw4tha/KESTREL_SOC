import { useState } from 'react'
import { useMitreCoverage } from '@/hooks/useMitre'
import { CoverageHeatmap } from '@/components/mitre/CoverageHeatmap'
import { ErrorState } from '@/components/ui/ErrorState'
import { SpinnerOverlay } from '@/components/ui/Spinner'

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

export function MitreCoverage() {
  const [selectedTechnique, setSelectedTechnique] = useState<{ id: string; name: string; alert_count?: number } | null>(null)

  const { data, isLoading, isError, refetch } = useMitreCoverage()

  if (isError) return <ErrorState title="Failed to load MITRE coverage" onRetry={() => refetch()} />
  if (isLoading) return <SpinnerOverlay />

  const tactics = data?.tactics ?? []
  const techniques = data?.techniques ?? []
  const summary = data?.summary ?? {}
  const techniquesDetected = summary.techniques_detected ?? techniques.filter((t) => (t.alert_count ?? 0) > 0).length
  const totalTechniques = summary.total_techniques ?? techniques.length
  const tacticsCovered = summary.tactics_covered ?? new Set(techniques.filter((t) => (t.alert_count ?? 0) > 0).map((t) => t.tactic_id)).size
  const coveragePct = summary.coverage_percentage ?? (totalTechniques ? Math.round((techniquesDetected / totalTechniques) * 1000) / 10 : 0)

  const detectedIds = new Set(
    techniques
      .filter((t) => (t.alert_count ?? 0) > 0)
      .map((t) => t.id)
  )
  const gaps = HIGH_PRIORITY_TECHNIQUES.filter(
    (t) => !detectedIds.has(t.id)
  )

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold text-soc-text">MITRE ATT&CK Coverage</h1>

      <div className="flex flex-wrap items-center gap-6 p-4 rounded-lg border border-soc-border bg-soc-surface">
        <span className="text-soc-muted text-sm">
          <span className="text-soc-text font-medium">{techniquesDetected}</span> / {totalTechniques} techniques detected
        </span>
        <span className="text-soc-muted text-sm">
          <span className="text-soc-text font-medium">{tacticsCovered}</span> / 12 tactics covered
        </span>
        <span className="text-2xl font-semibold text-soc-text">{coveragePct}%</span>
      </div>

      <CoverageHeatmap
        tactics={tactics}
        techniques={techniques}
        onTechniqueClick={(t) => setSelectedTechnique(t)}
      />

      <div className="rounded-lg border border-soc-border bg-soc-surface p-4">
        <h2 className="text-sm font-semibold text-soc-text mb-1">
          Detection Gaps
        </h2>
        <p className="text-xs text-soc-muted mb-4">
          High-priority techniques with no current detections
        </p>
        {gaps.length === 0 ? (
          <p className="text-green-400 text-sm">
            All high-priority techniques covered ✓
          </p>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {gaps.map((t) => (
              <div
                key={t.id}
                className="rounded border border-red-500/20 bg-red-500/5 p-3"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-mono text-red-400">{t.id}</span>
                  <span className="text-xs text-soc-muted">{t.tactic}</span>
                </div>
                <p className="text-sm text-soc-text">{t.name}</p>
                <p className="text-xs text-red-400 mt-1">No detections</p>
              </div>
            ))}
          </div>
        )}
      </div>

      {selectedTechnique && (
        <div className="fixed inset-y-0 right-0 w-full max-w-md bg-soc-surface border-l border-soc-border shadow-xl z-50 overflow-auto">
          <div className="p-4">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-soc-text">{selectedTechnique.name}</h3>
              <button
                type="button"
                onClick={() => setSelectedTechnique(null)}
                className="text-soc-muted hover:text-soc-text"
              >
                ×
              </button>
            </div>
            <p className="text-sm text-soc-muted">Technique ID: {selectedTechnique.id}</p>
            <p className="text-sm text-soc-muted">Alerts: {selectedTechnique.alert_count ?? 0}</p>
            <p className="text-sm text-soc-muted mt-2">Alerts that triggered this technique would load here. Click an alert to open detail.</p>
          </div>
        </div>
      )}
    </div>
  )
}
