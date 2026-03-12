import { TechniqueCard } from './TechniqueCard'
import type { MitreTactic, MitreTechnique } from '@/types/mitre'

interface TacticColumnProps {
  tactic: MitreTactic
  techniques: MitreTechnique[]
  onTechniqueClick?: (technique: MitreTechnique) => void
}

export function TacticColumn({ tactic, techniques, onTechniqueClick }: TacticColumnProps) {
  const detectedCount = techniques.filter((t) => (t.alert_count ?? 0) > 0).length
  const totalCount = techniques.length

  return (
    <div className="rounded-xl border border-soc-border bg-soc-surface/50 backdrop-blur-sm overflow-hidden flex flex-col">
      {/* Tactic header with gradient accent */}
      <div className="relative px-3 py-2.5 border-b border-soc-border bg-gradient-to-r from-blue-500/10 via-transparent to-transparent">
        <div className="flex items-center justify-between gap-2">
          <h3 className="text-xs font-bold text-soc-text uppercase tracking-wider leading-tight">
            {tactic.short_name ?? tactic.name}
          </h3>
          <span
            className={`text-[10px] font-semibold px-1.5 py-0.5 rounded-full ${detectedCount > 0
              ? 'bg-emerald-500/20 text-emerald-400'
              : 'bg-soc-border text-soc-muted'
              }`}
          >
            {detectedCount}/{totalCount}
          </span>
        </div>
      </div>

      {/* Technique cards */}
      <div className="p-2 space-y-1.5 flex-1">
        {techniques.length === 0 ? (
          <p className="text-[10px] text-soc-muted text-center py-3 italic">No techniques</p>
        ) : (
          techniques.map((t) => (
            <TechniqueCard
              key={t.id}
              technique={t}
              onClick={onTechniqueClick ? () => onTechniqueClick(t) : undefined}
            />
          ))
        )}
      </div>
    </div>
  )
}
