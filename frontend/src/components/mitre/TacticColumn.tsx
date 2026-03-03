import { TechniqueCard } from './TechniqueCard'
import type { MitreTactic, MitreTechnique } from '@/types/mitre'

interface TacticColumnProps {
  tactic: MitreTactic
  techniques: MitreTechnique[]
  onTechniqueClick?: (technique: MitreTechnique) => void
}

export function TacticColumn({ tactic, techniques, onTechniqueClick }: TacticColumnProps) {
  return (
    <div className="shrink-0 w-48 flex flex-col">
      <h3 className="text-xs font-semibold text-soc-muted uppercase tracking-wide mb-2 sticky top-0 bg-soc-bg py-1">
        {tactic.short_name ?? tactic.name}
      </h3>
      <div className="space-y-1.5">
        {techniques.map((t) => (
          <TechniqueCard
            key={t.id}
            technique={t}
            onClick={onTechniqueClick ? () => onTechniqueClick(t) : undefined}
          />
        ))}
      </div>
    </div>
  )
}
