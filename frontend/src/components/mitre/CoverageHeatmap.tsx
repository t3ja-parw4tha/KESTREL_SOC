import { TacticColumn } from './TacticColumn'
import type { MitreTactic, MitreTechnique } from '@/types/mitre'

interface CoverageHeatmapProps {
  tactics: MitreTactic[]
  techniques: MitreTechnique[]
  onTechniqueClick?: (technique: MitreTechnique) => void
}

export function CoverageHeatmap({ tactics, techniques, onTechniqueClick }: CoverageHeatmapProps) {
  const byTactic = tactics.map((tactic) => ({
    tactic,
    techniques: techniques.filter((tech) => tech.tactic_id === tactic.id),
  }))

  return (
    <div className="overflow-x-auto pb-4">
      <div className="flex gap-4 min-w-max">
        {byTactic.map(({ tactic, techniques: techs }) => (
          <TacticColumn
            key={tactic.id}
            tactic={tactic}
            techniques={techs}
            onTechniqueClick={onTechniqueClick}
          />
        ))}
      </div>
    </div>
  )
}
