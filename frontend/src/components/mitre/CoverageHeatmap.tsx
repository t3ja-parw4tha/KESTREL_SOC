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
    <div className="space-y-3">
      {/* Color legend */}
      <div className="flex items-center justify-end gap-4 text-[10px] text-muted-foreground">
        <span className="font-medium uppercase tracking-wide">Alert density:</span>
        <span className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-muted" />
          None
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-emerald-400" />
          Low
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-amber-400" />
          Medium
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-red-400" />
          High
        </span>
      </div>

      {/* Responsive wrapping grid — no more horizontal scroll */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
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
