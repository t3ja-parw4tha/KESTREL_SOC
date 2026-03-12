import { cn } from '@/utils/cn'
import type { MitreTechnique } from '@/types/mitre'

/* ── Heat color scale based on alert count ─────────────────────────────── */
function heatColor(count: number): string {
  if (count === 0) return 'bg-soc-bg border-soc-border text-soc-muted'
  if (count <= 3) return 'bg-emerald-500/15 border-emerald-500/30 text-emerald-400'
  if (count <= 10) return 'bg-amber-500/15 border-amber-500/30 text-amber-400'
  return 'bg-red-500/15 border-red-500/30 text-red-400'
}

function heatDot(count: number): string {
  if (count === 0) return 'bg-soc-border'
  if (count <= 3) return 'bg-emerald-400'
  if (count <= 10) return 'bg-amber-400'
  return 'bg-red-400'
}

interface TechniqueCardProps {
  technique: MitreTechnique
  className?: string
  onClick?: () => void
}

export function TechniqueCard({ technique, className, onClick }: TechniqueCardProps) {
  const count = technique.alert_count ?? 0
  const hasAlerts = count > 0

  return (
    <div
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onClick={onClick}
      onKeyDown={onClick ? (e) => e.key === 'Enter' && onClick() : undefined}
      className={cn(
        'group relative rounded-lg border px-3 py-2 text-xs transition-all duration-200',
        heatColor(count),
        onClick && 'cursor-pointer hover:scale-[1.03] hover:shadow-lg hover:shadow-black/20',
        className
      )}
      title={`${technique.id} — ${technique.name}${hasAlerts ? ` (${count} alert${count > 1 ? 's' : ''})` : ''}`}
    >
      {/* Heat indicator dot */}
      <div className="flex items-center gap-2">
        <span className={cn('h-2 w-2 rounded-full shrink-0', heatDot(count))} />
        <span className="font-mono font-semibold text-soc-text text-[11px]">{technique.id}</span>
        {hasAlerts && (
          <span className="ml-auto text-[10px] font-semibold tabular-nums opacity-80">
            {count}
          </span>
        )}
      </div>
      <p className="mt-1 text-[11px] leading-snug text-soc-muted truncate group-hover:text-soc-text transition-colors">
        {technique.name}
      </p>
    </div>
  )
}
