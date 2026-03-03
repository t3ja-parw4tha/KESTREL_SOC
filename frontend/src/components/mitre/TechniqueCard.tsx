import { cn } from '@/utils/cn'
import type { MitreTechnique } from '@/types/mitre'

const SEVERITY_CARD_CLASS: Record<string, string> = {
  critical: 'border-critical/40 bg-critical/10',
  high: 'border-high/40 bg-high/10',
  medium: 'border-medium/40 bg-medium/10',
  low: 'border-low/40 bg-low/10',
}

interface TechniqueCardProps {
  technique: MitreTechnique
  className?: string
  onClick?: () => void
}

export function TechniqueCard({ technique, className, onClick }: TechniqueCardProps) {
  const hasAlerts = (technique.alert_count ?? 0) > 0
  const severityClass = technique.severity
    ? SEVERITY_CARD_CLASS[technique.severity] ?? 'border-soc-border bg-soc-surface'
    : 'border-soc-border bg-soc-surface'

  return (
    <div
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onClick={onClick}
      onKeyDown={onClick ? (e) => e.key === 'Enter' && onClick() : undefined}
      className={cn(
        'rounded-lg border p-2 text-xs transition-colors',
        hasAlerts ? severityClass : 'border-soc-border bg-soc-bg text-soc-muted',
        onClick && 'cursor-pointer hover:opacity-90',
        className
      )}
      title={technique.name}
    >
      <div className="font-mono font-medium text-soc-text">{technique.id}</div>
      {technique.name && (
        <div className="mt-0.5 truncate text-soc-muted" title={technique.name}>
          {technique.name}
        </div>
      )}
      {hasAlerts && (
        <div className="mt-1 text-soc-muted">{technique.alert_count} alert(s)</div>
      )}
    </div>
  )
}
