import { cn } from '@/utils/cn'
import { getSeverityLabel, getSeverityColor, getSeverityDot, getStatusColor } from '@/utils/severity'
import type { Alert } from '@/types/alert'

interface BadgeProps {
  severity?: Alert['severity']
  status?: Alert['status']
  children?: React.ReactNode
  className?: string
}

export function Badge({ severity, status, children, className }: BadgeProps) {
  const label = children ?? (severity ? getSeverityLabel(severity) : status?.replace('_', ' ') ?? '')
  const styleClass = severity
    ? getSeverityColor(severity)
    : status
      ? getStatusColor(status)
      : 'bg-soc-border text-soc-muted border-soc-border'
  const dotClass = severity ? getSeverityDot(severity) : null

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-xs font-semibold border tracking-wide',
        styleClass,
        className
      )}
    >
      {dotClass && <span className={cn('w-1.5 h-1.5 rounded-full shrink-0', dotClass)} />}
      {label}
    </span>
  )
}
