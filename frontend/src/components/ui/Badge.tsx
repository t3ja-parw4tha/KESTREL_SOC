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
  const label = children ?? (severity ? getSeverityLabel(severity) : status?.replace(/_/g, ' ') ?? '')
  const styleClass = severity
    ? getSeverityColor(severity)
    : status
      ? getStatusColor(status)
      : 'bg-muted/50 text-muted-foreground border-border/50'
  const dotClass = severity ? getSeverityDot(severity) : null

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold border',
        styleClass,
        className
      )}
    >
      {dotClass && <span className={cn('w-1.5 h-1.5 rounded-full shrink-0', dotClass)} />}
      {label}
    </span>
  )
}
