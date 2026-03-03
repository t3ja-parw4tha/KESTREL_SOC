import { cn } from '@/utils/cn'
import { getSeverityLabel, getSeverityColor, getStatusColor } from '@/utils/severity'
import type { Alert } from '@/types/alert'

interface BadgeProps {
  severity?: Alert['severity']
  status?: Alert['status']
  children?: React.ReactNode
  className?: string
}

export function Badge({ severity, status, children, className }: BadgeProps) {
  const label = children ?? (severity ? getSeverityLabel(severity) : status ?? '')
  const styleClass = severity ? getSeverityColor(severity) : status ? getStatusColor(status) : 'bg-soc-border text-soc-muted'

  return (
    <span
      className={cn(
        'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border',
        styleClass,
        className
      )}
    >
      {label}
    </span>
  )
}
