import { Badge } from '@/components/ui/Badge'
import type { Alert } from '@/types/alert'

interface AlertBadgeProps {
  severity: Alert['severity']
  className?: string
}

export function AlertBadge({ severity, className }: AlertBadgeProps) {
  return <Badge severity={severity} className={className} />
}
