import { formatDateTime } from '@/utils/time'
import type { TimelineEvent } from '@/types/incident'
import { Bell, FileCheck, Zap } from 'lucide-react'
import { cn } from '@/utils/cn'

interface TimelineProps {
  events: TimelineEvent[]
  className?: string
}

const iconMap = {
  alert: Bell,
  decision: FileCheck,
  action: Zap,
}

export function Timeline({ events, className }: TimelineProps) {
  if (!events?.length) {
    return <p className="text-soc-muted text-sm">No timeline events</p>
  }

  return (
    <div className={cn('space-y-0', className)}>
      {events.map((event, i) => {
        const Icon = iconMap[event.type] ?? Bell
        return (
          <div key={event.id} className="flex gap-4 pb-4 last:pb-0">
            <div className="flex flex-col items-center shrink-0">
              <div className="w-8 h-8 rounded-full bg-soc-border flex items-center justify-center text-soc-muted">
                <Icon className="w-4 h-4" />
              </div>
              {i < events.length - 1 && (
                <div className="w-px flex-1 min-h-[24px] bg-soc-border mt-1" />
              )}
            </div>
            <div className="flex-1 min-w-0 pt-0.5">
              <p className="text-sm font-medium text-soc-text">{event.title}</p>
              <p className="text-xs text-soc-muted">{formatDateTime(event.timestamp)}</p>
              {event.description && (
                <p className="text-sm text-soc-muted mt-1">{event.description}</p>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}
