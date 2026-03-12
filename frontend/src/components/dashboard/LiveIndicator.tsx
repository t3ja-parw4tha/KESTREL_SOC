import { Wifi, WifiOff, Loader2 } from 'lucide-react'
import { cn } from '@/utils/cn'
import type { ConnectionStatus } from '@/hooks/useRealtimeAlerts'

const statusConfig: Record<
  ConnectionStatus,
  { icon: typeof Wifi; label: string; color: string }
> = {
  connected:    { icon: Wifi,    label: 'Live — real-time updates active',      color: 'text-success' },
  connecting:   { icon: Loader2, label: 'Connecting to real-time feed…',        color: 'text-severity-medium' },
  disconnected: { icon: WifiOff, label: 'Disconnected — using polling',         color: 'text-muted-foreground' },
  error:        { icon: WifiOff, label: 'WebSocket error — using polling',      color: 'text-severity-critical' },
}

interface LiveIndicatorProps {
  status: ConnectionStatus
  onReconnect?: () => void
  className?: string
}

export function LiveIndicator({ status, onReconnect, className }: LiveIndicatorProps) {
  const cfg = statusConfig[status]
  const Icon = cfg.icon
  const canRetry = status !== 'connected' && !!onReconnect

  return (
    <button
      type="button"
      onClick={canRetry ? onReconnect : undefined}
      title={cfg.label + (canRetry ? ' — Click to retry' : '')}
      className={cn(
        'relative flex items-center gap-1.5 px-2 py-1 rounded-md text-[10px] font-medium transition-colors',
        canRetry && 'hover:bg-muted cursor-pointer',
        !canRetry && 'cursor-default',
        cfg.color,
        className
      )}
    >
      {status === 'connected' && (
        <span className="absolute -left-0.5 top-1/2 -translate-y-1/2 h-1.5 w-1.5 rounded-full bg-success animate-pulse" />
      )}
      <Icon className={cn('h-3 w-3', status === 'connecting' && 'animate-spin')} />
      <span className="hidden sm:inline">
        {status === 'connected' ? 'Live' : status === 'connecting' ? 'Connecting' : 'Offline'}
      </span>
    </button>
  )
}
