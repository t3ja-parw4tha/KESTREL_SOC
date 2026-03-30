import { AlertTriangle, RefreshCw, WifiOff } from 'lucide-react'
import { cn } from '@/utils/cn'

interface ErrorBannerProps {
  title?: string
  message?: string
  onRetry?: () => void
  variant?: 'inline' | 'full'
  className?: string
}

export function ErrorBanner({
  title = 'Connection Error',
  message = 'Unable to reach the backend API. Showing cached or demo data.',
  onRetry,
  variant = 'inline',
  className,
}: ErrorBannerProps) {
  if (variant === 'full') {
    return (
      <div className={cn('flex flex-col items-center justify-center py-16 text-center space-y-4', className)}>
        <div className="h-14 w-14 rounded-2xl bg-destructive/10 flex items-center justify-center">
          <WifiOff className="h-7 w-7 text-destructive" />
        </div>
        <div className="space-y-1">
          <h3 className="text-sm font-semibold">{title}</h3>
          <p className="text-xs text-muted-foreground max-w-sm">{message}</p>
        </div>
        {onRetry && (
          <button
            onClick={onRetry}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg border border-border bg-card hover:bg-muted transition-colors"
          >
            <RefreshCw className="h-3 w-3" /> Retry
          </button>
        )}
      </div>
    )
  }

  return (
    <div className={cn(
      'flex items-center gap-3 px-4 py-2.5 rounded-lg border border-destructive/20 bg-destructive/5 text-xs',
      className
    )}>
      <AlertTriangle className="h-3.5 w-3.5 text-destructive shrink-0" />
      <span className="text-muted-foreground flex-1">
        <span className="font-semibold text-foreground">{title}:</span> {message}
      </span>
      {onRetry && (
        <button
          onClick={onRetry}
          className="inline-flex items-center gap-1 h-6 px-2 text-[10px] rounded hover:bg-muted/50 transition-colors"
        >
          <RefreshCw className="h-3 w-3" /> Retry
        </button>
      )}
    </div>
  )
}
