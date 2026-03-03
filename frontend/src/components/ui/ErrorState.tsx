import { AlertCircle } from 'lucide-react'

interface ErrorStateProps {
  title?: string
  message?: string
  onRetry?: () => void
}

export function ErrorState({
  title = 'Something went wrong',
  message,
  onRetry,
}: ErrorStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-12 px-4 text-center">
      <AlertCircle className="w-12 h-12 text-critical mb-3" />
      <p className="text-soc-text font-medium">{title}</p>
      {message && <p className="text-soc-muted text-sm mt-1 max-w-sm">{message}</p>}
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-4 px-4 py-2 rounded-lg bg-soc-border text-soc-text hover:bg-soc-border/80 text-sm"
        >
          Retry
        </button>
      )}
    </div>
  )
}
