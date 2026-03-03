import { Bell, LogOut, RefreshCw } from 'lucide-react'
import { useAuth } from '@/security/AuthContext'
import { useQueryClient } from '@tanstack/react-query'
import { formatRelativeTime } from '@/utils/time'
import { cn } from '@/utils/cn'

interface TopBarProps {
  criticalCount?: number
  highCount?: number
  lastUpdated?: string
  isRefetching?: boolean
}

export function TopBar({
  criticalCount = 0,
  highCount = 0,
  lastUpdated,
  isRefetching = false,
}: TopBarProps) {
  const { user, logout } = useAuth()
  const queryClient = useQueryClient()

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ['alerts'] })
    queryClient.invalidateQueries({ queryKey: ['dashboard'] })
    queryClient.invalidateQueries({ queryKey: ['incidents'] })
    queryClient.invalidateQueries({ queryKey: ['mitre'] })
  }

  return (
    <header className="h-14 border-b border-soc-border bg-soc-surface flex items-center justify-between px-6 shrink-0">
      <div className="flex items-center gap-4">
        <span className="text-soc-muted text-sm">Critical</span>
        <span className="rounded px-2 py-0.5 text-sm font-medium bg-red-500/20 text-red-400 border border-red-500/30">
          {criticalCount}
        </span>
        <span className="text-soc-muted text-sm">High</span>
        <span className="rounded px-2 py-0.5 text-sm font-medium bg-orange-500/20 text-orange-400 border border-orange-500/30">
          {highCount}
        </span>
        {lastUpdated && (
          <span className="text-soc-muted text-xs">
            Updated {formatRelativeTime(lastUpdated)}
            {isRefetching && (
              <RefreshCw className="inline-block w-3 h-3 ml-1 animate-spin" aria-hidden />
            )}
          </span>
        )}
      </div>
      <div className="flex items-center gap-4">
        <button
          type="button"
          onClick={handleRefresh}
          disabled={isRefetching}
          className={cn(
            'p-2 rounded-lg hover:bg-soc-border/50 text-soc-muted hover:text-soc-text transition-colors disabled:opacity-50',
            isRefetching && 'animate-spin'
          )}
          aria-label="Refresh data"
        >
          <RefreshCw className="w-5 h-5" />
        </button>
        <button
          type="button"
          className="p-2 rounded-lg hover:bg-soc-border/50 text-soc-muted hover:text-soc-text transition-colors"
          aria-label="Notifications"
        >
          <Bell className="w-5 h-5" />
        </button>
        <div className="flex items-center gap-3">
          <div className="text-right hidden sm:block">
            <p className="text-sm font-medium text-soc-text">
              {user?.username ?? 'Unknown'}
            </p>
            <p className="text-xs text-soc-muted capitalize">
              {user?.role?.replace('_', ' ') ?? 'viewer'}
            </p>
          </div>
          <div className="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center text-white text-sm font-semibold">
            {(user?.username ?? 'U')[0].toUpperCase()}
          </div>
          <button
            type="button"
            onClick={logout}
            title="Sign out"
            className="p-1.5 rounded-lg text-soc-muted hover:text-red-400 hover:bg-red-500/10 transition-colors"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  )
}
