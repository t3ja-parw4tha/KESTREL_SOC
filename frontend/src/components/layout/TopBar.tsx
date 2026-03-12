import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Bell, LogOut, RefreshCw, Sun, Moon, Search } from 'lucide-react'
import { useAuth } from '@/security/AuthContext'
import { useTheme } from '@/contexts/ThemeContext'
import { useQueryClient } from '@tanstack/react-query'
import { formatRelativeTime } from '@/utils/time'
import { cn } from '@/utils/cn'

interface TopBarProps {
  lastUpdated?: string | null
  isRefetching?: boolean
}

export function TopBar({
  lastUpdated,
  isRefetching,
}: TopBarProps) {
  const { user, logout } = useAuth()
  const { theme, toggleTheme } = useTheme()
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [searchQuery, setSearchQuery] = useState('')

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ['alerts'] })
    queryClient.invalidateQueries({ queryKey: ['dashboard'] })
    queryClient.invalidateQueries({ queryKey: ['incidents'] })
    queryClient.invalidateQueries({ queryKey: ['mitre'] })
  }

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const q = searchQuery.trim()
    if (q) navigate(`/app/alerts?search=${encodeURIComponent(q)}`)
  }

  return (
    <header className="h-14 border-b border-border bg-background/80 backdrop-blur-xl flex items-center justify-between px-5 shrink-0 relative z-10 transition-colors duration-300">
      {/* Search */}
      <form onSubmit={handleSearchSubmit} className="flex-1 max-w-sm hidden sm:block">
        <div className="relative group">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground pointer-events-none transition-colors group-focus-within:text-blue-400" />
          <input
            type="search"
            placeholder="Search alerts... (/)"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg border border-border bg-muted/50 text-foreground text-sm placeholder:text-muted-foreground/60
                       focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500/60 transition-all duration-150"
            aria-label="Search alerts"
          />
        </div>
      </form>

      <div className="flex items-center gap-1 ml-auto">
        {/* Last updated */}
        {lastUpdated && (
          <span className="text-[11px] text-muted-foreground/70 mr-2 hidden md:flex items-center gap-1">
            {isRefetching && <RefreshCw className="w-3 h-3 animate-spin" aria-hidden />}
            {!isRefetching && `Updated ${formatRelativeTime(lastUpdated)}`}
          </span>
        )}

        {/* Icon actions */}
        {[
          {
            label: theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode',
            icon: theme === 'light' ? <Moon className="w-4 h-4" /> : <Sun className="w-4 h-4" />,
            onClick: toggleTheme,
          },
          {
            label: 'Refresh data',
            icon: <RefreshCw className={cn('w-4 h-4', isRefetching && 'animate-spin')} />,
            onClick: handleRefresh,
            disabled: isRefetching,
          },
          {
            label: 'Notifications',
            icon: (
              <span className="relative">
                <Bell className="w-4 h-4" />
                <span className="absolute -top-1 -right-1 flex h-3.5 w-3.5 items-center justify-center rounded-full bg-severity-critical text-[8px] font-bold text-white">3</span>
              </span>
            ),
            onClick: undefined as (() => void) | undefined,
          },
        ].map(({ label, icon, onClick, disabled }) => (
          <button
            key={label}
            type="button"
            onClick={onClick}
            disabled={disabled}
            title={label}
            aria-label={label}
            className="p-2 rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent transition-all duration-150 disabled:opacity-40"
          >
            {icon}
          </button>
        ))}

        {/* Divider */}
        <div className="w-px h-6 bg-border mx-1" />

        {/* User */}
        <div className="flex items-center gap-2.5 pl-1">
          <div className="text-right hidden sm:block">
            <p className="text-xs font-semibold text-foreground leading-tight">
              {user?.username ?? 'Unknown'}
            </p>
            <p className="text-[10px] text-muted-foreground capitalize leading-tight">
              {user?.role?.replace(/_/g, ' ') ?? 'viewer'}
            </p>
          </div>
          {/* Avatar with gradient */}
          <div
            className="w-7 h-7 rounded-full flex items-center justify-center text-white text-xs font-bold ring-2 ring-border shrink-0"
            style={{ background: 'linear-gradient(135deg, #3b5bdb, #7c3aed)' }}
          >
            {(user?.username || 'U')[0]?.toUpperCase() || 'U'}
          </div>
          <button
            type="button"
            onClick={logout}
            title="Sign out"
            aria-label="Sign out"
            className="p-1.5 rounded-lg text-muted-foreground hover:text-red-400 hover:bg-red-500/10 transition-all duration-150"
          >
            <LogOut className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </header>
  )
}
