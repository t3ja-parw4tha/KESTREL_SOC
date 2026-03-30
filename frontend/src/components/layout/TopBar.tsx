import { useState, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Bell, LogOut, RefreshCw, Sun, Moon, Search, PanelLeftClose, PanelLeftOpen, AlertTriangle, X } from 'lucide-react'
import { useAuth } from '@/security/AuthContext'
import { useTheme } from '@/contexts/ThemeContext'
import { useQueryClient, useQuery } from '@tanstack/react-query'
import { formatRelativeTime } from '@/utils/time'
import { cn } from '@/utils/cn'
import { getAlerts } from '@/api/alerts'

// ─── Notification bell with real alerts dropdown ───────────────────────────────
const SEVERITY_COLORS: Record<string, string> = {
  Critical: 'text-severity-critical bg-severity-critical/10 border-severity-critical/30',
  High: 'text-severity-high bg-severity-high/10 border-severity-high/30',
}

const SEEN_KEY = 'soc_notif_seen_at'

function NotificationBell() {
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  // Poll recent critical/high open alerts every 30 seconds
  const { data } = useQuery({
    queryKey: ['notifications'],
    queryFn: () => getAlerts({ severity: 'Critical', status: 'open', limit: 5 }),
    refetchInterval: 30_000,
    staleTime: 15_000,
  })

  const { data: highData } = useQuery({
    queryKey: ['notifications-high'],
    queryFn: () => getAlerts({ severity: 'High', status: 'open', limit: 5 }),
    refetchInterval: 30_000,
    staleTime: 15_000,
  })

  const alerts = [
    ...(data?.alerts ?? []),
    ...(highData?.alerts ?? []),
  ].sort((a, b) => (b.created_at || '').localeCompare(a.created_at || '')).slice(0, 8)

  // Track seen timestamp
  const [seenAt, setSeenAt] = useState<number>(() => {
    const v = localStorage.getItem(SEEN_KEY)
    return v ? parseInt(v, 10) : 0
  })

  const unread = alerts.filter(a => new Date(a.created_at).getTime() > seenAt).length

  const markSeen = () => {
    const now = Date.now()
    localStorage.setItem(SEEN_KEY, String(now))
    setSeenAt(now)
  }

  // Close on outside click
  useEffect(() => {
    function handler(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={() => { setOpen(v => !v); if (!open) markSeen() }}
        title="Notifications"
        aria-label="Notifications"
        className="p-2 rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent transition-all duration-150 relative"
      >
        <Bell className="w-4 h-4" />
        {unread > 0 && (
          <span className="absolute -top-1 -right-1 flex h-3.5 w-3.5 items-center justify-center rounded-full bg-severity-critical text-[8px] font-bold text-white animate-pulse-glow">
            {unread > 9 ? '9+' : unread}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-2 w-80 rounded-xl border border-border bg-card shadow-xl z-[120] overflow-hidden pointer-events-auto">
          <div className="flex items-center justify-between px-4 py-3 border-b border-border">
            <span className="text-xs font-semibold text-foreground">Notifications</span>
            <button type="button" onClick={() => setOpen(false)} className="text-muted-foreground hover:text-foreground">
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
          {alerts.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
              <Bell className="w-6 h-6 mb-2 opacity-30" />
              <p className="text-xs">No critical or high alerts open</p>
            </div>
          ) : (
            <div className="divide-y divide-border/50 max-h-72 overflow-y-auto">
              {alerts.map(alert => (
                <button
                  key={alert.id}
                  type="button"
                  className="w-full text-left px-4 py-3 hover:bg-muted/50 transition-colors"
                  onClick={() => { navigate(`/app/alerts/${alert.id}`); setOpen(false) }}
                >
                  <div className="flex items-start gap-2">
                    <AlertTriangle className={cn('w-3.5 h-3.5 mt-0.5 shrink-0',
                      alert.severity === 'Critical' ? 'text-severity-critical' : 'text-severity-high')} />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium text-foreground truncate">{alert.title}</p>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className={cn('inline-flex items-center px-1 py-0.5 rounded border text-[9px] font-semibold uppercase',
                          SEVERITY_COLORS[alert.severity] || '')}>
                          {alert.severity}
                        </span>
                        <span className="text-[10px] text-muted-foreground">{formatRelativeTime(alert.created_at)}</span>
                        <span className="text-[10px] text-muted-foreground">{alert.source}</span>
                      </div>
                    </div>
                  </div>
                </button>
              ))}
            </div>
          )}
          <div className="px-4 py-2 border-t border-border">
            <button type="button" onClick={() => { navigate('/app/alerts?severity=Critical'); setOpen(false) }}
              className="text-xs text-primary hover:underline">View all critical alerts →</button>
          </div>
        </div>
      )}
    </div>
  )
}

interface TopBarProps {
  lastUpdated?: string | null
  isRefetching?: boolean
  sidebarOpen?: boolean
  onToggleSidebar?: () => void
}

export function TopBar({
  lastUpdated,
  isRefetching,
  sidebarOpen = true,
  onToggleSidebar,
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
    queryClient.invalidateQueries({ queryKey: ['notifications'] })
    queryClient.invalidateQueries({ queryKey: ['notifications-high'] })
  }

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const q = searchQuery.trim()
    if (q) navigate(`/app/alerts?search=${encodeURIComponent(q)}`)
  }

  return (
    <header className="h-14 border-b border-border bg-background/80 backdrop-blur-xl flex items-center gap-2 px-3 shrink-0 relative z-30 transition-colors duration-300">
      {/* Sidebar toggle */}
      <button
        type="button"
        onClick={onToggleSidebar}
        title={sidebarOpen ? 'Collapse sidebar' : 'Expand sidebar'}
        aria-label={sidebarOpen ? 'Collapse sidebar' : 'Expand sidebar'}
        className="p-2 rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent transition-all duration-150 shrink-0"
      >
        {sidebarOpen
          ? <PanelLeftClose className="w-4 h-4" />
          : <PanelLeftOpen className="w-4 h-4" />
        }
      </button>

      {/* Search */}
      <form onSubmit={handleSearchSubmit} className="flex-1 max-w-sm hidden sm:block">
        <div className="relative group">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground pointer-events-none transition-colors group-focus-within:text-blue-400" />
          <input
            type="search"
            data-search-input
            placeholder='Search alerts, incidents, IOCs… ( / )'
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

        {/* Theme toggle */}
        <button
          type="button"
          onClick={toggleTheme}
          title={theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode'}
          aria-label={theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode'}
          className="p-2 rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent transition-all duration-150"
        >
          {theme === 'light' ? <Moon className="w-4 h-4" /> : <Sun className="w-4 h-4" />}
        </button>

        {/* Refresh */}
        <button
          type="button"
          onClick={handleRefresh}
          title="Refresh data"
          aria-label="Refresh data"
          disabled={isRefetching}
          className="p-2 rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent transition-all duration-150 disabled:opacity-40"
        >
          <RefreshCw className={cn('w-4 h-4', isRefetching && 'animate-spin')} />
        </button>

        {/* Notification bell */}
        <NotificationBell />

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
