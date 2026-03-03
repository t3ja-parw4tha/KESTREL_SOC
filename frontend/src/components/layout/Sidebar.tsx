import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  AlertTriangle,
  Flame,
  Target,
  Server,
  Shield,
  Users,
  Github,
  Settings as SettingsIcon,
} from 'lucide-react'
import { cn } from '@/utils/cn'
import { useAuth } from '@/security/AuthContext'

const PLATFORM_VERSION = '0.1.0'

const nav = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/alerts', label: 'Alerts', icon: AlertTriangle, badgeKey: 'alerts' },
  { to: '/incidents', label: 'Incidents', icon: Flame, badgeKey: 'incidents' },
  { to: '/mitre', label: 'MITRE Coverage', icon: Target },
  { to: '/sources', label: 'Sources', icon: Server },
]

interface SidebarProps {
  openAlertsCount?: number
  openIncidentsCount?: number
}

export function Sidebar({ openAlertsCount = 0, openIncidentsCount = 0 }: SidebarProps) {
  const { user } = useAuth()

  const getBadge = (key: string) => {
    if (key === 'alerts') return openAlertsCount
    if (key === 'incidents') return openIncidentsCount
    return null
  }

  return (
    <aside className="w-56 shrink-0 border-r border-soc-border bg-soc-surface flex flex-col">
      <div className="p-4 border-b border-soc-border flex items-center gap-2">
        <Shield className="w-6 h-6 text-soc-low shrink-0" aria-hidden />
        <h1 className="text-lg font-semibold text-soc-text truncate">KESTREL</h1>
      </div>
      <nav className="flex-1 p-2 space-y-0.5">
        {nav.map(({ to, label, icon: Icon, badgeKey }) => {
          const badge = badgeKey ? getBadge(badgeKey) : null
          return (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 px-3 py-2 rounded-lg text-soc-muted transition-colors',
                  isActive
                    ? 'bg-soc-border/50 text-soc-text border-l-4 border-l-blue-500 -ml-0.5 pl-[11px]'
                    : 'hover:bg-soc-border/30 hover:text-soc-text'
                )
              }
            >
              <Icon className="w-5 h-5 shrink-0" aria-hidden />
              <span className="flex-1 truncate">{label}</span>
              {badge != null && badge > 0 && (
                <span
                  className={cn(
                    'shrink-0 min-w-[20px] h-5 px-1.5 rounded-full text-xs font-medium flex items-center justify-center',
                    badgeKey === 'alerts' ? 'bg-amber-500/20 text-amber-400' : 'bg-orange-500/20 text-orange-400'
                  )}
                >
                  {badge > 99 ? '99+' : badge}
                </span>
              )}
            </NavLink>
          )
        })}
      </nav>
      {user?.role === 'admin' && (
        <div className="mt-auto pt-4 border-t border-soc-border px-2 space-y-1">
          <NavLink
            to="/users"
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors',
                isActive
                  ? 'bg-soc-border text-soc-text'
                  : 'text-soc-muted hover:text-soc-text hover:bg-soc-border/50'
              )
            }
          >
            <Users className="w-4 h-4" aria-hidden />
            <span className="flex-1 truncate">Users</span>
          </NavLink>
          <NavLink
            to="/settings"
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors',
                isActive
                  ? 'bg-soc-border text-soc-text'
                  : 'text-soc-muted hover:text-soc-text hover:bg-soc-border/50'
              )
            }
          >
            <SettingsIcon className="w-4 h-4" aria-hidden />
            <span className="flex-1 truncate">Settings</span>
          </NavLink>
        </div>
      )}
      <div className="p-2 border-t border-soc-border">
        <div className="px-3 py-2 text-xs text-soc-muted">
          v{PLATFORM_VERSION}
        </div>
        <a
          href="https://github.com"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-soc-muted hover:bg-soc-border/30 hover:text-soc-text text-xs"
        >
          <Github className="w-4 h-4" aria-hidden />
          GitHub
        </a>
      </div>
    </aside>
  )
}
