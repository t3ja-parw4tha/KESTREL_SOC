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
  Workflow,
  Search,
  FileText,
} from 'lucide-react'
import { cn } from '@/utils/cn'
import { useAuth } from '@/security/AuthContext'

const PLATFORM_VERSION = '0.1.0'

const nav = [
  { to: '/app', label: 'Dashboard', icon: LayoutDashboard, end: true, badgeKey: undefined },
  { to: '/app/alerts', label: 'Alerts', icon: AlertTriangle, end: false, badgeKey: 'alerts' as const },
  { to: '/app/incidents', label: 'Incidents', icon: Flame, end: false, badgeKey: 'incidents' as const },
  { to: '/app/mitre', label: 'MITRE Coverage', icon: Target, end: false, badgeKey: undefined },
  { to: '/app/hunting', label: 'Threat Hunting', icon: Search, end: false, badgeKey: undefined },
  { to: '/app/playbooks', label: 'Playbooks', icon: Workflow, end: false, badgeKey: undefined },
  { to: '/app/reports', label: 'Reports', icon: FileText, end: false, badgeKey: undefined },
  { to: '/app/sources', label: 'Sources', icon: Server, end: false, badgeKey: undefined },
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
    <aside className="w-56 shrink-0 h-screen border-r border-border bg-card backdrop-blur-xl flex flex-col overflow-hidden relative z-10 transition-colors duration-300">
      {/* Ambient depth — dark mode only */}
      <div className="pointer-events-none absolute inset-0 hidden dark:block">
        <div className="absolute -top-[40%] -left-[30%] w-[120%] h-[70%] rounded-full bg-blue-900/10 blur-[80px]" />
        <div className="absolute bottom-0 left-0 right-0 h-[40%] bg-gradient-to-t from-indigo-950/20 to-transparent" />
      </div>
      {/* Header / Brand */}
      <div className="h-14 px-4 border-b border-border flex items-center gap-2.5 shrink-0">
        <div className="relative shrink-0">
          <div className="absolute inset-0 rounded-lg bg-blue-500/20 blur-md" />
          <div className="relative w-7 h-7 rounded-lg bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center">
            <Shield className="w-4 h-4 text-white" aria-hidden />
          </div>
        </div>
        <h1
          className="text-base font-bold tracking-tight truncate"
          style={{
            background: 'linear-gradient(135deg, #60a5fa, #818cf8)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
          }}
        >
          KESTREL
        </h1>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-2 space-y-0.5 overflow-y-auto" aria-label="Main navigation">
        {nav.map(({ to, label, icon: Icon, end, badgeKey }) => {
          const badge = badgeKey ? getBadge(badgeKey) : null
          return (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                cn(
                  'group flex items-center gap-3 px-3 py-2 rounded-xl text-sm transition-all duration-150',
                  isActive
                    ? 'bg-primary/10 text-primary font-medium ring-1 ring-primary/20'
                    : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
                )
              }
            >
              {({ isActive }) => (
                <>
                  <Icon
                    className={cn(
                      'w-4 h-4 shrink-0 transition-colors',
                      isActive ? 'text-primary' : 'text-muted-foreground group-hover:text-accent-foreground'
                    )}
                    aria-hidden
                  />
                  <span className="flex-1 truncate">{label}</span>
                  {badge != null && badge > 0 && (
                    <span className={cn(
                      'shrink-0 min-w-[20px] h-5 px-1.5 rounded-full text-[11px] font-semibold flex items-center justify-center',
                      badgeKey === 'alerts'
                        ? 'bg-amber-500/20 text-amber-400'
                        : 'bg-orange-500/20 text-orange-400'
                    )}>
                      {badge > 99 ? '99+' : badge}
                    </span>
                  )}
                </>
              )}
            </NavLink>
          )
        })}
      </nav>

      {/* Admin section */}
      {user?.role === 'admin' && (
        <div className="pt-3 pb-1 border-t border-border px-2 space-y-0.5">
          <div className="px-3 py-1 text-[10px] font-bold text-muted-foreground/60 uppercase tracking-[0.1em]">
            Admin
          </div>
          {[
            { to: '/app/users', label: 'Users', Icon: Users },
            { to: '/app/settings', label: 'Settings', Icon: SettingsIcon },
          ].map(({ to, label, Icon }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 px-3 py-2 rounded-xl text-sm transition-all duration-150',
                  isActive
                    ? 'bg-primary/10 text-primary font-medium ring-1 ring-primary/20'
                    : 'text-muted-foreground hover:text-accent-foreground hover:bg-accent'
                )
              }
            >
              <Icon className="w-4 h-4 shrink-0" aria-hidden />
              <span className="flex-1 truncate">{label}</span>
            </NavLink>
          ))}
        </div>
      )}

      {/* Footer */}
      <div className="p-2 border-t border-border space-y-1">
        {/* System status */}
        <div className="px-3 py-2 flex items-center gap-2">
          <span className="relative flex h-2 w-2 shrink-0">
            <span className="absolute inline-flex h-full w-full rounded-full bg-emerald-500/60 animate-ping" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
          </span>
          <span className="text-[11px] text-muted-foreground">System online</span>
          <span className="ml-auto text-[10px] text-muted-foreground/50">v{PLATFORM_VERSION}</span>
        </div>
        <a
          href="https://github.com/t3ja-parw4tha/KESTREL_SOC"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-muted-foreground hover:bg-accent/30 hover:text-foreground text-xs transition-colors"
        >
          <Github className="w-3.5 h-3.5" aria-hidden />
          GitHub
        </a>
      </div>
    </aside>
  )
}
