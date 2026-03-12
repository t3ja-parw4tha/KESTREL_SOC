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
  { to: '/app',            label: 'Dashboard',      icon: LayoutDashboard, end: true,  badgeKey: undefined },
  { to: '/app/alerts',     label: 'Alerts',         icon: AlertTriangle,   end: false, badgeKey: 'alerts'     as const },
  { to: '/app/incidents',  label: 'Incidents',      icon: Flame,           end: false, badgeKey: 'incidents'  as const },
  { to: '/app/mitre',      label: 'MITRE Coverage', icon: Target,          end: false, badgeKey: undefined },
  { to: '/app/hunting',    label: 'Threat Hunting', icon: Search,          end: false, badgeKey: undefined },
  { to: '/app/playbooks',  label: 'Playbooks',      icon: Workflow,        end: false, badgeKey: undefined },
  { to: '/app/reports',    label: 'Reports',        icon: FileText,        end: false, badgeKey: undefined },
  { to: '/app/sources',    label: 'Sources',        icon: Server,          end: false, badgeKey: undefined },
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
    <aside
      className="w-56 shrink-0 h-screen border-r flex flex-col overflow-hidden relative z-10"
      style={{
        backgroundColor: 'hsl(var(--sidebar-background))',
        borderColor: 'hsl(var(--sidebar-border))',
      }}
    >
      {/* Ambient glow */}
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -top-[40%] -left-[30%] w-[120%] h-[70%] rounded-full bg-blue-900/10 blur-[80px]" />
        <div className="absolute bottom-0 left-0 right-0 h-[40%] bg-gradient-to-t from-indigo-950/20 to-transparent" />
      </div>

      {/* Header / Brand */}
      <div
        className="h-14 px-4 flex items-center gap-2.5 shrink-0 border-b"
        style={{ borderColor: 'hsl(var(--sidebar-border))' }}
      >
        <div className="relative shrink-0">
          <div className="absolute inset-0 rounded-lg bg-blue-500/20 blur-md" />
          <div className="relative w-7 h-7 rounded-lg gradient-primary flex items-center justify-center">
            <Shield className="w-4 h-4 text-white" aria-hidden />
          </div>
        </div>
        <div className="flex flex-col">
          <span
            className="text-sm font-bold tracking-tight"
            style={{
              background: 'linear-gradient(135deg, #60a5fa, #818cf8)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
            }}
          >
            KESTREL
          </span>
          <span className="text-[9px] font-semibold uppercase tracking-[0.2em]" style={{ color: 'hsl(var(--sidebar-muted))' }}>
            SOC Platform
          </span>
        </div>
      </div>

      {/* Navigation */}
      <nav
        className="flex-1 p-2 space-y-0.5 overflow-y-auto scrollbar-thin"
        aria-label="Main navigation"
      >
        <div
          className="px-3 py-2 text-[9px] font-bold uppercase tracking-[0.2em]"
          style={{ color: 'hsl(var(--sidebar-muted))' }}
        >
          Operations
        </div>
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
                    ? 'font-medium shadow-sm'
                    : 'hover:opacity-100'
                )
              }
              style={({ isActive }) => ({
                backgroundColor: isActive ? 'hsl(var(--sidebar-accent))' : undefined,
                color: isActive ? 'hsl(var(--sidebar-primary))' : 'hsl(var(--sidebar-foreground) / 0.6)',
              })}
            >
              {({ isActive }) => (
                <>
                  <Icon
                    className="w-4 h-4 shrink-0 transition-colors"
                    style={{ color: isActive ? 'hsl(var(--sidebar-primary))' : undefined }}
                    aria-hidden
                  />
                  <span className="flex-1 truncate">{label}</span>
                  {badge != null && badge > 0 && (
                    <span
                      className={cn(
                        'shrink-0 min-w-[20px] h-5 px-1.5 rounded-full text-[11px] font-semibold flex items-center justify-center',
                        badgeKey === 'alerts'
                          ? 'bg-severity-critical/20 text-severity-critical'
                          : 'bg-severity-medium/20 text-severity-medium'
                      )}
                    >
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
        <div
          className="pt-3 pb-1 px-2 space-y-0.5 border-t"
          style={{ borderColor: 'hsl(var(--sidebar-border))' }}
        >
          <div
            className="px-3 py-1 text-[9px] font-bold uppercase tracking-[0.2em]"
            style={{ color: 'hsl(var(--sidebar-muted))' }}
          >
            Admin
          </div>
          {[
            { to: '/app/users',    label: 'Users',    Icon: Users },
            { to: '/app/settings', label: 'Settings', Icon: SettingsIcon },
          ].map(({ to, label, Icon }) => (
            <NavLink
              key={to}
              to={to}
              className="flex items-center gap-3 px-3 py-2 rounded-xl text-sm transition-all duration-150"
              style={({ isActive }) => ({
                backgroundColor: isActive ? 'hsl(var(--sidebar-accent))' : undefined,
                color: isActive ? 'hsl(var(--sidebar-primary))' : 'hsl(var(--sidebar-foreground) / 0.6)',
              })}
            >
              <Icon className="w-4 h-4 shrink-0" aria-hidden />
              <span className="flex-1 truncate">{label}</span>
            </NavLink>
          ))}
        </div>
      )}

      {/* Footer */}
      <div
        className="p-2 border-t space-y-1"
        style={{ borderColor: 'hsl(var(--sidebar-border))' }}
      >
        {/* User info */}
        {user && (
          <div className="px-3 py-2 flex items-center gap-2.5">
            <div
              className="w-7 h-7 rounded-full flex items-center justify-center text-white text-xs font-bold shrink-0 gradient-primary"
            >
              {(user.username || 'U')[0]?.toUpperCase()}
            </div>
            <div className="flex flex-col min-w-0">
              <span className="text-xs font-medium truncate" style={{ color: 'hsl(var(--sidebar-foreground))' }}>
                {user.username}
              </span>
              <span className="text-[10px] capitalize" style={{ color: 'hsl(var(--sidebar-muted))' }}>
                {user.role}
              </span>
            </div>
          </div>
        )}

        {/* System status */}
        <div className="px-3 py-1.5 flex items-center gap-2">
          <span className="relative flex h-2 w-2 shrink-0">
            <span className="absolute inline-flex h-full w-full rounded-full bg-success/60 animate-ping" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-success" />
          </span>
          <span className="text-[11px]" style={{ color: 'hsl(var(--sidebar-muted))' }}>
            System online
          </span>
          <span className="ml-auto text-[10px]" style={{ color: 'hsl(var(--sidebar-muted) / 0.5)' }}>
            v{PLATFORM_VERSION}
          </span>
        </div>

        <a
          href="https://github.com/t3ja-parw4tha/KESTREL_SOC"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs transition-colors hover:opacity-100"
          style={{ color: 'hsl(var(--sidebar-muted))' }}
        >
          <Github className="w-3.5 h-3.5" aria-hidden />
          GitHub
        </a>
      </div>
    </aside>
  )
}
