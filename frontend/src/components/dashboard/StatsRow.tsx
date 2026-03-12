import { cn } from '@/utils/cn'
import { TrendingUp, TrendingDown, type LucideIcon } from 'lucide-react'

export interface StatItem {
  label: string
  value: number | string
  icon?: React.ReactNode | LucideIcon
  variant?: 'default' | 'critical' | 'high' | 'blue' | 'green'
  cardTint?: 'neutral' | 'good' | 'warning' | 'danger'
  pulse?: boolean
  subtitle?: string
  trend?: { value: number; label?: string } | null
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'default'
}

interface StatsRowProps {
  stats: StatItem[]
}

const variantGradient: Record<NonNullable<StatItem['variant']>, string> = {
  default:  'from-primary/10 to-transparent border-primary/10',
  critical: 'from-severity-critical/20 to-severity-critical/5 border-severity-critical/20',
  high:     'from-severity-high/20 to-severity-high/5 border-severity-high/20',
  blue:     'from-primary/20 to-primary/5 border-primary/20',
  green:    'from-success/20 to-success/5 border-success/20',
}

const variantText: Record<NonNullable<StatItem['variant']>, string> = {
  default:  'text-foreground',
  critical: 'text-severity-critical',
  high:     'text-severity-high',
  blue:     'text-primary',
  green:    'text-success',
}

const variantIconBg: Record<NonNullable<StatItem['variant']>, string> = {
  default:  'bg-background/50',
  critical: 'bg-background/50',
  high:     'bg-background/50',
  blue:     'bg-background/50',
  green:    'bg-background/50',
}

export function StatsRow({ stats }: StatsRowProps) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4 stagger-children">
      {stats.map(({ label, value, icon, variant = 'default', pulse, subtitle, trend }) => {
        const gradient = variantGradient[variant]
        const textColor = variantText[variant]
        const iconBg = variantIconBg[variant]
        return (
          <div
            key={label}
            className={cn(
              'glass-card-hover bg-gradient-to-br p-5 flex flex-col gap-3 relative overflow-hidden group',
              gradient
            )}
          >
            {/* Subtle corner glow */}
            <div className="absolute -top-8 -right-8 w-24 h-24 rounded-full bg-current opacity-[0.04] group-hover:opacity-[0.08] transition-opacity duration-500" />

            <div className="flex items-center justify-between relative">
              <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                {label}
              </span>
              {icon && (
                <div className={cn('flex h-8 w-8 items-center justify-center rounded-lg', iconBg)}>
                  {icon as React.ReactNode}
                </div>
              )}
            </div>

            <div className="flex items-end justify-between relative">
              <span
                className={cn(
                  'text-3xl font-bold tabular-nums tracking-tight leading-none',
                  textColor,
                  pulse && 'animate-pulse-glow'
                )}
              >
                {value}
              </span>
              {trend != null && (
                <span
                  className={cn(
                    'flex items-center gap-0.5 text-xs font-semibold px-1.5 py-0.5 rounded-md mb-0.5',
                    trend.value > 0
                      ? 'text-severity-critical bg-severity-critical/10'
                      : 'text-success bg-success/10'
                  )}
                >
                  {trend.value > 0 ? (
                    <TrendingUp className="h-3 w-3" />
                  ) : (
                    <TrendingDown className="h-3 w-3" />
                  )}
                  {Math.abs(trend.value)}%
                </span>
              )}
            </div>

            {subtitle && (
              <p className="text-[11px] text-muted-foreground truncate relative">{subtitle}</p>
            )}
          </div>
        )
      })}
    </div>
  )
}
