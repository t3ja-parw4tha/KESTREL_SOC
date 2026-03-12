import { cn } from '@/utils/cn'
import { TrendingUp, TrendingDown } from 'lucide-react'

export interface StatItem {
  label: string
  value: number | string
  icon?: React.ReactNode
  variant?: 'default' | 'critical' | 'high' | 'blue' | 'green'
  cardTint?: 'neutral' | 'good' | 'warning' | 'danger'
  pulse?: boolean
  subtitle?: string
  trend?: { value: number; label?: string } | null
}

interface StatsRowProps {
  stats: StatItem[]
}

const variantConfig: Record<NonNullable<StatItem['variant']>, { text: string; iconBg: string }> = {
  default:  { text: 'text-foreground',                        iconBg: 'bg-muted' },
  critical: { text: 'text-severity-critical',                 iconBg: 'bg-severity-critical/10' },
  high:     { text: 'text-severity-high',                     iconBg: 'bg-severity-high/10' },
  blue:     { text: 'text-primary',                           iconBg: 'bg-primary/10' },
  green:    { text: 'text-success',                           iconBg: 'bg-success/10' },
}

export function StatsRow({ stats }: StatsRowProps) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
      {stats.map(({ label, value, icon, variant = 'default', pulse, subtitle, trend }) => {
        const cfg = variantConfig[variant]
        return (
          <div
            key={label}
            className="glass-card rounded-xl p-5 transition-all duration-200 hover:-translate-y-0.5"
            style={{ boxShadow: 'var(--shadow-card)' }}
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-medium text-muted-foreground">{label}</span>
              {icon && (
                <div className={cn('p-1.5 rounded-lg', cfg.iconBg)}>
                  {icon}
                </div>
              )}
            </div>
            <div className="flex items-end gap-2">
              <span className={cn('text-3xl font-bold tabular-nums tracking-tight leading-none', cfg.text, pulse && 'animate-pulse')}>
                {value}
              </span>
              {trend != null && (
                <span className={cn('flex items-center gap-0.5 text-xs font-medium mb-0.5', trend.value > 0 ? 'text-severity-critical' : 'text-success')}>
                  {trend.value > 0 ? <TrendingUp className="h-3 w-3" /> : <TrendingDown className="h-3 w-3" />}
                  {Math.abs(trend.value)}%
                </span>
              )}
            </div>
            {subtitle && <p className="text-[11px] text-muted-foreground mt-1.5 truncate">{subtitle}</p>}
          </div>
        )
      })}
    </div>
  )
}
