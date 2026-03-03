import { Card } from '@/components/ui/Card'
import { cn } from '@/utils/cn'

export interface StatItem {
  label: string
  value: number | string
  icon?: React.ReactNode
  variant?: 'default' | 'critical' | 'high' | 'blue' | 'green'
  pulse?: boolean
}

interface StatsRowProps {
  stats: StatItem[]
}

const variantClasses: Record<NonNullable<StatItem['variant']>, string> = {
  default: 'text-soc-text',
  critical: 'text-red-400',
  high: 'text-orange-400',
  blue: 'text-blue-400',
  green: 'text-emerald-400',
}

export function StatsRow({ stats }: StatsRowProps) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
      {stats.map(({ label, value, icon, variant = 'default', pulse }) => (
        <Card key={label} className="flex items-center gap-4">
          <div className="p-2 rounded-lg bg-soc-border/50 shrink-0">{icon}</div>
          <div className="min-w-0 flex-1">
            <p
              className={cn(
                'text-2xl font-semibold',
                variantClasses[variant],
                pulse && 'animate-pulse'
              )}
            >
              {value}
            </p>
            <p className="text-sm text-soc-muted truncate">{label}</p>
          </div>
        </Card>
      ))}
    </div>
  )
}
