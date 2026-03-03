import { cn } from '@/utils/cn'

interface CardProps {
  children: React.ReactNode
  className?: string
  onClick?: () => void
}

export function Card({ children, className, onClick }: CardProps) {
  return (
    <div
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onClick={onClick}
      onKeyDown={onClick ? (e) => e.key === 'Enter' && onClick() : undefined}
      className={cn(
        'rounded-xl border border-soc-border bg-soc-surface p-4',
        onClick && 'cursor-pointer hover:border-soc-border transition-colors',
        className
      )}
    >
      {children}
    </div>
  )
}

interface CardHeaderProps {
  title: string
  action?: React.ReactNode
  className?: string
}

export function CardHeader({ title, action, className }: CardHeaderProps) {
  return (
    <div className={cn('flex items-center justify-between mb-4', className)}>
      <h3 className="text-sm font-semibold text-soc-text">{title}</h3>
      {action}
    </div>
  )
}
