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
        'rounded-2xl border border-border/50 bg-card p-5 backdrop-blur-xl',
        'transition-all duration-200',
        onClick
          ? 'cursor-pointer hover:-translate-y-0.5 active:translate-y-0 active:scale-[0.995]'
          : '',
        className
      )}
      style={
        onClick
          ? undefined
          : { boxShadow: 'var(--shadow-card)' }
      }
      {...(onClick ? {
        onMouseEnter: (e) => { (e.currentTarget as HTMLDivElement).style.boxShadow = 'var(--shadow-card-hover)' },
        onMouseLeave: (e) => { (e.currentTarget as HTMLDivElement).style.boxShadow = 'var(--shadow-card)' },
      } : {})}
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
      <h3 className="text-sm font-semibold text-foreground">{title}</h3>
      {action}
    </div>
  )
}
