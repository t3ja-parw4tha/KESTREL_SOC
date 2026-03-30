import { Inbox } from 'lucide-react'

interface EmptyStateProps {
  title?: string
  description?: string
  icon?: React.ReactNode
}

export function EmptyState({
  title = 'No data',
  description,
  icon,
}: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-12 px-4 text-center">
      <div className="text-muted-foreground mb-3">
        {icon ?? <Inbox className="w-12 h-12" />}
      </div>
      <p className="text-foreground font-medium">{title}</p>
      {description && <p className="text-muted-foreground text-sm mt-1 max-w-sm">{description}</p>}
    </div>
  )
}
