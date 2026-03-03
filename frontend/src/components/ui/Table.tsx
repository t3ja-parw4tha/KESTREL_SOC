import { cn } from '@/utils/cn'

interface TableProps {
  children: React.ReactNode
  className?: string
}

export function Table({ children, className }: TableProps) {
  return (
    <div className={cn('overflow-x-auto rounded-lg border border-soc-border', className)}>
      <table className="w-full text-sm text-left text-soc-text">{children}</table>
    </div>
  )
}

export function TableHead({ children, className }: { children: React.ReactNode; className?: string }) {
  return <thead className={cn('bg-soc-surface text-soc-muted uppercase text-xs', className)}>{children}</thead>
}

export function TableBody({ children }: { children: React.ReactNode }) {
  return <tbody className="divide-y divide-soc-border">{children}</tbody>
}

export function TableRow({
  children,
  className,
  onClick,
}: {
  children: React.ReactNode
  className?: string
  onClick?: () => void
}) {
  return (
    <tr
      className={cn(
        'bg-soc-surface hover:bg-soc-border/30 transition-colors',
        onClick && 'cursor-pointer',
        className
      )}
      onClick={onClick}
    >
      {children}
    </tr>
  )
}

export function TableHeader({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <th scope="col" className={cn('px-4 py-3 font-medium', className)}>
      {children}
    </th>
  )
}

export function TableCell({ children, className, title }: { children: React.ReactNode; className?: string; title?: string }) {
  return <td className={cn('px-4 py-3', className)} title={title}>{children}</td>
}
