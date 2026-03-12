import { cn } from '@/utils/cn'

interface TableProps {
  children: React.ReactNode
  className?: string
}

export function Table({ children, className }: TableProps) {
  return (
    <div className={cn('overflow-x-auto rounded-2xl border border-soc-border', className)} style={{ boxShadow: 'var(--shadow-card)' }}>
      <table className="w-full text-sm text-left text-soc-text">{children}</table>
    </div>
  )
}

export function TableHead({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <thead className={cn('bg-soc-surface border-b border-soc-border text-soc-muted uppercase text-[11px] tracking-wider', className)}>
      {children}
    </thead>
  )
}

export function TableBody({ children }: { children: React.ReactNode }) {
  return <tbody className="divide-y divide-soc-border/60">{children}</tbody>
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
        'bg-soc-surface transition-all duration-100 group',
        onClick
          ? 'cursor-pointer hover:bg-blue-500/[0.04] dark:hover:bg-blue-500/[0.06]'
          : 'hover:bg-soc-border/20',
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
    <th scope="col" className={cn('px-4 py-3 font-semibold', className)}>
      {children}
    </th>
  )
}

export function TableCell({ children, className, title, onClick }: {
  children: React.ReactNode
  className?: string
  title?: string
  onClick?: (e: React.MouseEvent) => void
}) {
  return (
    <td className={cn('px-4 py-3', className)} title={title} onClick={onClick}>
      {children}
    </td>
  )
}
