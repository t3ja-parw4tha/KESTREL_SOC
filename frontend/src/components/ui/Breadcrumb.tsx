import { Link } from 'react-router-dom'
import { ChevronRight } from 'lucide-react'

export interface BreadcrumbItem {
  label: string
  to?: string
}

interface BreadcrumbProps {
  items: BreadcrumbItem[]
}

export function Breadcrumb({ items }: BreadcrumbProps) {
  return (
    <nav className="flex items-center gap-1 text-sm text-soc-muted mb-1" aria-label="Breadcrumb">
      {items.map((item, i) => (
        <span key={i} className="flex items-center gap-1">
          {i > 0 && <ChevronRight className="w-3.5 h-3.5 text-soc-border shrink-0" aria-hidden />}
          {item.to ? (
            <Link to={item.to} className="hover:text-soc-text transition-colors">
              {item.label}
            </Link>
          ) : (
            <span className="text-soc-text font-medium">{item.label}</span>
          )}
        </span>
      ))}
    </nav>
  )
}
