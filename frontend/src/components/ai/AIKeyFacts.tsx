import type { AISummary } from '@/types/decision'
import { CheckCircle2 } from 'lucide-react'

interface AIKeyFactsProps {
  data: AISummary | null
  loading?: boolean
}

export function AIKeyFacts({ data, loading }: AIKeyFactsProps) {
  if (loading) {
    return (
      <ul className="space-y-2">
        {[1, 2, 3].map((i) => (
          <li key={i} className="flex gap-2 animate-pulse">
            <div className="w-4 h-4 bg-soc-border rounded shrink-0 mt-0.5" />
            <div className="h-4 bg-soc-border rounded flex-1" />
          </li>
        ))}
      </ul>
    )
  }

  if (!data?.key_facts?.length) return null

  return (
    <ul className="space-y-2">
      {data.key_facts.map((fact, i) => (
        <li key={i} className="flex gap-2 text-sm text-soc-text">
          <CheckCircle2 className="w-4 h-4 text-safe shrink-0 mt-0.5" />
          <span>{fact}</span>
        </li>
      ))}
    </ul>
  )
}
