import type { AISummary as AISummaryType } from '@/types/decision'

interface AISummaryProps {
  data: AISummaryType | null
  loading?: boolean
}

export function AISummary({ data, loading }: AISummaryProps) {
  if (loading) {
    return (
      <div className="animate-pulse space-y-2">
        <div className="h-4 bg-muted rounded w-3/4" />
        <div className="h-4 bg-muted rounded w-full" />
        <div className="h-4 bg-muted rounded w-5/6" />
      </div>
    )
  }

  if (!data) return null

  return (
    <div className="space-y-4">
      <p className="text-foreground">{data.summary}</p>
      {data.confidence != null && (
        <p className="text-sm text-muted-foreground">Confidence: {Math.round(data.confidence * 100)}%</p>
      )}
    </div>
  )
}
