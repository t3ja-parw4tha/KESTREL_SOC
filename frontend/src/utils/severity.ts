export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low'
export type AlertStatus = 'open' | 'in_progress' | 'resolved' | 'false_positive'

export function getSeverityColor(severity: SeverityLevel | string): string {
  switch (severity) {
    case 'Critical':
      return 'bg-red-500/20 text-red-400 border-red-500/30'
    case 'High':
      return 'bg-orange-500/20 text-orange-400 border-orange-500/30'
    case 'Medium':
      return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
    case 'Low':
      return 'bg-blue-500/20 text-blue-400 border-blue-500/30'
    default:
      return 'bg-slate-500/20 text-slate-400 border-slate-500/30'
  }
}

export function getSeverityDot(severity: SeverityLevel | string): string {
  switch (severity) {
    case 'Critical':
      return 'bg-red-500'
    case 'High':
      return 'bg-orange-500'
    case 'Medium':
      return 'bg-yellow-500'
    case 'Low':
      return 'bg-blue-500'
    default:
      return 'bg-slate-500'
  }
}

export function getStatusColor(status: AlertStatus | string): string {
  switch (status) {
    case 'open':
      return 'bg-amber-500/20 text-amber-400 border-amber-500/30'
    case 'in_progress':
      return 'bg-blue-500/20 text-blue-400 border-blue-500/30'
    case 'resolved':
      return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
    case 'false_positive':
      return 'bg-slate-500/20 text-slate-400 border-slate-500/30'
    default:
      return 'bg-soc-border text-soc-muted border-soc-border'
  }
}

export function getRiskScoreColor(score: number | null | undefined): string {
  if (score == null) return 'text-soc-muted'
  if (score > 75) return 'text-red-400'
  if (score > 50) return 'text-orange-400'
  if (score > 25) return 'text-yellow-400'
  return 'text-blue-400'
}

export function getSeverityLabel(severity: SeverityLevel | string): string {
  return String(severity)
}
