export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low'
export type AlertStatus = 'open' | 'in_progress' | 'resolved' | 'false_positive'

export function getSeverityColor(severity: SeverityLevel | string): string {
  switch (severity) {
    case 'Critical': return 'bg-severity-critical/15 text-severity-critical border-severity-critical/30'
    case 'High':     return 'bg-severity-high/15 text-severity-high border-severity-high/30'
    case 'Medium':   return 'bg-severity-medium/15 text-severity-medium border-severity-medium/30'
    case 'Low':      return 'bg-severity-low/15 text-severity-low border-severity-low/30'
    default:         return 'bg-muted/50 text-muted-foreground border-border/50'
  }
}

export function getSeverityDot(severity: SeverityLevel | string): string {
  switch (severity) {
    case 'Critical': return 'bg-severity-critical'
    case 'High':     return 'bg-severity-high'
    case 'Medium':   return 'bg-severity-medium'
    case 'Low':      return 'bg-severity-low'
    default:         return 'bg-muted-foreground'
  }
}

export function getStatusColor(status: AlertStatus | string): string {
  switch (status) {
    case 'open':           return 'bg-primary/15 text-primary border-primary/30'
    case 'new':            return 'bg-primary/15 text-primary border-primary/30'
    case 'in_progress':    return 'bg-severity-medium/15 text-severity-medium border-severity-medium/30'
    case 'resolved':       return 'bg-success/15 text-success border-success/30'
    case 'false_positive': return 'bg-muted/50 text-muted-foreground border-border/50'
    default:               return 'bg-muted/50 text-muted-foreground border-border/50'
  }
}

export function getRiskScoreColor(score: number | null | undefined): string {
  if (score == null) return 'text-muted-foreground'
  if (score > 75) return 'text-severity-critical'
  if (score > 50) return 'text-severity-high'
  if (score > 25) return 'text-severity-medium'
  return 'text-severity-low'
}

export function getSeverityLabel(severity: SeverityLevel | string): string {
  return String(severity)
}
