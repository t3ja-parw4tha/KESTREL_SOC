// SLA thresholds in hours per severity
const SLA_HOURS: Record<string, number> = {
  Critical: 1,
  High: 4,
  Medium: 24,
  Low: 72,
}

export interface SlaStatus {
  breached: boolean
  /** Remaining time string like "2h 30m" or "Breached 1h ago" */
  label: string
  /** Elapsed hours */
  elapsedHours: number
  /** SLA threshold hours */
  thresholdHours: number
}

export function getSlaStatus(createdAt: string, severity: string, status: string): SlaStatus | null {
  // Only track SLA for open / in-progress alerts
  if (status === 'resolved' || status === 'false_positive' || status === 'closed') return null

  const threshold = SLA_HOURS[severity] ?? 24
  const created = new Date(createdAt)
  const now = new Date()
  const elapsedMs = now.getTime() - created.getTime()
  const elapsedHours = elapsedMs / (1000 * 60 * 60)
  const remainingMs = threshold * 60 * 60 * 1000 - elapsedMs
  const breached = elapsedHours > threshold

  let label: string
  if (breached) {
    const overHours = Math.floor(elapsedHours - threshold)
    const overMins = Math.floor(((elapsedHours - threshold) * 60) % 60)
    label = overHours > 0 ? `+${overHours}h ${overMins}m` : `+${overMins}m`
  } else {
    const remHours = Math.floor(remainingMs / (1000 * 60 * 60))
    const remMins = Math.floor((remainingMs % (1000 * 60 * 60)) / (1000 * 60))
    label = remHours > 0 ? `${remHours}h ${remMins}m` : `${remMins}m`
  }

  return { breached, label, elapsedHours, thresholdHours: threshold }
}

/** Format a Date as YYYY-MM-DD for use in <input type="date"> */
export function toDateInput(d: Date): string {
  return d.toISOString().slice(0, 10)
}

export function formatRelativeTime(iso: string): string {
  const date = new Date(iso)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffSec = Math.floor(diffMs / 1000)
  const diffMin = Math.floor(diffSec / 60)
  const diffHour = Math.floor(diffMin / 60)
  const diffDay = Math.floor(diffHour / 24)

  if (diffSec < 60) return 'Just now'
  if (diffMin < 60) return `${diffMin}m ago`
  if (diffHour < 24) return `${diffHour}h ago`
  if (diffDay < 7) return `${diffDay}d ago`
  return formatDateTime(iso)
}

export function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: 'short',
    timeStyle: 'short',
  })
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString()
}

/** Format for timeline: "Mar 3, 2026 at 14:32 UTC" */
export function formatTimelineTimestamp(iso: string): string {
  const d = new Date(iso)
  const datePart = d.toLocaleDateString('en-US', {
    timeZone: 'UTC',
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  })
  const timePart = d.toLocaleTimeString('en-US', {
    timeZone: 'UTC',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  })
  return `${datePart} at ${timePart} UTC`
}
