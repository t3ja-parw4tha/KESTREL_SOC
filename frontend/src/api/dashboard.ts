import { get } from './client'
import { getAlerts } from './alerts'
import type { Alert } from '@/types/alert'
import type { Incident } from '@/types/incident'

export interface DashboardStats {
  total_alerts: number
  open_critical: number
  open_high: number
  incidents_count: number
  coverage_pct: number
  alerts_by_severity: Record<string, number>
  volume_timeline: Array<{ date: string; count: number }>
  recent_alerts: Alert[]
  incidents: Incident[]
}

interface IncidentsResponse {
  items: unknown[]
  total: number
}

interface MitreCoverageResponse {
  summary?: { coverage_percentage?: number }
  tactics?: unknown[]
  techniques?: unknown[]
}

export async function fetchDashboardStats(): Promise<DashboardStats> {
  const safe = async <T>(fn: () => Promise<T>, fallback: T): Promise<T> => {
    try {
      return await fn()
    } catch {
      return fallback
    }
  }

  const emptyAlerts = { alerts: [], total: 0, page: 1, limit: 1 }

  const [
    allAlerts,
    criticalOpen,
    highOpen,
    critTotal,
    highTotal,
    medTotal,
    lowTotal,
    incidentsRes,
    mitreRes,
    recentRes,
  ] = await Promise.all([
    safe(() => getAlerts({ limit: 1 }), emptyAlerts),
    safe(() => getAlerts({ severity: 'Critical', status: 'open', limit: 1 }), emptyAlerts),
    safe(() => getAlerts({ severity: 'High', status: 'open', limit: 1 }), emptyAlerts),
    safe(() => getAlerts({ severity: 'Critical', limit: 1 }), emptyAlerts),
    safe(() => getAlerts({ severity: 'High', limit: 1 }), emptyAlerts),
    safe(() => getAlerts({ severity: 'Medium', limit: 1 }), emptyAlerts),
    safe(() => getAlerts({ severity: 'Low', limit: 1 }), emptyAlerts),
    safe(() => get<IncidentsResponse>('/incidents'), { items: [], total: 0 }),
    safe(() => get<{ summary?: { coverage_percentage?: number } }>('/mitre/coverage'), { summary: {} }),
    safe(() => getAlerts({ page: 1, limit: 10 }), emptyAlerts),
  ])

  const bySeverity: Record<string, number> = {
    Critical: critTotal.total,
    High: highTotal.total,
    Medium: medTotal.total,
    Low: lowTotal.total,
  }

  const volumeMap: Record<string, number> = {}
  recentRes.alerts.forEach((a) => {
    const d = a.created_at?.slice(0, 10) || ''
    if (d) volumeMap[d] = (volumeMap[d] || 0) + 1
  })
  const volume_timeline = Object.entries(volumeMap)
    .map(([date, count]) => ({ date, count }))
    .sort((a, b) => a.date.localeCompare(b.date))

  const incidents = Array.isArray(incidentsRes.items) ? (incidentsRes.items as Incident[]) : []

  return {
    total_alerts: allAlerts.total,
    open_critical: criticalOpen.total,
    open_high: highOpen.total,
    incidents_count: incidentsRes.total,
    coverage_pct: (mitreRes as { summary?: { coverage_percentage?: number } })?.summary?.coverage_percentage ?? 0,
    alerts_by_severity: bySeverity,
    volume_timeline,
    recent_alerts: recentRes.alerts,
    incidents,
  }
}
