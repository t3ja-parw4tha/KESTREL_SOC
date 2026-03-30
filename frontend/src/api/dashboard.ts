import { get } from './client'
import type { Alert } from '@/types/alert'
import type { Incident } from '@/types/incident'

export interface DashboardStats {
  total_alerts: number
  open_critical: number
  open_high: number
  incidents_count: number
  coverage_pct: number
  techniques_detected: number
  total_techniques: number
  alerts_by_severity: Record<string, number>
  volume_timeline: Array<{ date: string; count: number; critical: number; high: number; medium: number; low: number }>
  recent_alerts: Alert[]
  incidents: Incident[]
  alerts_trend?: number | null
  crit_trend?: number | null
  high_trend?: number | null
  trend_period?: 'day' | 'week' | 'month'
  sla_breach_total?: number
  sla_breach_by_sev?: Record<string, number>
  mttr_hours?: number | null
  last_ingest_at?: string | null
  ingest_lag_minutes?: number | null
}

export type TrendPeriod = 'day' | 'week' | 'month'

export async function fetchDashboardStats(trendPeriod: TrendPeriod = 'day'): Promise<DashboardStats> {
  return get<DashboardStats>(`/dashboard/stats?trend_period=${trendPeriod}`)
}
