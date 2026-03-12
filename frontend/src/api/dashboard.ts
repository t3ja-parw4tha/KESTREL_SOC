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
  volume_timeline: Array<{ date: string; count: number }>
  recent_alerts: Alert[]
  incidents: Incident[]
}

export async function fetchDashboardStats(): Promise<DashboardStats> {
  return get<DashboardStats>('/dashboard/stats')
}
