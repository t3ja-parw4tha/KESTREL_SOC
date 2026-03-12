import { get } from './client'

export interface ReportSummary {
  period_days: number
  total_alerts: number
  prev_total_alerts: number
  open_critical: number
  resolved: number
  resolved_pct: number
  false_positives: number
  incidents_count: number
  alerts_by_severity: Record<string, number>
  top_sources: Array<{ source: string; count: number }>
  volume_timeline: Array<{ date: string; count: number }>
  top_tactics: Array<{ tactic: string; count: number }>
  coverage_pct: number
  techniques_detected: number
  total_techniques: number
}

export interface AnalystActivityRow {
  analyst: string
  alerts_triaged: number
  comments_added: number
}

export interface AnalystActivity {
  period_days: number
  analysts: AnalystActivityRow[]
}

export function getReportSummary(days: number): Promise<ReportSummary> {
  return get<ReportSummary>(`/reports/summary?days=${days}`)
}

export function getAnalystActivity(days: number): Promise<AnalystActivity> {
  return get<AnalystActivity>(`/reports/analyst-activity?days=${days}`)
}
