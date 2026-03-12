export interface MitreTechnique {
  technique_id: string
  technique_name: string
  tactic: string
}

export interface VTResult {
  indicator: string
  malicious_count: number
  suspicious_count?: number
  total_engines?: number
  detection_ratio?: number
  threat_categories?: string[]
  permalink?: string
  cached?: boolean
  error?: string
}

export interface AbuseResult {
  ip: string
  abuse_score: number
  isp?: string
  usage_type?: string
  country_code?: string
  total_reports?: number
  categories?: string[]
  permalink?: string
  cached?: boolean
}

export interface FeedMatch {
  indicator: string
  feed_name: string
  confidence?: number
  source?: string
}

export interface IocGroup {
  ips: string[]
  domains: string[]
  hashes: string[]
  cves: string[]
}

export interface Enrichment {
  /** Structured IOC groups written by the backend enrichment pipeline. */
  iocs: IocGroup
  vt_results: VTResult[]
  abuse_results: AbuseResult[]
  feed_matches: FeedMatch[]
  risk_modifier: number
  summary: string
}

export type AlertStatus =
  | 'open'
  | 'in_progress'
  | 'resolved'
  | 'false_positive'

export interface Alert {
  id: string
  title: string
  source: string
  severity: 'Low' | 'Medium' | 'High' | 'Critical'
  category: string
  status: AlertStatus
  assigned_to: string | null
  asset_id: string | null
  user_id: string | null
  source_ip: string | null
  dest_ip: string | null
  mitre_techniques: MitreTechnique[]
  risk_score: number | null
  risk_level: string | null
  confidence: number | null
  incident_group_id: string | null
  ai_summary: string | null
  ai_key_facts: Record<string, unknown> | null
  ai_remediation: Record<string, unknown> | null
  ai_next_steps: Record<string, unknown> | null
  enrichment: Enrichment | null
  created_at: string
  updated_at: string
  raw?: Record<string, unknown>
  decision?: {
    risk_score?: number
    risk_level?: string
    confidence?: number
    explanation?: { items?: string[] }
    recommended_actions?: { items?: string[] }
    mitre_techniques?: unknown
    correlation_rule_triggered?: string | null
  }
}

export interface AlertsResponse {
  alerts: Alert[]
  total: number
  page: number
  limit: number
}

export interface AlertFiltersParams {
  severity?: string
  status?: string
  source?: string
  category?: string
  search?: string
  assigned_to?: string
  date_from?: string
  date_to?: string
  page?: number
  limit?: number
}
