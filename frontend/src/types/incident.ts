export interface Incident {
  incident_id: string
  alert_count: number
  max_risk_score: number | null
  highest_severity: string
  alert_ids: string[]
  status?: string
}

export interface IncidentListResponse {
  items: Incident[]
  total: number
}

export interface IncidentDetailAlert {
  id: string
  title: string
  severity: string
  risk_score: number | null
  created_at: string | null
}

export interface IncidentDetail {
  incident_id: string
  alerts: IncidentDetailAlert[]
  mitre_techniques: unknown[]
  attack_timeline: unknown[]
  recommended_actions: string[]
}

export interface TimelineEvent {
  id: string
  timestamp: string
  type: 'alert' | 'decision' | 'action'
  title: string
  description?: string
  metadata?: Record<string, unknown>
}
