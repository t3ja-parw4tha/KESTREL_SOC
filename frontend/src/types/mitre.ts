export interface MitreTactic {
  id: string
  name: string
  short_name?: string
  technique_ids: string[]
}

export interface MitreTechnique {
  id: string
  name: string
  tactic_id: string
  tactic_name?: string
  description?: string
  alert_count?: number
  severity?: 'critical' | 'high' | 'medium' | 'low'
}

export interface MitreCoverageResponse {
  tactics: MitreTactic[]
  techniques: MitreTechnique[]
  summary?: { coverage_percentage?: number; techniques_detected?: number; total_techniques?: number; tactics_covered?: number }
  matrix?: Record<string, number>
}
