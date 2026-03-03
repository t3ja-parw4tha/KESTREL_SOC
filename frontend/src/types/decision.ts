export type DecisionAction = 'escalate' | 'dismiss' | 'enrich' | 'notify' | 'contain'

export interface DecisionEngineOutput {
  alert_id: string
  action: DecisionAction
  confidence: number
  score: number
  reasoning?: string
  recommended_playbook?: string
  mitre_techniques?: string[]
}

export interface AISummary {
  summary: string
  key_facts: string[]
  recommended_actions?: string[]
  confidence?: number
}
