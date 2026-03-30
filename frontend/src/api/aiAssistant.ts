import { get, post } from './client'

export interface AIChatMessage {
  id: string
  role: 'user' | 'assistant'
  message: string
  analyst: string | null
  created_at: string | null
}

export interface AIChatRequest {
  context_type: 'alert' | 'incident'
  context_id: string
  message: string
}

export interface AIChatResponse {
  reply: AIChatMessage
  context_type: 'alert' | 'incident'
  context_id: string
}

export interface ShiftHandoverResponse {
  generated_at: string
  open_incidents: number
  critical_open_alerts: number
  high_open_alerts: number
  handover: string
}

export async function getAIChatHistory(contextType: 'alert' | 'incident', contextId: string): Promise<AIChatMessage[]> {
  return get<AIChatMessage[]>('/ai-assistant/history', {
    params: {
      context_type: contextType,
      context_id: contextId,
    },
  })
}

export async function sendAIChatMessage(payload: AIChatRequest): Promise<AIChatResponse> {
  return post<AIChatResponse>('/ai-assistant/chat', payload)
}

export async function generateShiftHandover(): Promise<ShiftHandoverResponse> {
  return post<ShiftHandoverResponse>('/ai-assistant/shift-handover')
}
