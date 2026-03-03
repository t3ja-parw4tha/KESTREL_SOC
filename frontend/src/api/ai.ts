import { apiClient } from './client'
import type { AISummary } from '@/types/decision'

export async function fetchAISummary(alertId: string): Promise<AISummary> {
  const { data } = await apiClient.post<AISummary>(`/ai/analyze`, { alert_id: alertId })
  return data
}
