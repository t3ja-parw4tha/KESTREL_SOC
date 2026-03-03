import { get } from './client'
import type { IncidentListResponse, IncidentDetail } from '@/types/incident'

export async function fetchIncidents(): Promise<IncidentListResponse> {
  return get<IncidentListResponse>('/incidents')
}

export async function fetchIncidentById(id: string): Promise<IncidentDetail> {
  return get<IncidentDetail>(`/incidents/${id}`)
}
