import { get, post, patch } from './client'
import type { Alert, AlertsResponse, AlertFiltersParams } from '@/types/alert'

export interface Analyst {
  id: number
  username: string
  role: string
}

interface BackendAlertsResponse {
  items: Alert[]
  total: number
  page: number
  limit: number
}

function toAlertsResponse(data: BackendAlertsResponse): AlertsResponse {
  return {
    alerts: data.items,
    total: data.total,
    page: data.page,
    limit: data.limit,
  }
}

export async function getAlerts(params?: AlertFiltersParams): Promise<AlertsResponse> {
  const backendParams: Record<string, string | number | undefined> = {
    page: params?.page ?? 1,
    limit: params?.limit ?? 50,
    severity: params?.severity,
    status: params?.status,
    source: params?.source,
    category: params?.category,
    search: params?.search,
    assigned_to: params?.assigned_to,
    date_from: params?.date_from,
    date_to: params?.date_to,
  }
  const filtered = Object.fromEntries(
    Object.entries(backendParams).filter(([, v]) => v !== undefined && v !== '')
  )
  const data = await get<BackendAlertsResponse>('/alerts', { params: filtered })
  return toAlertsResponse(data)
}

export async function getAlert(id: string): Promise<Alert> {
  return get<Alert>(`/alerts/${id}`)
}

export async function updateAlertStatus(
  id: string,
  status: Alert['status']
): Promise<{ id: string; status: string }> {
  return patch<{ id: string; status: string }>(`/alerts/${id}`, { status })
}

export interface BulkPatchBody {
  alert_ids: string[]
  status?: string
  assigned_to?: string | null
  assign_comment?: string
}

export interface BulkPatchResponse {
  updated: number
  failed: number
  error_ids: string[]
}

export async function bulkPatchAlerts(body: BulkPatchBody): Promise<BulkPatchResponse> {
  return patch<BulkPatchResponse>('/alerts/bulk', body)
}

export async function assignAlert(
  id: string,
  assignedTo: string | null,
  assignComment?: string,
): Promise<{ id: string; status: string }> {
  const body: Record<string, unknown> = { assigned_to: assignedTo }
  if (assignComment) body.assign_comment = assignComment
  return patch<{ id: string; status: string }>(`/alerts/${id}`, body)
}

export async function pickUpAlert(
  id: string,
): Promise<{ id: string; status: string; assigned_to?: string; noop?: boolean }> {
  return post<{ id: string; status: string; assigned_to?: string; noop?: boolean }>(
    `/alerts/${id}/pick-up`
  )
}

export async function getAnalysts(): Promise<{ analysts: Analyst[] }> {
  return get<{ analysts: Analyst[] }>('/auth/users/analysts')
}

export async function addComment(id: string, comment: string): Promise<{ id: string; text: string; timestamp: string }> {
  return post<{ id: string; text: string; timestamp: string }>(`/alerts/${id}/comments`, { text: comment })
}

export async function triggerAI(id: string): Promise<{ alert_id: string; ai_summary: string | null; ai_key_facts: unknown; ai_affected: unknown; ai_evidence: unknown; ai_remediation: unknown; ai_next_steps: unknown; cached: boolean }> {
  return post(`/ai/summarize`, { alert_id: id })
}

export interface TimelineItem {
  action: string
  timestamp: string
  analyst: string | null
  details: Record<string, unknown> | null
}

export async function getTimeline(id: string): Promise<{ items: TimelineItem[] }> {
  return get<{ items: TimelineItem[] }>(`/alerts/${id}/timeline`)
}
