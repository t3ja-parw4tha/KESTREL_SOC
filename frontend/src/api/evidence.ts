import { apiClient, get, post } from './client'

export interface EvidenceItem {
  id: string
  alert_id: string | null
  incident_id: string | null
  attachment_type: 'file' | 'url'
  name: string
  content_type: string | null
  size_bytes: number | null
  external_url: string | null
  sha256: string | null
  notes: string | null
  uploaded_by: string | null
  created_at: string | null
}

export interface AddUrlPayload {
  url: string
  name?: string
  notes?: string
}

export async function listAlertEvidence(alertId: string): Promise<EvidenceItem[]> {
  return get<EvidenceItem[]>(`/evidence/alerts/${alertId}`)
}

export async function listIncidentEvidence(incidentId: string): Promise<EvidenceItem[]> {
  return get<EvidenceItem[]>(`/evidence/incidents/${incidentId}`)
}

export async function addAlertEvidenceUrl(alertId: string, payload: AddUrlPayload): Promise<EvidenceItem> {
  return post<EvidenceItem>(`/evidence/alerts/${alertId}/url`, payload)
}

export async function addIncidentEvidenceUrl(incidentId: string, payload: AddUrlPayload): Promise<EvidenceItem> {
  return post<EvidenceItem>(`/evidence/incidents/${incidentId}/url`, payload)
}

export async function uploadAlertEvidenceFile(alertId: string, file: File, notes?: string): Promise<EvidenceItem> {
  const form = new FormData()
  form.append('file', file)
  if (notes?.trim()) form.append('notes', notes.trim())
  const res = await apiClient.post<EvidenceItem>(`/evidence/alerts/${alertId}/file`, form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return res.data
}

export async function uploadIncidentEvidenceFile(incidentId: string, file: File, notes?: string): Promise<EvidenceItem> {
  const form = new FormData()
  form.append('file', file)
  if (notes?.trim()) form.append('notes', notes.trim())
  const res = await apiClient.post<EvidenceItem>(`/evidence/incidents/${incidentId}/file`, form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return res.data
}

export async function downloadEvidenceFile(evidenceId: string, filename: string): Promise<void> {
  const res = await apiClient.get<Blob>(`/evidence/${evidenceId}/download`, {
    responseType: 'blob',
  })
  const blobUrl = window.URL.createObjectURL(res.data)
  const link = document.createElement('a')
  link.href = blobUrl
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.URL.revokeObjectURL(blobUrl)
}
