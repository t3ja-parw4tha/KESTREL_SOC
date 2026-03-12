import { get, post, patch } from './client'

export interface Incident {
  id: string
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  status: 'open' | 'in_progress' | 'contained' | 'resolved' | 'closed'
  assigned_to: string | null
  alert_count: number
  created_at: string
  updated_at: string
  mitre_tactics: string[]
}

export interface IncidentsResponse {
  items: Incident[]
  total: number
  page: number
  page_size: number
}

export interface IncidentFilters {
  status?: string
  severity?: string
  search?: string
  page?: number
  page_size?: number
}

// ─── Demo / fallback data ─────────────────────────────────────────────────────
export const demoIncidents: Incident[] = [
  {
    id: 'INC-001',
    title: 'Coordinated Brute Force Campaign',
    description: 'Multiple brute force login attempts detected across several endpoints from a known botnet IP range. Over 15,000 failed login attempts in the past 6 hours targeting Active Directory accounts.',
    severity: 'critical',
    status: 'in_progress',
    assigned_to: 'Sarah Chen',
    alert_count: 12,
    created_at: '2026-03-12T02:15:00Z',
    updated_at: '2026-03-12T08:30:00Z',
    mitre_tactics: ['Credential Access', 'Initial Access'],
  },
  {
    id: 'INC-002',
    title: 'Suspicious Data Exfiltration via DNS',
    description: 'Anomalous DNS query patterns detected from internal host 10.0.5.42. Large encoded payloads in TXT record queries to an unregistered domain. Potential data exfiltration channel.',
    severity: 'high',
    status: 'open',
    assigned_to: null,
    alert_count: 8,
    created_at: '2026-03-11T18:45:00Z',
    updated_at: '2026-03-11T18:45:00Z',
    mitre_tactics: ['Exfiltration', 'Command and Control'],
  },
  {
    id: 'INC-003',
    title: 'Lateral Movement — Pass-the-Hash Detected',
    description: 'Pass-the-Hash activity identified on domain controller DC02. Attacker appears to be moving laterally using compromised service account credentials.',
    severity: 'critical',
    status: 'contained',
    assigned_to: 'Marcus Webb',
    alert_count: 6,
    created_at: '2026-03-10T14:20:00Z',
    updated_at: '2026-03-11T22:10:00Z',
    mitre_tactics: ['Lateral Movement', 'Defense Evasion'],
  },
  {
    id: 'INC-004',
    title: 'Malware Infection — Workstation HR-PC-019',
    description: 'Trojan detected on HR department workstation. Malware attempting to establish C2 connection to known malicious IP. Machine has been isolated from the network.',
    severity: 'high',
    status: 'resolved',
    assigned_to: 'Sarah Chen',
    alert_count: 4,
    created_at: '2026-03-09T09:00:00Z',
    updated_at: '2026-03-10T16:00:00Z',
    mitre_tactics: ['Execution', 'Command and Control'],
  },
  {
    id: 'INC-005',
    title: 'Phishing Campaign Targeting Finance Team',
    description: 'Coordinated phishing emails sent to 12 finance team members. 3 users clicked the malicious link. Credential harvesting page mimicking internal SSO portal.',
    severity: 'medium',
    status: 'closed',
    assigned_to: 'Alex Rivera',
    alert_count: 15,
    created_at: '2026-03-07T11:30:00Z',
    updated_at: '2026-03-08T14:00:00Z',
    mitre_tactics: ['Initial Access'],
  },
  {
    id: 'INC-006',
    title: 'Unauthorized Cloud Storage Access',
    description: 'Unusual access patterns to S3 buckets from an IP in an unexpected geographic region. Multiple sensitive documents downloaded outside business hours.',
    severity: 'medium',
    status: 'open',
    assigned_to: null,
    alert_count: 3,
    created_at: '2026-03-11T23:15:00Z',
    updated_at: '2026-03-11T23:15:00Z',
    mitre_tactics: ['Collection', 'Exfiltration'],
  },
]

export const incidentsApi = {
  list: (filters?: IncidentFilters) =>
    get<IncidentsResponse>('/incidents', { params: filters }),

  get: (id: string) => get<Incident>(`/incidents/${id}`),

  create: (data: Partial<Incident>) =>
    post<Incident>('/incidents', data),

  update: (id: string, data: Partial<Incident>) =>
    patch<Incident>(`/incidents/${id}`, data),
}
