import { get, post } from './client'

export interface HuntQuery {
  id: string
  name: string
  description: string
  query: string
  type: 'kql' | 'sigma' | 'yara' | 'custom'
  created_by: string
  created_at: string
  last_run: string | null
  results_count: number
  status: 'saved' | 'running' | 'completed' | 'failed'
}

export interface HuntResult {
  id: string
  timestamp: string
  source: string
  host: string
  event_type: string
  details: string
  risk_score: number
}

export const demoHunts: HuntQuery[] = [
  {
    id: 'HUNT-001',
    name: 'PowerShell Empire Detection',
    description: 'Detect PowerShell Empire C2 beaconing patterns in process creation logs',
    query: 'DeviceProcessEvents\n| where FileName == "powershell.exe"\n| where ProcessCommandLine has_any("-enc", "-encodedcommand", "-ep bypass")\n| project Timestamp, DeviceName, ProcessCommandLine, AccountName\n| sort by Timestamp desc',
    type: 'kql',
    created_by: 'Sarah Chen',
    created_at: '2026-03-10T08:00:00Z',
    last_run: '2026-03-12T06:00:00Z',
    results_count: 23,
    status: 'completed',
  },
  {
    id: 'HUNT-002',
    name: 'DNS Tunneling Indicators',
    description: 'Hunt for DNS tunneling by detecting high-entropy subdomains and unusual query volumes',
    query: 'DeviceNetworkEvents\n| where RemotePort == 53\n| extend QueryLength = strlen(RemoteUrl)\n| where QueryLength > 50\n| project Timestamp, DeviceName, RemoteUrl, QueryLength\n| sort by QueryLength desc',
    type: 'kql',
    created_by: 'Marcus Webb',
    created_at: '2026-03-09T14:30:00Z',
    last_run: '2026-03-11T22:00:00Z',
    results_count: 7,
    status: 'completed',
  },
  {
    id: 'HUNT-003',
    name: 'Credential Dumping via LSASS',
    description: 'Detect attempts to access LSASS memory for credential extraction',
    query: 'title: LSASS Memory Access\nstatus: experimental\nlogsource:\n  category: process_access\n  product: windows\ndetection:\n  selection:\n    TargetImage|endswith: "\\lsass.exe"\n  condition: selection',
    type: 'sigma',
    created_by: 'Alex Rivera',
    created_at: '2026-03-08T10:00:00Z',
    last_run: null,
    results_count: 0,
    status: 'saved',
  },
  {
    id: 'HUNT-004',
    name: 'Suspicious Scheduled Tasks',
    description: 'Identify newly created scheduled tasks that may indicate persistence mechanisms',
    query: 'DeviceRegistryEvents\n| where ActionType == "RegistryValueSet"\n| where RegistryKey has "\\Schedule\\TaskCache\\Tasks"\n| project Timestamp, DeviceName, RegistryKey, RegistryValueData\n| sort by Timestamp desc',
    type: 'kql',
    created_by: 'Sarah Chen',
    created_at: '2026-03-07T16:00:00Z',
    last_run: '2026-03-12T03:00:00Z',
    results_count: 4,
    status: 'completed',
  },
  {
    id: 'HUNT-005',
    name: 'Emotet YARA Rule',
    description: 'YARA rule to detect Emotet dropper patterns in memory',
    query: 'rule Emotet_Dropper {\n  meta:\n    description = "Detects Emotet dropper"\n    author = "Kestrel SOC"\n  strings:\n    $s1 = "CreateProcessW" ascii\n    $s2 = {6A 40 68 00 10 00 00}\n    $s3 = "RunDLL32" nocase\n  condition:\n    uint16(0) == 0x5A4D and\n    filesize < 500KB and\n    2 of ($s*)\n}',
    type: 'yara',
    created_by: 'Marcus Webb',
    created_at: '2026-03-06T12:00:00Z',
    last_run: '2026-03-10T18:00:00Z',
    results_count: 1,
    status: 'completed',
  },
]

export const demoResults: HuntResult[] = [
  { id: 'R-001', timestamp: '2026-03-12T05:45:12Z', source: 'Sysmon', host: 'WS-FIN-042', event_type: 'Process Creation', details: 'powershell.exe -enc SQBFAFgAIAAoA...', risk_score: 92 },
  { id: 'R-002', timestamp: '2026-03-12T05:32:08Z', source: 'Sysmon', host: 'WS-HR-019', event_type: 'Process Creation', details: 'powershell.exe -encodedcommand JABzAD0...', risk_score: 88 },
  { id: 'R-003', timestamp: '2026-03-12T04:18:55Z', source: 'Sysmon', host: 'SRV-APP-03', event_type: 'Process Creation', details: 'powershell.exe -enc dwBoAGkAbABl...', risk_score: 85 },
  { id: 'R-004', timestamp: '2026-03-12T03:50:22Z', source: 'Wazuh', host: 'WS-DEV-011', event_type: 'Process Creation', details: 'powershell.exe -enc JABjAGwAaQBl...', risk_score: 78 },
  { id: 'R-005', timestamp: '2026-03-12T02:15:41Z', source: 'Sysmon', host: 'WS-FIN-042', event_type: 'Process Creation', details: 'powershell.exe -enc SQBuAHYAbwBr...', risk_score: 91 },
]

export const huntingApi = {
  listHunts: () => get<HuntQuery[]>('/hunting/queries'),
  getHunt: (id: string) => get<HuntQuery>(`/hunting/queries/${id}`),
  createHunt: (data: Partial<HuntQuery>) => post<HuntQuery>('/hunting/queries', data),
  runHunt: (id: string) => post<{ results: HuntResult[] }>(`/hunting/queries/${id}/run`),
  getResults: (id: string) => get<HuntResult[]>(`/hunting/queries/${id}/results`),
}
