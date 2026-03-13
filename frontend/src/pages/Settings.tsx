import { useState, useEffect, useCallback } from 'react'
import { useAuth } from '@/security/AuthContext'
import {
  Sparkles,
  Database,
  Bell,
  Users,
  Eye,
  EyeOff,
  Save,
  Pencil,
  Trash2,
  Lock,
  Loader2,
  X,
  BookOpen,
  Brain,
  Zap,
  Cloud,
  Cpu,
  CheckCircle,
  MessageSquare,
  Phone,
  Ticket,
  Monitor,
  Wifi,
} from 'lucide-react'
import { toast } from 'sonner'
import { cn } from '@/utils/cn'
import { SetupGuideModal } from '@/components/sources/SetupGuideModal'
import { get, post, del } from '@/api/client'

type Tab = 'ai' | 'sources' | 'notifications' | 'users'

interface SettingsData {
  settings: Record<string, string>
  configured: Record<string, boolean>
}

const REDACTED = '[REDACTED]'
const TEST_PASSED_KEY = 'kestrel_source_tested_'

type SourceType = 'SIEM' | 'Cloud' | 'Enrichment' | 'IDS/IPS' | 'OS' | 'EDR'

interface SourceDef {
  id: string
  name: string
  type: SourceType
  description: string
  keys: string[]
  testSource: string | null
  requiredKeys: string[]
  keyLabels: Record<string, string>
  sensitiveKeys: Set<string>
  /** For push-only: ingest API source name (e.g. WindowsEventLog) to check alert count. */
  ingestSourceName?: string
}

const SOURCES: SourceDef[] = [
  {
    id: 'sentinel',
    name: 'Microsoft Sentinel',
    type: 'SIEM',
    description: 'Pull alerts from Azure Log Analytics via KQL',
    keys: ['AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'LOGANALYTICS_WORKSPACE_ID'],
    testSource: 'sentinel',
    requiredKeys: ['AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'LOGANALYTICS_WORKSPACE_ID'],
    keyLabels: {
      AZURE_TENANT_ID: 'Tenant ID',
      AZURE_CLIENT_ID: 'Client ID',
      AZURE_CLIENT_SECRET: 'Client Secret',
      LOGANALYTICS_WORKSPACE_ID: 'Workspace ID',
    },
    sensitiveKeys: new Set(['AZURE_CLIENT_SECRET']),
  },
  {
    id: 'guardduty',
    name: 'AWS GuardDuty',
    type: 'Cloud',
    description: 'Pull threat findings from AWS GuardDuty',
    keys: ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_REGION'],
    testSource: 'guardduty',
    requiredKeys: ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_REGION'],
    keyLabels: {
      AWS_ACCESS_KEY_ID: 'Access Key ID',
      AWS_SECRET_ACCESS_KEY: 'Secret Access Key',
      AWS_REGION: 'Region',
    },
    sensitiveKeys: new Set(['AWS_SECRET_ACCESS_KEY']),
  },
  {
    id: 'virustotal',
    name: 'VirusTotal',
    type: 'Enrichment',
    description: 'IP and file hash reputation enrichment',
    keys: ['VIRUSTOTAL_API_KEY'],
    testSource: 'virustotal',
    requiredKeys: ['VIRUSTOTAL_API_KEY'],
    keyLabels: { VIRUSTOTAL_API_KEY: 'API Key' },
    sensitiveKeys: new Set(['VIRUSTOTAL_API_KEY']),
  },
  {
    id: 'abuseipdb',
    name: 'AbuseIPDB',
    type: 'Enrichment',
    description: 'IP abuse confidence scoring and geo lookup',
    keys: ['ABUSEIPDB_API_KEY'],
    testSource: 'abuseipdb',
    requiredKeys: ['ABUSEIPDB_API_KEY'],
    keyLabels: { ABUSEIPDB_API_KEY: 'API Key' },
    sensitiveKeys: new Set(['ABUSEIPDB_API_KEY']),
  },
  {
    id: 'suricata',
    name: 'Suricata IDS',
    type: 'IDS/IPS',
    description: 'Network IDS — push logs via ingest API or EVE JSON path',
    keys: ['SURICATA_EVE_PATH'],
    testSource: null,
    requiredKeys: ['SURICATA_EVE_PATH'],
    keyLabels: { SURICATA_EVE_PATH: 'EVE JSON Path' },
    sensitiveKeys: new Set(),
    ingestSourceName: 'Suricata',
  },
  {
    id: 'windows_event',
    name: 'Windows Event Log',
    type: 'OS',
    description: 'Ingest Windows Event Logs via agent or forwarder',
    keys: [],
    testSource: null,
    requiredKeys: [],
    keyLabels: {},
    sensitiveKeys: new Set(),
    ingestSourceName: 'WindowsEventLog',
  },
  {
    id: 'defender',
    name: 'Microsoft Defender',
    type: 'EDR',
    description: 'Pull alerts from Microsoft Defender for Endpoint',
    keys: [],
    testSource: null,
    requiredKeys: [],
    keyLabels: {},
    sensitiveKeys: new Set(),
    ingestSourceName: 'Defender',
  },
  {
    id: 'snort',
    name: 'Snort',
    type: 'IDS/IPS',
    description: 'Network IDS/IPS — push logs via ingest API',
    keys: [],
    testSource: null,
    requiredKeys: [],
    keyLabels: {},
    sensitiveKeys: new Set(),
    ingestSourceName: 'Snort',
  },
]

interface AiDef {
  id: string
  name: string
  description: string
  keys: string[]
  requiredKeys: string[]
  keyLabels: Record<string, string>
  sensitiveKeys: Set<string>
}

const AI_PROVIDERS: AiDef[] = [
  {
    id: 'openai',
    name: 'OpenAI',
    description: 'Powers alert triage, summarization, and remediation suggestions',
    keys: ['AI_PROVIDER', 'OPENAI_API_KEY'],
    requiredKeys: ['OPENAI_API_KEY'],
    keyLabels: { AI_PROVIDER: 'Provider', OPENAI_API_KEY: 'API Key' },
    sensitiveKeys: new Set(['OPENAI_API_KEY']),
  },
  {
    id: 'anthropic',
    name: 'Anthropic Claude',
    description: 'Alternative AI provider for alert analysis',
    keys: ['ANTHROPIC_API_KEY'],
    requiredKeys: ['ANTHROPIC_API_KEY'],
    keyLabels: { ANTHROPIC_API_KEY: 'API Key' },
    sensitiveKeys: new Set(['ANTHROPIC_API_KEY']),
  },
  {
    id: 'azure_openai',
    name: 'Azure OpenAI',
    description: 'Enterprise Azure OpenAI deployment',
    keys: ['AZURE_OPENAI_API_KEY', 'AZURE_OPENAI_ENDPOINT'],
    requiredKeys: ['AZURE_OPENAI_API_KEY', 'AZURE_OPENAI_ENDPOINT'],
    keyLabels: {
      AZURE_OPENAI_API_KEY: 'API Key',
      AZURE_OPENAI_ENDPOINT: 'Endpoint',
    },
    sensitiveKeys: new Set(['AZURE_OPENAI_API_KEY']),
  },
]

const PUSH_SOURCE_IDS = ['windows_event', 'defender', 'suricata', 'snort']

/* ─── AI Provider Visual Config ─── */
const AI_VISUAL: Record<string, { icon: React.ElementType; accent: string; ring: string; color: string; model: string }> = {
  openai: { icon: Zap, accent: 'text-emerald-400', ring: 'ring-emerald-500/40 border-emerald-500/30', color: 'from-emerald-500/20 to-teal-500/10', model: 'GPT-4o' },
  anthropic: { icon: Brain, accent: 'text-orange-400', ring: 'ring-orange-500/40 border-orange-500/30', color: 'from-orange-500/20 to-amber-500/10', model: 'Claude 3.5 Sonnet' },
  azure_openai: { icon: Cloud, accent: 'text-blue-400', ring: 'ring-blue-500/40 border-blue-500/30', color: 'from-blue-500/20 to-cyan-500/10', model: 'GPT-4 Turbo (Azure)' },
}

/* ─── Notification Integrations ─── */
interface NotifIntegration {
  id: string
  name: string
  description: string
  icon: React.ElementType
}
const NOTIF_INTEGRATIONS: NotifIntegration[] = [
  { id: 'slack', name: 'Slack', description: 'Send alerts to Slack channels', icon: MessageSquare },
  { id: 'pagerduty', name: 'PagerDuty', description: 'Escalate critical incidents', icon: Phone },
  { id: 'jira', name: 'Jira', description: 'Create tickets from incidents', icon: Ticket },
  { id: 'teams', name: 'Microsoft Teams', description: 'Send notifications to Teams', icon: Users },
  { id: 'servicenow', name: 'ServiceNow', description: 'Sync incidents to ITSM workflows', icon: Monitor },
  { id: 'opsgenie', name: 'Opsgenie', description: 'On-call alerting and escalation', icon: Bell },
]

const NOTIF_TRIGGERS = [
  { label: 'Critical alerts', key: 'notif_critical', defaultOn: true },
  { label: 'High severity alerts', key: 'notif_high', defaultOn: false },
  { label: 'Incident updates', key: 'notif_incidents', defaultOn: true },
  { label: 'Playbook failures', key: 'notif_playbooks', defaultOn: false },
  { label: 'System status changes', key: 'notif_system', defaultOn: false },
]

function getTestPassed(sourceId: string): boolean {
  try {
    return localStorage.getItem(TEST_PASSED_KEY + sourceId) === '1'
  } catch {
    return false
  }
}

function setTestPassed(sourceId: string, passed: boolean): void {
  try {
    if (passed) localStorage.setItem(TEST_PASSED_KEY + sourceId, '1')
    else localStorage.removeItem(TEST_PASSED_KEY + sourceId)
  } catch {
    /* ignore */
  }
}

function mapTestMessage(sourceId: string, status: string, message: string, form: Record<string, string>): string {
  if (status === 'ok') {
    if (sourceId === 'sentinel' && form.LOGANALYTICS_WORKSPACE_ID && form.LOGANALYTICS_WORKSPACE_ID !== REDACTED) {
      return `Connection successful — pulling from workspace ${form.LOGANALYTICS_WORKSPACE_ID}`
    }
    if (sourceId === 'guardduty' && form.AWS_REGION && form.AWS_REGION !== REDACTED) {
      return `Connection successful — GuardDuty active in ${form.AWS_REGION}`
    }
    if (sourceId === 'virustotal') return 'Connection successful — requests remaining depend on your API tier'
    if (sourceId === 'abuseipdb') return 'Connection successful — requests remaining depend on your API tier'
    return message
  }
  const lower = (message || '').toLowerCase()
  if (sourceId === 'sentinel') {
    if (lower.includes('tenant') || message === 'Sentinel not configured') return 'Missing Tenant ID'
    if (lower.includes('client_id') || lower.includes('client id')) return 'Missing Client ID'
    if (lower.includes('client_secret') || lower.includes('client secret')) return 'Missing Client Secret'
    if (lower.includes('workspace')) return 'Missing Workspace ID'
    if (message.includes('401') || lower.includes('auth failed')) return 'Authentication failed — check Client ID and Client Secret'
    if (message.includes('404') || lower.includes('not found')) return 'Workspace not found — check Workspace ID'
    if (lower.includes('network') || lower.includes('connect') || lower.includes('timeout')) return 'Cannot reach Azure — check network connectivity'
  }
  if (sourceId === 'guardduty') {
    if (lower.includes('credential') || lower.includes('invalid')) return 'Invalid AWS credentials'
    if (lower.includes('region')) return 'Invalid AWS region'
    if (lower.includes('access') || lower.includes('permission')) return 'Credentials valid but no GuardDuty access — check IAM permissions'
  }
  if (sourceId === 'virustotal') {
    if (message.includes('403') || lower.includes('invalid')) return 'Invalid API key'
    if (message.includes('429')) return 'Rate limit hit — check your API tier'
  }
  if (sourceId === 'abuseipdb') {
    if (message.includes('401') || lower.includes('invalid')) return 'Invalid API key'
  }
  return message || 'Connection failed'
}

export function Settings() {
  const { user } = useAuth()
  const [tab, setTab] = useState<Tab>('ai')
  const [data, setData] = useState<SettingsData | null>(null)
  const [form, setForm] = useState<Record<string, string>>({})
  const [showSecrets, setShowSecrets] = useState<Record<string, boolean>>({})
  const [saving, setSaving] = useState(false)
  const [saveMsg, setSaveMsg] = useState('')
  const [integrationStates, setIntegrationStates] = useState<Record<string, boolean>>(
    Object.fromEntries(NOTIF_INTEGRATIONS.map((i) => [i.id, i.id === 'slack']))
  )
  const [triggerStates, setTriggerStates] = useState<Record<string, boolean>>(
    Object.fromEntries(NOTIF_TRIGGERS.map((t) => [t.key, t.defaultOn]))
  )
  const [testingIntegration, setTestingIntegration] = useState<string | null>(null)

  const [editingSourceId, setEditingSourceId] = useState<string | null>(null)
  const [editingAiId, setEditingAiId] = useState<string | null>(null)
  const [testingSourceId, setTestingSourceId] = useState<string | null>(null)
  const [testMessage, setTestMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  const [deleteConfirmSource, setDeleteConfirmSource] = useState<SourceDef | null>(null)
  const [deleteConfirmAi, setDeleteConfirmAi] = useState<AiDef | null>(null)
  const [setupGuideSourceId, setSetupGuideSourceId] = useState<string | null>(null)
  const [pushSourceAlertCounts, setPushSourceAlertCounts] = useState<Record<string, number>>({})
  const [fieldTouched, setFieldTouched] = useState<Record<string, boolean>>({})
  const [editForm, setEditForm] = useState<Record<string, string>>({})
  const [editAiForm, setEditAiForm] = useState<Record<string, string>>({})

  const loadSettings = useCallback(async () => {
    const d = await get<SettingsData>('/settings').catch(() => null)
    if (d) {
      setData(d)
      setForm(d.settings || {})
    }
  }, [])

  useEffect(() => {
    loadSettings()
  }, [loadSettings])

  useEffect(() => {
    if (tab !== 'sources') return
    const sources = ['Suricata', 'Snort', 'WindowsEventLog', 'Defender']
    Promise.all(
      sources.map(async (source) => {
        const data = await get<{ total: number }>(
          `/alerts?source=${encodeURIComponent(source)}&limit=1`
        ).catch(() => ({ total: 0 }))
        return { source, total: data.total ?? 0 }
      })
    ).then((results) => {
      setPushSourceAlertCounts(
        results.reduce((acc, { source, total }) => ({ ...acc, [source]: total }), {})
      )
    })
  }, [tab])

  const save = async (keys: string[]) => {
    setSaving(true)
    setSaveMsg('')
    const subset = Object.fromEntries(
      keys.filter((k) => (form[k] ?? '').trim() !== '' && (form[k] ?? '').trim() !== REDACTED).map((k) => [k, (form[k] ?? '').trim()])
    )
    if (Object.keys(subset).length === 0) {
      setSaving(false)
      setSaveMsg('Nothing to save')
      setTimeout(() => setSaveMsg(''), 2000)
      return
    }
    try {
      await post('/settings', { settings: subset })
      setSaveMsg('Saved successfully')
      loadSettings()
      setTimeout(() => setSaveMsg(''), 3000)
    } catch {
      setSaveMsg('Save failed')
    } finally {
      setSaving(false)
    }
  }

  const testConn = async (source: string) => {
    setTestingSourceId(source)
    setTestMessage(null)
    try {
      const d = await post<{ status: string; message: string }>(
        `/settings/test/${source}`
      ).catch(() => ({ status: 'error', message: 'Connection failed' }))
      const status = d.status || 'error'
      const rawMessage = d.message || ''
      const sourceDef = SOURCES.find((s) => s.testSource === source)
      const displayMessage = sourceDef ? mapTestMessage(sourceDef.id, status, rawMessage, editForm) : rawMessage
      setTestMessage(status === 'ok' ? { type: 'success', text: displayMessage } : { type: 'error', text: displayMessage })
      if (sourceDef) setTestPassed(sourceDef.id, status === 'ok')
    } finally {
      setTestingSourceId(null)
    }
  }

  const sourceHasValues = (def: SourceDef, settings: Record<string, string>) =>
    def.keys.length > 0 && def.keys.every((k) => (settings[k] ?? '').trim() !== '')

  const sourceStatus = (def: SourceDef): 'configured' | 'push_ready' | 'not_configured' | 'active' => {
    const settings = data?.settings ?? {}
    const hasValues = sourceHasValues(def, settings)
    const testPassed = getTestPassed(def.id)
    if (def.testSource && testPassed && hasValues) return 'configured'
    if (def.ingestSourceName && (pushSourceAlertCounts[def.ingestSourceName] ?? 0) > 0) return 'active'
    if (!def.testSource && hasValues) return 'push_ready'
    if (PUSH_SOURCE_IDS.includes(def.id)) return 'push_ready'
    return 'not_configured'
  }

  const deleteSource = async (def: SourceDef) => {
    for (const key of def.keys) {
      await del(`/settings/${key}`).catch(() => { })
    }
    setTestPassed(def.id, false)
    await loadSettings()
    setDeleteConfirmSource(null)
    toast.success(`${def.name} integration removed`)
  }

  const openEdit = (def: SourceDef) => {
    setEditingAiId(null)
    const initial: Record<string, string> = {}
    def.keys.forEach((k) => {
      const v = data?.settings?.[k] ?? form[k] ?? ''
      initial[k] = v === REDACTED ? '' : v
    })
    setEditForm(initial)
    setFieldTouched({})
    setTestMessage(null)
    setEditingSourceId(def.id)
  }

  const closeEdit = () => {
    setEditingSourceId(null)
    setTestMessage(null)
    setFieldTouched({})
  }

  const aiHasValues = (def: AiDef, settings: Record<string, string>) =>
    def.requiredKeys.length > 0 && def.requiredKeys.every((k) => (settings[k] ?? '').trim() !== '')

  const aiStatus = (def: AiDef): 'configured' | 'not_configured' => {
    const settings = data?.settings ?? {}
    return aiHasValues(def, settings) ? 'configured' : 'not_configured'
  }

  const openEditAi = (def: AiDef) => {
    setEditingSourceId(null)
    const initial: Record<string, string> = {}
    def.keys.forEach((k) => {
      const v = data?.settings?.[k] ?? form[k] ?? ''
      initial[k] = v === REDACTED ? '' : v
    })
    setEditAiForm(initial)
    setFieldTouched({})
    setEditingAiId(def.id)
  }

  const closeEditAi = () => {
    setEditingAiId(null)
    setFieldTouched({})
  }

  const saveEditFormAi = async (def: AiDef) => {
    const errors: string[] = []
    def.requiredKeys.forEach((k) => {
      const v = editAiForm[k]?.trim() ?? ''
      const existing = data?.settings?.[k]
      if (!v && existing !== REDACTED) errors.push(k)
    })
    if (errors.length > 0) {
      setFieldTouched(errors.reduce((acc, k) => ({ ...acc, [k]: true }), {}))
      return
    }
    const toSend: Record<string, string> = {}
    def.keys.forEach((k) => {
      const v = editAiForm[k]?.trim() ?? ''
      if (v && v !== REDACTED) toSend[k] = v
    })
    if (Object.keys(toSend).length === 0 && def.requiredKeys.length > 0) return
    setSaving(true)
    try {
      await post('/settings', { settings: toSend })
      await loadSettings()
      setSaveMsg('Saved successfully')
      setTimeout(() => setSaveMsg(''), 3000)
    } finally {
      setSaving(false)
    }
  }

  const deleteAi = async (def: AiDef) => {
    for (const key of def.keys) {
      await del(`/settings/${key}`).catch(() => { })
    }
    await loadSettings()
    setDeleteConfirmAi(null)
    toast.success(`${def.name} configuration removed`)
  }

  const saveEditForm = async (def: SourceDef) => {
    const errors: string[] = []
    def.requiredKeys.forEach((k) => {
      const v = editForm[k]?.trim() ?? ''
      const existing = data?.settings?.[k]
      if (!v && existing !== REDACTED) errors.push(k)
    })
    if (errors.length > 0) {
      setFieldTouched(errors.reduce((acc, k) => ({ ...acc, [k]: true }), {}))
      return
    }
    const toSend: Record<string, string> = {}
    def.keys.forEach((k) => {
      const v = editForm[k]?.trim() ?? ''
      if (v && v !== REDACTED) toSend[k] = v
    })
    if (Object.keys(toSend).length === 0 && def.requiredKeys.length > 0) return
    setSaving(true)
    try {
      await post('/settings', { settings: toSend })
      await loadSettings()
      setSaveMsg('Saved successfully')
      setTimeout(() => setSaveMsg(''), 3000)
    } finally {
      setSaving(false)
    }
  }

  const runTestFromEdit = async (def: SourceDef) => {
    const missing = def.requiredKeys.find((k) => {
      const v = editForm[k]?.trim() ?? ''
      const existing = data?.settings?.[k]
      return !v && existing !== REDACTED
    })
    if (missing) {
      const label = def.keyLabels[missing] || missing
      setTestMessage({ type: 'error', text: `Missing ${label}` })
      return
    }
    if (!def.testSource) return
    await saveEditForm(def)
    await testConn(def.testSource)
  }

  const field = (
    key: string,
    label: string,
    placeholder: string,
    sensitive = false,
    type = 'text'
  ) => {
    const show = showSecrets[key]
    const inputType = sensitive && !show ? 'password' : type
    return (
      <div key={key}>
        <label className="block text-xs text-muted-foreground mb-1">{label}</label>
        <div className="relative">
          <input
            type={inputType}
            value={form[key] ?? ''}
            onChange={(e) => setForm((prev) => ({ ...prev, [key]: e.target.value }))}
            placeholder={placeholder}
            className="w-full px-3 py-2 rounded border border-border bg-background text-foreground text-sm pr-10 focus:outline-none focus:border-blue-500"
          />
          {sensitive && (
            <button
              type="button"
              onClick={() => setShowSecrets((prev) => ({ ...prev, [key]: !prev[key] }))}
              className="absolute right-2 top-2.5 text-muted-foreground hover:text-foreground"
            >
              {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          )}
        </div>
      </div>
    )
  }

  const sectionCard = (
    title: string,
    description: string,
    configuredKey: string | null,
    fields: JSX.Element[],
    saveKeys: string[],
    _testSource?: string
  ) => {
    const isConfigured = configuredKey ? data?.configured[configuredKey] : false
    return (
      <div className="rounded-xl border border-border/50 bg-muted/20 p-4 space-y-3">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold">{title}</h3>
            {configuredKey && (
              <span
                className={cn(
                  'text-[10px] px-1.5 py-0.5 rounded border',
                  isConfigured ? 'bg-green-500/15 text-green-400 border-green-500/30' : 'bg-muted text-muted-foreground border-border'
                )}
              >
                {isConfigured ? 'Configured' : 'Not configured'}
              </span>
            )}
          </div>
          <p className="text-xs text-muted-foreground mt-0.5">{description}</p>
        </div>
        <div className="space-y-3">{fields}</div>
        <div className="flex items-center gap-2 pt-1">
          <button
            type="button"
            onClick={() => save(saveKeys)}
            disabled={saving}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg gradient-primary text-primary-foreground text-xs font-medium disabled:opacity-50"
          >
            {saving ? <Loader2 className="w-3 h-3 animate-spin" /> : <Save className="w-3 h-3" />}
            Save
          </button>
        </div>
      </div>
    )
  }

  const TABS = [
    { id: 'ai' as Tab, label: 'AI Configuration', icon: Sparkles },
    { id: 'sources' as Tab, label: 'Source Integrations', icon: Database },
    { id: 'notifications' as Tab, label: 'Notifications', icon: Bell },
    { id: 'users' as Tab, label: 'Users', icon: Users },
  ]

  if (!user || user.role !== 'admin') {
    return (
      <div className="rounded-lg border border-border bg-card p-6">
        <h1 className="text-lg font-semibold text-foreground mb-2">Settings</h1>
        <p className="text-sm text-muted-foreground">Only administrators can view and edit platform settings.</p>
      </div>
    )
  }

  const editingSource = editingSourceId ? SOURCES.find((s) => s.id === editingSourceId) : null
  const editingAi = editingAiId ? AI_PROVIDERS.find((a) => a.id === editingAiId) : null

  return (
    <div className="space-y-6 max-w-4xl animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold tracking-tight">Settings</h1>
          <p className="text-xs text-muted-foreground">Configuration saved locally — never pushed to repository</p>
        </div>
        {saveMsg && (
          <span className="text-green-400 text-sm flex items-center gap-1">
            <Save className="w-4 h-4" /> {saveMsg}
          </span>
        )}
      </div>

      <div className="flex gap-1 p-1 rounded-xl bg-muted/50 w-fit">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            type="button"
            onClick={() => setTab(id)}
            className={cn(
              'flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg transition-all',
              tab === id ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'
            )}
          >
            <Icon className="w-3.5 h-3.5" />
            {label}
          </button>
        ))}
      </div>

      {tab === 'ai' && (
        <div className="space-y-4">
          <div>
            <h2 className="text-sm font-semibold">AI Triage Provider</h2>
            <p className="text-[11px] text-muted-foreground mt-0.5">Select and configure the AI model for automated alert analysis</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {AI_PROVIDERS.map((def) => {
            const status = aiStatus(def)
            const isConfigured = status === 'configured'
            const visual = AI_VISUAL[def.id] ?? { icon: Cpu, accent: 'text-muted-foreground', ring: 'ring-border border-border', color: 'from-muted/40 to-muted/20', model: '' }
            const Icon = visual.icon
            return (
              <div
                key={def.id}
                className={cn(
                  'relative rounded-xl border overflow-hidden transition-all duration-300',
                  isConfigured
                    ? `ring-2 ${visual.ring} bg-gradient-to-br ${visual.color}`
                    : 'border-border/50 bg-card/50 hover:bg-card/80 hover:border-border'
                )}
              >
                {isConfigured && (
                  <div className="absolute top-3 right-3">
                    <div className="h-6 w-6 rounded-full bg-primary flex items-center justify-center">
                      <CheckCircle className="h-3.5 w-3.5 text-primary-foreground" />
                    </div>
                  </div>
                )}
                <div className="p-5">
                  <div className="flex items-start gap-3 mb-3">
                    <div className={cn('h-10 w-10 rounded-lg flex items-center justify-center', isConfigured ? 'bg-background/80' : 'bg-muted/50')}>
                      <Icon className={cn('h-5 w-5', isConfigured ? visual.accent : 'text-muted-foreground')} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h3 className="text-sm font-semibold">{def.name}</h3>
                      <p className="text-[10px] text-muted-foreground font-mono">{visual.model}</p>
                    </div>
                  </div>
                  <p className="text-[11px] text-muted-foreground leading-relaxed mb-4">{def.description}</p>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => openEditAi(def)}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-border text-muted-foreground hover:text-foreground hover:bg-muted/30 transition-colors"
                      aria-label={`Edit ${def.name}`}
                    >
                      <Pencil className="w-3 h-3" /> Configure
                    </button>
                  {isConfigured && (
                    <button
                      type="button"
                      onClick={() => setDeleteConfirmAi(def)}
                      className="p-2 rounded border border-border text-muted-foreground hover:text-red-400 hover:bg-red-500/10 transition-colors"
                      aria-label={`Delete ${def.name}`}
                    >
                      <Trash2 className="w-3 h-3" />
                    </button>
                  )}
                  </div>
                </div>
              </div>
            )
          })}
          </div>
        </div>
      )}

      {tab === 'sources' && (
        <div className="space-y-3">
          <div>
            <h2 className="text-sm font-semibold">Source Integrations</h2>
            <p className="text-[11px] text-muted-foreground mt-0.5">Configure data sources and log collectors for the platform</p>
          </div>
          {SOURCES.map((def) => {
            const status = sourceStatus(def)
            const isConfigured = status === 'configured'
            const isPushOnly = PUSH_SOURCE_IDS.includes(def.id)
            return (
              <div
                key={def.id}
                className="glass-card rounded-xl p-4 flex items-center justify-between gap-4"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2 mb-1">
                    <h3 className="text-sm font-semibold">{def.name}</h3>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground border border-border">{def.type}</span>
                    <span
                      className={cn(
                        'text-[10px] px-1.5 py-0.5 rounded border',
                        (status === 'configured' || status === 'active') && 'bg-green-500/15 text-green-400 border-green-500/30',
                        status === 'push_ready' && 'bg-blue-500/15 text-blue-400 border-blue-500/30',
                        status === 'not_configured' && 'bg-muted text-muted-foreground border-border'
                      )}
                    >
                      {status === 'configured' ? 'Configured' : status === 'active' ? 'Active' : status === 'push_ready' ? 'Push Ready' : 'Not Configured'}
                    </span>
                  </div>
                  <p className="text-xs text-muted-foreground">{def.description}</p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {isPushOnly && (
                    <button
                      type="button"
                      onClick={() => setSetupGuideSourceId(def.id)}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded border border-border text-muted-foreground hover:text-foreground hover:bg-muted/30 text-sm"
                      aria-label={`Setup guide for ${def.name}`}
                    >
                      <BookOpen className="w-4 h-4" />
                      Setup Guide
                    </button>
                  )}
                  {def.keys.length > 0 && (
                    <button
                      type="button"
                      onClick={() => openEdit(def)}
                      className="p-2 rounded border border-border text-muted-foreground hover:text-foreground hover:bg-muted/30"
                      aria-label={`Edit ${def.name}`}
                    >
                      <Pencil className="w-4 h-4" />
                    </button>
                  )}
                  {isConfigured && def.keys.length > 0 && (
                    <button
                      type="button"
                      onClick={() => setDeleteConfirmSource(def)}
                      className="p-2 rounded border border-border text-muted-foreground hover:text-red-400 hover:bg-red-500/10"
                      aria-label={`Delete ${def.name}`}
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {tab === 'notifications' && (
        <div className="space-y-6">
          {/* Alert Trigger Toggles */}
          <div className="glass-card rounded-xl p-5">
            <h2 className="text-sm font-semibold mb-1">Alert Notifications</h2>
            <p className="text-[11px] text-muted-foreground mb-4">Configure which events trigger notifications</p>
            <div className="divide-y divide-border/40">
              {NOTIF_TRIGGERS.map((trigger) => (
                <div key={trigger.key} className="flex items-center justify-between py-3">
                  <span className="text-sm font-medium">{trigger.label}</span>
                  <button
                    type="button"
                    role="switch"
                    aria-checked={triggerStates[trigger.key]}
                    onClick={() => setTriggerStates((prev) => ({ ...prev, [trigger.key]: !prev[trigger.key] }))}
                    className={cn(
                      'relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200',
                      triggerStates[trigger.key] ? 'bg-primary' : 'bg-muted'
                    )}
                  >
                    <span className={cn(
                      'pointer-events-none inline-block h-4 w-4 rounded-full bg-white shadow-lg transition-transform duration-200',
                      triggerStates[trigger.key] ? 'translate-x-4' : 'translate-x-0'
                    )} />
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Integration Cards */}
          <div className="glass-card rounded-xl p-5">
            <h2 className="text-sm font-semibold mb-1">Connected Services</h2>
            <p className="text-[11px] text-muted-foreground mb-4">Manage external notification integrations</p>
            <div className="space-y-3">
              {NOTIF_INTEGRATIONS.map((integration) => {
                const isConnected = integrationStates[integration.id] ?? false
                const Icon = integration.icon
                return (
                  <div
                    key={integration.id}
                    className="flex items-center justify-between p-4 rounded-xl border border-border/40 bg-card/40"
                  >
                    <div className="flex items-center gap-3">
                      <div className="h-10 w-10 rounded-lg bg-muted/50 flex items-center justify-center">
                        <Icon className="h-5 w-5 text-muted-foreground" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <h3 className="text-sm font-semibold">{integration.name}</h3>
                          {isConnected && (
                            <span className="text-[9px] px-1.5 py-0.5 rounded bg-green-500/15 text-green-400 border border-green-500/30">Connected</span>
                          )}
                        </div>
                        <p className="text-xs text-muted-foreground">{integration.description}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {isConnected && (
                        <button
                          type="button"
                          onClick={async () => {
                            setTestingIntegration(integration.id)
                            await new Promise((r) => setTimeout(r, 1000))
                            setTestingIntegration(null)
                            toast.success(`${integration.name} test sent`)
                          }}
                          disabled={testingIntegration === integration.id}
                          className="flex items-center gap-1 px-2.5 py-1.5 text-xs rounded-lg border border-border text-muted-foreground hover:text-foreground hover:bg-muted/30 transition-colors disabled:opacity-50"
                        >
                          {testingIntegration === integration.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <Wifi className="h-3 w-3" />}
                          Test
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={() => {
                          setIntegrationStates((prev) => ({ ...prev, [integration.id]: !isConnected }))
                          toast.success(isConnected ? `${integration.name} disconnected` : `${integration.name} connected`)
                        }}
                        className={cn(
                          'px-3 py-1.5 text-xs font-medium rounded-lg transition-colors',
                          isConnected
                            ? 'border border-border text-muted-foreground hover:text-foreground hover:bg-muted/30'
                            : 'gradient-primary text-primary-foreground'
                        )}
                      >
                        {isConnected ? 'Configure' : 'Connect'}
                      </button>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Webhook/Email config */}
          <div className="glass-card rounded-xl p-5 space-y-4">
            <h2 className="text-sm font-semibold">Webhook & Email</h2>
            {sectionCard(
              'Slack Webhook',
              'Send critical alert notifications to a Slack channel',
              'slack',
              [field('SLACK_WEBHOOK_URL', 'Webhook URL', 'https://hooks.slack.com/services/...', true)],
              ['SLACK_WEBHOOK_URL']
            )}
            {sectionCard(
              'Alert Email',
              'Send email notifications for critical alerts',
              null,
              [field('ALERT_EMAIL', 'Alert Email Address', 'soc@yourcompany.com')],
              ['ALERT_EMAIL']
            )}
          </div>
        </div>
      )}

      {tab === 'users' && (
        <div className="glass-card rounded-xl p-5">
          <h3 className="text-sm font-semibold mb-1">User Management</h3>
          <p className="text-xs text-muted-foreground mb-4">Create and manage analyst accounts with role-based access</p>
          <a
            href="/app/users"
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg gradient-primary text-primary-foreground text-sm"
          >
            <Users className="w-4 h-4" />
            Manage Users
          </a>
        </div>
      )}

      {/* Edit panel (slide-in) */}
      {editingSource && (
        <>
          <div
            className="fixed inset-0 bg-black/50 z-40"
            onClick={closeEdit}
            aria-hidden
          />
          <div className="fixed inset-y-0 right-0 w-full max-w-md bg-card border-l border-border shadow-xl z-50 overflow-auto">
            <div className="p-4">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold text-foreground">Configure {editingSource.name}</h2>
                <button type="button" onClick={closeEdit} className="p-2 text-muted-foreground hover:text-foreground">
                  <X className="w-5 h-5" />
                </button>
              </div>
              {editingSource.keys.length === 0 ? (
                <p className="text-sm text-muted-foreground">No configuration options for this source yet.</p>
              ) : (
                <div className="space-y-4">
                  {editingSource.keys.map((key) => {
                    const label = editingSource.keyLabels[key] || key
                    const isSensitive = editingSource.sensitiveKeys.has(key)
                    const savedVal = data?.settings?.[key]
                    const isRedacted = savedVal === REDACTED
                    const displayValue = editForm[key] ?? (isRedacted ? '' : savedVal ?? '')
                    const showRedactedPlaceholder = isRedacted && !displayValue && !fieldTouched[key]
                    const show = showSecrets[key]
                    const isRequired = editingSource.requiredKeys.includes(key)
                    const isEmpty = !(displayValue?.trim())
                    const showRequiredError = isRequired && fieldTouched[key] && isEmpty && !isRedacted
                    const showLock = isRedacted && (isEmpty || !fieldTouched[key])

                    return (
                      <div key={key}>
                        <label className="block text-xs text-muted-foreground mb-1 flex items-center gap-1.5">
                          {label}
                          {showLock && <Lock className="w-3 h-3 text-muted-foreground" aria-hidden />}
                        </label>
                        <div className="relative">
                          <input
                            type={isSensitive && !show ? 'password' : 'text'}
                            value={displayValue}
                            onChange={(e) => {
                              setEditForm((prev) => ({ ...prev, [key]: e.target.value }))
                              setTestMessage(null)
                            }}
                            onFocus={() => {
                              if (isRedacted && !editForm[key]) setEditForm((prev) => ({ ...prev, [key]: '' }))
                              setFieldTouched((prev) => ({ ...prev, [key]: true }))
                            }}
                            placeholder={showRedactedPlaceholder ? REDACTED : ''}
                            className={cn(
                              'w-full px-3 py-2 rounded border bg-background text-foreground text-sm pr-10 focus:outline-none focus:border-blue-500',
                              showRequiredError ? 'border-red-500' : 'border-border'
                            )}
                          />
                          {isSensitive && (
                            <button
                              type="button"
                              onClick={() => setShowSecrets((prev) => ({ ...prev, [key]: !prev[key] }))}
                              className="absolute right-2 top-2.5 text-muted-foreground hover:text-foreground"
                            >
                              {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                            </button>
                          )}
                        </div>
                        {showRequiredError && <p className="text-xs text-red-400 mt-0.5">Required</p>}
                      </div>
                    )
                  })}
                </div>
              )}
              {editingSource.keys.length > 0 && (
                <div className="mt-6 space-y-3">
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => saveEditForm(editingSource)}
                      disabled={saving || editingSource.requiredKeys.some((k) => {
                        const hasValue = (editForm[k] ?? '').trim() !== ''
                        const isRedactedKept = data?.settings?.[k] === REDACTED
                        return !hasValue && !isRedactedKept
                      })}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-blue-600 text-white text-sm hover:bg-blue-700 disabled:opacity-50"
                    >
                      {saving ? <Loader2 className="w-3 h-3 animate-spin" /> : <Save className="w-3 h-3" />}
                      Save
                    </button>
                    {editingSource.testSource && (
                      <button
                        type="button"
                        onClick={() => runTestFromEdit(editingSource)}
                        disabled={testingSourceId === editingSource.testSource}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded border border-border text-foreground text-sm hover:bg-muted/30 disabled:opacity-50"
                      >
                        {testingSourceId === editingSource.testSource ? (
                          <Loader2 className="w-3 h-3 animate-spin" />
                        ) : null}
                        Test Connection
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={closeEdit}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded border border-border text-muted-foreground text-sm hover:bg-muted/30"
                    >
                      Cancel
                    </button>
                  </div>
                  {testMessage && (
                    <p className={cn('text-sm', testMessage.type === 'success' ? 'text-green-400' : 'text-red-400')}>
                      {testMessage.text}
                    </p>
                  )}
                </div>
              )}
            </div>
          </div>
        </>
      )}

      {/* AI Edit panel (slide-in) */}
      {editingAi && (
        <>
          <div
            className="fixed inset-0 bg-black/50 z-40"
            onClick={closeEditAi}
            aria-hidden
          />
          <div className="fixed inset-y-0 right-0 w-full max-w-md bg-card border-l border-border shadow-xl z-50 overflow-auto">
            <div className="p-4">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold text-foreground">Configure {editingAi.name}</h2>
                <button type="button" onClick={closeEditAi} className="p-2 text-muted-foreground hover:text-foreground">
                  <X className="w-5 h-5" />
                </button>
              </div>
              <div className="space-y-4">
                {editingAi.keys.map((key) => {
                  const label = editingAi.keyLabels[key] || key
                  const isSensitive = editingAi.sensitiveKeys.has(key)
                  const savedVal = data?.settings?.[key]
                  const isRedacted = savedVal === REDACTED
                  const displayValue = editAiForm[key] ?? (isRedacted ? '' : savedVal ?? '')
                  const showRedactedPlaceholder = isRedacted && !displayValue && !fieldTouched[key]
                  const show = showSecrets[key]
                  const isRequired = editingAi.requiredKeys.includes(key)
                  const isEmpty = !(displayValue?.trim())
                  const showRequiredError = isRequired && fieldTouched[key] && isEmpty && !isRedacted
                  const showLock = isRedacted && (isEmpty || !fieldTouched[key])

                  return (
                    <div key={key}>
                      <label className="block text-xs text-muted-foreground mb-1 flex items-center gap-1.5">
                        {label}
                        {showLock && <Lock className="w-3 h-3 text-muted-foreground" aria-hidden />}
                      </label>
                      <div className="relative">
                        <input
                          type={isSensitive && !show ? 'password' : 'text'}
                          value={displayValue}
                          onChange={(e) => setEditAiForm((prev) => ({ ...prev, [key]: e.target.value }))}
                          onFocus={() => {
                            if (isRedacted && !editAiForm[key]) setEditAiForm((prev) => ({ ...prev, [key]: '' }))
                            setFieldTouched((prev) => ({ ...prev, [key]: true }))
                          }}
                          placeholder={showRedactedPlaceholder ? REDACTED : ''}
                          className={cn(
                            'w-full px-3 py-2 rounded border bg-background text-foreground text-sm pr-10 focus:outline-none focus:border-blue-500',
                            showRequiredError ? 'border-red-500' : 'border-border'
                          )}
                        />
                        {isSensitive && (
                          <button
                            type="button"
                            onClick={() => setShowSecrets((prev) => ({ ...prev, [key]: !prev[key] }))}
                            className="absolute right-2 top-2.5 text-muted-foreground hover:text-foreground"
                          >
                            {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                          </button>
                        )}
                      </div>
                      {showRequiredError && <p className="text-xs text-red-400 mt-0.5">Required</p>}
                    </div>
                  )
                })}
              </div>
              <div className="mt-6 flex gap-2">
                <button
                  type="button"
                  onClick={() => saveEditFormAi(editingAi)}
                  disabled={saving || editingAi.requiredKeys.some((k) => {
                    const hasValue = (editAiForm[k] ?? '').trim() !== ''
                    const isRedactedKept = data?.settings?.[k] === REDACTED
                    return !hasValue && !isRedactedKept
                  })}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-blue-600 text-white text-sm hover:bg-blue-700 disabled:opacity-50"
                >
                  {saving ? <Loader2 className="w-3 h-3 animate-spin" /> : <Save className="w-3 h-3" />}
                  Save
                </button>
                <button
                  type="button"
                  onClick={closeEditAi}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded border border-border text-muted-foreground text-sm hover:bg-muted/30"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Delete confirmation modal */}
      {deleteConfirmSource && (
        <>
          <div className="fixed inset-0 bg-black/50 z-50" onClick={() => setDeleteConfirmSource(null)} aria-hidden />
          <div
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
            role="dialog"
            aria-modal="true"
            aria-labelledby="delete-title"
          >
            <div className="bg-card border border-border rounded-xl shadow-xl max-w-md w-full p-6">
              <h2 id="delete-title" className="text-lg font-semibold text-foreground mb-2">
                Remove {deleteConfirmSource.name} integration?
              </h2>
              <p className="text-sm text-muted-foreground mb-6">
                This will delete all saved credentials for {deleteConfirmSource.name}. KESTREL will stop pulling
                alerts from this source. This cannot be undone.
              </p>
              <div className="flex gap-2 justify-end">
                <button
                  type="button"
                  onClick={() => setDeleteConfirmSource(null)}
                  className="px-3 py-1.5 rounded-lg border border-border bg-background text-foreground text-sm hover:bg-muted/50"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={() => deleteSource(deleteConfirmSource)}
                  className="px-3 py-1.5 rounded-lg bg-red-600 text-white text-sm hover:bg-red-700"
                >
                  Remove Integration
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* AI delete confirmation modal */}
      {deleteConfirmAi && (
        <>
          <div className="fixed inset-0 bg-black/50 z-50" onClick={() => setDeleteConfirmAi(null)} aria-hidden />
          <div
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
            role="dialog"
            aria-modal="true"
            aria-labelledby="delete-ai-title"
          >
            <div className="bg-card border border-border rounded-xl shadow-xl max-w-md w-full p-6">
              <h2 id="delete-ai-title" className="text-lg font-semibold text-foreground mb-2">
                Remove {deleteConfirmAi.name} configuration?
              </h2>
              <p className="text-sm text-muted-foreground mb-6">
                This will delete all saved credentials for {deleteConfirmAi.name}. AI features using this provider
                will stop working. This cannot be undone.
              </p>
              <div className="flex gap-2 justify-end">
                <button
                  type="button"
                  onClick={() => setDeleteConfirmAi(null)}
                  className="px-3 py-1.5 rounded-lg border border-border bg-background text-foreground text-sm hover:bg-muted/50"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={() => deleteAi(deleteConfirmAi)}
                  className="px-3 py-1.5 rounded-lg bg-red-600 text-white text-sm hover:bg-red-700"
                >
                  Remove Configuration
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      <SetupGuideModal
        sourceId={setupGuideSourceId}
        onClose={() => setSetupGuideSourceId(null)}
      />
    </div>
  )
}

