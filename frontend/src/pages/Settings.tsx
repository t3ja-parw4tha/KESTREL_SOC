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
        <label className="block text-xs text-soc-muted mb-1">{label}</label>
        <div className="relative">
          <input
            type={inputType}
            value={form[key] ?? ''}
            onChange={(e) => setForm((prev) => ({ ...prev, [key]: e.target.value }))}
            placeholder={placeholder}
            className="w-full px-3 py-2 rounded border border-soc-border bg-soc-bg text-soc-text text-sm pr-10 focus:outline-none focus:border-blue-500"
          />
          {sensitive && (
            <button
              type="button"
              onClick={() => setShowSecrets((prev) => ({ ...prev, [key]: !prev[key] }))}
              className="absolute right-2 top-2.5 text-soc-muted hover:text-soc-text"
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
      <div className="rounded-lg border border-soc-border bg-soc-surface p-5 space-y-4">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold text-soc-text">{title}</h3>
            {configuredKey && (
              <span
                className={cn(
                  'text-xs px-2 py-0.5 rounded-full',
                  isConfigured ? 'bg-green-500/10 text-green-400 border border-green-500/20' : 'bg-soc-border text-soc-muted'
                )}
              >
                {isConfigured ? 'Configured' : 'Not configured'}
              </span>
            )}
          </div>
          <p className="text-xs text-soc-muted mt-0.5">{description}</p>
        </div>
        <div className="space-y-3">{fields}</div>
        <div className="flex items-center gap-2 pt-2">
          <button
            type="button"
            onClick={() => save(saveKeys)}
            disabled={saving}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-blue-600 text-white text-sm hover:bg-blue-700 disabled:opacity-50"
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
      <div className="rounded-lg border border-soc-border bg-soc-surface p-6">
        <h1 className="text-lg font-semibold text-soc-text mb-2">Settings</h1>
        <p className="text-sm text-soc-muted">Only administrators can view and edit platform settings.</p>
      </div>
    )
  }

  const editingSource = editingSourceId ? SOURCES.find((s) => s.id === editingSourceId) : null
  const editingAi = editingAiId ? AI_PROVIDERS.find((a) => a.id === editingAiId) : null

  return (
    <div className="space-y-6 max-w-3xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-soc-text">Settings</h1>
          <p className="text-sm text-soc-muted mt-0.5">Configuration saved locally — never pushed to repository</p>
        </div>
        {saveMsg && (
          <span className="text-green-400 text-sm flex items-center gap-1">
            <Save className="w-4 h-4" /> {saveMsg}
          </span>
        )}
      </div>

      <div className="flex gap-1 border-b border-soc-border">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            type="button"
            onClick={() => setTab(id)}
            className={cn(
              'flex items-center gap-2 px-4 py-2.5 text-sm border-b-2 transition-colors',
              tab === id ? 'border-blue-500 text-soc-text' : 'border-transparent text-soc-muted hover:text-soc-text'
            )}
          >
            <Icon className="w-4 h-4" />
            {label}
          </button>
        ))}
      </div>

      {tab === 'ai' && (
        <div className="space-y-3">
          {AI_PROVIDERS.map((def) => {
            const status = aiStatus(def)
            const isConfigured = status === 'configured'
            return (
              <div
                key={def.id}
                className="rounded-lg border border-soc-border bg-soc-surface p-4 flex items-center justify-between gap-4"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2 mb-1">
                    <h3 className="text-sm font-semibold text-soc-text">{def.name}</h3>
                    <span className="text-xs px-2 py-0.5 rounded bg-soc-border text-soc-muted">AI</span>
                    <span
                      className={cn(
                        'text-xs px-2 py-0.5 rounded',
                        status === 'configured' && 'bg-green-500/10 text-green-400 border border-green-500/20',
                        status === 'not_configured' && 'bg-soc-border text-soc-muted'
                      )}
                    >
                      {status === 'configured' ? 'Configured' : 'Not Configured'}
                    </span>
                  </div>
                  <p className="text-xs text-soc-muted">{def.description}</p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    type="button"
                    onClick={() => openEditAi(def)}
                    className="p-2 rounded border border-soc-border text-soc-muted hover:text-soc-text hover:bg-soc-border/30"
                    aria-label={`Edit ${def.name}`}
                  >
                    <Pencil className="w-4 h-4" />
                  </button>
                  {isConfigured && (
                    <button
                      type="button"
                      onClick={() => setDeleteConfirmAi(def)}
                      className="p-2 rounded border border-soc-border text-soc-muted hover:text-red-400 hover:bg-red-500/10"
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

      {tab === 'sources' && (
        <div className="space-y-3">
          {SOURCES.map((def) => {
            const status = sourceStatus(def)
            const isConfigured = status === 'configured'
            const isPushOnly = PUSH_SOURCE_IDS.includes(def.id)
            return (
              <div
                key={def.id}
                className="rounded-lg border border-soc-border bg-soc-surface p-4 flex items-center justify-between gap-4"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2 mb-1">
                    <h3 className="text-sm font-semibold text-soc-text">{def.name}</h3>
                    <span className="text-xs px-2 py-0.5 rounded bg-soc-border text-soc-muted">{def.type}</span>
                    <span
                      className={cn(
                        'text-xs px-2 py-0.5 rounded',
                        (status === 'configured' || status === 'active') && 'bg-green-500/10 text-green-400 border border-green-500/20',
                        status === 'push_ready' && 'bg-blue-500/10 text-blue-400 border border-blue-500/20',
                        status === 'not_configured' && 'bg-soc-border text-soc-muted'
                      )}
                    >
                      {status === 'configured' ? 'Configured' : status === 'active' ? 'Active' : status === 'push_ready' ? 'Push Ready' : 'Not Configured'}
                    </span>
                  </div>
                  <p className="text-xs text-soc-muted">{def.description}</p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {isPushOnly && (
                    <button
                      type="button"
                      onClick={() => setSetupGuideSourceId(def.id)}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded border border-soc-border text-soc-muted hover:text-soc-text hover:bg-soc-border/30 text-sm"
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
                      className="p-2 rounded border border-soc-border text-soc-muted hover:text-soc-text hover:bg-soc-border/30"
                      aria-label={`Edit ${def.name}`}
                    >
                      <Pencil className="w-4 h-4" />
                    </button>
                  )}
                  {isConfigured && def.keys.length > 0 && (
                    <button
                      type="button"
                      onClick={() => setDeleteConfirmSource(def)}
                      className="p-2 rounded border border-soc-border text-soc-muted hover:text-red-400 hover:bg-red-500/10"
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
        <div className="space-y-4">
          {sectionCard(
            'Slack',
            'Send critical alert notifications to a Slack channel',
            'slack',
            [field('SLACK_WEBHOOK_URL', 'Webhook URL', 'https://hooks.slack.com/services/...', true)],
            ['SLACK_WEBHOOK_URL']
          )}
          {sectionCard(
            'Email Alerts',
            'Send email notifications for critical alerts',
            null,
            [field('ALERT_EMAIL', 'Alert Email Address', 'soc@yourcompany.com')],
            ['ALERT_EMAIL']
          )}
        </div>
      )}

      {tab === 'users' && (
        <div className="rounded-lg border border-soc-border bg-soc-surface p-5">
          <h3 className="text-sm font-semibold text-soc-text mb-1">User Management</h3>
          <p className="text-xs text-soc-muted mb-4">Create and manage analyst accounts with role-based access</p>
          <a
            href="/app/users"
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded bg-blue-600 text-white text-sm hover:bg-blue-700"
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
          <div className="fixed inset-y-0 right-0 w-full max-w-md bg-soc-surface border-l border-soc-border shadow-xl z-50 overflow-auto">
            <div className="p-4">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold text-soc-text">Configure {editingSource.name}</h2>
                <button type="button" onClick={closeEdit} className="p-2 text-soc-muted hover:text-soc-text">
                  <X className="w-5 h-5" />
                </button>
              </div>
              {editingSource.keys.length === 0 ? (
                <p className="text-sm text-soc-muted">No configuration options for this source yet.</p>
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
                        <label className="block text-xs text-soc-muted mb-1 flex items-center gap-1.5">
                          {label}
                          {showLock && <Lock className="w-3 h-3 text-soc-muted" aria-hidden />}
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
                              'w-full px-3 py-2 rounded border bg-soc-bg text-soc-text text-sm pr-10 focus:outline-none focus:border-blue-500',
                              showRequiredError ? 'border-red-500' : 'border-soc-border'
                            )}
                          />
                          {isSensitive && (
                            <button
                              type="button"
                              onClick={() => setShowSecrets((prev) => ({ ...prev, [key]: !prev[key] }))}
                              className="absolute right-2 top-2.5 text-soc-muted hover:text-soc-text"
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
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded border border-soc-border text-soc-text text-sm hover:bg-soc-border/30 disabled:opacity-50"
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
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded border border-soc-border text-soc-muted text-sm hover:bg-soc-border/30"
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
          <div className="fixed inset-y-0 right-0 w-full max-w-md bg-soc-surface border-l border-soc-border shadow-xl z-50 overflow-auto">
            <div className="p-4">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold text-soc-text">Configure {editingAi.name}</h2>
                <button type="button" onClick={closeEditAi} className="p-2 text-soc-muted hover:text-soc-text">
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
                      <label className="block text-xs text-soc-muted mb-1 flex items-center gap-1.5">
                        {label}
                        {showLock && <Lock className="w-3 h-3 text-soc-muted" aria-hidden />}
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
                            'w-full px-3 py-2 rounded border bg-soc-bg text-soc-text text-sm pr-10 focus:outline-none focus:border-blue-500',
                            showRequiredError ? 'border-red-500' : 'border-soc-border'
                          )}
                        />
                        {isSensitive && (
                          <button
                            type="button"
                            onClick={() => setShowSecrets((prev) => ({ ...prev, [key]: !prev[key] }))}
                            className="absolute right-2 top-2.5 text-soc-muted hover:text-soc-text"
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
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded border border-soc-border text-soc-muted text-sm hover:bg-soc-border/30"
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
            <div className="bg-soc-surface border border-soc-border rounded-xl shadow-xl max-w-md w-full p-6">
              <h2 id="delete-title" className="text-lg font-semibold text-soc-text mb-2">
                Remove {deleteConfirmSource.name} integration?
              </h2>
              <p className="text-sm text-soc-muted mb-6">
                This will delete all saved credentials for {deleteConfirmSource.name}. KESTREL will stop pulling
                alerts from this source. This cannot be undone.
              </p>
              <div className="flex gap-2 justify-end">
                <button
                  type="button"
                  onClick={() => setDeleteConfirmSource(null)}
                  className="px-3 py-1.5 rounded-lg border border-soc-border bg-soc-bg text-soc-text text-sm hover:bg-soc-border/50"
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
            <div className="bg-soc-surface border border-soc-border rounded-xl shadow-xl max-w-md w-full p-6">
              <h2 id="delete-ai-title" className="text-lg font-semibold text-soc-text mb-2">
                Remove {deleteConfirmAi.name} configuration?
              </h2>
              <p className="text-sm text-soc-muted mb-6">
                This will delete all saved credentials for {deleteConfirmAi.name}. AI features using this provider
                will stop working. This cannot be undone.
              </p>
              <div className="flex gap-2 justify-end">
                <button
                  type="button"
                  onClick={() => setDeleteConfirmAi(null)}
                  className="px-3 py-1.5 rounded-lg border border-soc-border bg-soc-bg text-soc-text text-sm hover:bg-soc-border/50"
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
