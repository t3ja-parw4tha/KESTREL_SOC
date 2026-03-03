import { useState, useEffect } from 'react'
import { useAuth } from '@/security/AuthContext'
import {
  Sparkles,
  Database,
  Bell,
  Users,
  Eye,
  EyeOff,
  CheckCircle2,
  XCircle,
  Loader2,
  Save,
} from 'lucide-react'

type Tab = 'ai' | 'sources' | 'notifications' | 'users'

interface SettingsData {
  settings: Record<string, string>
  configured: Record<string, boolean>
}

export function Settings() {
  const { user } = useAuth()
  const [tab, setTab] = useState<Tab>('ai')
  const [data, setData] = useState<SettingsData | null>(null)
  const [form, setForm] = useState<Record<string, string>>({})
  const [showSecrets, setShowSecrets] = useState<Record<string, boolean>>({})
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<Record<string, { status: string; message: string }>>({})
  const [saveMsg, setSaveMsg] = useState('')

  useEffect(() => {
    loadSettings()
  }, [])

  const loadSettings = async () => {
    const res = await fetch('/api/v1/settings', {
      headers: {
        Authorization: `Bearer ${sessionStorage.getItem('kestrel_token')}`,
      },
    })
    if (res.ok) {
      const d = await res.json()
      setData(d)
      setForm(d.settings)
    }
  }

  const save = async (keys: string[]) => {
    setSaving(true)
    setSaveMsg('')
    const subset = Object.fromEntries(
      keys
        .filter((k) => (form[k] ?? '').trim() !== '')
        .map((k) => [k, form[k]])
    )
    if (Object.keys(subset).length === 0) {
      setSaving(false)
      setSaveMsg('Nothing to save')
      setTimeout(() => setSaveMsg(''), 2000)
      return
    }
    const res = await fetch('/api/v1/settings', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${sessionStorage.getItem('kestrel_token')}`,
      },
      body: JSON.stringify({ settings: subset }),
    })
    setSaving(false)
    if (res.ok) {
      setSaveMsg('Saved successfully')
      loadSettings()
      setTimeout(() => setSaveMsg(''), 3000)
    } else {
      setSaveMsg('Save failed')
    }
  }

  const testConn = async (source: string) => {
    setTesting(source)
    const res = await fetch(`/api/v1/settings/test/${source}`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${sessionStorage.getItem('kestrel_token')}`,
      },
    })
    const d = await res.json()
    setTestResult((prev) => ({ ...prev, [source]: d }))
    setTesting(null)
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
            onChange={(e) =>
              setForm((prev) => ({
                ...prev,
                [key]: e.target.value,
              }))
            }
            placeholder={placeholder}
            className="w-full px-3 py-2 rounded border border-soc-border 
                       bg-soc-bg text-soc-text text-sm pr-10
                       focus:outline-none focus:border-blue-500"
          />
          {sensitive && (
            <button
              type="button"
              onClick={() =>
                setShowSecrets((prev) => ({
                  ...prev,
                  [key]: !prev[key],
                }))
              }
              className="absolute right-2 top-2.5 
                         text-soc-muted hover:text-soc-text"
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
    testSource?: string
  ) => {
    const isConfigured = configuredKey ? data?.configured[configuredKey] : false
    return (
      <div className="rounded-lg border border-soc-border bg-soc-surface p-5 space-y-4">
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-soc-text">{title}</h3>
              {configuredKey && (
                <span
                  className={`text-xs px-2 py-0.5 rounded-full
                  ${
                    isConfigured
                      ? 'bg-green-500/10 text-green-400 border border-green-500/20'
                      : 'bg-soc-border text-soc-muted'
                  }`}
                >
                  {isConfigured ? 'Configured' : 'Not configured'}
                </span>
              )}
            </div>
            <p className="text-xs text-soc-muted mt-0.5">{description}</p>
          </div>
        </div>

        <div className="space-y-3">{fields}</div>

        <div className="flex items-center gap-2 pt-2">
          <button
            type="button"
            onClick={() => save(saveKeys)}
            disabled={saving}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 
                       rounded bg-blue-600 text-white text-sm 
                       hover:bg-blue-700 disabled:opacity-50"
          >
            {saving ? <Loader2 className="w-3 h-3 animate-spin" /> : <Save className="w-3 h-3" />}
            Save
          </button>

          {testSource && (
            <button
              type="button"
              onClick={() => testConn(testSource)}
              disabled={testing === testSource}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 
                         rounded border border-soc-border text-soc-muted 
                         text-sm hover:text-soc-text disabled:opacity-50"
            >
              {testing === testSource ? <Loader2 className="w-3 h-3 animate-spin" /> : null}
              Test Connection
            </button>
          )}

          {testSource && testResult[testSource] && (
            <span
              className={`text-xs flex items-center gap-1
              ${
                testResult[testSource].status === 'ok'
                  ? 'text-green-400'
                  : 'text-red-400'
              }`}
            >
              {testResult[testSource].status === 'ok' ? (
                <CheckCircle2 className="w-3 h-3" />
              ) : (
                <XCircle className="w-3 h-3" />
              )}
              {testResult[testSource].message}
            </span>
          )}
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
        <p className="text-sm text-soc-muted">
          Only administrators can view and edit platform settings.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-soc-text">Settings</h1>
          <p className="text-sm text-soc-muted mt-0.5">
            Configuration saved locally — never pushed to repository
          </p>
        </div>
        {saveMsg && (
          <span className="text-green-400 text-sm flex items-center gap-1">
            <CheckCircle2 className="w-4 h-4" /> {saveMsg}
          </span>
        )}
      </div>

      <div className="flex gap-1 border-b border-soc-border">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            type="button"
            onClick={() => setTab(id)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm 
                        border-b-2 transition-colors
              ${
                tab === id
                  ? 'border-blue-500 text-soc-text'
                  : 'border-transparent text-soc-muted hover:text-soc-text'
              }`}
          >
            <Icon className="w-4 h-4" />
            {label}
          </button>
        ))}
      </div>

      {tab === 'ai' && (
        <div className="space-y-4">
          {sectionCard(
            'OpenAI',
            'Powers alert triage, summarization, and remediation suggestions',
            'ai',
            [field('AI_PROVIDER', 'Provider', 'openai', false), field('OPENAI_API_KEY', 'API Key', 'sk-...', true)],
            ['AI_PROVIDER', 'OPENAI_API_KEY']
          )}
          {sectionCard(
            'Anthropic Claude',
            'Alternative AI provider for alert analysis',
            null,
            [field('ANTHROPIC_API_KEY', 'API Key', 'sk-ant-...', true)],
            ['ANTHROPIC_API_KEY']
          )}
          {sectionCard(
            'Azure OpenAI',
            'Enterprise Azure OpenAI deployment',
            null,
            [
              field('AZURE_OPENAI_API_KEY', 'API Key', 'your-key', true),
              field('AZURE_OPENAI_ENDPOINT', 'Endpoint', 'https://your-resource.openai.azure.com'),
            ],
            ['AZURE_OPENAI_API_KEY', 'AZURE_OPENAI_ENDPOINT']
          )}
        </div>
      )}

      {tab === 'sources' && (
        <div className="space-y-4">
          {sectionCard(
            'Microsoft Sentinel',
            'Pull alerts from Azure Log Analytics via KQL',
            'sentinel',
            [
              field('AZURE_TENANT_ID', 'Tenant ID', 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'),
              field('AZURE_CLIENT_ID', 'Client ID', 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'),
              field('AZURE_CLIENT_SECRET', 'Client Secret', 'your-secret', true),
              field('LOGANALYTICS_WORKSPACE_ID', 'Workspace ID', 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'),
            ],
            ['AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'LOGANALYTICS_WORKSPACE_ID'],
            'sentinel'
          )}
          {sectionCard(
            'AWS GuardDuty',
            'Pull threat findings from AWS GuardDuty',
            'guardduty',
            [
              field('AWS_ACCESS_KEY_ID', 'Access Key ID', 'AKIAIOSFODNN7EXAMPLE'),
              field('AWS_SECRET_ACCESS_KEY', 'Secret Access Key', 'your-secret', true),
              field('AWS_REGION', 'Region', 'us-east-1'),
            ],
            ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_REGION'],
            'guardduty'
          )}
          {sectionCard(
            'VirusTotal',
            'IP and file hash reputation enrichment',
            'virustotal',
            [field('VIRUSTOTAL_API_KEY', 'API Key', 'your-vt-api-key', true)],
            ['VIRUSTOTAL_API_KEY'],
            'virustotal'
          )}
          {sectionCard(
            'AbuseIPDB',
            'IP abuse confidence scoring and geo lookup',
            'abuseipdb',
            [field('ABUSEIPDB_API_KEY', 'API Key', 'your-abuseipdb-key', true)],
            ['ABUSEIPDB_API_KEY'],
            'abuseipdb'
          )}
          {sectionCard(
            'Suricata / Snort',
            'Network IDS/IPS — push logs via ingest API or file path',
            null,
            [field('SURICATA_EVE_PATH', 'EVE JSON Path', '/var/log/suricata/eve.json')],
            ['SURICATA_EVE_PATH']
          )}
        </div>
      )}

      {tab === 'notifications' && (
        <div className="space-y-4">
          {sectionCard(
            'Slack',
            'Send critical alert notifications to a Slack channel',
            'slack',
            [field('SLACK_WEBHOOK_URL', 'Webhook URL', 'https://hooks.slack.com/services/...', true)],
            ['SLACK_WEBHOOK_URL'],
            'slack'
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
          <p className="text-xs text-soc-muted mb-4">
            Create and manage analyst accounts with role-based access
          </p>

          <a
            href="/users"
            className="inline-flex items-center gap-2 px-3 py-1.5 
                       rounded bg-blue-600 text-white text-sm 
                       hover:bg-blue-700"
          >
            <Users className="w-4 h-4" />
            Manage Users
          </a>
        </div>
      )}
    </div>
  )
}

