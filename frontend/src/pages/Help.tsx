import { useState } from 'react'
import {
  BookOpen, Terminal, Users, AlertTriangle, Keyboard,
  Copy, CheckCircle2, ChevronRight,
} from 'lucide-react'
import { cn } from '@/utils/cn'
import { toast } from 'sonner'

type Tab = 'guide' | 'api' | 'roles' | 'severity' | 'shortcuts'

const TABS: Array<{ id: Tab; label: string; icon: React.ElementType }> = [
  { id: 'guide', label: 'Getting Started', icon: BookOpen },
  { id: 'api', label: 'Ingest API', icon: Terminal },
  { id: 'roles', label: 'Roles & Permissions', icon: Users },
  { id: 'severity', label: 'Severity Guide', icon: AlertTriangle },
  { id: 'shortcuts', label: 'Keyboard Shortcuts', icon: Keyboard },
]

// ── Reusable primitives ────────────────────────────────────────────────────────
function SectionHeading({ children }: { children: React.ReactNode }) {
  return <h2 className="text-base font-semibold text-soc-text mb-3">{children}</h2>
}

function SubHeading({ children }: { children: React.ReactNode }) {
  return <h3 className="text-sm font-semibold text-soc-text mt-5 mb-2">{children}</h3>
}

function InfoBox({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-4 text-sm text-soc-muted">
      {children}
    </div>
  )
}

function CodeBlock({ code, language = 'bash' }: { code: string; language?: string }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true)
      toast.success('Copied to clipboard')
      setTimeout(() => setCopied(false), 2000)
    })
  }
  return (
    <div className="relative rounded-lg border border-soc-border bg-soc-bg overflow-hidden">
      <div className="flex items-center justify-between px-4 py-1.5 border-b border-soc-border bg-soc-border/30">
        <span className="text-xs text-soc-muted font-mono">{language}</span>
        <button
          type="button"
          onClick={copy}
          className="inline-flex items-center gap-1 text-xs text-soc-muted hover:text-soc-text transition-colors"
        >
          {copied ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="overflow-x-auto p-4 text-xs text-soc-text leading-relaxed">
        <code>{code}</code>
      </pre>
    </div>
  )
}

function StepCard({ step, title, children }: { step: number; title: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-4">
      <div className="shrink-0 w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center text-white text-sm font-bold">
        {step}
      </div>
      <div className="flex-1 pb-6 border-b border-soc-border last:border-0 last:pb-0">
        <p className="font-medium text-soc-text mb-1">{title}</p>
        <div className="text-sm text-soc-muted space-y-1">{children}</div>
      </div>
    </div>
  )
}

function Table({ headers, rows }: { headers: string[]; rows: (string | React.ReactNode)[][] }) {
  return (
    <div className="rounded-lg border border-soc-border overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-soc-border bg-soc-border/20">
            {headers.map((h) => (
              <th key={h} className="text-left px-4 py-2.5 text-xs font-medium text-soc-muted uppercase tracking-wide">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-soc-border">
          {rows.map((row, ri) => (
            <tr key={ri} className="hover:bg-soc-border/20">
              {row.map((cell, ci) => (
                <td key={ci} className="px-4 py-2.5 text-soc-text">
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ── Tab: Getting Started ──────────────────────────────────────────────────────
function GettingStarted() {
  return (
    <div className="space-y-6 max-w-2xl">
      <InfoBox>
        KESTREL is an AI-assisted SOC platform. It ingests alerts from multiple log
        sources, maps them to MITRE ATT&CK, scores risk, and uses AI to help analysts
        triage faster.
      </InfoBox>

      <div className="space-y-0">
        <SectionHeading>Quick start guide</SectionHeading>
        <div className="space-y-0">
          <StepCard step={1} title="Complete the setup wizard">
            <p>
              On first launch you'll be directed to <strong className="text-soc-text">/setup</strong>.
              Create your admin account (password must be 12+ characters, mixed case, numbers, and symbols).
            </p>
          </StepCard>
          <StepCard step={2} title="Connect a log source">
            <p>
              Go to <strong className="text-soc-text">Settings → Source Integrations</strong> and configure
              at least one source. Pull sources (Sentinel, GuardDuty, VirusTotal, AbuseIPDB) need API keys.
              Push sources (Suricata, Windows Event Log, Defender, Snort) send logs via the Ingest API.
            </p>
          </StepCard>
          <StepCard step={3} title="Ingest your first alert">
            <p>
              Use the <strong className="text-soc-text">Ingest API</strong> (see the Ingest API tab) or wait
              for the pull connector to sync. New alerts appear immediately on the Dashboard.
            </p>
          </StepCard>
          <StepCard step={4} title="Triage an alert">
            <p>
              Click any alert in <strong className="text-soc-text">Alerts</strong>. The Overview tab shows
              risk score, recommended actions, and affected assets. Run AI Analysis for a plain-English
              summary and remediation steps.
            </p>
          </StepCard>
          <StepCard step={5} title="Add analysts and set roles">
            <p>
              Admins can create additional users at <strong className="text-soc-text">Settings → Users</strong>.
              Choose <em>analyst</em> for front-line triage or <em>senior_analyst</em> to also run playbooks.
            </p>
          </StepCard>
          <StepCard step={6} title="Review coverage with Reports">
            <p>
              Go to <strong className="text-soc-text">Reports → Detection Coverage</strong> to see which
              MITRE ATT&CK techniques have no detections — your detection gaps. Use this to prioritise
              new rules or log sources.
            </p>
          </StepCard>
        </div>
      </div>

      <div>
        <SectionHeading>Navigation overview</SectionHeading>
        <div className="space-y-2 text-sm text-soc-muted">
          {[
            ['Dashboard', 'Live KPIs, volume trends, recent alerts, and active incidents.'],
            ['Alerts', 'Full paginated alert list with filtering by severity, status, source, and free text.'],
            ['Alert Detail', 'Tabs: Overview (risk), AI Analysis, Enrichment (IOCs, VT, AbuseIPDB), MITRE, Timeline, Raw Log.'],
            ['Incidents', 'Alerts grouped by correlation into incidents. Shows combined MITRE chain and recommended actions.'],
            ['MITRE Coverage', 'ATT&CK heatmap showing technique detection coverage across all 12 tactics.'],
            ['Sources', 'Status of all configured log sources (connected / push-ready / not configured).'],
            ['Threat Hunting', 'Free-form search and pivot across alerts. Save searches to localStorage.'],
            ['Reports', 'Executive KPI summary, per-tactic coverage, and analyst activity — all printable.'],
          ].map(([page, desc]) => (
            <div key={page} className="flex gap-3">
              <ChevronRight className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
              <span><strong className="text-soc-text">{page}</strong> — {desc}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Tab: Ingest API ───────────────────────────────────────────────────────────
function IngestAPI() {
  const curlExample = `curl -X POST https://your-kestrel-host/api/v1/ingest \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "source": "suricata",
    "events": [
      {
        "event_type": "alert",
        "timestamp": "2025-03-08T10:00:00Z",
        "src_ip": "10.0.0.5",
        "dest_ip": "192.168.1.100",
        "alert": {
          "signature": "ET MALWARE Suspicious User-Agent",
          "severity": 2,
          "category": "malware"
        }
      }
    ]
  }'`

  const windowsExample = `{
  "source": "windows_eventlog",
  "events": [
    {
      "EventID": 4625,
      "TimeCreated": "2025-03-08T10:00:00Z",
      "ComputerName": "WORKSTATION-01",
      "TargetUserName": "administrator",
      "IpAddress": "10.0.0.5",
      "LogonType": 3,
      "SubStatus": "0xC000006A"
    }
  ]
}`

  const genericExample = `{
  "source": "generic",
  "events": [
    {
      "title": "Suspicious PowerShell Execution",
      "severity": "High",
      "category": "execution",
      "source_ip": "10.0.0.5",
      "timestamp": "2025-03-08T10:00:00Z",
      "raw": { "command": "powershell -enc ..." }
    }
  ]
}`

  return (
    <div className="space-y-6 max-w-3xl">
      <InfoBox>
        All push sources send logs to a single <strong className="text-soc-text">POST /api/v1/ingest</strong> endpoint.
        Authenticate with an API key generated in Settings → Source Integrations or via the admin panel.
      </InfoBox>

      <div>
        <SectionHeading>Endpoint</SectionHeading>
        <CodeBlock language="http" code="POST /api/v1/ingest" />
      </div>

      <div>
        <SectionHeading>Authentication</SectionHeading>
        <p className="text-sm text-soc-muted mb-3">
          Pass the API key in the <code className="text-blue-400">Authorization</code> header as a Bearer token,
          or in the <code className="text-blue-400">X-API-Key</code> header.
        </p>
        <CodeBlock language="http" code={`Authorization: Bearer soc_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n# or\nX-API-Key: soc_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`} />
      </div>

      <div>
        <SectionHeading>Request schema</SectionHeading>
        <Table
          headers={['Field', 'Type', 'Required', 'Description']}
          rows={[
            ['source', 'string', '✓', 'Source identifier (see supported sources below)'],
            ['events', 'array', '✓', 'Array of raw event objects (source-specific format)'],
          ]}
        />
      </div>

      <div>
        <SectionHeading>Supported source names</SectionHeading>
        <Table
          headers={['Source name', 'Description']}
          rows={[
            ['suricata', 'Suricata EVE JSON — alert, dns, http, tls event types'],
            ['windows_eventlog', 'Windows Security Event Log records (EventID, TimeCreated, etc.)'],
            ['defender', 'Microsoft Defender for Endpoint alerts'],
            ['aws_cloudtrail', 'AWS CloudTrail event records'],
            ['syslog', 'Generic syslog messages'],
            ['generic', 'Any JSON event — KESTREL will parse title, severity, category'],
          ]}
        />
      </div>

      <div>
        <SectionHeading>Examples</SectionHeading>
        <SubHeading>Suricata (curl)</SubHeading>
        <CodeBlock language="bash" code={curlExample} />
        <SubHeading>Windows Event Log</SubHeading>
        <CodeBlock language="json" code={windowsExample} />
        <SubHeading>Generic / custom source</SubHeading>
        <CodeBlock language="json" code={genericExample} />
      </div>

      <div>
        <SectionHeading>Response</SectionHeading>
        <CodeBlock language="json" code={`{
  "status": "ok",
  "ingested": 1,
  "alerts": ["alert-uuid-here"],
  "errors": []
}`} />
        <p className="text-sm text-soc-muted mt-3">
          Each ingested event is parsed, scored by the decision engine, MITRE-mapped, and queued for
          IOC enrichment in the background. The alert appears on the Dashboard within seconds.
        </p>
      </div>
    </div>
  )
}

// ── Tab: Roles & Permissions ─────────────────────────────────────────────────
function RolesTab() {
  const PERMISSIONS = [
    { perm: 'View Dashboard & KPIs', viewer: true, analyst: true, senior: true, admin: true },
    { perm: 'View Alerts', viewer: true, analyst: true, senior: true, admin: true },
    { perm: 'View Incidents', viewer: true, analyst: true, senior: true, admin: true },
    { perm: 'View MITRE Coverage', viewer: true, analyst: true, senior: true, admin: true },
    { perm: 'View Reports (Summary + Coverage)', viewer: true, analyst: true, senior: true, admin: true },
    { perm: 'Update Alert Status', viewer: false, analyst: true, senior: true, admin: true },
    { perm: 'Add Alert Comments', viewer: false, analyst: true, senior: true, admin: true },
    { perm: 'Assign Alerts', viewer: false, analyst: false, senior: true, admin: true },
    { perm: 'Run AI Analysis', viewer: false, analyst: true, senior: true, admin: true },
    { perm: 'View Sources', viewer: false, analyst: false, senior: true, admin: true },
    { perm: 'Run Decision Engine / Playbooks', viewer: false, analyst: false, senior: true, admin: true },
    { perm: 'Ingest Events (API)', viewer: false, analyst: true, senior: false, admin: true },
    { perm: 'View Analyst Activity (Reports)', viewer: false, analyst: false, senior: false, admin: true },
    { perm: 'Delete Alerts', viewer: false, analyst: false, senior: false, admin: true },
    { perm: 'Manage Sources & Settings', viewer: false, analyst: false, senior: false, admin: true },
    { perm: 'Create / Manage Users', viewer: false, analyst: false, senior: false, admin: true },
    { perm: 'View Audit Log', viewer: false, analyst: false, senior: false, admin: true },
    { perm: 'Generate API Keys', viewer: false, analyst: false, senior: false, admin: true },
  ]

  const Tick = ({ v }: { v: boolean }) => v
    ? <CheckCircle2 className="w-4 h-4 text-emerald-400" />
    : <span className="text-soc-muted/40">—</span>

  return (
    <div className="space-y-6 max-w-3xl">
      <InfoBox>
        Roles are assigned per user and enforced server-side on every request.
        The frontend hides unavailable UI elements, but the backend independently
        validates permissions on every API call.
      </InfoBox>
      <div className="rounded-lg border border-soc-border overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-soc-border bg-soc-border/20">
              <th className="text-left px-4 py-2.5 text-xs font-medium text-soc-muted uppercase tracking-wide">Permission</th>
              <th className="px-4 py-2.5 text-xs font-medium text-soc-muted uppercase tracking-wide text-center">Viewer</th>
              <th className="px-4 py-2.5 text-xs font-medium text-soc-muted uppercase tracking-wide text-center">Analyst</th>
              <th className="px-4 py-2.5 text-xs font-medium text-soc-muted uppercase tracking-wide text-center">Senior Analyst</th>
              <th className="px-4 py-2.5 text-xs font-medium text-soc-muted uppercase tracking-wide text-center">Admin</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-soc-border">
            {PERMISSIONS.map(({ perm, viewer, analyst, senior, admin }) => (
              <tr key={perm} className="hover:bg-soc-border/20">
                <td className="px-4 py-2.5 text-soc-text">{perm}</td>
                <td className="px-4 py-2.5 text-center"><Tick v={viewer} /></td>
                <td className="px-4 py-2.5 text-center"><Tick v={analyst} /></td>
                <td className="px-4 py-2.5 text-center"><Tick v={senior} /></td>
                <td className="px-4 py-2.5 text-center"><Tick v={admin} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div>
        <SectionHeading>Role descriptions</SectionHeading>
        <div className="space-y-3 text-sm text-soc-muted">
          <p><strong className="text-soc-text">Viewer</strong> — read-only access to Dashboard, Alerts, Incidents, and MITRE Coverage. Cannot change alert status, comment, or run AI.</p>
          <p><strong className="text-soc-text">Analyst</strong> — front-line triage. Can view and update alerts, run AI analysis, and ingest events via API.</p>
          <p><strong className="text-soc-text">Senior Analyst</strong> — all analyst permissions plus alert assignment, playbook execution, and source management.</p>
          <p><strong className="text-soc-text">Admin</strong> — full platform access including user management, settings, audit log, and API key generation.</p>
        </div>
      </div>
    </div>
  )
}

// ── Tab: Severity Guide ───────────────────────────────────────────────────────
function SeverityGuide() {
  const SEVERITY_DATA = [
    {
      level: 'Critical',
      score: '85–100',
      color: 'text-red-400',
      border: 'border-red-500/30 bg-red-500/5',
      dot: 'bg-red-500',
      meaning: 'Active compromise, confirmed threat, data exfiltration in progress.',
      sla: '15 minutes',
      examples: ['Ransomware execution detected', 'Credential dump successful', 'C2 beacon established'],
      actions: ['Isolate affected host immediately', 'Engage incident response', 'Preserve forensic evidence'],
    },
    {
      level: 'High',
      score: '65–84',
      color: 'text-orange-400',
      border: 'border-orange-500/30 bg-orange-500/5',
      dot: 'bg-orange-500',
      meaning: 'High-confidence threat indicator requiring urgent review.',
      sla: '1 hour',
      examples: ['Brute force successful login', 'Suspicious lateral movement', 'Privilege escalation attempt'],
      actions: ['Investigate correlated alerts', 'Check affected user accounts', 'Review endpoint logs'],
    },
    {
      level: 'Medium',
      score: '40–64',
      color: 'text-yellow-400',
      border: 'border-yellow-500/30 bg-yellow-500/5',
      dot: 'bg-yellow-500',
      meaning: 'Suspicious activity that warrants investigation but may be benign.',
      sla: '4 hours',
      examples: ['Multiple failed logins', 'Unusual network scan', 'Policy violation'],
      actions: ['Review user context', 'Check asset risk', 'Correlate with other alerts'],
    },
    {
      level: 'Low',
      score: '0–39',
      color: 'text-blue-400',
      border: 'border-blue-500/30 bg-blue-500/5',
      dot: 'bg-blue-500',
      meaning: 'Informational or low-confidence event. Low immediate risk.',
      sla: '24 hours',
      examples: ['Port scan from known scanner', 'Expired certificate warning', 'Auth from new device'],
      actions: ['Review during next shift', 'Update asset context', 'Mark as false positive if appropriate'],
    },
  ]

  return (
    <div className="space-y-4 max-w-2xl">
      <InfoBox>
        Risk scores are calculated by the decision engine based on source reliability,
        MITRE technique severity, IOC enrichment, and correlation with other alerts.
        Scores are normalised to 0–100.
      </InfoBox>
      {SEVERITY_DATA.map(({ level, score, color, border, dot, meaning, sla, examples, actions }) => (
        <div key={level} className={cn('rounded-lg border p-4 space-y-3', border)}>
          <div className="flex items-center gap-3">
            <div className={cn('w-3 h-3 rounded-full shrink-0', dot)} />
            <span className={cn('font-bold text-lg', color)}>{level}</span>
            <span className="text-soc-muted text-sm">Risk score {score}</span>
            <span className="ml-auto text-xs text-soc-muted border border-soc-border rounded px-2 py-0.5">SLA: {sla}</span>
          </div>
          <p className="text-sm text-soc-muted">{meaning}</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
            <div>
              <p className="text-xs font-medium text-soc-muted uppercase mb-1">Examples</p>
              <ul className="space-y-0.5 text-soc-muted">
                {examples.map((e) => <li key={e} className="flex gap-2"><span className="text-soc-muted/40">•</span>{e}</li>)}
              </ul>
            </div>
            <div>
              <p className="text-xs font-medium text-soc-muted uppercase mb-1">Recommended actions</p>
              <ul className="space-y-0.5 text-soc-muted">
                {actions.map((a) => <li key={a} className="flex gap-2"><span className="text-soc-muted/40">•</span>{a}</li>)}
              </ul>
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}

// ── Tab: Keyboard Shortcuts ───────────────────────────────────────────────────
function ShortcutsTab() {
  const SHORTCUTS = [
    { keys: ['/', 'Ctrl+K'], action: 'Focus search bar (TopBar)' },
    { keys: ['Enter'], action: 'Submit search / form' },
    { keys: ['Esc'], action: 'Close modal or side panel' },
    { keys: ['G', 'then', 'D'], action: 'Go to Dashboard' },
    { keys: ['G', 'then', 'A'], action: 'Go to Alerts' },
    { keys: ['G', 'then', 'I'], action: 'Go to Incidents' },
    { keys: ['G', 'then', 'M'], action: 'Go to MITRE Coverage' },
    { keys: ['G', 'then', 'H'], action: 'Go to Threat Hunting' },
    { keys: ['G', 'then', 'R'], action: 'Go to Reports' },
    { keys: ['G', 'then', '?'], action: 'Go to Help (this page)' },
  ]

  return (
    <div className="space-y-6 max-w-xl">
      <InfoBox>
        Most keyboard shortcuts work globally. Press <kbd className="text-xs bg-soc-border px-1.5 py-0.5 rounded">G</kbd> then
        the letter within 1 second to navigate.
      </InfoBox>
      <div className="rounded-lg border border-soc-border overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-soc-border bg-soc-border/20">
              <th className="text-left px-4 py-2.5 text-xs font-medium text-soc-muted uppercase tracking-wide">Shortcut</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-soc-muted uppercase tracking-wide">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-soc-border">
            {SHORTCUTS.map(({ keys, action }) => (
              <tr key={action} className="hover:bg-soc-border/20">
                <td className="px-4 py-2.5">
                  <div className="flex items-center gap-1 flex-wrap">
                    {keys.map((k) =>
                      k === 'then' ? (
                        <span key={k} className="text-soc-muted text-xs">then</span>
                      ) : (
                        <kbd
                          key={k}
                          className="text-xs font-mono bg-soc-border border border-soc-border/80 text-soc-text px-1.5 py-0.5 rounded shadow-sm"
                        >
                          {k}
                        </kbd>
                      )
                    )}
                  </div>
                </td>
                <td className="px-4 py-2.5 text-soc-muted">{action}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div>
        <SectionHeading>Alert detail tabs</SectionHeading>
        <p className="text-sm text-soc-muted mb-3">
          On an alert detail page, click a tab or use keyboard navigation (Tab key) to switch between:
        </p>
        <Table
          headers={['Tab', 'Content']}
          rows={[
            ['Overview', 'Risk score, recommended actions, affected assets, decision engine explanation'],
            ['AI Analysis', 'Plain-English summary, key facts, remediation steps, next actions'],
            ['Enrichment', 'IOC observables, VirusTotal results, AbuseIPDB scores, feed matches'],
            ['MITRE', 'Mapped ATT&CK techniques and tactics'],
            ['Timeline', 'Chronological audit history — status changes, comments, decisions'],
            ['Raw Log', 'Original event payload as JSON'],
          ]}
        />
      </div>
    </div>
  )
}

// ── Main Help page ────────────────────────────────────────────────────────────
export function Help() {
  const [tab, setTab] = useState<Tab>('guide')

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-soc-text">Help & Documentation</h1>
        <p className="text-sm text-soc-muted mt-0.5">Platform guide, API reference, and role information</p>
      </div>

      {/* Tab nav */}
      <div className="border-b border-soc-border">
        <nav className="flex flex-wrap gap-1">
          {TABS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              type="button"
              onClick={() => setTab(id)}
              className={cn(
                'flex items-center gap-2 py-2.5 px-3 text-sm font-medium border-b-2 transition-colors whitespace-nowrap',
                tab === id
                  ? 'border-blue-500 text-soc-text'
                  : 'border-transparent text-soc-muted hover:text-soc-text'
              )}
            >
              <Icon className="w-4 h-4" />
              {label}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab content */}
      <div>
        {tab === 'guide' && <GettingStarted />}
        {tab === 'api' && <IngestAPI />}
        {tab === 'roles' && <RolesTab />}
        {tab === 'severity' && <SeverityGuide />}
        {tab === 'shortcuts' && <ShortcutsTab />}
      </div>
    </div>
  )
}
