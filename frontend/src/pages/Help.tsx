import { useState, useMemo, useEffect, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  BookOpen, Terminal, Users, AlertTriangle, Keyboard,
  Copy, CheckCircle2, ChevronRight, Plug, Search, X, Sparkles, Shield,
} from 'lucide-react'
import { cn } from '@/utils/cn'
import { toast } from 'sonner'
import { SOURCE_CATALOG, type SourceType } from '@/data/sourcesCatalog'
import { SourceLogo } from '@/components/sources/SourceLogo'
import { SourceDocPanel } from '@/components/sources/SourceDocPanel'

type Tab = 'soc' | 'guide' | 'ai' | 'api' | 'roles' | 'severity' | 'shortcuts' | 'integrations'

const TABS: Array<{ id: Tab; label: string; icon: React.ElementType }> = [
  { id: 'soc', label: 'SOC Sections', icon: Shield },
  { id: 'guide', label: 'Getting Started', icon: BookOpen },
  { id: 'integrations', label: 'Integrations', icon: Plug },
  { id: 'ai', label: 'AI Providers', icon: Sparkles },
  { id: 'api', label: 'Ingest API', icon: Terminal },
  { id: 'roles', label: 'Roles & Permissions', icon: Users },
  { id: 'severity', label: 'Severity Guide', icon: AlertTriangle },
  { id: 'shortcuts', label: 'Keyboard Shortcuts', icon: Keyboard },
]

// ── Type badge colors (mirrors SourceDocPanel) ─────────────────────────────────
const TYPE_COLORS: Record<SourceType, string> = {
  SIEM:          'bg-violet-500/15 text-violet-400 border-violet-500/25',
  Cloud:         'bg-sky-500/15 text-sky-400 border-sky-500/25',
  EDR:           'bg-red-500/15 text-red-400 border-red-500/25',
  Identity:      'bg-blue-500/15 text-blue-400 border-blue-500/25',
  Network:       'bg-cyan-500/15 text-cyan-400 border-cyan-500/25',
  Email:         'bg-emerald-500/15 text-emerald-400 border-emerald-500/25',
  Enrichment:    'bg-amber-500/15 text-amber-400 border-amber-500/25',
  'IDS/IPS':     'bg-orange-500/15 text-orange-400 border-orange-500/25',
  OS:            'bg-slate-500/15 text-slate-400 border-slate-500/25',
  Vulnerability: 'bg-rose-500/15 text-rose-400 border-rose-500/25',
}

// ── Reusable primitives ────────────────────────────────────────────────────────
function SectionHeading({ children }: { children: React.ReactNode }) {
  return <h2 className="text-base font-semibold text-foreground mb-3">{children}</h2>
}

function SubHeading({ children }: { children: React.ReactNode }) {
  return <h3 className="text-sm font-semibold text-foreground mt-5 mb-2">{children}</h3>
}

function InfoBox({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-4 text-sm text-muted-foreground">
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
    <div className="relative rounded-lg border border-border bg-background overflow-hidden">
      <div className="flex items-center justify-between px-4 py-1.5 border-b border-border bg-muted/30">
        <span className="text-xs text-muted-foreground font-mono">{language}</span>
        <button
          type="button"
          onClick={copy}
          className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
        >
          {copied ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="overflow-x-auto p-4 text-xs text-foreground leading-relaxed">
        <code>{code}</code>
      </pre>
    </div>
  )
}

function StepCard({ step, title, children }: { step: number; title: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-4">
      <div className="shrink-0 w-8 h-8 rounded-full gradient-primary flex items-center justify-center text-white text-sm font-bold">
        {step}
      </div>
      <div className="flex-1 pb-6 border-b border-border last:border-0 last:pb-0">
        <p className="font-medium text-foreground mb-1">{title}</p>
        <div className="text-sm text-muted-foreground space-y-1">{children}</div>
      </div>
    </div>
  )
}

function Table({ headers, rows }: { headers: string[]; rows: (string | React.ReactNode)[][] }) {
  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border bg-muted/20">
            {headers.map((h) => (
              <th key={h} className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {rows.map((row, ri) => (
            <tr key={ri} className="hover:bg-muted/20">
              {row.map((cell, ci) => (
                <td key={ci} className="px-4 py-2.5 text-foreground">
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
              On first launch you'll be directed to <strong className="text-foreground">/setup</strong>.
              Create your admin account (password must be 12+ characters, mixed case, numbers, and symbols).
            </p>
          </StepCard>
          <StepCard step={2} title="Connect a log source">
            <p>
              Go to <strong className="text-foreground">Settings → Source Integrations</strong> and configure
              at least one source. Pull sources (Sentinel, GuardDuty, VirusTotal, AbuseIPDB) need API keys.
              Push sources (Suricata, Windows Event Log, Defender, Snort) send logs via the Ingest API.
            </p>
          </StepCard>
          <StepCard step={3} title="Ingest your first alert">
            <p>
              Use the <strong className="text-foreground">Ingest API</strong> (see the Ingest API tab) or wait
              for the pull connector to sync. New alerts appear immediately on the Dashboard.
            </p>
          </StepCard>
          <StepCard step={4} title="Triage an alert">
            <p>
              Click any alert in <strong className="text-foreground">Alerts</strong>. The Overview tab shows
              risk score, recommended actions, and affected assets. Run AI Analysis for a plain-English
              summary and remediation steps.
            </p>
          </StepCard>
          <StepCard step={5} title="Add analysts and set roles">
            <p>
              Admins can create additional users at <strong className="text-foreground">Settings → Users</strong>.
              Choose <em>analyst</em> for front-line triage or <em>senior_analyst</em> to also run playbooks.
            </p>
          </StepCard>
          <StepCard step={6} title="Review coverage with Reports">
            <p>
              Go to <strong className="text-foreground">Reports → Detection Coverage</strong> to see which
              MITRE ATT&CK techniques have no detections — your detection gaps. Use this to prioritise
              new rules or log sources.
            </p>
          </StepCard>
        </div>
      </div>

      <div>
        <SectionHeading>Navigation overview</SectionHeading>
        <div className="space-y-2 text-sm text-muted-foreground">
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
              <span><strong className="text-foreground">{page}</strong> — {desc}</span>
            </div>
          ))}
        </div>
      </div>

      <div>
        <SectionHeading>Your first week by role</SectionHeading>
        <Table
          headers={['Day', 'Viewer', 'Analyst', 'Senior Analyst', 'Admin']}
          rows={[
            [
              'Day 1',
              'Review dashboard, explore alerts (read-only)',
              'Complete setup wizard, connect first source, ingest test event',
              'All analyst tasks + review existing playbooks',
              'Complete setup wizard, configure SSO/LDAP, create user accounts',
            ],
            [
              'Day 2',
              'Read Severity Guide and MITRE Coverage',
              'Triage 5 real alerts, run AI analysis on each, create your first suppression rule',
              'Run a playbook dry-run, review pending detection rules',
              'Configure AI provider, test all source connections, set up scheduled reports',
            ],
            [
              'Day 3',
              'Read Help documentation for each section',
              'Complete the keyboard triage tutorial (press ? on Alerts page), create a hunt query',
              'Approve a detection rule change, review MITRE coverage gaps',
              'Review audit log, set up secret rotation policies, review security settings',
            ],
          ]}
        />
      </div>

      <div>
        <SectionHeading>Troubleshooting</SectionHeading>
        <div className="space-y-4">
          {[
            [
              'No alerts appearing after connecting a source',
              'Check the source shows green on Sources page; verify API key hasn\'t expired; check ingest lag is <5 minutes; for push sources, verify the agent is sending to the correct /ingest endpoint.',
            ],
            [
              'AI Analysis button is greyed out',
              'An AI provider must be configured in Settings → AI Configuration; verify the API key is valid using Test Connection.',
            ],
            [
              'Session expired / can\'t log in',
              'Session tokens expire after 8 hours of inactivity; log in again; if you keep getting expired errors check the server clock is synchronized (NTP).',
            ],
            [
              'Alert status won\'t update',
              'Your role may not have alerts:write permission; confirm your role is at least Analyst with your admin.',
            ],
            [
              'Source shows red/amber on dashboard',
              'Navigate to Sources page, click the source setup guide, re-test the API connection, check API key rotation date.',
            ],
            [
              'Playbook ran but nothing happened',
              'Check Playbooks → execution history for error details; verify the alert matched the trigger conditions; for high-risk actions check Resilience → Runbook Approvals for a pending approval.',
            ],
          ].map(([issue, resolution]) => (
            <div key={issue as string} className="rounded-lg border border-border bg-muted/10 p-4 text-sm">
              <p className="font-medium text-foreground mb-1">{issue}</p>
              <p className="text-muted-foreground">{resolution}</p>
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
        All push sources send logs to a single <strong className="text-foreground">POST /api/v1/ingest</strong> endpoint.
        Authenticate with an API key generated in Settings → Source Integrations or via the admin panel.
      </InfoBox>

      <div>
        <SectionHeading>Endpoint</SectionHeading>
        <CodeBlock language="http" code="POST /api/v1/ingest" />
      </div>

      <div>
        <SectionHeading>Authentication</SectionHeading>
        <p className="text-sm text-muted-foreground mb-3">
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
        <p className="text-sm text-muted-foreground mt-3">
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
    : <span className="text-muted-foreground/40">—</span>

  return (
    <div className="space-y-6 max-w-3xl">
      <InfoBox>
        Roles are assigned per user and enforced server-side on every request.
        The frontend hides unavailable UI elements, but the backend independently
        validates permissions on every API call.
      </InfoBox>
      <div className="rounded-lg border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/20">
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide">Permission</th>
              <th className="px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide text-center">Viewer</th>
              <th className="px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide text-center">Analyst</th>
              <th className="px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide text-center">Senior Analyst</th>
              <th className="px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide text-center">Admin</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {PERMISSIONS.map(({ perm, viewer, analyst, senior, admin }) => (
              <tr key={perm} className="hover:bg-muted/20">
                <td className="px-4 py-2.5 text-foreground">{perm}</td>
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
        <div className="space-y-3 text-sm text-muted-foreground">
          <p><strong className="text-foreground">Viewer</strong> — read-only access to Dashboard, Alerts, Incidents, and MITRE Coverage. Cannot change alert status, comment, or run AI.</p>
          <p><strong className="text-foreground">Analyst</strong> — front-line triage. Can view and update alerts, run AI analysis, and ingest events via API.</p>
          <p><strong className="text-foreground">Senior Analyst</strong> — all analyst permissions plus alert assignment, playbook execution, and source management.</p>
          <p><strong className="text-foreground">Admin</strong> — full platform access including user management, settings, audit log, and API key generation.</p>
        </div>
      </div>

      <div>
        <SectionHeading>When to use each role</SectionHeading>
        <div className="space-y-3 text-sm text-muted-foreground">
          <p><strong className="text-foreground">Viewer</strong> — Grant to executives, legal, auditors, and stakeholders who need visibility without modification rights. Also use as a "read-only API" role for integrations.</p>
          <p><strong className="text-foreground">Analyst</strong> — Standard front-line SOC tier-1 analyst. Handles alert triage, enrichment, and incident response. Most operators should be Analyst.</p>
          <p><strong className="text-foreground">Senior Analyst</strong> — Tier-2 lead, detection engineer, or IR lead. Can assign work to others, run playbooks, manage sources, and approve detection changes.</p>
          <p><strong className="text-foreground">Admin</strong> — Only for SOC platform owner and security engineering lead. Limit to 2-3 people. Admins can delete alerts, manage users, change settings, and view audit logs.</p>
        </div>
      </div>

      <div>
        <SectionHeading>Security model</SectionHeading>
        <div className="space-y-2 text-sm text-muted-foreground">
          {[
            'All permission checks are enforced server-side on every API request — the frontend hides UI elements but the backend is the authoritative enforcement point.',
            'Every authorization failure (403) is logged to the immutable AuditLog with actor, IP, resource, and timestamp.',
            'Sessions are limited to 3 concurrent tokens per user; additional logins revoke the oldest session.',
            'Admin accounts should use unique passwords and have MFA enabled when supported by the SSO provider.',
            'Role changes are logged: the audit record shows who changed the role, from what, to what, and when.',
          ].map((item) => (
            <div key={item} className="flex gap-3">
              <ChevronRight className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
              <span>{item}</span>
            </div>
          ))}
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
            <span className="text-muted-foreground text-sm">Risk score {score}</span>
            <span className="ml-auto text-xs text-muted-foreground border border-border rounded px-2 py-0.5">SLA: {sla}</span>
          </div>
          <p className="text-sm text-muted-foreground">{meaning}</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
            <div>
              <p className="text-xs font-medium text-muted-foreground uppercase mb-1">Examples</p>
              <ul className="space-y-0.5 text-muted-foreground">
                {examples.map((e) => <li key={e} className="flex gap-2"><span className="text-muted-foreground/40">•</span>{e}</li>)}
              </ul>
            </div>
            <div>
              <p className="text-xs font-medium text-muted-foreground uppercase mb-1">Recommended actions</p>
              <ul className="space-y-0.5 text-muted-foreground">
                {actions.map((a) => <li key={a} className="flex gap-2"><span className="text-muted-foreground/40">•</span>{a}</li>)}
              </ul>
            </div>
          </div>
        </div>
      ))}

      <div>
        <SectionHeading>False positive decision guide</SectionHeading>
        <div className="space-y-3">
          {[
            {
              step: 1,
              question: 'Is this alert from a known-good scanner, pen test, or monitoring tool?',
              yes: 'Check if the source is allowlisted. If yes, create a suppression rule. If it\'s a new scanner, verify with the team first.',
              no: 'Continue to step 2.',
            },
            {
              step: 2,
              question: 'Does the asset (IP/hostname) have a legitimate reason for this activity?',
              yes: 'Mark "False Positive" with a note explaining the context (backup job, patch deployment, user testing). Consider adding a suppression rule.',
              no: 'No / Unknown → Continue to step 3.',
            },
            {
              step: 3,
              question: 'Is the risk score below 30 and no correlated alerts exist?',
              yes: 'Low confidence. Review raw log, check asset context. If benign, mark False Positive.',
              no: 'Risk score ≥30 or correlated alerts exist → Do NOT mark False Positive without further investigation. Escalate to High/Critical handling.',
            },
            {
              step: 4,
              question: 'Has this exact pattern appeared as a confirmed false positive before?',
              yes: 'Mark False Positive, reference the prior case in your comment, and create a suppression rule to prevent recurrence.',
              no: 'Investigate further before deciding.',
            },
          ].map(({ step, question, yes, no }) => (
            <div key={step} className="rounded-lg border border-border bg-muted/10 p-4 text-sm space-y-2">
              <div className="flex items-start gap-3">
                <div className="shrink-0 w-6 h-6 rounded-full gradient-primary flex items-center justify-center text-white text-xs font-bold">
                  {step}
                </div>
                <p className="font-medium text-foreground">{question}</p>
              </div>
              <div className="ml-9 space-y-1 text-muted-foreground">
                <p><strong className="text-emerald-400">Yes →</strong> {yes}</p>
                <p><strong className="text-muted-foreground">No →</strong> {no}</p>
              </div>
            </div>
          ))}
        </div>
        <div className="mt-4 rounded-lg border border-orange-500/30 bg-orange-500/5 p-4 text-sm text-orange-300">
          <strong className="text-orange-400">Warning:</strong> Never mark a Critical or High alert as False Positive without a second analyst review. Risk score ≥65 alerts that are incorrectly dismissed are a leading cause of missed breaches.
        </div>
      </div>
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
        Most keyboard shortcuts work globally. Press <kbd className="text-xs bg-muted px-1.5 py-0.5 rounded">G</kbd> then
        the letter within 1 second to navigate.
      </InfoBox>
      <div className="rounded-lg border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/20">
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide">Shortcut</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {SHORTCUTS.map(({ keys, action }) => (
              <tr key={action} className="hover:bg-muted/20">
                <td className="px-4 py-2.5">
                  <div className="flex items-center gap-1 flex-wrap">
                    {keys.map((k) =>
                      k === 'then' ? (
                        <span key={k} className="text-muted-foreground text-xs">then</span>
                      ) : (
                        <kbd
                          key={k}
                          className="text-xs font-mono bg-muted border border-border/80 text-foreground px-1.5 py-0.5 rounded shadow-sm"
                        >
                          {k}
                        </kbd>
                      )
                    )}
                  </div>
                </td>
                <td className="px-4 py-2.5 text-muted-foreground">{action}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div>
        <SectionHeading>Alert detail tabs</SectionHeading>
        <p className="text-sm text-muted-foreground mb-3">
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

      <div>
        <SectionHeading>Triage keyboard mode</SectionHeading>
        <p className="text-sm text-muted-foreground mb-3">
          When on the Alerts page, press{' '}
          <kbd className="text-xs bg-muted px-1.5 py-0.5 rounded border border-border/80 font-mono">?</kbd>{' '}
          to enter keyboard triage mode. Navigate and action alerts without touching the mouse.
        </p>
        <Table
          headers={['Key', 'Action']}
          rows={[
            [<kbd className="text-xs font-mono bg-muted border border-border/80 text-foreground px-1.5 py-0.5 rounded shadow-sm">J</kbd>, 'Move to next alert'],
            [<kbd className="text-xs font-mono bg-muted border border-border/80 text-foreground px-1.5 py-0.5 rounded shadow-sm">K</kbd>, 'Move to previous alert'],
            [<kbd className="text-xs font-mono bg-muted border border-border/80 text-foreground px-1.5 py-0.5 rounded shadow-sm">Enter</kbd>, 'Open alert detail in slide-over panel'],
            [<kbd className="text-xs font-mono bg-muted border border-border/80 text-foreground px-1.5 py-0.5 rounded shadow-sm">A</kbd>, 'Assign alert to yourself (pick up)'],
            [<kbd className="text-xs font-mono bg-muted border border-border/80 text-foreground px-1.5 py-0.5 rounded shadow-sm">R</kbd>, 'Mark alert Resolved (prompts for note)'],
            [<kbd className="text-xs font-mono bg-muted border border-border/80 text-foreground px-1.5 py-0.5 rounded shadow-sm">F</kbd>, 'Mark as False Positive (prompts for reason)'],
            [<kbd className="text-xs font-mono bg-muted border border-border/80 text-foreground px-1.5 py-0.5 rounded shadow-sm">E</kbd>, 'Escalate to Incident'],
            [<kbd className="text-xs font-mono bg-muted border border-border/80 text-foreground px-1.5 py-0.5 rounded shadow-sm">S</kbd>, 'Create Suppression rule for this alert signature'],
            [<kbd className="text-xs font-mono bg-muted border border-border/80 text-foreground px-1.5 py-0.5 rounded shadow-sm">Esc</kbd>, 'Exit triage mode'],
          ]}
        />
      </div>
    </div>
  )
}

// ── Tab: SOC Sections Documentation ──────────────────────────────────────────
interface SocSectionDoc {
  id: string
  name: string
  route: string
  category: 'Operations' | 'Detection & Response' | 'Resilience & Governance' | 'Knowledge'
  whatItDoes: string
  socValue: string
  usedBy: string
  commonActions: string[]
  keywords: string[]
}

const SOC_SECTION_DOCS: SocSectionDoc[] = [
  {
    id: 'dashboard',
    name: 'Dashboard',
    route: '/app',
    category: 'Operations',
    whatItDoes: 'Provides the real-time SOC command view: open alerts/incidents, severity trends, source freshness, and immediate analyst workload.',
    socValue: 'Reduces detection-to-triage delay by helping analysts prioritize high-impact issues first and quickly spot spikes that indicate active campaigns.',
    usedBy: 'SOC manager, shift lead, tier-1 analysts',
    commonActions: ['Review critical/high queue at shift start', 'Track alert trend anomalies', 'Identify stale source feeds'],
    keywords: ['kpi', 'overview', 'triage', 'queue', 'trend', 'operations'],
  },
  {
    id: 'alerts',
    name: 'Alerts',
    route: '/app/alerts',
    category: 'Detection & Response',
    whatItDoes: 'Lists all detections with filtering by severity, status, source, owner, and text. Entry point for event-level investigation.',
    socValue: 'Ensures consistent triage workflow and evidence-backed decisions by keeping all alert context, enrichment, and status transitions in one place.',
    usedBy: 'Tier-1 and tier-2 analysts',
    commonActions: ['Filter high-risk alerts', 'Assign ownership', 'Update status/comments with investigation rationale'],
    keywords: ['investigation', 'queue', 'status', 'assignment', 'filtering', 'triage'],
  },
  {
    id: 'incidents',
    name: 'Incidents',
    route: '/app/incidents',
    category: 'Detection & Response',
    whatItDoes: 'Groups related alerts into incident threads to represent attack stories rather than isolated events.',
    socValue: 'Improves containment decisions by connecting lateral movement, repeated TTPs, and multi-host activity into one coordinated response unit.',
    usedBy: 'Tier-2 analysts, incident responders, SOC lead',
    commonActions: ['Validate incident scope', 'Track response timeline', 'Coordinate remediation and closure'],
    keywords: ['correlation', 'timeline', 'scope', 'containment', 'response'],
  },
  {
    id: 'assets',
    name: 'Assets',
    route: '/app/assets',
    category: 'Operations',
    whatItDoes: 'Maintains asset inventory and ownership context (criticality, department, risk, open alerts/incidents).',
    socValue: 'Enables business-aware prioritization so responders can escalate compromises on crown-jewel systems before low-impact endpoints.',
    usedBy: 'Analysts, vulnerability team, SOC lead',
    commonActions: ['Identify affected business owner', 'Update asset criticality', 'Re-enrich telemetry context'],
    keywords: ['cmdb', 'ownership', 'criticality', 'business impact', 'context'],
  },
  {
    id: 'mitre',
    name: 'MITRE Coverage',
    route: '/app/mitre',
    category: 'Detection & Response',
    whatItDoes: 'Displays ATT&CK tactic/technique coverage and highlights blind spots in detections and telemetry sources.',
    socValue: 'Guides detection engineering roadmap by showing where attackers can operate without visibility.',
    usedBy: 'Detection engineers, purple team, SOC architect',
    commonActions: ['Find uncovered techniques', 'Prioritize new rules', 'Review source-quality blind spots'],
    keywords: ['attack', 'coverage', 'gap analysis', 'detections', 'techniques'],
  },
  {
    id: 'hunting',
    name: 'Threat Hunting',
    route: '/app/hunting',
    category: 'Detection & Response',
    whatItDoes: 'Provides hunt workspace for hypothesis-driven queries, saved hunts, run results, and pivot-to-alert workflows.',
    socValue: 'Moves SOC from reactive to proactive by surfacing stealthy activity missed by static rules.',
    usedBy: 'Threat hunters, senior analysts',
    commonActions: ['Run and save hunt queries', 'Pivot findings to alerts', 'Track recurring hunt patterns'],
    keywords: ['hunt', 'hypothesis', 'pivot', 'query workspace', 'proactive'],
  },
  {
    id: 'playbooks',
    name: 'Playbooks',
    route: '/app/playbooks',
    category: 'Detection & Response',
    whatItDoes: 'Defines automated response logic (status changes, assignment, containment steps) triggered by alert conditions.',
    socValue: 'Standardizes repetitive response tasks and shortens mean time to contain while preserving auditability.',
    usedBy: 'SOC automation engineers, senior analysts, admins',
    commonActions: ['Create or tune playbook logic', 'Dry-run actions', 'Enable/disable high-risk automations'],
    keywords: ['soar', 'automation', 'response actions', 'orchestration', 'containment'],
  },
  {
    id: 'detection-rules',
    name: 'Detection Rules',
    route: '/app/detection-rules',
    category: 'Detection & Response',
    whatItDoes: 'Manages Sigma/custom detection rules including lifecycle, testing, approval, history, and rollback.',
    socValue: 'Maintains detection quality by enforcing safe change control before rules impact production triage.',
    usedBy: 'Detection engineers, senior analysts, admins',
    commonActions: ['Test rule against sample events', 'Submit and approve changes', 'Rollback noisy rule versions'],
    keywords: ['sigma', 'rule lifecycle', 'approval', 'rollback', 'quality gate'],
  },
  {
    id: 'resilience',
    name: 'Resilience',
    route: '/app/resilience',
    category: 'Resilience & Governance',
    whatItDoes: 'Control plane for QA replays, secret rotation checks, tenant isolation, runbook approvals, DR drills, AI governance, and source quality.',
    socValue: 'Improves SOC reliability and governance by proving controls work before incidents pressure the team.',
    usedBy: 'SOC lead, platform owner, security governance, IR managers',
    commonActions: ['Run detection QA gate', 'Review overdue secrets', 'Approve high-risk response actions'],
    keywords: ['governance', 'resilience', 'dr', 'qa', 'approval gate', 'control plane'],
  },
  {
    id: 'reports',
    name: 'Reports',
    route: '/app/reports',
    category: 'Operations',
    whatItDoes: 'Generates operational and executive summaries: alert trends, coverage posture, analyst activity, and compliance evidence.',
    socValue: 'Supports leadership decisions, audit readiness, and measurable SOC performance improvement.',
    usedBy: 'SOC manager, CISO staff, compliance stakeholders',
    commonActions: ['Export evidence snapshots', 'Review KPI movement', 'Share periodic SOC posture updates'],
    keywords: ['executive', 'kpi', 'compliance', 'audit', 'metrics'],
  },
  {
    id: 'sources',
    name: 'Sources',
    route: '/app/sources',
    category: 'Operations',
    whatItDoes: 'Tracks connector health and onboarding for SIEM, EDR, cloud, identity, network, and enrichment integrations.',
    socValue: 'Prevents silent visibility loss by exposing ingestion drift, stale feeds, and misconfigured collectors early.',
    usedBy: 'Platform engineers, SOC operations, detection engineers',
    commonActions: ['Onboard integrations', 'Diagnose stale source status', 'Validate source-specific setup docs'],
    keywords: ['connector', 'ingestion', 'integration', 'telemetry', 'health'],
  },
  {
    id: 'help',
    name: 'Help',
    route: '/app/help',
    category: 'Knowledge',
    whatItDoes: 'Central documentation hub with setup guides, API references, roles, severity model, provider docs, and contextual SOC runbooks.',
    socValue: 'Reduces onboarding time and process variance by keeping playbooks and platform guidance in one discoverable location.',
    usedBy: 'All SOC users, new joiners, cross-functional responders',
    commonActions: ['Search procedures quickly', 'Open source-specific setup docs', 'Follow contextual runbooks during incidents'],
    keywords: ['documentation', 'runbook', 'knowledge base', 'onboarding', 'search'],
  },
]

function SocSectionsTab() {
  const [query, setQuery] = useState('')
  const groupedOrder: Array<SocSectionDoc['category']> = [
    'Operations',
    'Detection & Response',
    'Resilience & Governance',
    'Knowledge',
  ]

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return SOC_SECTION_DOCS
    return SOC_SECTION_DOCS.filter((section) => {
      const haystack = [
        section.name,
        section.route,
        section.category,
        section.whatItDoes,
        section.socValue,
        section.usedBy,
        ...section.commonActions,
        ...section.keywords,
      ].join(' ').toLowerCase()
      return haystack.includes(q)
    })
  }, [query])

  const grouped = useMemo(() => {
    return groupedOrder.map((category) => ({
      category,
      items: filtered.filter((x) => x.category === category),
    }))
  }, [filtered])

  return (
    <div className="space-y-6 max-w-4xl animate-fade-in">
      <InfoBox>
        This reference explains each SOC section in KESTREL: what it does operationally and how it improves SOC outcomes.
        Use search to find workflows, capabilities, and section responsibilities.
      </InfoBox>

      <div className="relative max-w-lg">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search documentation by section, purpose, workflow, or keyword..."
          className="w-full pl-9 pr-10 py-2 rounded-lg border border-border bg-background text-sm"
        />
        {query && (
          <button
            type="button"
            onClick={() => setQuery('')}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
            aria-label="Clear documentation search"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {filtered.length === 0 ? (
        <div className="rounded-lg border border-border bg-card p-10 text-sm text-muted-foreground text-center">
          No documentation sections matched your search.
        </div>
      ) : (
        <div className="space-y-7">
          {grouped.map(({ category, items }) =>
            items.length === 0 ? null : (
              <section key={category} className="space-y-3">
                <h2 className="text-base font-semibold text-foreground">{category}</h2>
                <div className="space-y-3">
                  {items.map((section, idx) => (
                    <article key={section.id} className="rounded-xl border border-border/50 bg-card p-4 space-y-3">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <p className="text-sm font-semibold text-foreground">{idx + 1}. {section.name}</p>
                          <p className="text-xs text-muted-foreground font-mono mt-0.5">{section.route}</p>
                        </div>
                        <span className="text-[10px] px-2 py-0.5 rounded border border-border text-muted-foreground">{section.category}</span>
                      </div>

                      <div className="space-y-2 text-sm">
                        <p><strong className="text-foreground">What It Does:</strong> <span className="text-muted-foreground">{section.whatItDoes}</span></p>
                        <p><strong className="text-foreground">How It Helps SOC:</strong> <span className="text-muted-foreground">{section.socValue}</span></p>
                        <p><strong className="text-foreground">Primary Users:</strong> <span className="text-muted-foreground">{section.usedBy}</span></p>
                      </div>

                      <div>
                        <p className="text-xs font-medium text-muted-foreground uppercase mb-1.5">Common Actions</p>
                        <ul className="space-y-1 text-sm text-muted-foreground">
                          {section.commonActions.map((action) => (
                            <li key={action} className="flex gap-2"><span className="text-muted-foreground/40">•</span>{action}</li>
                          ))}
                        </ul>
                      </div>
                    </article>
                  ))}
                </div>
              </section>
            )
          )}
        </div>
      )}
    </div>
  )
}

// ── Tab: AI Providers ─────────────────────────────────────────────────────────
interface AiProviderDoc {
  id: string
  name: string
  badge: string
  badgeColor: string
  tier: 'Recommended' | 'Enterprise' | 'Self-hosted' | 'Budget-friendly'
  summary: string
  bestFor: string[]
  envKey: string
  model: string
  getKeyUrl: string
  steps: string[]
  envExample: string
}

const AI_PROVIDER_DOCS: AiProviderDoc[] = [
  {
    id: 'openai',
    name: 'OpenAI',
    badge: 'GPT-4o',
    badgeColor: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/25',
    tier: 'Recommended',
    summary: 'The most widely used AI provider. GPT-4o offers strong instruction-following, structured JSON output, and reliable alert triage quality.',
    bestFor: ['General alert triage', 'Remediation playbooks', 'Structured AI key facts'],
    envKey: 'OPENAI_API_KEY',
    model: 'gpt-4o',
    getKeyUrl: 'https://platform.openai.com/api-keys',
    steps: [
      'Sign in at platform.openai.com',
      'Go to API keys → Create new secret key',
      'Copy the key and paste it into Settings → AI Configuration → OpenAI',
      'Set AI_PROVIDER=openai to activate',
    ],
    envExample: 'OPENAI_API_KEY="sk-proj-..."\nAI_PROVIDER="openai"\nOPENAI_MODEL="gpt-4o"',
  },
  {
    id: 'anthropic',
    name: 'Anthropic Claude',
    badge: 'Claude 4 Sonnet',
    badgeColor: 'bg-orange-500/15 text-orange-400 border-orange-500/25',
    tier: 'Recommended',
    summary: 'Claude 4 Sonnet excels at long-context reasoning and nuanced threat analysis. Best choice if alert descriptions are verbose or require multi-step reasoning.',
    bestFor: ['Deep threat analysis', 'Long alert context', 'Chain-of-thought reasoning'],
    envKey: 'ANTHROPIC_API_KEY',
    model: 'claude-sonnet-4-6',
    getKeyUrl: 'https://console.anthropic.com',
    steps: [
      'Sign in at console.anthropic.com',
      'Go to API Keys → Create Key',
      'Copy the key and paste into Settings → AI Configuration → Anthropic Claude',
      'Set AI_PROVIDER=anthropic to activate',
    ],
    envExample: 'ANTHROPIC_API_KEY="sk-ant-..."\nAI_PROVIDER="anthropic"\nANTHROPIC_MODEL="claude-sonnet-4-6"',
  },
  {
    id: 'azure_openai',
    name: 'Azure OpenAI',
    badge: 'GPT-4o (Azure)',
    badgeColor: 'bg-blue-500/15 text-blue-400 border-blue-500/25',
    tier: 'Enterprise',
    summary: 'Same GPT-4o models but hosted in your Azure tenant. All data stays within your Azure region — ideal for compliance (HIPAA, FedRAMP, SOC 2).',
    bestFor: ['Enterprise compliance', 'Data residency requirements', 'Azure-native environments'],
    envKey: 'AZURE_OPENAI_API_KEY',
    model: 'gpt-4o (your deployment)',
    getKeyUrl: 'https://portal.azure.com',
    steps: [
      'In Azure Portal, create an Azure OpenAI resource',
      'Deploy a model (e.g. gpt-4o) in Azure AI Studio → Deployments',
      'Copy the API key and endpoint from Azure OpenAI → Keys and Endpoint',
      'Paste both into Settings → AI Configuration → Azure OpenAI',
      'Set AZURE_OPENAI_DEPLOYMENT to your deployment name',
    ],
    envExample: 'AZURE_OPENAI_API_KEY="..."\nAZURE_OPENAI_ENDPOINT="https://myinstance.openai.azure.com/"\nAZURE_OPENAI_DEPLOYMENT="gpt-4o"',
  },
  {
    id: 'gemini',
    name: 'Google Gemini',
    badge: 'Gemini 2.0 Flash',
    badgeColor: 'bg-violet-500/15 text-violet-400 border-violet-500/25',
    tier: 'Recommended',
    summary: 'Gemini 2.0 Flash is extremely fast and cost-efficient. Gemini 1.5 Pro supports a 1M token context window — useful for large log payloads.',
    bestFor: ['High-volume alert processing', 'Cost-sensitive deployments', 'Large context windows'],
    envKey: 'GEMINI_API_KEY',
    model: 'gemini-2.0-flash',
    getKeyUrl: 'https://aistudio.google.com/app/apikey',
    steps: [
      'Sign in at aistudio.google.com',
      'Click "Get API key" → Create API key in new project',
      'Copy the key and paste into Settings → AI Configuration → Google Gemini',
      'Set AI_PROVIDER=gemini to activate',
    ],
    envExample: 'GEMINI_API_KEY="AIza..."\nAI_PROVIDER="gemini"\nGEMINI_MODEL="gemini-2.0-flash"',
  },
  {
    id: 'bedrock',
    name: 'AWS Bedrock',
    badge: 'Claude via AWS',
    badgeColor: 'bg-amber-500/15 text-amber-400 border-amber-500/25',
    tier: 'Enterprise',
    summary: 'Run Claude, Llama, and Titan models via AWS. Uses your existing AWS IAM credentials — no new API keys needed if GuardDuty or CloudTrail are already configured.',
    bestFor: ['AWS-native environments', 'Reuse existing IAM credentials', 'Private model endpoints'],
    envKey: 'AWS_ACCESS_KEY_ID',
    model: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
    getKeyUrl: 'https://console.aws.amazon.com/bedrock',
    steps: [
      'Open AWS Console → Bedrock → Model access',
      'Request access to Claude 3.5 Sonnet (approval is instant)',
      'Ensure your IAM credentials have bedrock:InvokeModel permission',
      'AWS credentials (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY) are shared with GuardDuty',
      'Set BEDROCK_MODEL_ID to your chosen model and AI_PROVIDER=bedrock',
    ],
    envExample: 'AI_PROVIDER="bedrock"\nBEDROCK_MODEL_ID="anthropic.claude-3-5-sonnet-20241022-v2:0"\n# Reuses AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY',
  },
  {
    id: 'groq',
    name: 'Groq',
    badge: 'Llama 3.3 70B',
    badgeColor: 'bg-rose-500/15 text-rose-400 border-rose-500/25',
    tier: 'Budget-friendly',
    summary: 'Groq\'s LPU delivers extremely fast inference (500+ tokens/sec). Llama 3.3 70B is a strong open-source model at a fraction of GPT-4o\'s cost.',
    bestFor: ['High-speed triage', 'Cost reduction', 'Open-source model preference'],
    envKey: 'GROQ_API_KEY',
    model: 'llama-3.3-70b-versatile',
    getKeyUrl: 'https://console.groq.com/keys',
    steps: [
      'Sign up at console.groq.com',
      'Go to API Keys → Create API Key',
      'Copy and paste into Settings → AI Configuration → Groq',
      'Set AI_PROVIDER=groq to activate',
    ],
    envExample: 'GROQ_API_KEY="gsk_..."\nAI_PROVIDER="groq"\nGROQ_MODEL="llama-3.3-70b-versatile"',
  },
  {
    id: 'mistral',
    name: 'Mistral AI',
    badge: 'Mistral Large',
    badgeColor: 'bg-indigo-500/15 text-indigo-400 border-indigo-500/25',
    tier: 'Enterprise',
    summary: 'EU-hosted models with strong GDPR compliance. Mistral Large is competitive with GPT-4o on structured tasks and is a good choice for European deployments.',
    bestFor: ['EU data residency', 'GDPR compliance', 'Structured JSON output'],
    envKey: 'MISTRAL_API_KEY',
    model: 'mistral-large-latest',
    getKeyUrl: 'https://console.mistral.ai/api-keys/',
    steps: [
      'Sign up at console.mistral.ai',
      'Go to API Keys → Create new key',
      'Copy and paste into Settings → AI Configuration → Mistral AI',
      'Set AI_PROVIDER=mistral to activate',
    ],
    envExample: 'MISTRAL_API_KEY="..."\nAI_PROVIDER="mistral"\nMISTRAL_MODEL="mistral-large-latest"',
  },
  {
    id: 'ollama',
    name: 'Ollama (Self-hosted)',
    badge: 'Local',
    badgeColor: 'bg-slate-500/15 text-slate-400 border-slate-500/25',
    tier: 'Self-hosted',
    summary: 'Run open-source models (Llama 3.2, Mistral, Phi-3) completely locally. No data leaves your network — ideal for air-gapped environments or strict data privacy requirements.',
    bestFor: ['Air-gapped networks', 'Maximum data privacy', 'No API cost'],
    envKey: 'OLLAMA_BASE_URL',
    model: 'llama3.2',
    getKeyUrl: 'https://ollama.com',
    steps: [
      'Install Ollama: curl -fsSL https://ollama.com/install.sh | sh',
      'Pull a model: ollama pull llama3.2',
      'Ollama starts automatically at http://localhost:11434',
      'In Settings → AI Configuration → Ollama, set Base URL and Model name',
      'No API key needed — Ollama has no authentication by default',
    ],
    envExample: 'AI_PROVIDER="ollama"\nOLLAMA_BASE_URL="http://localhost:11434"\nOLLAMA_MODEL="llama3.2"',
  },
]

const TIER_COLORS: Record<string, string> = {
  'Recommended':  'bg-emerald-500/15 text-emerald-400 border-emerald-500/25',
  'Enterprise':   'bg-blue-500/15 text-blue-400 border-blue-500/25',
  'Budget-friendly': 'bg-amber-500/15 text-amber-400 border-amber-500/25',
  'Self-hosted':  'bg-slate-500/15 text-slate-400 border-slate-500/25',
}

function AIProvidersTab() {
  const [selected, setSelected] = useState<string | null>(null)

  if (selected) {
    const doc = AI_PROVIDER_DOCS.find((p) => p.id === selected)!
    return (
      <div className="max-w-2xl space-y-5 animate-fade-in">
        <button
          type="button"
          onClick={() => setSelected(null)}
          className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
        >
          ← Back to AI providers
        </button>

        <div>
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <h2 className="text-lg font-semibold">{doc.name}</h2>
            <span className={cn('text-[10px] px-2 py-0.5 rounded border font-mono', doc.badgeColor)}>{doc.badge}</span>
            <span className={cn('text-[10px] px-2 py-0.5 rounded border', TIER_COLORS[doc.tier])}>{doc.tier}</span>
          </div>
          <p className="text-sm text-muted-foreground">{doc.summary}</p>
        </div>

        <div>
          <SubHeading>Best for</SubHeading>
          <ul className="space-y-1">
            {doc.bestFor.map((b) => (
              <li key={b} className="flex items-center gap-2 text-sm text-muted-foreground">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                {b}
              </li>
            ))}
          </ul>
        </div>

        <div>
          <SubHeading>Setup steps</SubHeading>
          <div className="space-y-0">
            {doc.steps.map((step, i) => (
              <div key={i} className="flex gap-3 pb-3 border-b border-border last:border-0 last:pb-0">
                <div className="shrink-0 w-6 h-6 rounded-full gradient-primary flex items-center justify-center text-white text-xs font-bold">{i + 1}</div>
                <p className="text-sm text-muted-foreground pt-0.5">{step}</p>
              </div>
            ))}
          </div>
        </div>

        <div>
          <SubHeading>.env configuration</SubHeading>
          <CodeBlock code={doc.envExample} language="env" />
        </div>

        <InfoBox>
          After saving credentials in <strong className="text-foreground">Settings → AI Configuration</strong>, click{' '}
          <strong className="text-foreground">Test Connection</strong> to verify the key is valid before activating.
        </InfoBox>
      </div>
    )
  }

  return (
    <div className="space-y-5 animate-fade-in max-w-4xl">
      <InfoBox>
        KESTREL supports <strong className="text-foreground">8 AI providers</strong>. Only one is active at a time
        (set by <code className="font-mono text-xs">AI_PROVIDER</code> in Settings). You can configure multiple
        providers and switch between them without losing credentials.
      </InfoBox>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {AI_PROVIDER_DOCS.map((doc) => (
          <button
            key={doc.id}
            type="button"
            onClick={() => setSelected(doc.id)}
            className={cn(
              'glass-card text-left p-4 rounded-xl border border-border',
              'hover:border-primary/40 hover:bg-primary/5 transition-all group',
              'focus:outline-none focus:ring-2 focus:ring-primary/40'
            )}
          >
            <div className="flex items-start justify-between gap-2 mb-2">
              <div>
                <p className="font-medium text-sm text-foreground group-hover:text-primary transition-colors">{doc.name}</p>
                <span className={cn('text-[9px] px-1.5 py-0.5 rounded border font-mono', doc.badgeColor)}>{doc.badge}</span>
              </div>
              <span className={cn('text-[9px] px-1.5 py-0.5 rounded border whitespace-nowrap', TIER_COLORS[doc.tier])}>{doc.tier}</span>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed line-clamp-2">{doc.summary}</p>
            <p className="text-[10px] text-primary mt-2 opacity-0 group-hover:opacity-100 transition-opacity">View setup guide →</p>
          </button>
        ))}
      </div>

      <div>
        <SectionHeading>Comparison at a glance</SectionHeading>
        <Table
          headers={['Provider', 'Model', 'Tier', 'Data residency', 'Best for']}
          rows={AI_PROVIDER_DOCS.map((p) => [
            p.name,
            <span key="m" className="font-mono text-[11px]">{p.model}</span>,
            p.tier,
            p.id === 'azure_openai' ? 'Your Azure region' :
            p.id === 'bedrock' ? 'Your AWS region' :
            p.id === 'mistral' ? 'EU (France)' :
            p.id === 'ollama' ? 'Your server' :
            'USA',
            p.bestFor[0],
          ])}
        />
      </div>
    </div>
  )
}

// ── Tab: Integrations ─────────────────────────────────────────────────────────
function IntegrationsTab() {
  const [searchParams] = useSearchParams()
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [docSourceId, setDocSourceId] = useState<string | null>(() => searchParams.get('source'))

  // Update if URL param changes
  useEffect(() => {
    const s = searchParams.get('source')
    if (s) setDocSourceId(s)
  }, [searchParams])

  const allTypes = useMemo(() => {
    const s = new Set(SOURCE_CATALOG.map((s) => s.type))
    return ['all', ...Array.from(s).sort()]
  }, [])

  const filtered = useMemo(() => {
    const q = search.toLowerCase()
    return SOURCE_CATALOG.filter((s) => {
      const matchType = typeFilter === 'all' || s.type === typeFilter
      const matchSearch =
        !q ||
        s.name.toLowerCase().includes(q) ||
        s.vendor.toLowerCase().includes(q) ||
        s.type.toLowerCase().includes(q) ||
        s.helpTags.some((t) => t.toLowerCase().includes(q))
      return matchType && matchSearch
    })
  }, [search, typeFilter])

  // ── Show doc panel ──────────────────────────────────────────────────────────
  if (docSourceId) {
    return (
      <div className="max-w-3xl">
        <SourceDocPanel sourceId={docSourceId} onBack={() => setDocSourceId(null)} />
      </div>
    )
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Search + type filter */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
          <input
            type="text"
            placeholder="Search integrations…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-8 py-2 rounded-lg border border-border bg-background text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/40"
          />
          {search && (
            <button
              type="button"
              onClick={() => setSearch('')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="h-9 px-3 rounded-lg border border-border bg-background text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/40"
        >
          {allTypes.map((t) => (
            <option key={t} value={t}>
              {t === 'all' ? 'All types' : t}
            </option>
          ))}
        </select>
        <span className="self-center text-xs text-muted-foreground whitespace-nowrap">
          {filtered.length} of {SOURCE_CATALOG.length}
        </span>
      </div>

      {/* Grid */}
      {filtered.length === 0 ? (
        <div className="rounded-lg border border-border bg-card p-12 text-center text-sm text-muted-foreground">
          No integrations match your search.
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {filtered.map((source) => {
            const typeBadge = TYPE_COLORS[source.type] ?? 'bg-muted text-muted-foreground border-border'
            return (
              <button
                key={source.id}
                type="button"
                onClick={() => setDocSourceId(source.id)}
                className={cn(
                  'glass-card text-left p-4 rounded-xl border border-border',
                  'hover:border-primary/40 hover:bg-primary/5 transition-all group',
                  'focus:outline-none focus:ring-2 focus:ring-primary/40'
                )}
              >
                {/* Header */}
                <div className="flex items-start gap-3 mb-3">
                  <div
                    className="w-10 h-10 rounded-lg flex items-center justify-center border border-border shrink-0"
                    style={{ backgroundColor: source.logoBg }}
                  >
                    <SourceLogo sourceId={source.id} size={24} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="font-medium text-foreground text-sm leading-tight truncate group-hover:text-primary transition-colors">
                      {source.name}
                    </p>
                    <p className="text-xs text-muted-foreground truncate">{source.vendor}</p>
                  </div>
                </div>

                {/* Badges */}
                <div className="flex items-center gap-1.5 flex-wrap mb-2">
                  <span className={cn('inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border', typeBadge)}>
                    {source.type}
                  </span>
                  <span className={cn(
                    'inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border',
                    source.push
                      ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/25'
                      : 'bg-purple-500/15 text-purple-400 border-purple-500/25'
                  )}>
                    {source.push ? 'Push' : 'Pull'}
                  </span>
                </div>

                {/* Description */}
                <p className="text-xs text-muted-foreground leading-relaxed line-clamp-2">
                  {source.overview}
                </p>

                {/* CTA */}
                <p className="text-[10px] text-primary mt-2 opacity-0 group-hover:opacity-100 transition-opacity">
                  View setup guide →
                </p>
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ── Contextual Runbooks ───────────────────────────────────────────────────────

interface RunbookStep {
  title: string
  detail: string
}

interface RunbookDef {
  title: string
  subtitle: string
  icon: string
  steps: RunbookStep[]
}

const RUNBOOKS: Record<string, RunbookDef> = {
  alerts: {
    title: 'Alert Triage Runbook',
    subtitle: 'Step-by-step guide to investigating an alert',
    icon: '🚨',
    steps: [
      { title: 'Review severity and source', detail: 'Check the alert severity (Critical/High/Medium/Low) and the originating source. High and Critical alerts require immediate attention. Understand which connector or ingest source fired the alert.' },
      { title: 'Examine the raw payload', detail: 'Open the alert detail and review the raw log. Look for key fields: IP addresses, user accounts, process names, hashes, and file paths. These are your primary investigation pivots.' },
      { title: 'Check MITRE ATT&CK mapping', detail: 'Identify which tactic and technique the alert maps to. Use the MITRE heatmap to understand if this technique has been seen before across your environment.' },
      { title: 'Search for related alerts', detail: 'Use the Alerts filter to search for similar alerts by source IP, user, or technique. A cluster of related alerts may indicate an active incident rather than an isolated event.' },
      { title: 'Assign or escalate', detail: 'If the alert appears genuine, assign it to yourself or a senior analyst. If it meets incident criteria (multiple hosts, lateral movement, data exfiltration), escalate to an Incident and run the relevant Playbook.' },
      { title: 'Document your decision', detail: 'Update the alert status (Investigating, Resolved, or False Positive) and add a comment explaining your reasoning. This feeds the analyst activity audit log.' },
    ],
  },
  incidents: {
    title: 'Incident Response Runbook',
    subtitle: 'NIST-aligned IR lifecycle for active incidents',
    icon: '🔥',
    steps: [
      { title: 'Contain', detail: 'Immediately isolate affected systems to prevent lateral movement. Use EDR (CrowdStrike, SentinelOne) to quarantine endpoints. Revoke or disable compromised credentials in Identity (Azure AD, Okta). Block attacker IPs at the perimeter firewall.' },
      { title: 'Identify scope', detail: 'Enumerate all affected assets and accounts. Use the Timeline view to reconstruct the attack chain. Correlate alerts across sources to establish the full scope of compromise.' },
      { title: 'Eradicate', detail: 'Remove malware, unauthorized accounts, and persistence mechanisms (scheduled tasks, registry run keys, cron jobs, startup scripts). Re-image compromised endpoints if confidence in clean state is low.' },
      { title: 'Recover', detail: 'Restore systems from known-good backups. Re-enable contained assets after confirming clean state. Monitor recovery period closely with increased detection sensitivity.' },
      { title: 'Document', detail: 'Record timeline, IOCs, TTPs, affected assets, and remediation steps in the Incident detail. Capture all evidence before closing. Produce a post-incident report within 72 hours.' },
      { title: 'Lessons learned', detail: 'Schedule a retrospective within one week. Update detection rules, playbooks, and response procedures based on gaps identified during the incident.' },
    ],
  },
  playbooks: {
    title: 'Playbook Authoring Guide',
    subtitle: 'How to build effective automated response playbooks',
    icon: '📖',
    steps: [
      { title: 'Define the trigger condition', detail: 'Clearly define what alert types, severities, or patterns trigger this playbook. Overly broad triggers cause noise; overly narrow triggers miss coverage. Use MITRE technique filters where possible.' },
      { title: 'List all required permissions', detail: 'Identify which integrations and credentials the playbook needs (EDR API, firewall API, ticketing system). Ensure the service account running the playbook has least-privilege access.' },
      { title: 'Design the decision tree', detail: 'Map out the branching logic: what happens if containment fails? What if the asset is a critical server? Build in human-approval gates for irreversible actions (deletion, account lockout).' },
      { title: 'Add notification steps', detail: 'Every significant action should generate a notification: Slack alert, email to SOC lead, or ITSM ticket. Include context: who triggered it, what action was taken, affected assets.' },
      { title: 'Test in a staging environment', detail: 'Run the playbook against synthetic alerts in a non-production environment. Validate that each action executes correctly and all branching conditions work as expected.' },
      { title: 'Review and version', detail: 'Have a second analyst review the playbook logic before activation. Use semantic versioning (v1.0.0). Document the changelog for every update. Archive old versions.' },
    ],
  },
  hunting: {
    title: 'Threat Hunt Runbook',
    subtitle: 'Structure a hypothesis-driven threat hunt',
    icon: '🔍',
    steps: [
      { title: 'Form a hypothesis', detail: 'Start with a specific, falsifiable hypothesis: "Attackers using T1059 (Command and Scripting Interpreter) are present in our environment." Ground it in threat intelligence, industry reports, or recent incident learnings.' },
      { title: 'Identify data sources', detail: 'Determine which log sources contain the data needed to test your hypothesis (EDR telemetry, process creation logs, network flows, DNS queries). Verify data completeness and retention period.' },
      { title: 'Write and execute queries', detail: 'Use the Threat Hunting IDE to write KQL/SPL/Lucene queries. Start broad, then narrow. Look for statistical anomalies, rare processes, unusual parent-child process relationships, and off-hours activity.' },
      { title: 'Pivot on findings', detail: 'When you find something interesting, pivot: search for the same IOC across other hosts, look at the user account\'s other activity, trace the network connection to its destination. Use the Entity Pivot Panel.' },
      { title: 'Document and create detections', detail: 'For every technique you validate (or refute), document the query and findings. Convert successful hunting queries into persistent detection rules to close the coverage gap.' },
      { title: 'Report hunt results', detail: 'Produce a hunt summary: hypothesis, data sources examined, time range, findings, and recommendations. Even negative results (no evidence found) have value — record them.' },
    ],
  },
  default: {
    title: 'Quick Start Guide',
    subtitle: 'Get up and running with KESTREL SOC in minutes',
    icon: '⚡',
    steps: [
      { title: 'Complete setup', detail: 'Finish the Setup Wizard to create your admin account and configure your first data source.' },
      { title: 'Connect a data source', detail: 'Go to Settings → Source Integrations and add at least one SIEM, EDR, or cloud source.' },
      { title: 'Review the Dashboard', detail: 'The Dashboard shows your real-time security posture: alert volume, open criticals, MITRE coverage, and top incidents.' },
      { title: 'Triage your first alert', detail: 'Navigate to Alerts, sort by severity, and pick up a Critical alert. Use the AI Summary to accelerate triage.' },
      { title: 'Explore the MITRE heatmap', detail: 'The MITRE ATT&CK view shows which techniques are being detected. Use this to identify coverage gaps and prioritise detection engineering.' },
    ],
  },
}

function ContextualRunbooks({ context }: { context: string | null }) {
  const key = (context ?? 'default') as keyof typeof RUNBOOKS
  const runbook = (RUNBOOKS[key] ?? RUNBOOKS.default)!

  return (
    <div className="rounded-xl border border-primary/20 bg-primary/5 p-5 space-y-4">
      <div className="flex items-start gap-3">
        <span className="text-2xl leading-none mt-0.5">{runbook.icon}</span>
        <div>
          <h2 className="text-base font-semibold text-foreground">{runbook.title}</h2>
          <p className="text-xs text-muted-foreground mt-0.5">{runbook.subtitle}</p>
        </div>
      </div>
      <ol className="space-y-3">
        {runbook.steps.map((step, i) => (
          <li key={i} className="flex gap-3">
            <span className="shrink-0 w-6 h-6 rounded-full gradient-primary flex items-center justify-center text-white text-[10px] font-bold">
              {i + 1}
            </span>
            <div>
              <p className="text-sm font-medium text-foreground leading-snug">{step.title}</p>
              <p className="text-xs text-muted-foreground mt-0.5 leading-relaxed">{step.detail}</p>
            </div>
          </li>
        ))}
      </ol>
    </div>
  )
}

// ── Main Help page ────────────────────────────────────────────────────────────
export function Help() {
  const [searchParams] = useSearchParams()
  const context = searchParams.get('context')
  const [tab, setTab] = useState<Tab>(() => {
    const t = searchParams.get('tab')
    return (t && TABS.some((x) => x.id === t) ? t : 'soc') as Tab
  })

  // Deep-link: ?tab=integrations&source=crowdstrike
  useEffect(() => {
    const t = searchParams.get('tab')
    if (t && TABS.some((x) => x.id === t)) setTab(t as Tab)
  }, [searchParams])

  // Auto-scroll contextual runbook into view when context param is present
  const runbookRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (context && runbookRef.current) {
      runbookRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  }, [context])

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-semibold text-foreground">Help & Documentation</h1>
        <p className="text-sm text-muted-foreground mt-0.5">Platform guide, API reference, and role information</p>
      </div>

      {/* Contextual Runbooks — shown when ?context= param is present */}
      <div ref={runbookRef}>
        <ContextualRunbooks context={context} />
      </div>

      {/* Tab nav */}
      <div className="border-b border-border">
        <nav className="flex flex-wrap gap-1">
          {TABS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              type="button"
              onClick={() => setTab(id)}
              className={cn(
                'flex items-center gap-2 py-2.5 px-3 text-sm font-medium border-b-2 transition-colors whitespace-nowrap',
                tab === id
                  ? 'border-primary text-foreground'
                  : 'border-transparent text-muted-foreground hover:text-foreground'
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
        {tab === 'soc' && <SocSectionsTab />}
        {tab === 'guide' && <GettingStarted />}
        {tab === 'integrations' && <IntegrationsTab />}
        {tab === 'ai' && <AIProvidersTab />}
        {tab === 'api' && <IngestAPI />}
        {tab === 'roles' && <RolesTab />}
        {tab === 'severity' && <SeverityGuide />}
        {tab === 'shortcuts' && <ShortcutsTab />}
      </div>
    </div>
  )
}
