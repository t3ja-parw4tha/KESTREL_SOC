import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  ArrowLeft, Clock, User, Shield, Activity, Target,
  CheckCircle, Circle, ExternalLink, Download, Globe,
  Hash, Server, Monitor, Laptop, FileText, Plus,
} from 'lucide-react'
import { cn } from '@/utils/cn'
import { toast } from 'sonner'

// ─── Types ────────────────────────────────────────────────────────────────────
interface MitreTech { id: string; name: string; phase: string }
interface LinkedAlert { id: string; title: string; severity: string; status: string; source: string; created_at: string }
interface AffectedAsset { type: string; name: string; ip: string; os: string; status: string }
interface AttackerIP { ip: string; geo: string; isp: string; reputation: string; reports: number }
interface TimelineEntry { time: string; event: string; type: string; actor: string }
interface ResponseAction { id: string; label: string; completed: boolean; assignee: string | null }
interface ThreatIntel { source: string; url: string; label: string }
interface Artifact { name: string; type: string; size: string; uploaded_by: string }

interface IncidentData {
  id: string; title: string; description: string
  severity: 'critical' | 'high' | 'medium' | 'low'; status: string
  assigned_to: string | null; created_at: string; updated_at: string
  mitre_tactics: string[]; mitre_techniques: MitreTech[]
  linked_alerts: LinkedAlert[]; affected_assets: AffectedAsset[]
  attacker_ips: AttackerIP[]; timeline: TimelineEntry[]
  response_actions: ResponseAction[]; threat_intel: ThreatIntel[]; artifacts: Artifact[]
}

// ─── Demo data ────────────────────────────────────────────────────────────────
const demoIncidentDetails: Record<string, IncidentData> = {
  'INC-001': {
    id: 'INC-001',
    title: 'Coordinated Brute Force Campaign',
    description: 'Multiple brute force login attempts detected across several endpoints from a known botnet IP range. Over 15,000 failed login attempts in the past 6 hours targeting Active Directory accounts.',
    severity: 'critical', status: 'in_progress', assigned_to: 'Sarah Chen',
    created_at: '2026-03-12T02:15:00Z', updated_at: '2026-03-12T08:30:00Z',
    mitre_tactics: ['Credential Access', 'Initial Access'],
    mitre_techniques: [
      { id: 'T1110.001', name: 'Brute Force: Password Guessing', phase: 'Credential Access' },
      { id: 'T1078', name: 'Valid Accounts', phase: 'Initial Access' },
      { id: 'T1021.001', name: 'Remote Desktop Protocol', phase: 'Lateral Movement' },
    ],
    linked_alerts: [
      { id: 'ALR-001', title: 'Brute Force SSH Login Detected', severity: 'critical', status: 'new', source: 'Wazuh', created_at: '2026-03-12T08:15:00Z' },
      { id: 'ALR-004', title: 'Failed Login Attempt — admin', severity: 'high', status: 'new', source: 'Auth Logs', created_at: '2026-03-12T06:30:00Z' },
      { id: 'ALR-009', title: 'Multiple Failed RDP Logins', severity: 'high', status: 'in_progress', source: 'Sysmon', created_at: '2026-03-12T05:00:00Z' },
      { id: 'ALR-012', title: 'Account Lockout — svc_backup', severity: 'medium', status: 'new', source: 'Active Directory', created_at: '2026-03-12T04:45:00Z' },
    ],
    affected_assets: [
      { type: 'server', name: 'prod-web-01', ip: '10.0.1.15', os: 'Ubuntu 22.04', status: 'compromised' },
      { type: 'server', name: 'DC02', ip: '10.0.0.5', os: 'Windows Server 2022', status: 'targeted' },
      { type: 'workstation', name: 'WS-FIN-042', ip: '10.0.5.42', os: 'Windows 11', status: 'targeted' },
      { type: 'user', name: 'root', ip: '—', os: '—', status: 'compromised' },
      { type: 'user', name: 'svc_backup', ip: '—', os: '—', status: 'locked' },
    ],
    attacker_ips: [
      { ip: '185.220.101.34', geo: 'Netherlands', isp: 'TOR Exit Node', reputation: 'malicious', reports: 47 },
      { ip: '45.33.49.119', geo: 'United States', isp: 'DigitalOcean', reputation: 'suspicious', reports: 12 },
      { ip: '91.219.236.222', geo: 'Romania', isp: 'M247 Ltd', reputation: 'malicious', reports: 89 },
    ],
    timeline: [
      { time: '2026-03-12T02:15:00Z', event: 'Incident created from correlated alerts', type: 'system', actor: 'System' },
      { time: '2026-03-12T02:20:00Z', event: 'Auto-assigned to Sarah Chen (on-call)', type: 'system', actor: 'Playbook PB-001' },
      { time: '2026-03-12T03:00:00Z', event: 'Initial triage complete — confirmed brute force campaign', type: 'action', actor: 'Sarah Chen' },
      { time: '2026-03-12T04:00:00Z', event: 'Blocked IP 185.220.101.34 at perimeter firewall', type: 'action', actor: 'Sarah Chen' },
      { time: '2026-03-12T04:45:00Z', event: 'New alert ALR-012 linked: Account lockout svc_backup', type: 'correlation', actor: 'System' },
      { time: '2026-03-12T05:30:00Z', event: 'Blocked IP range 91.219.236.0/24 at firewall', type: 'action', actor: 'Marcus Webb' },
      { time: '2026-03-12T06:00:00Z', event: 'Verified no successful compromises in auth.log', type: 'action', actor: 'Sarah Chen' },
      { time: '2026-03-12T08:00:00Z', event: 'Rate limiting enabled on all SSH endpoints', type: 'action', actor: 'Alex Rivera' },
      { time: '2026-03-12T08:30:00Z', event: 'Status changed to In Progress — monitoring for new activity', type: 'action', actor: 'Sarah Chen' },
    ],
    response_actions: [
      { id: 'ra-1', label: 'Block attacker IPs at perimeter firewall', completed: true, assignee: 'Sarah Chen' },
      { id: 'ra-2', label: 'Verify no successful logins from attacker IPs', completed: true, assignee: 'Sarah Chen' },
      { id: 'ra-3', label: 'Enable SSH rate limiting on all production servers', completed: true, assignee: 'Alex Rivera' },
      { id: 'ra-4', label: 'Reset credentials for targeted accounts (root, svc_backup)', completed: false, assignee: 'Marcus Webb' },
      { id: 'ra-5', label: 'Deploy fail2ban on remaining SSH endpoints', completed: false, assignee: 'Alex Rivera' },
      { id: 'ra-6', label: 'Conduct post-incident review and update runbook', completed: false, assignee: 'Sarah Chen' },
      { id: 'ra-7', label: 'Submit IOCs to threat intelligence sharing platform', completed: false, assignee: 'Marcus Webb' },
    ],
    threat_intel: [
      { source: 'VirusTotal', url: 'https://www.virustotal.com', label: '185.220.101.34 — 12/94 detections' },
      { source: 'AbuseIPDB', url: 'https://www.abuseipdb.com', label: '185.220.101.34 — Confidence 100%' },
      { source: 'Shodan', url: 'https://www.shodan.io', label: '185.220.101.34 — Open ports: 22, 80, 443' },
      { source: 'TOR Project', url: 'https://metrics.torproject.org', label: 'Confirmed TOR exit node since 2025-11-02' },
    ],
    artifacts: [
      { name: 'auth.log (prod-web-01)', type: 'log', size: '4.2 MB', uploaded_by: 'Sarah Chen' },
      { name: 'pcap_capture_0312.pcap', type: 'pcap', size: '28.7 MB', uploaded_by: 'Marcus Webb' },
      { name: 'firewall_rules_before.txt', type: 'config', size: '1.1 KB', uploaded_by: 'Alex Rivera' },
      { name: 'memory_dump_ws-fin-042.raw', type: 'memory', size: '2.1 GB', uploaded_by: 'Marcus Webb' },
    ],
  },
}

function createFallbackIncident(id: string): IncidentData {
  return {
    id, severity: 'medium', status: 'open', assigned_to: null,
    title: `Incident ${id}`,
    description: 'Incident created from alert investigation. Details pending initial triage.',
    created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
    mitre_tactics: [], mitre_techniques: [], linked_alerts: [],
    timeline: [{ time: new Date().toISOString(), event: `Incident ${id} created`, type: 'system', actor: 'System' }],
    response_actions: [
      { id: 'ra-1', label: 'Perform initial triage and scope assessment', completed: false, assignee: null },
      { id: 'ra-2', label: 'Identify and contain affected assets', completed: false, assignee: null },
      { id: 'ra-3', label: 'Document findings and remediation steps', completed: false, assignee: null },
    ],
    affected_assets: [], attacker_ips: [], threat_intel: [], artifacts: [],
  }
}

// ─── Configs ──────────────────────────────────────────────────────────────────
const statusConfig: Record<string, { label: string; cls: string }> = {
  open: { label: 'Open', cls: 'bg-destructive/15 text-destructive border-destructive/30' },
  in_progress: { label: 'In Progress', cls: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30' },
  contained: { label: 'Contained', cls: 'bg-orange-500/15 text-orange-400 border-orange-500/30' },
  resolved: { label: 'Resolved', cls: 'bg-green-500/15 text-green-400 border-green-500/30' },
  closed: { label: 'Closed', cls: 'bg-muted/50 text-muted-foreground border-border' },
}
const severityColors: Record<string, string> = {
  critical: 'bg-severity-critical/15 text-severity-critical border-severity-critical/30',
  high: 'bg-severity-high/15 text-severity-high border-severity-high/30',
  medium: 'bg-severity-medium/15 text-severity-medium border-severity-medium/30',
  low: 'bg-severity-low/15 text-severity-low border-severity-low/30',
}

function AssetIcon({ type }: { type: string }) {
  switch (type) {
    case 'server': return <Server className="h-4 w-4 text-muted-foreground shrink-0" />
    case 'workstation': return <Laptop className="h-4 w-4 text-muted-foreground shrink-0" />
    case 'user': return <User className="h-4 w-4 text-muted-foreground shrink-0" />
    default: return <Monitor className="h-4 w-4 text-muted-foreground shrink-0" />
  }
}

// ─── Main page ────────────────────────────────────────────────────────────────
export function IncidentDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState('overview')

  const incident = demoIncidentDetails[id || 'INC-001'] || createFallbackIncident(id || 'INC-???')
  const [responseActions, setResponseActions] = useState(incident.response_actions)

  const completedActions = responseActions.filter(a => a.completed).length
  const progressPercent = responseActions.length > 0 ? Math.round((completedActions / responseActions.length) * 100) : 0
  const defaultStatus = { label: 'Open', cls: 'bg-destructive/15 text-destructive border-destructive/30' }
  const status = statusConfig[incident.status] ?? defaultStatus

  const toggleAction = (actionId: string) => {
    setResponseActions(prev => prev.map(a => a.id === actionId ? { ...a, completed: !a.completed } : a))
    toast.success('Response action updated')
  }

  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'alerts', label: `Linked Alerts (${incident.linked_alerts.length})` },
    { id: 'assets', label: 'Assets & IPs' },
    { id: 'response', label: 'Response Actions' },
    { id: 'timeline', label: 'Timeline' },
    { id: 'intel', label: 'Threat Intel' },
    { id: 'artifacts', label: 'Artifacts' },
  ]

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-start gap-4">
        <button type="button" onClick={() => navigate('/app/incidents')}
          className="p-2 rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent transition-colors mt-1 shrink-0">
          <ArrowLeft className="h-4 w-4" />
        </button>
        <div className="flex-1 min-w-0 space-y-2">
          <div className="flex items-center gap-3 flex-wrap">
            <span className="font-mono text-xs text-muted-foreground">{incident.id}</span>
            <span className={cn('inline-flex items-center px-1.5 py-0.5 rounded border text-[10px] font-semibold uppercase', severityColors[incident.severity])}>
              {incident.severity}
            </span>
            <span className={cn('inline-flex items-center px-1.5 py-0.5 rounded border text-[10px] font-semibold', status.cls)}>
              {status.label}
            </span>
            <span className="text-xs text-muted-foreground flex items-center gap-1">
              <Clock className="h-3 w-3" /> Created {new Date(incident.created_at).toLocaleString()}
            </span>
          </div>
          <h1 className="text-lg font-bold tracking-tight text-foreground">{incident.title}</h1>
          <p className="text-sm text-muted-foreground">{incident.description}</p>
          <div className="flex items-center gap-4 text-xs text-muted-foreground">
            {incident.assigned_to && (
              <span className="flex items-center gap-1"><User className="h-3 w-3" /> {incident.assigned_to}</span>
            )}
            <span className="flex items-center gap-1"><Shield className="h-3 w-3" /> {incident.linked_alerts.length} linked alerts</span>
            <span className="flex items-center gap-1"><Activity className="h-3 w-3" /> {completedActions}/{responseActions.length} actions complete</span>
          </div>
        </div>
      </div>

      {/* Progress bar */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between text-xs">
          <span className="text-muted-foreground">Response Progress</span>
          <span className="font-medium text-foreground">{progressPercent}%</span>
        </div>
        <div className="h-2 w-full rounded-full bg-muted/40 overflow-hidden">
          <div className="h-full rounded-full gradient-primary transition-all duration-500" style={{ width: `${progressPercent}%` }} />
        </div>
      </div>

      <div className="h-px bg-border/40" />

      {/* Tab bar */}
      <div className="flex items-center gap-0.5 bg-muted/50 rounded-lg p-1 overflow-x-auto">
        {tabs.map(tab => (
          <button key={tab.id} type="button" onClick={() => setActiveTab(tab.id)}
            className={cn('px-3 py-1.5 rounded-md text-xs font-medium transition-all whitespace-nowrap',
              activeTab === tab.id ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground')}>
            {tab.label}
          </button>
        ))}
      </div>

      {/* ─── Overview ─── */}
      {activeTab === 'overview' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="glass-card p-4 space-y-3">
            <h3 className="text-sm font-semibold flex items-center gap-2 text-foreground">
              <Target className="h-4 w-4 text-primary" /> MITRE ATT&CK Kill Chain
            </h3>
            <div className="flex flex-wrap gap-1.5">
              {incident.mitre_tactics.map(t => (
                <span key={t} className="inline-flex items-center px-2 py-0.5 rounded bg-muted/50 border border-border/40 text-[10px] text-muted-foreground">{t}</span>
              ))}
            </div>
            <div className="space-y-2">
              {incident.mitre_techniques.map(tech => (
                <div key={tech.id} className="flex items-center gap-3 text-xs p-2 rounded-lg bg-muted/30">
                  <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/50 bg-muted/40 text-[10px] font-mono shrink-0 text-foreground">{tech.id}</span>
                  <span className="flex-1 text-foreground">{tech.name}</span>
                  <span className="text-muted-foreground text-[10px]">{tech.phase}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="glass-card p-4 space-y-3">
            <h3 className="text-sm font-semibold text-foreground">Incident Summary</h3>
            {[
              { label: 'Severity', value: incident.severity.toUpperCase() },
              { label: 'Status', value: status.label },
              { label: 'Lead Analyst', value: incident.assigned_to || 'Unassigned' },
              { label: 'Linked Alerts', value: incident.linked_alerts.length },
              { label: 'Affected Assets', value: incident.affected_assets.length },
              { label: 'Attacker IPs', value: incident.attacker_ips.length },
              { label: 'Created', value: new Date(incident.created_at).toLocaleString() },
              { label: 'Last Updated', value: new Date(incident.updated_at).toLocaleString() },
            ].map(row => (
              <div key={row.label} className="flex justify-between items-center text-xs">
                <span className="text-muted-foreground">{row.label}</span>
                <span className="font-medium text-foreground">{row.value}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ─── Linked Alerts ─── */}
      {activeTab === 'alerts' && (
        <div className="space-y-3">
          {incident.linked_alerts.length === 0
            ? <div className="text-center py-12 text-sm text-muted-foreground">No linked alerts yet.</div>
            : incident.linked_alerts.map(alert => (
                <div key={alert.id} className="glass-card-hover cursor-pointer p-4"
                  onClick={() => navigate(`/app/alerts/${alert.id}`)} role="button" tabIndex={0}
                  onKeyDown={e => e.key === 'Enter' && navigate(`/app/alerts/${alert.id}`)}>
                  <div className="flex items-center gap-3 flex-wrap">
                    <span className="font-mono text-[10px] text-muted-foreground">{alert.id}</span>
                    <span className={cn('inline-flex items-center px-1.5 py-0.5 rounded border text-[10px] font-semibold uppercase', severityColors[alert.severity] || '')}>
                      {alert.severity}
                    </span>
                    <span className="text-xs font-medium flex-1 truncate text-foreground">{alert.title}</span>
                    <span className="inline-flex items-center px-1.5 py-0.5 rounded bg-muted/40 border border-border/30 text-[10px] text-muted-foreground">{alert.source}</span>
                    <span className="text-[10px] text-muted-foreground">{new Date(alert.created_at).toLocaleString()}</span>
                  </div>
                </div>
              ))
          }
        </div>
      )}

      {/* ─── Assets & IPs ─── */}
      {activeTab === 'assets' && (
        <div className="space-y-4">
          <div className="glass-card p-4 space-y-3">
            <h3 className="text-sm font-semibold text-foreground">Affected Assets</h3>
            {incident.affected_assets.length === 0
              ? <p className="text-xs text-muted-foreground text-center py-6">No affected assets identified yet.</p>
              : <div className="space-y-2">
                  {incident.affected_assets.map((asset, i) => (
                    <div key={i} className="flex items-center gap-3 text-xs p-3 rounded-lg bg-muted/20 border border-border/30">
                      <AssetIcon type={asset.type} />
                      <span className="font-medium min-w-[120px] text-foreground">{asset.name}</span>
                      <span className="font-mono text-muted-foreground">{asset.ip}</span>
                      <span className="text-muted-foreground">{asset.os}</span>
                      <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-primary/40 text-primary bg-primary/10 text-[10px] font-semibold ml-auto">{asset.status}</span>
                    </div>
                  ))}
                </div>
            }
          </div>
          <div className="glass-card p-4 space-y-3">
            <h3 className="text-sm font-semibold flex items-center gap-2 text-foreground">
              <Globe className="h-4 w-4 text-primary" /> Attacker IPs
            </h3>
            {incident.attacker_ips.length === 0
              ? <p className="text-xs text-muted-foreground text-center py-6">No attacker IPs identified yet.</p>
              : <div className="space-y-2">
                  {incident.attacker_ips.map((ip, i) => (
                    <div key={i} className="flex items-center gap-3 text-xs p-3 rounded-lg bg-muted/20 border border-border/30">
                      <Hash className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                      <code className="font-mono text-primary min-w-[130px]">{ip.ip}</code>
                      <span className="text-muted-foreground">{ip.geo}</span>
                      <span className="text-muted-foreground">{ip.isp}</span>
                      <span className={cn('inline-flex items-center px-1.5 py-0.5 rounded border text-[10px] font-semibold ml-auto',
                        ip.reputation === 'malicious' ? 'border-destructive/40 text-destructive bg-destructive/10' : 'border-yellow-500/40 text-yellow-400 bg-yellow-500/10')}>
                        {ip.reputation}
                      </span>
                      <span className="text-[10px] text-muted-foreground">{ip.reports} reports</span>
                    </div>
                  ))}
                </div>
            }
          </div>
        </div>
      )}

      {/* ─── Response Actions ─── */}
      {activeTab === 'response' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-foreground">Response Checklist</h3>
              <p className="text-[10px] text-muted-foreground">{completedActions} of {responseActions.length} actions completed</p>
            </div>
            <button type="button" className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg border border-border text-foreground text-xs hover:bg-accent transition-colors">
              <Plus className="h-3 w-3" /> Add Action
            </button>
          </div>
          <div className="h-2 w-full rounded-full bg-muted/40 overflow-hidden">
            <div className="h-full rounded-full gradient-primary transition-all duration-500" style={{ width: `${progressPercent}%` }} />
          </div>
          <div className="space-y-2">
            {responseActions.map(action => (
              <div key={action.id} className={cn('flex items-center gap-3 p-3 rounded-lg border transition-colors',
                action.completed ? 'bg-muted/10 border-border/20' : 'bg-card/50 border-border/40')}>
                <button type="button" onClick={() => toggleAction(action.id)}
                  className={cn('h-4 w-4 rounded shrink-0 border-2 flex items-center justify-center transition-colors',
                    action.completed ? 'bg-primary border-primary' : 'border-border hover:border-primary')}
                  aria-label={action.completed ? 'Mark incomplete' : 'Mark complete'}>
                  {action.completed && <span className="text-white text-[10px] font-bold">✓</span>}
                </button>
                <span className={cn('text-xs flex-1 text-foreground', action.completed && 'line-through text-muted-foreground')}>
                  {action.label}
                </span>
                {action.assignee && (
                  <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                    <User className="h-2.5 w-2.5" /> {action.assignee}
                  </span>
                )}
                {action.completed
                  ? <CheckCircle className="h-4 w-4 text-green-400 shrink-0" />
                  : <Circle className="h-4 w-4 text-muted-foreground/30 shrink-0" />
                }
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ─── Timeline ─── */}
      {activeTab === 'timeline' && (
        <div className="glass-card p-4">
          <h3 className="text-sm font-semibold text-foreground mb-4">Incident Timeline</h3>
          <div className="relative">
            {incident.timeline.map((entry, i) => (
              <div key={i} className="relative flex gap-4 pb-6 last:pb-0">
                {i < incident.timeline.length - 1 && (
                  <div className="absolute left-[11px] top-6 bottom-0 w-px bg-border" />
                )}
                <div className={cn('relative z-10 mt-1 h-[22px] w-[22px] shrink-0 rounded-full border-2 flex items-center justify-center',
                  entry.type === 'system' ? 'border-primary bg-primary/20' :
                  entry.type === 'correlation' ? 'border-purple-500 bg-purple-500/20' :
                  'border-green-500 bg-green-500/20')}>
                  <div className={cn('h-2 w-2 rounded-full',
                    entry.type === 'system' ? 'bg-primary' :
                    entry.type === 'correlation' ? 'bg-purple-500' : 'bg-green-500')} />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium text-foreground">{entry.event}</p>
                  <p className="text-[10px] text-muted-foreground mt-0.5 flex items-center gap-2 flex-wrap">
                    <span className="flex items-center gap-1"><Clock className="h-2.5 w-2.5" /> {new Date(entry.time).toLocaleString()}</span>
                    <span className="flex items-center gap-1"><User className="h-2.5 w-2.5" /> {entry.actor}</span>
                    <span className="inline-flex items-center px-1.5 py-0.5 rounded bg-muted/40 border border-border/30 text-[9px] capitalize">{entry.type}</span>
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ─── Threat Intel ─── */}
      {activeTab === 'intel' && (
        <div className="glass-card p-4 space-y-3">
          <h3 className="text-sm font-semibold flex items-center gap-2 text-foreground">
            <Globe className="h-4 w-4 text-primary" /> External Threat Intelligence
          </h3>
          {incident.threat_intel.length === 0
            ? <p className="text-xs text-muted-foreground text-center py-6">No external threat intelligence linked yet.</p>
            : <div className="space-y-2">
                {incident.threat_intel.map((intel, i) => (
                  <a key={i} href={intel.url} target="_blank" rel="noopener noreferrer"
                    className="flex items-center gap-3 text-xs p-3 rounded-lg bg-muted/20 border border-border/30 hover:bg-muted/40 transition-colors">
                    <span className="inline-flex items-center px-1.5 py-0.5 rounded bg-muted/50 border border-border/40 text-[10px] text-muted-foreground shrink-0">{intel.source}</span>
                    <span className="flex-1 text-primary truncate">{intel.label}</span>
                    <ExternalLink className="h-3 w-3 text-muted-foreground shrink-0" />
                  </a>
                ))}
              </div>
          }
        </div>
      )}

      {/* ─── Artifacts ─── */}
      {activeTab === 'artifacts' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-foreground">Artifact Gallery</h3>
            <button type="button" className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg border border-border text-foreground text-xs hover:bg-accent transition-colors">
              <Plus className="h-3 w-3" /> Upload Artifact
            </button>
          </div>
          {incident.artifacts.length === 0
            ? <div className="text-center py-12 text-sm text-muted-foreground">No artifacts uploaded yet.</div>
            : <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {incident.artifacts.map((artifact, i) => (
                  <div key={i} className="glass-card-hover cursor-pointer p-4 flex items-center gap-3">
                    <div className="h-10 w-10 rounded-lg bg-muted/50 flex items-center justify-center shrink-0">
                      <FileText className="h-5 w-5 text-muted-foreground" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium truncate text-foreground">{artifact.name}</p>
                      <p className="text-[10px] text-muted-foreground">{artifact.type.toUpperCase()} · {artifact.size} · by {artifact.uploaded_by}</p>
                    </div>
                    <button type="button" title="Download" className="h-8 w-8 flex items-center justify-center rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent transition-colors shrink-0">
                      <Download className="h-3.5 w-3.5" />
                    </button>
                  </div>
                ))}
              </div>
          }
        </div>
      )}
    </div>
  )
}
