import { useMemo, useState } from "react";
import { useQuery } from '@tanstack/react-query'
import { Shield, Target, Grid3X3, AlertTriangle } from "lucide-react";
import { get } from '@/api/client'

interface Technique {
  id: string;
  name: string;
  detected: boolean;
  alertCount: number;
  severity?: "critical" | "high" | "medium" | "low";
  description?: string;
  dataSources?: string[];
  platforms?: string[];
}

interface Tactic {
  name: string;
  techniques: Technique[];
}

interface LiveCoverageEntry {
  technique_id: string;
  technique_name: string;
  tactic: string;
  alert_count: number;
  max_severity: string;
  max_risk_score: number;
}

interface LiveCoverageResponse {
  coverage: LiveCoverageEntry[];
  total_techniques: number;
}

const mitreTactics: Tactic[] = [
  {
    name: "Initial Access",
    techniques: [
      { id: "T1078", name: "Valid Accounts", detected: true, alertCount: 12, severity: "critical", description: "Adversaries may obtain and abuse credentials of existing accounts.", dataSources: ["Auth Logs", "AD Events"], platforms: ["Windows", "Linux", "Cloud"] },
      { id: "T1566", name: "Phishing", detected: true, alertCount: 8, severity: "high", description: "Adversaries may send phishing messages to gain access.", dataSources: ["Email Gateway", "Web Proxy"], platforms: ["Windows", "macOS", "Linux"] },
      { id: "T1190", name: "Exploit Public-Facing App", detected: true, alertCount: 3, severity: "medium", description: "Adversaries may exploit vulnerabilities in internet-facing applications.", dataSources: ["WAF", "IDS"], platforms: ["Windows", "Linux"] },
      { id: "T1133", name: "External Remote Services", detected: false, alertCount: 0, description: "Adversaries may leverage remote services to access internal networks.", dataSources: ["VPN Logs"], platforms: ["Windows", "Linux"] },
      { id: "T1200", name: "Hardware Additions", detected: false, alertCount: 0 },
    ],
  },
  {
    name: "Execution",
    techniques: [
      { id: "T1059", name: "Command & Scripting", detected: true, alertCount: 25, severity: "critical", description: "Adversaries may abuse command and script interpreters.", dataSources: ["Sysmon", "EDR"], platforms: ["Windows", "Linux", "macOS"] },
      { id: "T1204", name: "User Execution", detected: true, alertCount: 6, severity: "high", description: "Adversaries may rely on a user to execute malicious content.", dataSources: ["Sysmon"], platforms: ["Windows", "macOS"] },
      { id: "T1053", name: "Scheduled Task/Job", detected: true, alertCount: 4, severity: "medium", description: "Adversaries may abuse task scheduling to execute malicious code.", dataSources: ["Sysmon", "Windows Events"], platforms: ["Windows", "Linux"] },
      { id: "T1047", name: "WMI", detected: true, alertCount: 2, severity: "low", description: "Adversaries may abuse WMI for execution.", dataSources: ["Sysmon"], platforms: ["Windows"] },
      { id: "T1559", name: "Inter-Process Comm", detected: false, alertCount: 0 },
    ],
  },
  {
    name: "Persistence",
    techniques: [
      { id: "T1547", name: "Boot/Logon Autostart", detected: true, alertCount: 7, severity: "high", description: "Adversaries may configure system settings to automatically execute a program during system boot.", dataSources: ["Registry", "Sysmon"], platforms: ["Windows", "macOS", "Linux"] },
      { id: "T1136", name: "Create Account", detected: true, alertCount: 3, severity: "medium", description: "Adversaries may create accounts to maintain access.", dataSources: ["AD Events"], platforms: ["Windows", "Linux", "Cloud"] },
      { id: "T1543", name: "Create/Modify System Process", detected: false, alertCount: 0 },
      { id: "T1546", name: "Event Triggered Execution", detected: false, alertCount: 0 },
    ],
  },
  {
    name: "Privilege Escalation",
    techniques: [
      { id: "T1548", name: "Abuse Elevation Control", detected: true, alertCount: 5, severity: "high", description: "Adversaries may circumvent mechanisms designed to control elevation of privilege.", dataSources: ["Sysmon", "EDR"], platforms: ["Windows", "macOS", "Linux"] },
      { id: "T1134", name: "Access Token Manipulation", detected: false, alertCount: 0 },
      { id: "T1068", name: "Exploitation for Privilege Escalation", detected: true, alertCount: 2, severity: "medium", description: "Adversaries may exploit software vulnerabilities to elevate privileges.", dataSources: ["EDR"], platforms: ["Windows", "Linux"] },
    ],
  },
  {
    name: "Defense Evasion",
    techniques: [
      { id: "T1027", name: "Obfuscated Files", detected: true, alertCount: 15, severity: "high", description: "Adversaries may make files or information difficult to discover.", dataSources: ["Sysmon", "AV"], platforms: ["Windows", "Linux", "macOS"] },
      { id: "T1070", name: "Indicator Removal", detected: true, alertCount: 4, severity: "medium" },
      { id: "T1562", name: "Impair Defenses", detected: true, alertCount: 3, severity: "high" },
      { id: "T1036", name: "Masquerading", detected: false, alertCount: 0 },
      { id: "T1112", name: "Modify Registry", detected: true, alertCount: 6, severity: "medium" },
      { id: "T1218", name: "System Binary Proxy", detected: false, alertCount: 0 },
    ],
  },
  {
    name: "Credential Access",
    techniques: [
      { id: "T1110", name: "Brute Force", detected: true, alertCount: 18, severity: "critical", description: "Adversaries may use brute force to attempt access to accounts.", dataSources: ["Auth Logs", "Wazuh"], platforms: ["Windows", "Linux", "Cloud"] },
      { id: "T1003", name: "OS Credential Dumping", detected: true, alertCount: 5, severity: "critical" },
      { id: "T1555", name: "Credentials from Password Stores", detected: false, alertCount: 0 },
      { id: "T1552", name: "Unsecured Credentials", detected: true, alertCount: 2, severity: "low" },
    ],
  },
  {
    name: "Discovery",
    techniques: [
      { id: "T1087", name: "Account Discovery", detected: true, alertCount: 8, severity: "medium" },
      { id: "T1082", name: "System Info Discovery", detected: true, alertCount: 3, severity: "low" },
      { id: "T1083", name: "File & Directory Discovery", detected: false, alertCount: 0 },
      { id: "T1046", name: "Network Service Scan", detected: true, alertCount: 6, severity: "medium" },
    ],
  },
  {
    name: "Lateral Movement",
    techniques: [
      { id: "T1021", name: "Remote Services", detected: true, alertCount: 9, severity: "high" },
      { id: "T1080", name: "Taint Shared Content", detected: false, alertCount: 0 },
      { id: "T1550", name: "Use Alternate Auth Material", detected: true, alertCount: 4, severity: "critical" },
    ],
  },
  {
    name: "Collection",
    techniques: [
      { id: "T1005", name: "Data from Local System", detected: true, alertCount: 3, severity: "medium" },
      { id: "T1114", name: "Email Collection", detected: false, alertCount: 0 },
      { id: "T1074", name: "Data Staged", detected: true, alertCount: 2, severity: "low" },
    ],
  },
  {
    name: "Command & Control",
    techniques: [
      { id: "T1071", name: "Application Layer Protocol", detected: true, alertCount: 11, severity: "high" },
      { id: "T1573", name: "Encrypted Channel", detected: true, alertCount: 7, severity: "medium" },
      { id: "T1105", name: "Ingress Tool Transfer", detected: false, alertCount: 0 },
      { id: "T1572", name: "Protocol Tunneling", detected: true, alertCount: 3, severity: "high" },
    ],
  },
  {
    name: "Exfiltration",
    techniques: [
      { id: "T1048", name: "Exfil Over Alt Protocol", detected: true, alertCount: 5, severity: "critical" },
      { id: "T1041", name: "Exfil Over C2 Channel", detected: false, alertCount: 0 },
      { id: "T1567", name: "Exfil Over Web Service", detected: false, alertCount: 0 },
    ],
  },
  {
    name: "Impact",
    techniques: [
      { id: "T1486", name: "Data Encrypted for Impact", detected: false, alertCount: 0 },
      { id: "T1489", name: "Service Stop", detected: true, alertCount: 1, severity: "low" },
      { id: "T1529", name: "System Shutdown/Reboot", detected: false, alertCount: 0 },
    ],
  },
];

// Static totals used as fallback baseline
const staticTotalTechniques = mitreTactics.reduce((s, t) => s + t.techniques.length, 0);

const severityBg: Record<string, string> = {
  critical: "bg-red-500/20 border-red-500/40 text-red-400",
  high: "bg-orange-500/20 border-orange-500/40 text-orange-400",
  medium: "bg-yellow-500/20 border-yellow-500/40 text-yellow-400",
  low: "bg-blue-500/20 border-blue-500/40 text-blue-400",
};

const severityDot: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-blue-500",
};

const defaultSev = { bg: "bg-muted/30 border-border/30 text-muted-foreground/50", dot: "bg-muted" };

const MitreCoverage = () => {
  const [selectedTechnique, setSelectedTechnique] = useState<Technique | null>(null);
  const [selectedTactic, setSelectedTactic] = useState<string>("");

  // Live coverage query — silently falls back to static data on error
  const { data: liveCoverageData } = useQuery({
    queryKey: ['mitre-live-coverage'],
    queryFn: () => get<LiveCoverageResponse>('/mitre/coverage'),
    retry: 1,
  });

  const { data: sourceQuality } = useQuery({
    queryKey: ['mitre-source-quality'],
    queryFn: () => get<{ items: Array<{ source: string; quality_score: number; techniques_detected: number; blind_spots: string[] }> }>('/resilience/mitre/source-quality'),
  })

  // Build a lookup map from the live coverage response
  const liveCoverageMap = useMemo<Record<string, LiveCoverageEntry>>(() => {
    if (!liveCoverageData?.coverage) return {};
    return Object.fromEntries(liveCoverageData.coverage.map((e) => [e.technique_id, e]));
  }, [liveCoverageData]);

  // Merge live data over static fallback data
  const mergedTactics = useMemo<Tactic[]>(() => {
    if (Object.keys(liveCoverageMap).length === 0) return mitreTactics;
    return mitreTactics.map((tactic) => ({
      ...tactic,
      techniques: tactic.techniques.map((tech) => {
        const live = liveCoverageMap[tech.id];
        if (!live) return tech;
        return {
          ...tech,
          detected: live.alert_count > 0,
          alertCount: live.alert_count,
          severity: (live.max_severity as Technique["severity"]) ?? tech.severity,
        };
      }),
    }));
  }, [liveCoverageMap]);

  const totalTechniques = staticTotalTechniques;
  const detectedTechniques = mergedTactics.reduce((s, t) => s + t.techniques.filter((x) => x.detected).length, 0);
  const coveragePct = Math.round((detectedTechniques / totalTechniques) * 100);
  const tacticsWithDetection = mergedTactics.filter((t) => t.techniques.some((x) => x.detected)).length;

  const gaps = mergedTactics
    .flatMap((t) => t.techniques.filter((x) => !x.detected).map((x) => ({ ...x, tactic: t.name })))
    .slice(0, 10);

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-lg font-bold tracking-tight flex items-center gap-2">
          <Grid3X3 className="h-5 w-5 text-primary" /> MITRE ATT&CK Coverage
        </h1>
        <p className="text-xs text-muted-foreground">Detection coverage across the ATT&CK framework</p>
      </div>

      {/* KPI Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="glass-card rounded-xl p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Coverage</p>
              <p className="text-3xl font-bold text-primary">{coveragePct}%</p>
            </div>
            <Shield className="h-8 w-8 text-primary/30" />
          </div>
          <div className="mt-2 h-1.5 rounded-full bg-muted overflow-hidden">
            <div className="h-full rounded-full gradient-primary transition-all" style={{ width: `${coveragePct}%` }} />
          </div>
        </div>
        <div className="glass-card rounded-xl p-4">
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Detected</p>
          <p className="text-3xl font-bold text-green-400">{detectedTechniques}</p>
          <p className="text-[10px] text-muted-foreground mt-1">of {totalTechniques} techniques</p>
        </div>
        <div className="glass-card rounded-xl p-4">
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Gaps</p>
          <p className="text-3xl font-bold text-destructive">{totalTechniques - detectedTechniques}</p>
          <p className="text-[10px] text-muted-foreground mt-1">undetected techniques</p>
        </div>
        <div className="glass-card rounded-xl p-4">
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Tactics</p>
          <p className="text-3xl font-bold">{tacticsWithDetection}</p>
          <p className="text-[10px] text-muted-foreground mt-1">of {mitreTactics.length} with coverage</p>
        </div>
      </div>

      {/* Heatmap Grid */}
      <div className="glass-card rounded-xl p-4">
        <h2 className="text-sm font-semibold mb-4">Technique Heatmap</h2>
        <div className="overflow-x-auto">
          <div
            className="grid gap-1"
            style={{ gridTemplateColumns: `repeat(${mergedTactics.length}, minmax(90px, 1fr))` }}
          >
            {/* Tactic Headers */}
            {mergedTactics.map((tactic) => {
              const detected = tactic.techniques.filter((t) => t.detected).length;
              return (
                <div key={tactic.name} className="text-center pb-2 border-b border-border/30">
                  <p className="text-[9px] font-semibold truncate" title={tactic.name}>{tactic.name}</p>
                  <p className="text-[8px] text-muted-foreground">{detected}/{tactic.techniques.length}</p>
                </div>
              );
            })}
            {/* Technique Cells - row by row */}
            {Array.from({ length: Math.max(...mergedTactics.map((t) => t.techniques.length)) }).map((_, rowIdx) => (
              mergedTactics.map((tactic) => {
                const tech = tactic.techniques[rowIdx];
                if (!tech) return <div key={`${tactic.name}-${rowIdx}`} />;
                const sev = tech.severity ?? "low";
                const cls = tech.detected ? (severityBg[sev] ?? defaultSev.bg) : defaultSev.bg;
                return (
                  <button
                    key={tech.id}
                    onClick={() => { setSelectedTechnique(tech); setSelectedTactic(tactic.name); }}
                    className={`rounded p-1 text-[8px] leading-tight transition-all hover:scale-105 hover:z-10 border cursor-pointer text-left ${cls}`}
                    title={`${tech.id}: ${tech.name}`}
                  >
                    <span className="font-mono block">{tech.id}</span>
                    <span className="block truncate">{tech.name}</span>
                    {tech.detected && (
                      <span className="block mt-0.5 font-bold">{tech.alertCount} alerts</span>
                    )}
                  </button>
                );
              })
            ))}
          </div>
        </div>
      </div>

      {/* Gap Analysis */}
      <div className="glass-card rounded-xl p-4">
        <h2 className="text-sm font-semibold mb-4 flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 text-destructive" /> High Priority Gaps
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {gaps.map((g) => (
            <div key={g.id} className="flex items-center gap-3 p-2 rounded-lg bg-muted/20 border border-border/30">
              <span className="font-mono text-[9px] border border-border rounded px-1.5 py-0.5 text-muted-foreground shrink-0">{g.id}</span>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium truncate">{g.name}</p>
                <p className="text-[10px] text-muted-foreground">{(g as Technique & { tactic: string }).tactic}</p>
              </div>
              <span className="text-[9px] shrink-0 px-1.5 py-0.5 rounded bg-destructive/15 text-destructive border border-destructive/30">No detections</span>
            </div>
          ))}
        </div>
      </div>

      <div className="glass-card rounded-xl p-4">
        <h2 className="text-sm font-semibold mb-3">Source Quality by ATT&CK Coverage</h2>
        <div className="space-y-2">
          {(sourceQuality?.items ?? []).slice(0, 8).map((item) => (
            <div key={item.source} className="rounded-lg border border-border/40 bg-muted/20 p-2.5 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-medium">{item.source}</span>
                <span className="text-blue-400">{item.quality_score}%</span>
              </div>
              <p className="text-muted-foreground mt-1">Techniques detected: {item.techniques_detected}</p>
              {item.blind_spots.length > 0 && (
                <p className="text-muted-foreground">Blind spots: {item.blind_spots.join(', ')}</p>
              )}
            </div>
          ))}
          {(sourceQuality?.items ?? []).length === 0 && (
            <p className="text-xs text-muted-foreground">No source quality telemetry yet.</p>
          )}
        </div>
      </div>

      {/* Technique Detail Modal */}
      {selectedTechnique && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
          onClick={(e) => e.target === e.currentTarget && setSelectedTechnique(null)}
          role="dialog"
          aria-modal="true"
        >
          <div className="glass-card-elevated rounded-2xl shadow-2xl shadow-black/40 p-6 max-w-md w-full mx-4">
            {/* Header */}
            <div className="flex items-start justify-between gap-4 mb-4">
              <div>
                <span className="inline-block text-xs font-mono font-bold px-2 py-0.5 rounded border border-border text-muted-foreground mb-2">
                  {selectedTechnique.id}
                </span>
                <h2 className="text-base font-bold leading-snug">{selectedTechnique.name}</h2>
                <p className="text-xs text-muted-foreground mt-0.5">Tactic: {selectedTactic}</p>
              </div>
              <button
                type="button"
                onClick={() => setSelectedTechnique(null)}
                className="text-muted-foreground hover:text-foreground transition-colors text-xl leading-none mt-1"
                aria-label="Close"
              >
                ×
              </button>
            </div>

            {/* Detection status */}
            <div className="mb-4">
              {selectedTechnique.detected ? (
                <span className={`inline-flex items-center gap-1.5 text-xs font-semibold px-2 py-1 rounded border ${severityBg[selectedTechnique.severity ?? "low"] ?? defaultSev.bg}`}>
                  <span className={`h-1.5 w-1.5 rounded-full ${severityDot[selectedTechnique.severity ?? "low"] ?? defaultSev.dot}`} />
                  {selectedTechnique.alertCount} alerts · {selectedTechnique.severity}
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 text-xs font-semibold px-2 py-1 rounded border bg-destructive/15 text-destructive border-destructive/30">
                  Not Detected
                </span>
              )}
            </div>

            {selectedTechnique.description && (
              <p className="text-xs text-muted-foreground leading-relaxed mb-4">{selectedTechnique.description}</p>
            )}

            {selectedTechnique.dataSources && (
              <div className="mb-4">
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5">Data Sources</p>
                <div className="flex flex-wrap gap-1">
                  {selectedTechnique.dataSources.map((ds) => (
                    <span key={ds} className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground border border-border">{ds}</span>
                  ))}
                </div>
              </div>
            )}

            {selectedTechnique.platforms && (
              <div className="mb-4">
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5">Platforms</p>
                <div className="flex flex-wrap gap-1">
                  {selectedTechnique.platforms.map((p) => (
                    <span key={p} className="text-[10px] px-1.5 py-0.5 rounded border border-border text-muted-foreground">{p}</span>
                  ))}
                </div>
              </div>
            )}

            <div className="flex gap-2 justify-end pt-4 border-t border-border/50">
              {selectedTechnique.detected && (
                <button
                  type="button"
                  className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium rounded-lg gradient-primary text-primary-foreground"
                  onClick={() => setSelectedTechnique(null)}
                >
                  <Target className="h-3 w-3" /> View Alerts
                </button>
              )}
              <button
                type="button"
                onClick={() => setSelectedTechnique(null)}
                className="px-3 py-1.5 text-xs font-medium rounded-lg border border-border text-muted-foreground hover:text-foreground hover:bg-muted/30 transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default MitreCoverage;
