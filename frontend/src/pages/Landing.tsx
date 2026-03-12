import { useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '@/security/AuthContext'
import {
  Shield,
  Target,
  Brain,
  Zap,
  ArrowRight,
  Workflow,
  KeyRound,
  Lock,
  Sun,
  Moon,
  ChevronRight,
  Activity,
  AlertTriangle
} from 'lucide-react'
import { useTheme } from '@/contexts/ThemeContext'

export function Landing() {
  const { isAuthenticated, hydrated } = useAuth()
  const { theme, toggleTheme } = useTheme()
  const navigate = useNavigate()

  useEffect(() => {
    if (hydrated && isAuthenticated) {
      navigate('/app', { replace: true })
    }
  }, [hydrated, isAuthenticated, navigate])

  if (!hydrated) {
    return (
      <div className="min-h-screen bg-soc-bg flex items-center justify-center">
        <div className="w-8 h-8 rounded-full border-4 border-blue-500/30 border-t-blue-500 animate-spin" />
      </div>
    )
  }

  if (isAuthenticated) {
    return (
      <div className="min-h-screen bg-soc-bg flex items-center justify-center">
        <div className="w-8 h-8 rounded-full border-4 border-blue-500/30 border-t-blue-500 animate-spin" />
      </div>
    )
  }

  const features = [
    {
      icon: Workflow,
      title: 'Automation & SOAR',
      description: 'Build conditional playbooks to auto-triage, elevate, or resolve alerts instantly without human intervention.',
      color: 'text-indigo-500 dark:text-indigo-400',
      bg: 'bg-indigo-500/10 dark:bg-indigo-500/20',
      glow: 'group-hover:shadow-[0_0_30px_-5px_max(rgba(99,102,241,0.2),rgba(0,0,0,0))] dark:group-hover:shadow-[0_0_30px_-5px_max(rgba(99,102,241,0.4),rgba(0,0,0,0))]'
    },
    {
      icon: Target,
      title: 'MITRE ATT&CK Mapping',
      description: 'Every alert is enriched and mapped to kill-chain techniques. Visualize detection gaps on a dynamic heatmap.',
      color: 'text-rose-500 dark:text-rose-400',
      bg: 'bg-rose-500/10 dark:bg-rose-500/20',
      glow: 'group-hover:shadow-[0_0_30px_-5px_max(rgba(244,63,94,0.2),rgba(0,0,0,0))] dark:group-hover:shadow-[0_0_30px_-5px_max(rgba(244,63,94,0.4),rgba(0,0,0,0))]'
    },
    {
      icon: Brain,
      title: 'AI-Powered Triage',
      description: 'Leverage LLMs for plain-English alert summaries, root cause analysis, and actionable remediation steps.',
      color: 'text-emerald-500 dark:text-emerald-400',
      bg: 'bg-emerald-500/10 dark:bg-emerald-500/20',
      glow: 'group-hover:shadow-[0_0_30px_-5px_max(rgba(16,185,129,0.2),rgba(0,0,0,0))] dark:group-hover:shadow-[0_0_30px_-5px_max(rgba(16,185,129,0.4),rgba(0,0,0,0))]'
    },
    {
      icon: Zap,
      title: 'Risk Scoring Engine',
      description: 'Advanced correlation algorithms dynamically adjust alert severity based on asset criticality and past incidents.',
      color: 'text-amber-500 dark:text-amber-400',
      bg: 'bg-amber-500/10 dark:bg-amber-500/20',
      glow: 'group-hover:shadow-[0_0_30px_-5px_max(rgba(245,158,11,0.2),rgba(0,0,0,0))] dark:group-hover:shadow-[0_0_30px_-5px_max(rgba(245,158,11,0.4),rgba(0,0,0,0))]'
    },
    {
      icon: Shield,
      title: 'Multi-Source Ingestion',
      description: 'Normalize logs from AWS GuardDuty, Azure Sentinel, CrowdStrike, Zeek, Snort, and generic Syslog.',
      color: 'text-blue-500 dark:text-blue-400',
      bg: 'bg-blue-500/10 dark:bg-blue-500/20',
      glow: 'group-hover:shadow-[0_0_30px_-5px_max(rgba(59,130,246,0.2),rgba(0,0,0,0))] dark:group-hover:shadow-[0_0_30px_-5px_max(rgba(59,130,246,0.4),rgba(0,0,0,0))]'
    },
    {
      icon: KeyRound,
      title: 'Enterprise SSO',
      description: 'Frictionless integration with Okta, Microsoft Entra ID, and other OIDC providers with automated user provisioning.',
      color: 'text-cyan-500 dark:text-cyan-400',
      bg: 'bg-cyan-500/10 dark:bg-cyan-500/20',
      glow: 'group-hover:shadow-[0_0_30px_-5px_max(rgba(6,182,212,0.2),rgba(0,0,0,0))] dark:group-hover:shadow-[0_0_30px_-5px_max(rgba(6,182,212,0.4),rgba(0,0,0,0))]'
    },
  ]

  return (
    <div className="min-h-screen bg-soc-bg text-soc-text font-sans selection:bg-blue-500/30 overflow-x-hidden transition-colors duration-500">
      <a
        href="#main-content"
        className="absolute left-4 top-4 -translate-y-[9999px] focus:translate-y-0 z-[100] px-4 py-2 rounded-lg bg-blue-600 text-white text-sm font-medium focus:outline-none focus:ring-2 focus:ring-blue-400"
      >
        Skip to main content
      </a>

      {/* Dynamic Background */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden z-0">
        <div className="absolute inset-0 bg-[linear-gradient(rgba(0,0,0,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(0,0,0,0.03)_1px,transparent_1px)] dark:bg-[linear-gradient(rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.02)_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)]" />
        <div className="absolute -top-[40%] -left-[10%] w-[70%] h-[70%] rounded-full bg-blue-400/20 dark:bg-blue-900/10 blur-[120px] mix-blend-multiply dark:mix-blend-screen transition-colors duration-700" />
        <div className="absolute top-[20%] -right-[20%] w-[60%] h-[60%] rounded-full bg-indigo-400/20 dark:bg-indigo-900/10 blur-[120px] mix-blend-multiply dark:mix-blend-screen transition-colors duration-700" />
      </div>

      <header className="relative z-50 border-b border-soc-border bg-soc-surface/40 backdrop-blur-xl transition-colors duration-500">
        <div className="max-w-7xl mx-auto px-6 h-20 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-blue-600 to-indigo-600 shadow-lg shadow-blue-500/20">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <span className="text-2xl font-bold tracking-tight text-soc-text">KESTREL</span>
          </div>
          <nav className="flex items-center gap-6">
            <button
              type="button"
              onClick={toggleTheme}
              className="p-2 rounded-full hover:bg-black/5 dark:hover:bg-white/5 text-soc-muted hover:text-soc-text transition-colors"
              title={theme === 'light' ? 'Dark mode' : 'Light mode'}
            >
              {theme === 'light' ? <Moon className="w-5 h-5" /> : <Sun className="w-5 h-5" />}
            </button>
            <Link
              to="/setup"
              className="text-sm font-medium text-soc-text hover:text-blue-500 transition-colors"
            >
              Admin Setup
            </Link>
            <Link
              to="/login"
              className="text-sm px-5 py-2.5 rounded-full bg-soc-text text-soc-bg font-semibold hover:opacity-90 transition-all shadow-lg shadow-black/10 dark:shadow-white/10"
            >
              Sign In
            </Link>
          </nav>
        </div>
      </header>

      <main id="main-content" className="relative z-10" tabIndex={-1}>
        {/* Hero Section */}
        <section className="relative pt-32 pb-20 lg:pt-48 lg:pb-32 overflow-hidden">
          <div className="max-w-7xl mx-auto px-6 text-center">
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-blue-500/30 bg-blue-500/10 text-blue-600 dark:text-blue-400 text-sm font-medium mb-8 backdrop-blur-sm">
              <span className="w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
              Next-Gen SOC Platform
            </div>

            <h1 className="text-5xl md:text-7xl font-extrabold tracking-tight mb-8">
              <span className="text-soc-text">Cut through the noise.</span>
              <br />
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-600 via-indigo-500 to-purple-500 dark:from-blue-400 dark:via-indigo-400 dark:to-purple-400">
                Automate the response.
              </span>
            </h1>

            <p className="text-lg md:text-xl text-soc-muted max-w-3xl mx-auto mb-12 leading-relaxed">
              KESTREL is the modern, AI-assisted security orchestration platform.
              Aggregate alerts, map to MITRE ATT&CK, execute SOAR playbooks automatically,
              and let AI triage the rest.
            </p>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <Link
                to="/login"
                className="w-full sm:w-auto flex items-center justify-center gap-2 px-8 py-4 rounded-full bg-soc-text text-soc-bg font-bold text-lg hover:scale-105 transition-transform duration-300 shadow-xl shadow-black/10 dark:shadow-white/10"
              >
                Launch Console
                <ArrowRight className="w-5 h-5" />
              </Link>
              <Link
                to="/setup"
                className="w-full sm:w-auto flex items-center justify-center gap-2 px-8 py-4 rounded-full border border-soc-border bg-soc-surface text-soc-text font-semibold text-lg hover:bg-black/5 dark:hover:bg-white/5 transition-colors backdrop-blur-md"
              >
                Initial Setup
                <ChevronRight className="w-5 h-5 text-soc-muted" />
              </Link>
            </div>
          </div>
        </section>

        {/* Realistic Mockup Preview */}
        <section className="max-w-6xl mx-auto px-6 pb-32">
          <div className="relative rounded-2xl border border-soc-border bg-soc-surface backdrop-blur-xl shadow-[0_0_50px_rgba(0,0,0,0.1)] dark:shadow-[0_0_50px_rgba(99,102,241,0.15)] overflow-hidden transform perspective-1000 rotate-x-2 lg:scale-105 transition-all duration-500 hover:shadow-[0_0_80px_rgba(0,0,0,0.15)] dark:hover:shadow-[0_0_80px_rgba(99,102,241,0.25)]">

            {/* Browser frame */}
            <div className="h-10 border-b border-soc-border bg-soc-surface/50 flex items-center px-4 gap-2">
              <div className="flex gap-2.5">
                <div className="w-3 h-3 rounded-full bg-rose-500/80 hover:bg-rose-500 transition-colors cursor-pointer" />
                <div className="w-3 h-3 rounded-full bg-amber-500/80 hover:bg-amber-500 transition-colors cursor-pointer" />
                <div className="w-3 h-3 rounded-full bg-emerald-500/80 hover:bg-emerald-500 transition-colors cursor-pointer" />
              </div>
              <div className="ml-6 px-4 py-1 text-xs text-soc-muted font-mono bg-soc-border/50 rounded-md border border-soc-border flex-1 max-w-md flex items-center gap-2 m-auto justify-center">
                <Lock className="w-3 h-3" /> https://kestrel.security.internal/app/dashboard
              </div>
            </div>

            {/* App UI */}
            <div className="flex h-[500px] text-left">

              {/* Sidebar */}
              <div className="w-48 border-r border-soc-border p-3 flex flex-col gap-2 bg-soc-surface/30">
                <div className="flex items-center gap-2 mb-6 px-2 mt-2">
                  <Shield className="w-5 h-5 text-blue-500" />
                  <span className="font-bold text-sm text-soc-text">KESTREL</span>
                </div>
                <div className="px-3 py-2 rounded-lg bg-blue-500/10 text-blue-600 dark:text-blue-400 text-xs font-medium border border-blue-500/20 flex items-center gap-2">
                  <Activity className="w-3.5 h-3.5" /> Dashboard
                </div>
                <div className="px-3 py-2 rounded-lg text-soc-muted text-xs font-medium hover:bg-soc-border/50 transition-colors flex items-center gap-2">
                  <AlertTriangle className="w-3.5 h-3.5" /> Alerts <span className="ml-auto bg-rose-500 text-white text-[10px] px-1.5 rounded-full">12</span>
                </div>
                <div className="px-3 py-2 rounded-lg text-soc-muted text-xs font-medium hover:bg-soc-border/50 transition-colors flex items-center gap-2">
                  <Workflow className="w-3.5 h-3.5" /> Playbooks
                </div>
                <div className="px-3 py-2 rounded-lg text-soc-muted text-xs font-medium hover:bg-soc-border/50 transition-colors flex items-center gap-2">
                  <Target className="w-3.5 h-3.5" /> MITRE ATT&CK
                </div>
              </div>

              {/* Main Content */}
              <div className="flex-1 p-6 flex flex-col gap-6 bg-gradient-to-br from-transparent to-indigo-900/5 overflow-hidden">

                {/* Header Metrics */}
                <div className="flex justify-between items-end">
                  <div>
                    <h2 className="text-xl font-bold text-soc-text mb-1">Overview</h2>
                    <p className="text-xs text-soc-muted">Last 24 hours across all active sources.</p>
                  </div>
                  <div className="flex gap-2">
                    <span className="px-3 py-1.5 text-xs font-medium rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">System Healthy</span>
                  </div>
                </div>

                {/* Scorecards */}
                <div className="grid grid-cols-3 gap-4">
                  <div className="p-4 rounded-xl bg-soc-surface border border-soc-border shadow-sm">
                    <p className="text-xs text-soc-muted mb-2">High Severity Alerts</p>
                    <div className="flex items-end justify-between">
                      <span className="text-2xl font-bold text-rose-500 dark:text-rose-400">12</span>
                      <span className="text-xs text-rose-500 dark:text-rose-400 flex items-center">↑ 4 today</span>
                    </div>
                  </div>
                  <div className="p-4 rounded-xl bg-soc-surface border border-soc-border shadow-sm">
                    <p className="text-xs text-soc-muted mb-2">AI Triage Rate</p>
                    <div className="flex items-end justify-between">
                      <span className="text-2xl font-bold text-emerald-500 dark:text-emerald-400">98.5%</span>
                      <span className="text-xs text-soc-muted">of 1,204 total</span>
                    </div>
                  </div>
                  <div className="p-4 rounded-xl bg-soc-surface border border-soc-border shadow-sm">
                    <p className="text-xs text-soc-muted mb-2">Playbooks Executed</p>
                    <div className="flex items-end justify-between">
                      <span className="text-2xl font-bold text-indigo-500 dark:text-indigo-400">84</span>
                      <span className="text-xs text-emerald-500 dark:text-emerald-400">Automated</span>
                    </div>
                  </div>
                </div>

                {/* Alert Table & AI Pane */}
                <div className="flex-1 flex gap-4 h-full min-h-0">

                  {/* Table */}
                  <div className="flex-[2] rounded-xl bg-soc-surface border border-soc-border flex flex-col overflow-hidden shadow-sm">
                    <div className="border-b border-soc-border px-4 py-3 flex text-xs font-semibold text-soc-muted uppercase tracking-wider bg-soc-border/20">
                      <div className="w-24">Severity</div>
                      <div className="flex-1">Alert Title</div>
                      <div className="w-32 text-right">Source</div>
                    </div>
                    {/* Rows */}
                    <div className="flex flex-col">
                      <div className="px-4 py-3 flex items-center text-xs border-b border-soc-border/50 hover:bg-soc-border/30 cursor-pointer bg-blue-500/5">
                        <div className="w-24"><span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20">CRITICAL</span></div>
                        <div className="flex-1 font-medium text-soc-text truncate pr-4">Suspicious PowerShell Execution detected on DC-01</div>
                        <div className="w-32 text-right text-soc-muted">CrowdStrike</div>
                      </div>
                      <div className="px-4 py-3 flex items-center text-xs border-b border-soc-border/50 hover:bg-soc-border/30 cursor-pointer">
                        <div className="w-24"><span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20">HIGH</span></div>
                        <div className="flex-1 font-medium text-soc-text truncate pr-4">Multiple failed SSH logins for user 'root'</div>
                        <div className="w-32 text-right text-soc-muted">Syslog</div>
                      </div>
                      <div className="px-4 py-3 flex items-center text-xs border-b border-soc-border/50 hover:bg-soc-border/30 cursor-pointer">
                        <div className="w-24"><span className="px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-500/20">MEDIUM</span></div>
                        <div className="flex-1 font-medium text-soc-text truncate pr-4">Unusual outbound traffic to known Tor exit node</div>
                        <div className="w-32 text-right text-soc-muted">Suricata</div>
                      </div>
                    </div>
                  </div>

                  {/* AI Triage Panel */}
                  <div className="flex-[1] rounded-xl bg-gradient-to-br from-indigo-500/10 to-blue-500/5 border border-indigo-500/20 p-4 flex flex-col gap-3 shadow-sm">
                    <div className="flex items-center gap-2 text-indigo-600 dark:text-indigo-400 mb-1">
                      <Brain className="w-4 h-4" />
                      <span className="text-xs font-bold uppercase tracking-wider">AI Analysis</span>
                    </div>
                    <div className="text-sm font-medium text-soc-text">PowerShell Execution (DC-01)</div>
                    <p className="text-[11px] leading-relaxed text-soc-text/80">
                      I analyzed this event. The payload is heavily obfuscated Base64, consistent with Cobalt Strike deployment.
                      Command involves `IEX(New-Object Net.WebClient).DownloadString`.
                    </p>
                    <div className="mt-auto space-y-2">
                      <span className="block text-[10px] font-semibold text-soc-muted uppercase">Recommended Actions</span>
                      <div className="bg-soc-border/30 border border-soc-border rounded-lg p-2 text-xs flex items-center gap-2 cursor-pointer hover:bg-soc-border/50 transition-colors text-soc-text">
                        <Shield className="w-3 h-3 text-emerald-500" /> Contain Host (DC-01)
                      </div>
                      <div className="bg-soc-border/30 border border-soc-border rounded-lg p-2 text-xs flex items-center gap-2 cursor-pointer hover:bg-soc-border/50 transition-colors opacity-60 text-soc-text">
                        <Workflow className="w-3 h-3 text-blue-500" /> Elevate to P1 Incident
                      </div>
                    </div>
                  </div>

                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Features Grid */}
        <section className="relative z-20 py-24 bg-soc-surface/40 border-y border-soc-border backdrop-blur-xl">
          <div className="max-w-7xl mx-auto px-6">
            <div className="text-center mb-16">
              <h2 className="text-3xl md:text-4xl font-bold text-soc-text mb-4">
                Everything an analyst needs
              </h2>
              <p className="text-soc-muted max-w-2xl mx-auto text-lg">
                Stop jumping between tabs. KESTREL consolidates alerts, enrichment, automation, and identity into a single pane of glass.
              </p>
            </div>

            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
              {features.map((feat) => (
                <div
                  key={feat.title}
                  className={`group relative p-8 rounded-2xl bg-soc-surface border border-soc-border hover:border-blue-500/30 transition-all duration-300 ${feat.glow} shadow-sm`}
                >
                  <div className={`inline-flex p-3 rounded-xl ${feat.bg} ${feat.color} mb-6 ring-1 ring-black/5 dark:ring-white/10 group-hover:scale-110 transition-transform duration-300`}>
                    <feat.icon className="w-6 h-6" />
                  </div>
                  <h3 className="text-xl font-semibold text-soc-text mb-3 tracking-tight">
                    {feat.title}
                  </h3>
                  <p className="text-soc-muted tracking-wide transition-colors leading-relaxed">
                    {feat.description}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Bottom CTA */}
        <section className="py-32 relative overflow-hidden">
          <div className="absolute inset-0 bg-blue-900/5 [mask-image:radial-gradient(ellipse_at_center,black,transparent_70%)]" />
          <div className="max-w-4xl mx-auto px-6 text-center relative z-10">
            <h2 className="text-4xl font-bold text-soc-text mb-6">
              Ready to secure your enterprise?
            </h2>
            <p className="text-xl text-soc-muted mb-10 max-w-2xl mx-auto">
              Deploy KESTREL in minutes. Hook up your identity provider, stream your alerts, and let the playbooks run.
            </p>
            <Link
              to="/login"
              className="inline-flex items-center gap-2 px-8 py-4 rounded-full bg-gradient-to-r from-blue-600 to-indigo-600 text-white font-bold text-lg hover:from-blue-500 hover:to-indigo-500 hover:shadow-[0_0_40px_-10px_rgba(99,102,241,0.6)] transition-all duration-300 transform hover:-translate-y-1"
            >
              Sign in with Enterprise SSO
              <ArrowRight className="w-5 h-5" />
            </Link>
          </div>
        </section>
      </main>

      <footer className="relative z-20 border-t border-soc-border bg-soc-bg py-8">
        <div className="max-w-7xl mx-auto px-6 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-blue-500" />
            <span className="font-bold text-soc-text tracking-widest">KESTREL</span>
          </div>
          <p className="text-soc-muted text-sm">
            © {new Date().getFullYear()} Kestrel Security Platform. Building robust SOCs.
          </p>
        </div>
      </footer>
    </div>
  )
}
