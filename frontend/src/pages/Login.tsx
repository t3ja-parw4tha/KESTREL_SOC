import { useState } from 'react'
import { useNavigate, useLocation, Link } from 'react-router-dom'
import { useAuth } from '@/security/AuthContext'
import {
  Shield, Eye, EyeOff, Mail, Lock, User,
  Activity, Zap, Globe, CheckCircle2, ArrowRight,
} from 'lucide-react'

function parseUserFromToken(token: string) {
  try {
    const part = token.split('.')[1]
    if (!part) return null
    const payload = JSON.parse(atob(part))
    const role = ['admin', 'senior_analyst', 'analyst', 'viewer'].includes(payload.role)
      ? payload.role : 'viewer'
    return {
      id: String(payload.sub ?? ''),
      username: String(payload.username ?? 'user'),
      role: role as 'admin' | 'senior_analyst' | 'analyst' | 'viewer',
    }
  } catch { return null }
}

// Fake "live" threat events for the left panel atmosphere
const LIVE_EVENTS = [
  { time: '00:12', msg: 'Brute force blocked — 45.83.12.190', sev: 'high' },
  { time: '00:31', msg: 'Lateral movement detected — ws-142', sev: 'critical' },
  { time: '01:05', msg: 'Phishing URL quarantined — user@corp.com', sev: 'medium' },
  { time: '02:18', msg: 'Privilege escalation attempt — svc-account', sev: 'critical' },
  { time: '03:44', msg: 'C2 callback blocked — 91.219.62.14', sev: 'high' },
]
const SEV_COLOR = { critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400' }

export function Login() {
  const [username, setUsername]       = useState('')
  const [password, setPassword]       = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError]             = useState('')
  const [loading, setLoading]         = useState(false)
  const [ssoEmail, setSsoEmail]       = useState('')
  const [ssoOpen, setSsoOpen]         = useState(false)
  const { login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const from = (location.state as { from?: { pathname: string } })?.from?.pathname ?? '/app'

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const res = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        setError(data.detail ?? 'Invalid username or password')
        return
      }
      const data = await res.json()
      const token = data.access_token
      const user = parseUserFromToken(token)
      if (!user) { setError('Invalid token received'); return }
      if (user.username === 'user') user.username = username
      login(token, user)
      navigate(from, { replace: true })
    } catch {
      setError('Could not connect to server')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex overflow-hidden" style={{ background: 'hsl(222, 47%, 5%)' }}>

      {/* ── LEFT PANEL — branding + live activity ──────────────────────────── */}
      <div className="hidden lg:flex lg:w-[58%] relative flex-col overflow-hidden"
           style={{ background: 'linear-gradient(135deg, hsl(222,47%,7%) 0%, hsl(230,50%,9%) 50%, hsl(240,48%,8%) 100%)' }}>

        {/* Animated grid */}
        <div className="absolute inset-0 opacity-[0.035]"
             style={{ backgroundImage: 'linear-gradient(rgba(99,102,241,1) 1px, transparent 1px), linear-gradient(90deg,rgba(99,102,241,1) 1px,transparent 1px)', backgroundSize: '48px 48px' }} />

        {/* Large ambient orb */}
        <div className="absolute top-[-20%] left-[-10%] w-[70%] h-[70%] rounded-full opacity-20 animate-float"
             style={{ background: 'radial-gradient(circle, hsl(240,80%,40%) 0%, transparent 70%)' }} />
        <div className="absolute bottom-[-15%] right-[-5%] w-[50%] h-[60%] rounded-full opacity-10 animate-float [animation-delay:3s]"
             style={{ background: 'radial-gradient(circle, hsl(260,80%,50%) 0%, transparent 70%)' }} />

        {/* Radar rings — centered */}
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="absolute rounded-full border border-blue-500/[0.06]"
                 style={{ width: `${i * 160}px`, height: `${i * 160}px` }} />
          ))}
          {/* Sweep */}
          <div className="absolute w-[640px] h-[640px] rounded-full overflow-hidden opacity-20"
               style={{ animation: 'spin 8s linear infinite' }}>
            <div className="absolute inset-0 rounded-full"
                 style={{ background: 'conic-gradient(from 0deg, transparent 0deg, hsl(217,91%,60%) 1deg, transparent 60deg)' }} />
          </div>
        </div>

        {/* Content */}
        <div className="relative z-10 flex flex-col h-full p-10 xl:p-14">
          {/* Top: logo */}
          <div className="flex items-center gap-3">
            <div className="relative">
              <div className="absolute inset-0 rounded-xl blur-md scale-125 opacity-60 animate-glow-pulse"
                   style={{ background: 'linear-gradient(135deg,hsl(217,91%,60%),hsl(240,80%,60%))' }} />
              <div className="relative w-9 h-9 rounded-xl gradient-primary flex items-center justify-center">
                <Shield className="w-4.5 h-4.5 text-white" />
              </div>
            </div>
            <span className="text-sm font-bold tracking-[0.2em] text-white/60 uppercase">Kestrel SOC</span>
          </div>

          {/* Middle: headline */}
          <div className="flex-1 flex flex-col justify-center mt-[-10%]">
            <div className="mb-3">
              <span className="inline-flex items-center gap-1.5 text-[10px] font-semibold tracking-[0.15em] uppercase text-blue-400/80 bg-blue-500/10 border border-blue-500/20 rounded-full px-3 py-1">
                <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />
                AI-Powered Detection
              </span>
            </div>
            <h1 className="text-4xl xl:text-5xl font-bold text-white leading-tight mb-4">
              Security Operations<br />
              <span style={{ background: 'linear-gradient(135deg,#60a5fa,#818cf8,#a78bfa)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                at machine speed.
              </span>
            </h1>
            <p className="text-white/40 text-sm leading-relaxed max-w-[340px]">
              Unified threat detection, AI-assisted triage, and incident response — from alert to resolution in minutes.
            </p>

            {/* Feature pills */}
            <div className="flex flex-wrap gap-2 mt-6">
              {[
                { icon: Zap,          label: 'Real-time alerts' },
                { icon: Activity,     label: 'AI triage' },
                { icon: Globe,        label: '30+ integrations' },
                { icon: CheckCircle2, label: 'MITRE ATT&CK mapped' },
              ].map(({ icon: Icon, label }) => (
                <div key={label} className="flex items-center gap-1.5 text-[11px] text-white/50 bg-white/[0.04] border border-white/[0.06] rounded-full px-3 py-1">
                  <Icon className="w-3 h-3 text-blue-400/70" />
                  {label}
                </div>
              ))}
            </div>
          </div>

          {/* Bottom: live threat feed */}
          <div className="border-t border-white/[0.06] pt-5">
            <div className="flex items-center gap-2 mb-3">
              <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
              <span className="text-[10px] font-semibold uppercase tracking-widest text-white/30">Live threat feed</span>
            </div>
            <div className="space-y-2">
              {LIVE_EVENTS.slice(0, 3).map((ev, i) => (
                <div key={i} className="flex items-center gap-3 text-[11px]">
                  <span className="font-mono text-white/20 w-10 shrink-0">{ev.time}</span>
                  <span className={`w-1 h-1 rounded-full shrink-0 ${ev.sev === 'critical' ? 'bg-red-400' : ev.sev === 'high' ? 'bg-orange-400' : 'bg-yellow-400'}`} />
                  <span className="text-white/40 truncate">{ev.msg}</span>
                  <span className={`shrink-0 font-medium ${SEV_COLOR[ev.sev as keyof typeof SEV_COLOR]}`}>{ev.sev}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* ── RIGHT PANEL — login form ────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col items-center justify-center relative px-6 py-12"
           style={{ background: 'hsl(222,47%,5%)' }}>

        {/* Subtle right-side ambient */}
        <div className="absolute top-[-20%] right-[-20%] w-[60%] h-[60%] rounded-full opacity-[0.06] pointer-events-none animate-float [animation-delay:1s]"
             style={{ background: 'radial-gradient(circle, hsl(217,91%,60%) 0%, transparent 70%)' }} />

        <div className="relative w-full max-w-[360px] animate-scale-in">

          {/* Mobile-only back link */}
          <Link to="/" className="lg:hidden inline-flex items-center gap-1 text-white/30 hover:text-white/60 text-xs mb-6 transition-colors">
            ← Back to home
          </Link>

          {/* Mobile-only logo */}
          <div className="lg:hidden flex flex-col items-center mb-8">
            <div className="relative mb-3">
              <div className="absolute inset-0 rounded-2xl blur-lg scale-125 opacity-60 animate-glow-pulse"
                   style={{ background: 'linear-gradient(135deg,hsl(217,91%,60%),hsl(240,80%,60%))' }} />
              <div className="relative w-12 h-12 rounded-2xl gradient-primary flex items-center justify-center">
                <Shield className="w-6 h-6 text-white" />
              </div>
            </div>
            <h2 className="text-xl font-bold tracking-widest uppercase" style={{ background: 'linear-gradient(135deg,#60a5fa,#818cf8,#a78bfa)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              KESTREL
            </h2>
            <p className="text-xs text-white/30 mt-0.5">AI-assisted threat detection</p>
          </div>

          {/* Form header */}
          <div className="mb-7">
            <h2 className="text-2xl font-bold text-white mb-1">Welcome back</h2>
            <p className="text-sm text-white/35">Sign in to your SOC workspace</p>
          </div>

          {/* Error */}
          {error && (
            <div className="mb-5 p-3 rounded-xl border border-red-500/20 bg-red-500/[0.08] animate-fade-in">
              <p className="text-xs text-red-400" role="alert">{error}</p>
            </div>
          )}

          {/* Credentials form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="login-username" className="block text-[10px] font-semibold text-white/35 mb-2 uppercase tracking-[0.15em]">
                Username
              </label>
              <div className="relative group">
                <User className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-white/20 group-focus-within:text-blue-400/60 transition-colors pointer-events-none" />
                <input
                  id="login-username"
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="johndoe"
                  autoComplete="username"
                  required
                  className="w-full pl-10 pr-4 py-3 rounded-xl text-sm text-white placeholder:text-white/20 transition-all duration-200 focus:outline-none"
                  style={{
                    background: 'rgba(255,255,255,0.04)',
                    border: '1px solid rgba(255,255,255,0.08)',
                  }}
                  onFocus={(e) => { e.target.style.border = '1px solid rgba(99,102,241,0.5)'; e.target.style.boxShadow = '0 0 0 3px rgba(99,102,241,0.12)' }}
                  onBlur={(e) => { e.target.style.border = '1px solid rgba(255,255,255,0.08)'; e.target.style.boxShadow = 'none' }}
                />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-2">
                <label htmlFor="login-password" className="block text-[10px] font-semibold text-white/35 uppercase tracking-[0.15em]">
                  Password
                </label>
                <button type="button" className="text-[10px] text-blue-400/60 hover:text-blue-400 transition-colors">
                  Forgot password?
                </button>
              </div>
              <div className="relative group">
                <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-white/20 group-focus-within:text-blue-400/60 transition-colors pointer-events-none" />
                <input
                  id="login-password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  autoComplete="current-password"
                  required
                  className="w-full pl-10 pr-11 py-3 rounded-xl text-sm text-white placeholder:text-white/20 transition-all duration-200 focus:outline-none"
                  style={{
                    background: 'rgba(255,255,255,0.04)',
                    border: '1px solid rgba(255,255,255,0.08)',
                  }}
                  onFocus={(e) => { e.target.style.border = '1px solid rgba(99,102,241,0.5)'; e.target.style.boxShadow = '0 0 0 3px rgba(99,102,241,0.12)' }}
                  onBlur={(e) => { e.target.style.border = '1px solid rgba(255,255,255,0.08)'; e.target.style.boxShadow = 'none' }}
                />
                <button type="button" onClick={() => setShowPassword((v) => !v)} aria-label="Toggle visibility"
                  className="absolute right-3.5 top-1/2 -translate-y-1/2 text-white/20 hover:text-white/50 transition-colors">
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Remember me */}
            <label className="flex items-center gap-2.5 cursor-pointer select-none">
              <input type="checkbox" className="w-3.5 h-3.5 rounded border border-white/20 bg-white/5 accent-indigo-500 cursor-pointer" />
              <span className="text-xs text-white/35">Remember me for 30 days</span>
            </label>

            {/* Submit */}
            <button type="submit" disabled={loading}
              className="w-full py-3 rounded-xl font-semibold text-sm text-white flex items-center justify-center gap-2 transition-all duration-200 active:scale-[0.99] disabled:opacity-50 disabled:cursor-not-allowed mt-2"
              style={{
                background: loading ? 'rgba(99,102,241,0.4)' : 'linear-gradient(135deg, hsl(217,91%,55%), hsl(240,80%,55%))',
                boxShadow: loading ? 'none' : '0 4px 24px rgba(99,102,241,0.4), inset 0 1px 0 rgba(255,255,255,0.15)',
              }}
              onMouseEnter={(e) => { if (!loading) e.currentTarget.style.boxShadow = '0 6px 32px rgba(99,102,241,0.55), inset 0 1px 0 rgba(255,255,255,0.2)' }}
              onMouseLeave={(e) => { if (!loading) e.currentTarget.style.boxShadow = '0 4px 24px rgba(99,102,241,0.4), inset 0 1px 0 rgba(255,255,255,0.15)' }}
            >
              {loading ? (
                <>
                  <span className="w-4 h-4 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                  Authenticating…
                </>
              ) : (
                <>
                  Sign in
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Divider */}
          <div className="my-5 flex items-center gap-3">
            <div className="flex-1 h-px" style={{ background: 'rgba(255,255,255,0.06)' }} />
            <span className="text-[10px] text-white/20 shrink-0 uppercase tracking-widest">or</span>
            <div className="flex-1 h-px" style={{ background: 'rgba(255,255,255,0.06)' }} />
          </div>

          {/* SSO */}
          {!ssoOpen ? (
            <button type="button" onClick={() => setSsoOpen(true)}
              className="w-full py-2.5 rounded-xl text-sm font-medium text-white/50 hover:text-white/80 transition-all duration-200"
              style={{ border: '1px solid rgba(255,255,255,0.07)', background: 'rgba(255,255,255,0.03)' }}
              onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(255,255,255,0.06)'; e.currentTarget.style.borderColor = 'rgba(255,255,255,0.12)' }}
              onMouseLeave={(e) => { e.currentTarget.style.background = 'rgba(255,255,255,0.03)'; e.currentTarget.style.borderColor = 'rgba(255,255,255,0.07)' }}
            >
              Continue with SSO
            </button>
          ) : (
            <form className="space-y-3 animate-fade-in"
              onSubmit={(e) => { e.preventDefault(); if (ssoEmail) window.location.href = `/api/v1/auth/sso/login?email=${encodeURIComponent(ssoEmail)}` }}>
              <div className="relative">
                <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-white/20 pointer-events-none" />
                <input type="email" value={ssoEmail} onChange={(e) => setSsoEmail(e.target.value)} placeholder="name@company.com" autoFocus
                  className="w-full pl-10 pr-4 py-3 rounded-xl text-sm text-white placeholder:text-white/20 focus:outline-none transition-all"
                  style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}
                  onFocus={(e) => { e.target.style.border = '1px solid rgba(99,102,241,0.5)'; e.target.style.boxShadow = '0 0 0 3px rgba(99,102,241,0.12)' }}
                  onBlur={(e) => { e.target.style.border = '1px solid rgba(255,255,255,0.08)'; e.target.style.boxShadow = 'none' }}
                />
              </div>
              <div className="flex gap-2">
                <button type="submit" disabled={!ssoEmail}
                  className="flex-1 py-2.5 rounded-xl text-sm font-medium text-white transition-all disabled:opacity-30 disabled:cursor-not-allowed"
                  style={{ background: 'rgba(99,102,241,0.25)', border: '1px solid rgba(99,102,241,0.3)' }}>
                  Continue with SSO
                </button>
                <button type="button" onClick={() => { setSsoOpen(false); setSsoEmail('') }}
                  className="px-4 py-2.5 rounded-xl text-xs text-white/30 hover:text-white/60 transition-colors"
                  style={{ border: '1px solid rgba(255,255,255,0.07)' }}>
                  Cancel
                </button>
              </div>
            </form>
          )}

          {/* Footer */}
          <div className="mt-8 pt-6 border-t flex items-center justify-between" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
            <p className="text-[10px] text-white/15">Kestrel SOC Platform</p>
            <div className="flex items-center gap-1 text-[10px] text-white/15">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500/60" />
              Secure · Encrypted
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
