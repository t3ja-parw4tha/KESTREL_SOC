import { useState } from 'react'
import { useNavigate, useLocation, Link } from 'react-router-dom'
import { useAuth } from '@/security/AuthContext'
import { Shield, Eye, EyeOff, Mail, Lock, User } from 'lucide-react'

function parseUserFromToken(token: string) {
  try {
    const part = token.split('.')[1]
    if (!part) return null
    const payload = JSON.parse(atob(part))
    const role = ['admin', 'senior_analyst', 'analyst', 'viewer'].includes(payload.role) ? payload.role : 'viewer'
    return {
      id: String(payload.sub ?? ''),
      username: String(payload.username ?? 'user'),
      role: role as 'admin' | 'senior_analyst' | 'analyst' | 'viewer',
    }
  } catch {
    return null
  }
}

export function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [ssoEmail, setSsoEmail] = useState('')
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
    <div className="min-h-screen flex items-center justify-center relative overflow-hidden bg-[#07070f]">
      {/* Ambient background blobs */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute -top-[30%] -left-[10%] w-[70%] h-[70%] rounded-full bg-indigo-900/20 blur-[120px]" />
        <div className="absolute top-[40%] -right-[15%] w-[60%] h-[60%] rounded-full bg-blue-900/15 blur-[100px]" />
        <div className="absolute bottom-[10%] left-[20%] w-[40%] h-[40%] rounded-full bg-violet-900/10 blur-[80px]" />
        <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.025)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.025)_1px,transparent_1px)] bg-[size:48px_48px] [mask-image:radial-gradient(ellipse_80%_80%_at_50%_50%,#000_60%,transparent_100%)]" />
      </div>

      <div className="relative w-full max-w-sm mx-4 animate-slide-up">
        <Link to="/" className="inline-flex items-center gap-1.5 text-white/35 hover:text-white/65 text-sm mb-6 transition-colors">
          ← Back to home
        </Link>

        {/* Glass card */}
        <div className="rounded-2xl border border-white/[0.08] bg-white/[0.04] backdrop-blur-2xl p-8"
             style={{ boxShadow: '0 16px 48px rgba(0,0,0,0.6), 0 0 0 1px rgba(255,255,255,0.04)' }}>

          {/* Logo */}
          <div className="flex flex-col items-center mb-8">
            <div className="relative mb-4">
              <div className="absolute inset-0 rounded-2xl bg-blue-500/25 blur-xl scale-150" />
              <div className="relative w-14 h-14 rounded-2xl bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center"
                   style={{ boxShadow: '0 8px 24px rgba(76,110,245,0.5)' }}>
                <Shield className="w-7 h-7 text-white" />
              </div>
            </div>
            <h1 className="text-2xl font-bold tracking-tight"
                style={{ background: 'linear-gradient(135deg,#60a5fa,#818cf8,#a78bfa)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              KESTREL
            </h1>
            <p className="text-sm text-white/35 mt-1">AI-assisted threat detection</p>
          </div>

          {error && (
            <div className="mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/20 animate-fade-in">
              <p className="text-sm text-red-400" role="alert">{error}</p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="login-username" className="block text-[11px] font-semibold text-white/40 mb-1.5 uppercase tracking-widest">
                Username
              </label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-white/20 pointer-events-none" />
                <input
                  id="login-username"
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full pl-9 pr-3 py-2.5 rounded-lg border border-white/[0.08] bg-white/[0.06] text-white placeholder:text-white/20 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500/50 transition-all"
                  placeholder="johndoe"
                  autoComplete="username"
                  required
                />
              </div>
            </div>

            <div>
              <label htmlFor="login-password" className="block text-[11px] font-semibold text-white/40 mb-1.5 uppercase tracking-widest">
                Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-white/20 pointer-events-none" />
                <input
                  id="login-password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-9 pr-10 py-2.5 rounded-lg border border-white/[0.08] bg-white/[0.06] text-white placeholder:text-white/20 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500/50 transition-all"
                  placeholder="••••••••"
                  autoComplete="current-password"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-white/20 hover:text-white/50 transition-colors"
                  aria-label="Toggle visibility"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 mt-2 rounded-lg font-semibold text-sm text-white
                         bg-gradient-to-r from-blue-600 to-indigo-600
                         hover:from-blue-500 hover:to-indigo-500
                         active:scale-[0.99] transition-all duration-150
                         disabled:opacity-50 disabled:cursor-not-allowed"
              style={{ boxShadow: loading ? 'none' : '0 1px 2px rgba(0,0,0,0.3), inset 0 1px 0 rgba(255,255,255,0.1), 0 4px 20px rgba(76,110,245,0.35)' }}
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <span className="w-4 h-4 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                  Signing in...
                </span>
              ) : 'Sign in'}
            </button>
          </form>

          <div className="my-6 flex items-center gap-3">
            <div className="flex-1 h-px bg-white/[0.07]" />
            <span className="text-xs text-white/25 shrink-0">or continue with SSO</span>
            <div className="flex-1 h-px bg-white/[0.07]" />
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault()
              if (ssoEmail) window.location.href = `/api/v1/auth/sso/login?email=${encodeURIComponent(ssoEmail)}`
            }}
            className="space-y-3"
          >
            <div className="relative">
              <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-white/20 pointer-events-none" />
              <input
                type="email"
                value={ssoEmail}
                onChange={(e) => setSsoEmail(e.target.value)}
                placeholder="name@company.com"
                className="w-full pl-9 pr-3 py-2.5 rounded-lg border border-white/[0.08] bg-white/[0.06] text-white placeholder:text-white/20 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500/50 transition-all"
              />
            </div>
            <button
              type="submit"
              disabled={loading || !ssoEmail}
              className="w-full py-2.5 rounded-lg border border-white/[0.12] bg-white/[0.05] text-white/70
                         hover:bg-white/[0.09] hover:border-white/20 hover:text-white
                         text-sm font-medium transition-all duration-150 active:scale-[0.99]
                         disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Sign in with SSO
            </button>
          </form>
        </div>

        <p className="text-center text-xs text-white/15 mt-6">KESTREL SOC Platform · Secure Access</p>
      </div>
    </div>
  )
}
