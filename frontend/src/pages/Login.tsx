import { useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { useAuth } from '@/security/AuthContext'

function parseUserFromToken(token: string) {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]))
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
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const { login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const from = (location.state as { from?: { pathname: string } })?.from?.pathname ?? '/'

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
      if (!user) {
        setError('Invalid token received')
        return
      }
      login(token, user)
      navigate(from, { replace: true })
    } catch {
      setError('Could not connect to server')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-soc-bg">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-sm p-6 rounded-lg border border-soc-border bg-soc-surface shadow"
      >
        <h1 className="text-xl font-semibold text-soc-text mb-1">SOC Platform</h1>
        <p className="text-sm text-soc-muted mb-4">Sign in to continue</p>
        {error && (
          <p
            className="text-sm text-red-400 mb-3 p-2 rounded bg-red-500/10 border border-red-500/20"
            role="alert"
          >
            {error}
          </p>
        )}
        <label className="block text-sm text-soc-muted mb-1">Username</label>
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          className="w-full px-3 py-2 rounded border border-soc-border bg-soc-bg text-soc-text mb-3 focus:outline-none focus:border-blue-500"
          autoComplete="username"
          required
        />
        <label className="block text-sm text-soc-muted mb-1">Password</label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="w-full px-3 py-2 rounded border border-soc-border bg-soc-bg text-soc-text mb-4 focus:outline-none focus:border-blue-500"
          autoComplete="current-password"
          required
        />
        <button
          type="submit"
          disabled={loading}
          className="w-full py-2 rounded bg-blue-600 text-white font-medium hover:bg-blue-700 disabled:opacity-50 transition-colors"
        >
          {loading ? 'Signing in...' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}

