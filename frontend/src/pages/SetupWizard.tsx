import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { CheckCircle2 } from 'lucide-react'

export function SetupWizard() {
  const [step, setStep] = useState(1)
  const [form, setForm] = useState({
    username: '',
    password: '',
    confirmPassword: '',
    aiProvider: 'openai',
    aiKey: '',
  })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  const createAdmin = async () => {
    if (form.password !== form.confirmPassword) {
      setError('Passwords do not match')
      return
    }
    setLoading(true)
    setError('')
    try {
      const res = await fetch('/api/v1/auth/setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: form.username,
          password: form.password,
        }),
      })
      if (!res.ok) {
        const d = await res.json().catch(() => ({}))
        setError(d.detail ?? 'Setup failed')
        return
      }
      setStep(2)
    } catch {
      setError('Could not connect to server')
    } finally {
      setLoading(false)
    }
  }

  const saveAI = async () => {
    if (!form.aiKey) {
      setStep(3)
      return
    }
    const keyName = form.aiProvider === 'openai' ? 'OPENAI_API_KEY' : 'ANTHROPIC_API_KEY'

    const loginRes = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: form.username,
        password: form.password,
      }),
    })
    if (!loginRes.ok) {
      setStep(3)
      return
    }
    const { access_token } = await loginRes.json()

    await fetch('/api/v1/settings', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${access_token}`,
      },
      body: JSON.stringify({
        settings: {
          AI_PROVIDER: form.aiProvider,
          [keyName]: form.aiKey,
        },
      }),
    })
    setStep(3)
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <div className="w-full max-w-md">
        <Link
          to="/"
          className="inline-flex items-center gap-2 text-muted-foreground hover:text-foreground text-sm mb-4 transition-colors"
        >
          ← Back to home
        </Link>
        <div className="p-8 rounded-xl border border-border bg-card shadow-xl">
        <div className="flex items-center gap-3 mb-8">
          <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center">
            <span className="text-white font-bold text-sm">K</span>
          </div>
          <div>
            <h1 className="text-lg font-semibold text-foreground">KESTREL</h1>
            <p className="text-xs text-muted-foreground">First-time setup</p>
          </div>
        </div>

        <div className="flex gap-2 mb-6">
          {[1, 2, 3].map((s) => (
            <div
              key={s}
              className={`h-1 flex-1 rounded-full transition-colors ${
                s <= step ? 'bg-blue-500' : 'bg-muted'
              }`}
            />
          ))}
        </div>

        {step === 1 && (
          <div className="space-y-4">
            <div>
              <h2 className="text-base font-medium text-foreground">Create Admin Account</h2>
              <p className="text-xs text-muted-foreground mt-0.5">
                This account will have full access to KESTREL
              </p>
            </div>
            {error && (
              <p className="text-red-400 text-sm p-2 rounded bg-red-500/10 border border-red-500/20">
                {error}
              </p>
            )}
            <input
              placeholder="Username"
              value={form.username}
              onChange={(e) => setForm({ ...form, username: e.target.value })}
              className="w-full px-3 py-2 rounded border border-border bg-background text-foreground text-sm"
            />
            <input
              type="password"
              placeholder="Password (min 12 characters)"
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              className="w-full px-3 py-2 rounded border border-border bg-background text-foreground text-sm"
            />
            <input
              type="password"
              placeholder="Confirm password"
              value={form.confirmPassword}
              onChange={(e) => setForm({ ...form, confirmPassword: e.target.value })}
              className="w-full px-3 py-2 rounded border border-border bg-background text-foreground text-sm"
            />
            <button
              type="button"
              onClick={createAdmin}
              disabled={loading}
              className="w-full py-2 rounded bg-blue-600 text-white text-sm font-medium hover:opacity-90 disabled:opacity-50"
            >
              {loading ? 'Creating...' : 'Create Account →'}
            </button>
          </div>
        )}

        {step === 2 && (
          <div className="space-y-4">
            <div>
              <h2 className="text-base font-medium text-foreground">Configure AI Provider</h2>
              <p className="text-xs text-muted-foreground mt-0.5">
                Powers alert triage and summarization. Skip to configure later.
              </p>
            </div>
            <select
              value={form.aiProvider}
              onChange={(e) => setForm({ ...form, aiProvider: e.target.value })}
              className="w-full px-3 py-2 rounded border border-border bg-background text-foreground text-sm"
            >
              <option value="openai">OpenAI (GPT-4o-mini)</option>
              <option value="anthropic">Anthropic (Claude)</option>
            </select>
            <input
              type="password"
              placeholder={form.aiProvider === 'openai' ? 'sk-...' : 'sk-ant-...'}
              value={form.aiKey}
              onChange={(e) => setForm({ ...form, aiKey: e.target.value })}
              className="w-full px-3 py-2 rounded border border-border bg-background text-foreground text-sm"
            />
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setStep(3)}
                className="flex-1 py-2 rounded border border-border text-muted-foreground text-sm hover:text-foreground"
              >
                Skip for now
              </button>
              <button
                type="button"
                onClick={saveAI}
                className="flex-1 py-2 rounded-lg gradient-primary text-white text-sm font-medium hover:opacity-90"
              >
                Save &amp; Continue →
              </button>
            </div>
          </div>
        )}

        {step === 3 && (
          <div className="text-center space-y-4">
            <div className="w-12 h-12 rounded-full bg-green-500/10 border border-green-500/20 flex items-center justify-center mx-auto">
              <CheckCircle2 className="w-6 h-6 text-green-400" />
            </div>
            <div>
              <h2 className="text-base font-medium text-foreground">KESTREL is ready</h2>
              <p className="text-xs text-muted-foreground mt-0.5">
                Configure source integrations in Settings anytime
              </p>
            </div>
            <button
              type="button"
              onClick={() => navigate('/login')}
              className="w-full py-2 rounded-lg gradient-primary text-white text-sm font-medium hover:opacity-90"
            >
              Go to Login →
            </button>
          </div>
        )}
        </div>
      </div>
    </div>
  )
}

