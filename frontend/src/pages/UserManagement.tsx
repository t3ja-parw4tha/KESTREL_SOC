import { useEffect, useMemo, useState } from 'react'
import { useAuth } from '@/security/AuthContext'

type UserRow = {
  id: string | number
  username: string
  email?: string | null
  role: 'admin' | 'senior_analyst' | 'analyst' | 'viewer'
  is_active: boolean
  created_at?: string | null
}

export function UserManagement() {
  const { user } = useAuth()
  const [users, setUsers] = useState<UserRow[]>([])
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({
    username: '',
    password: '',
    role: 'analyst',
    email: '',
  })
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [busyId, setBusyId] = useState<string | number | null>(null)

  const authHeader = useMemo(() => {
    const token = sessionStorage.getItem('kestrel_token')
    return token ? { Authorization: `Bearer ${token}` } : {}
  }, [])

  useEffect(() => {
    fetchUsers()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const fetchUsers = async () => {
    setError('')
    setSuccess('')
    const res = await fetch('/api/v1/auth/users', {
      headers: {
        ...authHeader,
      },
    })
    const data = await res.json()
    setUsers((data?.users ?? []) as UserRow[])
  }

  const createUser = async () => {
    setError('')
    setSuccess('')
    const res = await fetch('/api/v1/auth/users', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...authHeader,
      },
      body: JSON.stringify(form),
    })
    if (res.ok) {
      setSuccess('User created successfully')
      setShowForm(false)
      setForm({ username: '', password: '', role: 'analyst', email: '' })
      await fetchUsers()
    } else {
      const d = await res.json().catch(() => ({}))
      setError(d?.detail ?? 'Failed to create user')
    }
  }

  const updateUser = async (id: string | number, patch: { role?: string; is_active?: boolean }) => {
    setError('')
    setSuccess('')
    setBusyId(id)
    try {
      const res = await fetch(`/api/v1/auth/users/${id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          ...authHeader,
        },
        body: JSON.stringify(patch),
      })
      if (res.ok) {
        setSuccess('User updated')
        await fetchUsers()
      } else {
        const d = await res.json().catch(() => ({}))
        setError(d?.detail ?? 'Failed to update user')
      }
    } finally {
      setBusyId(null)
    }
  }

  if (!user || user.role !== 'admin') return null

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold text-soc-text">
          User Management
        </h1>
        <button
          onClick={() => setShowForm(true)}
          className="px-3 py-1.5 rounded-lg bg-blue-600 text-white text-sm hover:bg-blue-700"
        >
          + Create User
        </button>
      </div>

      {error && <p className="text-red-400 text-sm">{error}</p>}
      {success && <p className="text-green-400 text-sm">{success}</p>}

      {showForm && (
        <div className="rounded-lg border border-soc-border bg-soc-surface p-4 space-y-3 max-w-md">
          <h2 className="text-sm font-semibold text-soc-text">
            New User
          </h2>
          <input
            placeholder="Username"
            value={form.username}
            onChange={(e) => setForm({ ...form, username: e.target.value })}
            className="w-full px-3 py-2 rounded border border-soc-border bg-soc-bg text-soc-text text-sm"
          />
          <input
            type="password"
            placeholder="Password (min 12 chars)"
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
            className="w-full px-3 py-2 rounded border border-soc-border bg-soc-bg text-soc-text text-sm"
          />
          <select
            value={form.role}
            onChange={(e) => setForm({ ...form, role: e.target.value })}
            className="w-full px-3 py-2 rounded border border-soc-border bg-soc-bg text-soc-text text-sm"
          >
            <option value="viewer">Viewer</option>
            <option value="analyst">Analyst</option>
            <option value="senior_analyst">Senior Analyst</option>
            <option value="admin">Admin</option>
          </select>
          <input
            placeholder="Email (optional)"
            value={form.email}
            onChange={(e) => setForm({ ...form, email: e.target.value })}
            className="w-full px-3 py-2 rounded border border-soc-border bg-soc-bg text-soc-text text-sm"
          />
          <div className="flex gap-2">
            <button
              onClick={createUser}
              className="px-3 py-1.5 rounded bg-blue-600 text-white text-sm hover:bg-blue-700"
            >
              Create
            </button>
            <button
              onClick={() => setShowForm(false)}
              className="px-3 py-1.5 rounded border border-soc-border text-soc-muted text-sm"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      <div className="rounded-lg border border-soc-border bg-soc-surface overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-soc-border">
              <th className="text-left px-4 py-3 text-soc-muted">Username</th>
              <th className="text-left px-4 py-3 text-soc-muted">Role</th>
              <th className="text-left px-4 py-3 text-soc-muted">Status</th>
              <th className="text-left px-4 py-3 text-soc-muted">Created</th>
              <th className="text-left px-4 py-3 text-soc-muted">Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr
                key={u.id}
                className="border-b border-soc-border/50 hover:bg-soc-border/20"
              >
                <td className="px-4 py-3 text-soc-text">{u.username}</td>
                <td className="px-4 py-3">
                  <span className="px-2 py-0.5 rounded text-xs bg-blue-500/10 text-blue-400 border border-blue-500/20 capitalize">
                    {u.role?.replace('_', ' ')}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className={u.is_active ? 'text-green-400 text-xs' : 'text-red-400 text-xs'}>
                    {u.is_active ? 'Active' : 'Inactive'}
                  </span>
                </td>
                <td className="px-4 py-3 text-soc-muted text-xs">
                  {u.created_at?.slice(0, 10) ?? '-'}
                </td>
                <td className="px-4 py-3">
                  <div className="flex gap-2 items-center">
                    <select
                      value={u.role}
                      onChange={(e) => updateUser(u.id, { role: e.target.value })}
                      disabled={busyId === u.id}
                      className="px-2 py-1 rounded border border-soc-border bg-soc-bg text-soc-text text-xs"
                    >
                      <option value="viewer">Viewer</option>
                      <option value="analyst">Analyst</option>
                      <option value="senior_analyst">Senior Analyst</option>
                      <option value="admin">Admin</option>
                    </select>
                    <button
                      type="button"
                      onClick={() => updateUser(u.id, { is_active: !u.is_active })}
                      disabled={busyId === u.id}
                      className="px-2 py-1 rounded border border-soc-border text-soc-muted hover:text-soc-text text-xs"
                    >
                      {u.is_active ? 'Deactivate' : 'Activate'}
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

