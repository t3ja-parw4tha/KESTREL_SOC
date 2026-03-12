import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, act } from '@testing-library/react'
import { AuthProvider, useAuth } from '@/security/AuthContext'

// Helper: a non-expired JWT payload
function makeToken(role = 'analyst', expOffsetSeconds = 3600): string {
  const payload = {
    sub: '1',
    username: 'testuser',
    role,
    exp: Math.floor(Date.now() / 1000) + expOffsetSeconds,
  }
  return [
    'eyJhbGciOiJSUzI1NiJ9',
    btoa(JSON.stringify(payload)).replace(/=/g, ''),
    'sig',
  ].join('.')
}

function Consumer() {
  const { isAuthenticated, user, hydrated } = useAuth()
  return (
    <div>
      <span data-testid="hydrated">{String(hydrated)}</span>
      <span data-testid="authenticated">{String(isAuthenticated)}</span>
      <span data-testid="username">{user?.username ?? 'none'}</span>
      <span data-testid="role">{user?.role ?? 'none'}</span>
    </div>
  )
}

function LoginConsumer() {
  const { login, logout, isAuthenticated } = useAuth()
  return (
    <div>
      <span data-testid="authenticated">{String(isAuthenticated)}</span>
      <button onClick={() => login(makeToken(), { id: '1', username: 'testuser', role: 'analyst' })}>
        Login
      </button>
      <button onClick={logout}>Logout</button>
    </div>
  )
}

describe('AuthProvider', () => {
  beforeEach(() => {
    sessionStorage.clear()
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false } as Response))
  })

  it('starts unauthenticated and hydrates', async () => {
    render(<AuthProvider><Consumer /></AuthProvider>)
    // Eventually hydrates
    await act(async () => {})
    expect(screen.getByTestId('hydrated').textContent).toBe('true')
    expect(screen.getByTestId('authenticated').textContent).toBe('false')
    expect(screen.getByTestId('username').textContent).toBe('none')
  })

  it('login sets isAuthenticated and user', async () => {
    render(<AuthProvider><LoginConsumer /></AuthProvider>)
    await act(async () => {})

    await act(async () => {
      screen.getByRole('button', { name: 'Login' }).click()
    })

    expect(screen.getByTestId('authenticated').textContent).toBe('true')
  })

  it('login persists token to sessionStorage', async () => {
    render(<AuthProvider><LoginConsumer /></AuthProvider>)
    await act(async () => {})

    await act(async () => {
      screen.getByRole('button', { name: 'Login' }).click()
    })

    expect(sessionStorage.getItem('kestrel_token')).not.toBeNull()
    expect(sessionStorage.getItem('kestrel_user')).not.toBeNull()
  })

  it('logout clears state and sessionStorage', async () => {
    render(<AuthProvider><LoginConsumer /></AuthProvider>)
    await act(async () => {})

    await act(async () => {
      screen.getByRole('button', { name: 'Login' }).click()
    })
    expect(screen.getByTestId('authenticated').textContent).toBe('true')

    await act(async () => {
      screen.getByRole('button', { name: 'Logout' }).click()
    })

    expect(screen.getByTestId('authenticated').textContent).toBe('false')
    expect(sessionStorage.getItem('kestrel_token')).toBeNull()
  })

  it('hydrates from sessionStorage when token is still valid', async () => {
    const token = makeToken()
    sessionStorage.setItem('kestrel_token', token)
    sessionStorage.setItem('kestrel_user', JSON.stringify({ id: '1', username: 'testuser', role: 'analyst' }))

    render(<AuthProvider><Consumer /></AuthProvider>)
    await act(async () => {})

    expect(screen.getByTestId('authenticated').textContent).toBe('true')
    expect(screen.getByTestId('username').textContent).toBe('testuser')
  })

  it('does not hydrate from sessionStorage when token is expired', async () => {
    const expiredToken = makeToken('analyst', -3600) // expired 1 hour ago
    sessionStorage.setItem('kestrel_token', expiredToken)
    sessionStorage.setItem('kestrel_user', JSON.stringify({ id: '1', username: 'testuser', role: 'analyst' }))

    render(<AuthProvider><Consumer /></AuthProvider>)
    await act(async () => {})

    expect(screen.getByTestId('authenticated').textContent).toBe('false')
  })
})
