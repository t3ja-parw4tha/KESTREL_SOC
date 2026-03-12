/**
 * Auth context: token in memory only, session expiry, logout clears all.
 * No tokens or PII in URL params.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { clearToken, setToken as setClientToken, getToken, setCsrfToken } from '@/api/client'
import { secondsUntilExpiry, SESSION_INACTIVITY_MS } from '@/security/display'

async function fetchAndStoreCsrfToken(bearerToken: string): Promise<void> {
  try {
    const res = await fetch('/api/v1/auth/csrf-token', {
      headers: { Authorization: `Bearer ${bearerToken}` },
    })
    if (res.ok) {
      const data = (await res.json()) as { csrf_token?: string }
      if (data.csrf_token) setCsrfToken(data.csrf_token)
    }
  } catch {
    // Non-critical — CSRF token fetch failure does not block the user
  }
}

export type Role = 'admin' | 'senior_analyst' | 'analyst' | 'viewer'

export interface User {
  id: string
  username: string
  role: Role
}

interface AuthState {
  token: string | null
  user: User | null
  isAuthenticated: boolean
  /** Whether the session expiry warning is currently visible. */
  sessionWarning: boolean
  /** User has seen/dismissed the warning for this token; don't show again. */
  sessionWarningAcknowledged: boolean
}

interface AuthContextValue extends AuthState {
  login: (token: string, user: User) => void
  logout: () => void
  dismissSessionWarning: () => void
  setSessionWarning: (value: boolean) => void
  /** True when we've checked sessionStorage and initial auth state. */
  hydrated: boolean
}

const defaultState: AuthState = {
  token: null,
  user: null,
  isAuthenticated: false,
  sessionWarning: false,
  sessionWarningAcknowledged: false,
}

const AuthContext = createContext<AuthContextValue | null>(null)

function parseUserFromToken(token: string): User | null {
  try {
    const payload = token.split('.')[1]
    if (!payload) return null
    const decoded = JSON.parse(atob(payload)) as {
      sub?: string
      username?: string
      role?: string
    }
    const role = (decoded.role as Role) ?? 'viewer'
    return {
      id: decoded.sub ?? '',
      username: decoded.username ?? 'user',
      role: ['admin', 'senior_analyst', 'analyst', 'viewer'].includes(role)
        ? role
        : 'viewer',
    }
  } catch {
    return null
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>(defaultState)
  const [hydrated, setHydrated] = useState(false)
  /** Last time we saw user activity (mouse, key, click, scroll). Used for inactivity warning. */
  const lastActivityRef = useRef(Date.now())

  const logout = useCallback(() => {
    // Fire-and-forget: revoke the refresh cookie server-side so it cannot be reused.
    // Do not await — local state must clear immediately regardless of network.
    const currentToken = getToken()
    fetch('/api/v1/auth/logout', {
      method: 'POST',
      headers: currentToken ? { Authorization: `Bearer ${currentToken}` } : {},
    }).catch(() => { /* ignore network errors during logout */ })

    clearToken()
    sessionStorage.removeItem('kestrel_token')
    sessionStorage.removeItem('kestrel_user')
    setState({
      token: null,
      user: null,
      isAuthenticated: false,
      sessionWarning: false,
      sessionWarningAcknowledged: false,
    })
  }, [])

  const login = useCallback((token: string, user: User) => {
    setClientToken(token)
    sessionStorage.setItem('kestrel_token', token)
    sessionStorage.setItem('kestrel_user', JSON.stringify(user))
    lastActivityRef.current = Date.now()
    setState({
      token,
      user,
      isAuthenticated: true,
      sessionWarning: false,
      sessionWarningAcknowledged: false,
    })
    // Fetch CSRF token after login so mutating API requests are protected
    fetchAndStoreCsrfToken(token).catch(() => { /* non-critical */ })
  }, [])

  const dismissSessionWarning = useCallback(() => {
    lastActivityRef.current = Date.now() // reset inactivity on dismiss
    setState((s) => ({
      ...s,
      sessionWarning: false,
      sessionWarningAcknowledged: true,
    }))
  }, [])

  const setSessionWarning = useCallback((value: boolean) => {
    setState((s) => ({
      ...s,
      sessionWarning: value,
      // If we explicitly turn the warning on again, clear acknowledgement.
      sessionWarningAcknowledged: value ? false : s.sessionWarningAcknowledged,
    }))
  }, [])

  // Restore session from sessionStorage on mount if token is still valid.
  useEffect(() => {
    // 1. Check if we just completed an SSO login (backend sets a temp cookie)
    const ssoMatch = document.cookie.match(new RegExp('(^| )sso_access_token=([^;]+)'));
    if (ssoMatch && ssoMatch[2]) {
      const ssoToken = ssoMatch[2];
      // Consume and destroy the temp cookie
      document.cookie = 'sso_access_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
      const user = parseUserFromToken(ssoToken);
      if (user) {
        setClientToken(ssoToken);
        sessionStorage.setItem('kestrel_token', ssoToken);
        sessionStorage.setItem('kestrel_user', JSON.stringify(user));
        lastActivityRef.current = Date.now();
        setState({
          token: ssoToken,
          user,
          isAuthenticated: true,
          sessionWarning: false,
          sessionWarningAcknowledged: false,
        });
        setHydrated(true);
        return;
      }
    }

    // 2. Otherwise fallback to standard session storage
    const savedToken = sessionStorage.getItem('kestrel_token')
    const savedUser = sessionStorage.getItem('kestrel_user')
    if (!savedToken || !savedUser) {
      setHydrated(true)
      return
    }
    try {
      const user = JSON.parse(savedUser) as User
      const payloadPart = savedToken.split('.')[1]
      if (!payloadPart) {
        sessionStorage.removeItem('kestrel_token')
        sessionStorage.removeItem('kestrel_user')
        setHydrated(true)
        return
      }
      const payload = JSON.parse(atob(payloadPart)) as { exp?: number }
      const exp = payload.exp ?? 0
      if (exp * 1000 > Date.now()) {
        setClientToken(savedToken)
        lastActivityRef.current = Date.now()
        setState({
          token: savedToken,
          user,
          isAuthenticated: true,
          sessionWarning: false,
          sessionWarningAcknowledged: false,
        })
        // Re-fetch CSRF token on page reload so mutating requests remain protected
        fetchAndStoreCsrfToken(savedToken).catch(() => { /* non-critical */ })
      } else {
        sessionStorage.removeItem('kestrel_token')
        sessionStorage.removeItem('kestrel_user')
      }
    } catch {
      sessionStorage.removeItem('kestrel_token')
      sessionStorage.removeItem('kestrel_user')
    } finally {
      setHydrated(true)
    }
  }, [])

  // Logout when JWT actually expires.
  useEffect(() => {
    if (!state.token) return
    const token = state.token
    const interval = setInterval(() => {
      const secs = secondsUntilExpiry(token)
      if (secs === null || secs <= 0) logout()
    }, 5000)
    return () => clearInterval(interval)
  }, [state.token, logout])

  // Session warning after 5 minutes of inactivity (no mouse, key, click, scroll).
  useEffect(() => {
    if (!state.token) return

    const onActivity = () => {
      lastActivityRef.current = Date.now()
    }
    const events = ['mousedown', 'keydown', 'scroll', 'mousemove', 'touchstart'] as const
    events.forEach((e) => window.addEventListener(e, onActivity))

    const interval = setInterval(() => {
      const elapsed = Date.now() - lastActivityRef.current
      if (elapsed >= SESSION_INACTIVITY_MS) {
        setState((s) => {
          if (s.sessionWarning) return s
          return { ...s, sessionWarning: true }
        })
      }
    }, 10000) // check every 10 s

    return () => {
      events.forEach((e) => window.removeEventListener(e, onActivity))
      clearInterval(interval)
    }
  }, [state.token])

  const value = useMemo<AuthContextValue>(
    () => ({
      ...state,
      login,
      logout,
      dismissSessionWarning,
      setSessionWarning,
      hydrated,
    }),
    [state, login, logout, dismissSessionWarning, setSessionWarning, hydrated]
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
