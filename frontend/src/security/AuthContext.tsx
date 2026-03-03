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
  useState,
  type ReactNode,
} from 'react'
import { clearToken, getToken, setToken as setClientToken } from '@/api/client'
import {
  getJwtExpiry,
  secondsUntilExpiry,
  SESSION_WARNING_SECONDS,
} from '@/security/display'

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
  sessionWarning: boolean
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

  const logout = useCallback(() => {
    clearToken()
    sessionStorage.removeItem('kestrel_token')
    sessionStorage.removeItem('kestrel_user')
    setState({
      token: null,
      user: null,
      isAuthenticated: false,
      sessionWarning: false,
    })
  }, [])

  const login = useCallback((token: string, user: User) => {
    setClientToken(token)
    sessionStorage.setItem('kestrel_token', token)
    sessionStorage.setItem('kestrel_user', JSON.stringify(user))
    setState({
      token,
      user,
      isAuthenticated: true,
      sessionWarning: false,
    })
  }, [])

  const dismissSessionWarning = useCallback(() => {
    setState((s) => ({ ...s, sessionWarning: false }))
  }, [])

  const setSessionWarning = useCallback((value: boolean) => {
    setState((s) => ({ ...s, sessionWarning: value }))
  }, [])

  // Restore session from sessionStorage on mount if token is still valid.
  useEffect(() => {
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
        setState({
          token: savedToken,
          user,
          isAuthenticated: true,
          sessionWarning: false,
        })
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

  // Session expiry check: warn 2 min before, logout on expiry.
  useEffect(() => {
    if (!state.token) return
    const interval = setInterval(() => {
      const secs = secondsUntilExpiry(state.token!)
      if (secs === null || secs <= 0) {
        logout()
        return
      }
      if (secs <= SESSION_WARNING_SECONDS) {
        setState((s) => ({ ...s, sessionWarning: true }))
      }
    }, 5000)
    return () => clearInterval(interval)
  }, [state.token, logout])

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
