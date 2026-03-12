/**
 * Route protection: require auth, optional role. Redirect to /login if not authenticated.
 * Log unauthorized access attempts.
 */

import { Navigate, useLocation } from 'react-router-dom'
import { useAuth } from '@/security/AuthContext'
import type { Role } from '@/security/AuthContext'

const LOG_CATEGORY = 'auth.unauthorized'

/** Roles allowed for a route. Empty array = any authenticated user. */
export interface ProtectedRouteProps {
  children: React.ReactNode
  /** Required roles (any of). Empty = any authenticated user. */
  allowedRoles?: Role[]
}

export function ProtectedRoute({ children, allowedRoles = [] }: ProtectedRouteProps) {
  const { isAuthenticated, user, hydrated } = useAuth()
  const location = useLocation()

  // Wait until AuthProvider has checked sessionStorage before deciding.
  if (!hydrated) {
    return (
      <div className="min-h-screen bg-soc-bg flex items-center justify-center">
        <div className="text-soc-muted">Loading...</div>
      </div>
    )
  }

  if (!isAuthenticated || !user) {
    if (typeof window !== 'undefined') {
      try {
        console.warn(`[${LOG_CATEGORY}] unauthenticated access attempt to`, location.pathname)
      } catch {
        // no-op
      }
    }
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  if (allowedRoles.length > 0 && !allowedRoles.includes(user.role)) {
    if (typeof window !== 'undefined') {
      try {
        console.warn(
          `[${LOG_CATEGORY}] insufficient role for ${location.pathname}`,
          { role: user.role, allowed: allowedRoles }
        )
      } catch {
        // no-op
      }
    }
    return <Navigate to="/app" replace />
  }

  return <>{children}</>
}

/**
 * /admin/* → admin only
 */
export function AdminRoute({ children }: { children: React.ReactNode }) {
  return (
    <ProtectedRoute allowedRoles={['admin']}>
      {children}
    </ProtectedRoute>
  )
}

/**
 * /sources/* → senior_analyst or admin only
 */
export function SourcesRoute({ children }: { children: React.ReactNode }) {
  return (
    <ProtectedRoute allowedRoles={['senior_analyst', 'admin']}>
      {children}
    </ProtectedRoute>
  )
}
