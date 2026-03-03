/**
 * Session timeout warning: shown 2 minutes before JWT expiry.
 * Auto-logout on expiry; clear all in-memory tokens on logout.
 */

import { useAuth } from '@/security/AuthContext'

export function SessionTimeoutModal() {
  const { sessionWarning, logout, dismissSessionWarning } = useAuth()

  if (!sessionWarning) return null

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
      role="dialog"
      aria-labelledby="session-timeout-title"
    >
      <div className="bg-soc-card border border-soc-border rounded-lg shadow-lg p-6 max-w-sm mx-4">
        <h2 id="session-timeout-title" className="text-lg font-semibold text-soc-text mb-2">
          Session expiring
        </h2>
        <p className="text-sm text-soc-muted mb-4">
          Your session will expire in about 2 minutes. Sign in again to continue.
        </p>
        <div className="flex gap-2 justify-end">
          <button
            type="button"
            onClick={dismissSessionWarning}
            className="px-3 py-1.5 text-sm rounded border border-soc-border text-soc-muted hover:bg-soc-border/50"
          >
            Dismiss
          </button>
          <button
            type="button"
            onClick={logout}
            className="px-3 py-1.5 text-sm rounded bg-soc-primary text-white hover:opacity-90"
          >
            Sign out
          </button>
        </div>
      </div>
    </div>
  )
}
