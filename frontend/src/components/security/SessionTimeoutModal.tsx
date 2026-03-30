/**
 * Session timeout warning: shown after 5 minutes of inactivity.
 * Auto-logout on JWT expiry; clear all in-memory tokens on logout.
 */

import { useAuth } from '@/security/AuthContext'

export function SessionTimeoutModal() {
  const { sessionWarning, logout, dismissSessionWarning } = useAuth()

  if (!sessionWarning) return null

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm"
      role="dialog"
      aria-labelledby="session-timeout-title"
      aria-modal="true"
    >
      <div className="bg-card border-2 border-border rounded-xl shadow-2xl p-6 max-w-sm mx-4 w-full opacity-100">
        <h2 id="session-timeout-title" className="text-lg font-semibold text-foreground mb-2">
          Session expiring
        </h2>
        <p className="text-sm text-muted-foreground mb-4">
          You’ve been inactive for 5 minutes. Stay signed in or sign out.
        </p>
        <div className="flex gap-2 justify-end">
          <button
            type="button"
            onClick={dismissSessionWarning}
            className="px-3 py-1.5 text-sm rounded-lg border border-border bg-background text-foreground hover:bg-muted/50 font-medium"
          >
            Dismiss
          </button>
          <button
            type="button"
            onClick={logout}
            className="px-3 py-1.5 text-sm rounded-lg gradient-primary text-white hover:opacity-90 font-medium"
          >
            Sign out
          </button>
        </div>
      </div>
    </div>
  )
}
