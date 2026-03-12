/**
 * Sensitive data handling in UI: masking, clipboard, session.
 * OWASP: minimize exposure of secrets and PII.
 */

const CLIPBOARD_CLEAR_MS = 30_000

/**
 * Mask API key: show first 4 and last 4 characters (e.g. soc_****...****).
 */
export function maskApiKey(key: string): string {
  if (!key || key.length < 12) return '****'
  const start = key.slice(0, 4)
  const end = key.slice(-4)
  return `${start}****...****${end}`
}

/**
 * Mask IP partially: show first two octets, mask last two (e.g. 192.168.*.*).
 */
export function maskIpPartial(ip: string): string {
  if (!ip) return '*.*.*.*'
  const parts = ip.trim().split('.')
  if (parts.length !== 4) return '*.*.*.*'
  return `${parts[0]}.${parts[1]}.*.*`
}

/**
 * Schedule clipboard clear after copy of sensitive data.
 * Call after copying API keys or tokens.
 */
export function scheduleClipboardClear(): void {
  if (typeof navigator?.clipboard?.writeText !== 'function') return
  const clear = () => {
    try {
      navigator.clipboard.writeText('')
    } catch {
      // ignore
    }
  }
  window.setTimeout(clear, CLIPBOARD_CLEAR_MS)
}

/**
 * Parse JWT payload (no verification; verification is server-side).
 * Used only for reading exp for client-side session warning.
 */
export function getJwtExpiry(token: string): number | null {
  try {
    const payload = token.split('.')[1]
    if (!payload) return null
    const decoded = JSON.parse(atob(payload)) as { exp?: number }
    return typeof decoded.exp === 'number' ? decoded.exp : null
  } catch {
    return null
  }
}

/**
 * Seconds until JWT expires (exp is in seconds since epoch).
 */
export function secondsUntilExpiry(token: string): number | null {
  const exp = getJwtExpiry(token)
  if (exp == null) return null
  return Math.max(0, exp - Math.floor(Date.now() / 1000))
}

/**
 * Inactivity threshold: show session warning after this many milliseconds with no user activity.
 * 5 minutes.
 */
export const SESSION_INACTIVITY_MS = 5 * 60 * 1000
