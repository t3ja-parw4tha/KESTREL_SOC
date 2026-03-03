import DOMPurify from 'dompurify'

/**
 * Sanitize HTML for safe display. Never use dangerouslySetInnerHTML without this.
 * OWASP: allow only safe tags and no attributes that could execute script.
 */
export function sanitizeHTML(dirty: string): string {
  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br'],
    ALLOWED_ATTR: [],
    FORBID_TAGS: ['script', 'object', 'embed', 'link', 'style'],
  })
}

/**
 * Safe display of raw log data: escape HTML entities to prevent XSS.
 */
export function sanitizeLogValue(value: unknown): string {
  if (typeof value === 'string') {
    return value
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;')
  }
  return String(value)
}

/**
 * Safe URL validation before navigation or use in href/src.
 * Only allow http: and https: to prevent javascript: or data: injection.
 */
export function isSafeUrl(url: string): boolean {
  try {
    const parsed = new URL(url)
    return ['http:', 'https:'].includes(parsed.protocol)
  } catch {
    return false
  }
}
