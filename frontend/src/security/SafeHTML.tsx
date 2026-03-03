/**
 * Safe HTML display: always sanitize with sanitizeHTML before using dangerouslySetInnerHTML.
 * Use this component for any user- or API-sourced HTML content.
 */

import { sanitizeHTML } from '@/security/sanitize'

interface SafeHTMLProps {
  html: string
  className?: string
  tag?: keyof JSX.IntrinsicElements
}

export function SafeHTML({ html, className, tag: Tag = 'div' }: SafeHTMLProps) {
  const sanitized = sanitizeHTML(html)
  return (
    <Tag
      className={className}
      dangerouslySetInnerHTML={{ __html: sanitized }}
    />
  )
}
