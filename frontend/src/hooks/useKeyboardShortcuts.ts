/**
 * Global keyboard shortcuts:
 *   / or Ctrl+K  — focus the TopBar search input
 *   Esc          — blur focused input (handled natively)
 *   G then D     — Go to Dashboard
 *   G then A     — Go to Alerts
 *   G then I     — Go to Incidents
 *   G then M     — Go to MITRE Coverage
 *   G then H     — Go to Threat Hunting
 *   G then R     — Go to Reports
 *   G then P     — Go to Playbooks
 *   G then S     — Go to Sources
 *   G then ?     — Go to Help
 *
 * Shortcuts are inactive when focus is inside an input, textarea, select, or
 * contenteditable element so they never interfere with typing.
 */

import { useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'

const NAVIGATE_MAP: Record<string, string> = {
  d: '/app',
  a: '/app/alerts',
  i: '/app/incidents',
  m: '/app/mitre',
  h: '/app/hunting',
  r: '/app/reports',
  p: '/app/playbooks',
  s: '/app/sources',
  '?': '/app/help',
}

/** Returns true when the event target is an interactive text element. */
function isTextTarget(target: EventTarget | null): boolean {
  if (!target) return false
  const el = target as HTMLElement
  return (
    el.tagName === 'INPUT' ||
    el.tagName === 'TEXTAREA' ||
    el.tagName === 'SELECT' ||
    el.isContentEditable
  )
}

export function useKeyboardShortcuts(): void {
  const navigate = useNavigate()
  const gPressedRef = useRef(false)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      // Focus search bar: / (when not in an input) or Ctrl+K anywhere
      if (e.key === '/' && !isTextTarget(e.target)) {
        e.preventDefault()
        const input = document.querySelector<HTMLInputElement>('[data-search-input], input[type="search"]')
        input?.focus()
        return
      }
      if (e.ctrlKey && e.key === 'k') {
        e.preventDefault()
        const input = document.querySelector<HTMLInputElement>('[data-search-input], input[type="search"]')
        input?.focus()
        return
      }

      // G + letter navigation — skip if in a text element or modifier held
      if (isTextTarget(e.target) || e.ctrlKey || e.altKey || e.metaKey) {
        if (gPressedRef.current) {
          gPressedRef.current = false
          if (timerRef.current) clearTimeout(timerRef.current)
        }
        return
      }

      if (gPressedRef.current) {
        gPressedRef.current = false
        if (timerRef.current) clearTimeout(timerRef.current)
        const dest = NAVIGATE_MAP[e.key.toLowerCase()] ?? NAVIGATE_MAP[e.key]
        if (dest) {
          e.preventDefault()
          navigate(dest)
        }
      } else if (e.key === 'g' || e.key === 'G') {
        gPressedRef.current = true
        timerRef.current = setTimeout(() => {
          gPressedRef.current = false
        }, 1000)
      }
    }

    window.addEventListener('keydown', onKeyDown)
    return () => {
      window.removeEventListener('keydown', onKeyDown)
      if (timerRef.current) clearTimeout(timerRef.current)
    }
  }, [navigate])
}
