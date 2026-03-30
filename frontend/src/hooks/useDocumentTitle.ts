import { useEffect } from 'react'

const APP_TITLE = 'KESTREL'

const PATH_TITLES: Record<string, string> = {
  '/app': 'Dashboard',
  '/app/alerts': 'Alerts',
  '/app/incidents': 'Incidents',
  '/app/assets': 'Assets',
  '/app/mitre': 'MITRE Coverage',
  '/app/sources': 'Sources',
  '/app/hunting': 'Threat Hunting',
  '/app/reports': 'Reports',
  '/app/settings': 'Settings',
  '/app/users': 'Users',
  '/app/404': 'Not found',
}

function getTitleForPath(pathname: string): string {
  if (PATH_TITLES[pathname]) return `${PATH_TITLES[pathname]} | ${APP_TITLE}`
  if (pathname.startsWith('/app/alerts/')) return `Alert | ${APP_TITLE}`
  if (pathname.startsWith('/app/incidents/')) return `Incident | ${APP_TITLE}`
  return APP_TITLE
}

/**
 * Sets document.title based on the current pathname. Use inside app layout for /app/* routes.
 */
export function useDocumentTitle(pathname: string) {
  useEffect(() => {
    const title = getTitleForPath(pathname)
    document.title = title
    return () => {
      document.title = APP_TITLE
    }
  }, [pathname])
}
