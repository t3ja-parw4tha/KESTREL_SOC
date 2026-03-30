/** Centralized route paths — change here, fixes everywhere */
export const ROUTES = {
  dashboard:   '/app/dashboard',
  alerts:      '/app/alerts',
  incidents:   '/app/incidents',
  mitre:       '/app/mitre',
  sources:     '/app/sources',
  reports:     '/app/reports',
  playbooks:   '/app/playbooks',
  settings:    '/app/settings',
  help:        '/app/help',
  alert:       (id: string) => `/app/alerts/${id}`,
  incident:    (id: string) => `/app/incidents/${id}`,
} as const
