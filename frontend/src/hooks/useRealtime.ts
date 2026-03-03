import { useQuery } from '@tanstack/react-query'
import { getAlerts } from '@/api/alerts'

const POLL_MS = 30_000

/**
 * Poll alerts for live updates (e.g. dashboard widget).
 */
export function useRealtimeAlerts(intervalMs = POLL_MS) {
  return useQuery({
    queryKey: ['alerts', 'realtime'],
    queryFn: () => getAlerts({ page: 1, limit: 20 }),
    refetchInterval: intervalMs,
  })
}
