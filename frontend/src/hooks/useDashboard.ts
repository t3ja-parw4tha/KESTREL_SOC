import { useQuery } from '@tanstack/react-query'
import { fetchDashboardStats, type TrendPeriod } from '@/api/dashboard'

const REFETCH_INTERVAL_MS = 30_000

export function useDashboardStats(
  refetchInterval = REFETCH_INTERVAL_MS,
  trendPeriod: TrendPeriod = 'day',
) {
  return useQuery({
    queryKey: ['dashboard', 'stats', trendPeriod],
    queryFn: () => fetchDashboardStats(trendPeriod),
    refetchInterval,
  })
}

export function useRecentAlerts() {
  const { data, ...rest } = useDashboardStats()
  return {
    ...rest,
    data: data ? { items: data.recent_alerts } : undefined,
  }
}

export function useSecurityStatus() {
  return useQuery({
    queryKey: ['dashboard', 'security-status'],
    queryFn: async () => {
      const { get } = await import('@/api/client')
      return get<unknown>('/security/status')
    },
  })
}
