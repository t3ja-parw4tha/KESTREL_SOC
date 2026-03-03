import { useQuery, useQueryClient } from '@tanstack/react-query'
import { getAlerts, getAlert } from '@/api/alerts'
import type { AlertFiltersParams } from '@/types/alert'

export function useAlerts(params?: AlertFiltersParams) {
  return useQuery({
    queryKey: ['alerts', params],
    queryFn: () => getAlerts(params),
  })
}

export function useAlert(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ['alert', id],
    queryFn: () => getAlert(id!),
    enabled: !!id && enabled,
  })
}

export function useAlertsInvalidate() {
  const queryClient = useQueryClient()
  return () => queryClient.invalidateQueries({ queryKey: ['alerts'] })
}
