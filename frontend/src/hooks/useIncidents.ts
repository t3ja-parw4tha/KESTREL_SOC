import { useQuery } from '@tanstack/react-query'
import { incidentsApi } from '@/api/incidents'

export function useIncidents() {
  return useQuery({
    queryKey: ['incidents'],
    queryFn: () => incidentsApi.list(),
  })
}

export function useIncident(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ['incident', id],
    queryFn: () => incidentsApi.get(id!),
    enabled: !!id && enabled,
  })
}
