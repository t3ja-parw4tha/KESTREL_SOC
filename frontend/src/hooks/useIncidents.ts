import { useQuery } from '@tanstack/react-query'
import { fetchIncidents, fetchIncidentById } from '@/api/incidents'

export function useIncidents() {
  return useQuery({
    queryKey: ['incidents'],
    queryFn: fetchIncidents,
  })
}

export function useIncident(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ['incident', id],
    queryFn: () => fetchIncidentById(id!),
    enabled: !!id && enabled,
  })
}
