import { useQuery } from '@tanstack/react-query'
import { fetchMitreCoverage } from '@/api/mitre'

export function useMitreCoverage() {
  return useQuery({
    queryKey: ['mitre', 'coverage'],
    queryFn: fetchMitreCoverage,
  })
}
