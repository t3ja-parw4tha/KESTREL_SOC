import { get } from './client'
import type { MitreCoverageResponse } from '@/types/mitre'

export async function fetchMitreCoverage(): Promise<MitreCoverageResponse> {
  return get<MitreCoverageResponse>('/mitre/coverage')
}
