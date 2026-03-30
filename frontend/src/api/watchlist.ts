import { get, post, patch, del } from './client'

export type IndicatorType = 'ip' | 'domain' | 'hash' | 'cidr' | 'url' | 'email'

export interface WatchlistEntry {
  id: number
  indicator: string
  indicator_type: IndicatorType
  tag: string
  confidence: number
  notes: string | null
  is_active: boolean
  match_count: number
  last_matched_at: string | null
  created_at: string
}

export interface WatchlistCreateRequest {
  indicator: string
  indicator_type?: IndicatorType
  tag?: string
  confidence?: number
  notes?: string
}

export async function getWatchlist(activeOnly = false): Promise<WatchlistEntry[]> {
  return get<WatchlistEntry[]>(`/watchlist${activeOnly ? '?active_only=true' : ''}`)
}

export async function createWatchlistEntry(data: WatchlistCreateRequest): Promise<WatchlistEntry> {
  return post<WatchlistEntry>('/watchlist', data)
}

export async function updateWatchlistEntry(
  id: number,
  data: Partial<WatchlistCreateRequest & { is_active: boolean }>,
): Promise<WatchlistEntry> {
  return patch<WatchlistEntry>(`/watchlist/${id}`, data)
}

export async function deleteWatchlistEntry(id: number): Promise<void> {
  return del<void>(`/watchlist/${id}`)
}
