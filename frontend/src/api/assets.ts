import { get, patch, post } from './client'

export interface AssetListItem {
  asset_id: string
  hostname: string | null
  ip_address: string | null
  asset_type: string | null
  owner: string | null
  department: string | null
  criticality: 'low' | 'medium' | 'high' | 'critical'
  risk_score: number | null
  open_alerts: number
  open_incidents: number
  last_alert_at: string | null
  updated_at: string | null
  confidence_score?: number | null
  last_enriched_at?: string | null
}

export interface AssetDetail extends AssetListItem {
  id: number
  os: string | null
  tags: string[]
  notes: string | null
  created_at: string | null
  created_by: string | null
}

export interface AssetsResponse {
  items: AssetListItem[]
  total: number
  page: number
  limit: number
}

export interface AssetFilters {
  search?: string
  owner?: string
  criticality?: string
  min_risk?: number
  max_risk?: number
  sort_by?: 'updated_at' | 'asset_id' | 'hostname' | 'risk_score'
  sort_dir?: 'asc' | 'desc'
  page?: number
  limit?: number
}

export interface CreateAssetBody {
  asset_id: string
  hostname?: string | null
  ip_address?: string | null
  asset_type?: string | null
  os?: string | null
  owner?: string | null
  department?: string | null
  criticality?: 'low' | 'medium' | 'high' | 'critical'
  risk_score?: number | null
  tags?: string[]
  notes?: string | null
}

export interface UpdateAssetBody {
  hostname?: string | null
  ip_address?: string | null
  asset_type?: string | null
  os?: string | null
  owner?: string | null
  department?: string | null
  criticality?: 'low' | 'medium' | 'high' | 'critical'
  risk_score?: number | null
  tags?: string[]
  notes?: string | null
}

export async function getAssets(filters?: AssetFilters): Promise<AssetsResponse> {
  const params: Record<string, string | number | undefined> = {
    search: filters?.search,
    owner: filters?.owner,
    criticality: filters?.criticality,
    min_risk: filters?.min_risk,
    max_risk: filters?.max_risk,
    sort_by: filters?.sort_by,
    sort_dir: filters?.sort_dir,
    page: filters?.page ?? 1,
    limit: filters?.limit ?? 50,
  }
  const filtered = Object.fromEntries(Object.entries(params).filter(([, v]) => v !== undefined && v !== ''))
  return get<AssetsResponse>('/assets', { params: filtered })
}

export async function getAsset(assetId: string): Promise<AssetDetail> {
  return get<AssetDetail>(`/assets/${encodeURIComponent(assetId)}`)
}

export async function createAsset(body: CreateAssetBody): Promise<AssetDetail> {
  return post<AssetDetail>('/assets', body)
}

export async function updateAsset(assetId: string, body: UpdateAssetBody): Promise<AssetDetail> {
  return patch<AssetDetail>(`/assets/${encodeURIComponent(assetId)}`, body)
}

export async function enrichAsset(assetId: string): Promise<AssetDetail> {
  return post<AssetDetail>(`/assets/${encodeURIComponent(assetId)}/enrich`, {})
}
