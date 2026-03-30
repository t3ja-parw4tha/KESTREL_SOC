import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { HardDrive, Pencil, Plus, Search, Zap } from 'lucide-react'
import { createAsset, enrichAsset, getAssets, type AssetListItem, updateAsset } from '@/api/assets'
import { cn } from '@/utils/cn'
import { useAuth } from '@/security/AuthContext'

type Criticality = 'low' | 'medium' | 'high' | 'critical'

interface AssetFormState {
  asset_id: string
  hostname: string
  ip_address: string
  asset_type: string
  os: string
  owner: string
  department: string
  criticality: Criticality
  risk_score: string
  tags: string
  notes: string
}

const defaultForm: AssetFormState = {
  asset_id: '',
  hostname: '',
  ip_address: '',
  asset_type: '',
  os: '',
  owner: '',
  department: '',
  criticality: 'medium',
  risk_score: '',
  tags: '',
  notes: '',
}

const criticalityBadge: Record<Criticality, string> = {
  low: 'bg-green-500/15 text-green-400 border-green-500/30',
  medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
}

function toFormState(item: AssetListItem): AssetFormState {
  return {
    asset_id: item.asset_id,
    hostname: item.hostname ?? '',
    ip_address: item.ip_address ?? '',
    asset_type: item.asset_type ?? '',
    os: '',
    owner: item.owner ?? '',
    department: item.department ?? '',
    criticality: item.criticality,
    risk_score: item.risk_score != null ? String(item.risk_score) : '',
    tags: '',
    notes: '',
  }
}

export function Assets() {
  const queryClient = useQueryClient()
  const { user } = useAuth()
  const isViewer = user?.role === 'viewer'

  const [search, setSearch] = useState('')
  const [criticality, setCriticality] = useState<'all' | Criticality>('all')
  const [formOpen, setFormOpen] = useState(false)
  const [editingAssetId, setEditingAssetId] = useState<string | null>(null)
  const [formError, setFormError] = useState('')
  const [form, setForm] = useState<AssetFormState>(defaultForm)

  const { data, isLoading, isError } = useQuery({
    queryKey: ['assets', search, criticality],
    queryFn: () =>
      getAssets({
        search: search || undefined,
        criticality: criticality === 'all' ? undefined : criticality,
        sort_by: 'risk_score',
        sort_dir: 'desc',
      }),
  })

  const createMutation = useMutation({
    mutationFn: createAsset,
    onSuccess: async () => {
      setFormOpen(false)
      setEditingAssetId(null)
      setForm(defaultForm)
      await queryClient.invalidateQueries({ queryKey: ['assets'] })
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ assetId, payload }: { assetId: string; payload: Parameters<typeof updateAsset>[1] }) =>
      updateAsset(assetId, payload),
    onSuccess: async () => {
      setFormOpen(false)
      setEditingAssetId(null)
      setForm(defaultForm)
      await queryClient.invalidateQueries({ queryKey: ['assets'] })
    },
  })

  const enrichMutation = useMutation({
    mutationFn: (aid: string) => enrichAsset(aid),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['assets'] }),
  })

  const assets = data?.items ?? []
  const topRisk = useMemo(() => assets.reduce((max, a) => Math.max(max, a.risk_score ?? 0), 0), [assets])

  const openCreate = () => {
    setEditingAssetId(null)
    setForm(defaultForm)
    setFormError('')
    setFormOpen(true)
  }

  const openEdit = (item: AssetListItem) => {
    setEditingAssetId(item.asset_id)
    setForm(toFormState(item))
    setFormError('')
    setFormOpen(true)
  }

  const closeModal = () => {
    setFormOpen(false)
    setEditingAssetId(null)
    setFormError('')
    setForm(defaultForm)
  }

  const onSubmit = async () => {
    setFormError('')
    if (!editingAssetId && !form.asset_id.trim()) {
      setFormError('Asset ID is required.')
      return
    }

    const parsedRisk = form.risk_score.trim() === '' ? null : Number(form.risk_score)
    if (parsedRisk != null && (Number.isNaN(parsedRisk) || parsedRisk < 0 || parsedRisk > 100)) {
      setFormError('Risk score must be between 0 and 100.')
      return
    }

    const payload = {
      asset_id: form.asset_id.trim(),
      hostname: form.hostname.trim() || null,
      ip_address: form.ip_address.trim() || null,
      asset_type: form.asset_type.trim() || null,
      os: form.os.trim() || null,
      owner: form.owner.trim() || null,
      department: form.department.trim() || null,
      criticality: form.criticality,
      risk_score: parsedRisk,
      tags: form.tags
        .split(',')
        .map((t) => t.trim())
        .filter((t) => t.length > 0),
      notes: form.notes.trim() || null,
    }

    try {
      if (editingAssetId) {
        const { asset_id: _, ...updatePayload } = payload
        await updateMutation.mutateAsync({ assetId: editingAssetId, payload: updatePayload })
      } else {
        await createMutation.mutateAsync(payload)
      }
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Could not save asset.')
    }
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="space-y-1">
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <HardDrive className="h-6 w-6 text-blue-400" /> Asset Inventory
          </h1>
          <p className="text-sm text-muted-foreground">
            CMDB-first triage context with owner, criticality, and active security workload.
          </p>
        </div>
        {!isViewer && (
          <button
            type="button"
            onClick={openCreate}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg gradient-primary text-white text-sm font-semibold hover:opacity-90"
          >
            <Plus className="w-4 h-4" /> Add Asset
          </button>
        )}
      </div>

      <div className="glass-card border border-border/50 rounded-xl p-4 space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <label className="relative md:col-span-2">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by asset id, hostname, IP, owner"
              className="w-full pl-9 pr-3 py-2 rounded-lg border border-border bg-background text-sm"
            />
          </label>
          <select
            value={criticality}
            onChange={(e) => setCriticality(e.target.value as 'all' | Criticality)}
            className="px-3 py-2 rounded-lg border border-border bg-background text-sm"
          >
            <option value="all">All criticality</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <div className="flex items-center gap-4 text-xs text-muted-foreground">
          <span>Total Assets: {data?.total ?? 0}</span>
          <span>Highest Risk Score: {topRisk.toFixed(1)}</span>
        </div>
      </div>

      {isLoading && <div className="text-sm text-muted-foreground">Loading assets...</div>}
      {isError && (
        <div className="text-sm text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2">
          Could not load asset inventory.
        </div>
      )}

      {!isLoading && !isError && (
        <div className="glass-card rounded-xl border border-border/50 overflow-hidden">
          <div className="overflow-auto">
            <table className="w-full text-sm min-w-[1100px]">
              <thead className="bg-muted/30 text-muted-foreground text-xs uppercase tracking-wider">
                <tr>
                  <th className="text-left px-4 py-3 font-semibold">Asset</th>
                  <th className="text-left px-4 py-3 font-semibold">Owner</th>
                  <th className="text-left px-4 py-3 font-semibold">Criticality</th>
                  <th className="text-left px-4 py-3 font-semibold">Risk</th>
                  <th className="text-left px-4 py-3 font-semibold">Confidence</th>
                  <th className="text-left px-4 py-3 font-semibold">Open Alerts</th>
                  <th className="text-left px-4 py-3 font-semibold">Open Incidents</th>
                  <th className="text-left px-4 py-3 font-semibold">Last Alert</th>
                  {!isViewer && <th className="text-right px-4 py-3 font-semibold">Actions</th>}
                </tr>
              </thead>
              <tbody>
                {assets.map((a) => (
                  <tr key={a.asset_id} className="border-t border-border/40 hover:bg-muted/20 transition-colors">
                    <td className="px-4 py-3">
                      <div className="font-mono text-xs text-foreground">{a.asset_id}</div>
                      <div className="text-xs text-muted-foreground">{a.hostname || a.ip_address || 'Unresolved host'}</div>
                    </td>
                    <td className="px-4 py-3 text-xs">{a.owner || 'Unassigned'}</td>
                    <td className="px-4 py-3">
                      <span className={cn('inline-flex items-center px-2 py-0.5 rounded-full border text-[11px] font-semibold uppercase', criticalityBadge[a.criticality])}>
                        {a.criticality}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-semibold">{a.risk_score != null ? a.risk_score.toFixed(1) : '-'}</td>
                    <td className="px-4 py-3">
                      {a.confidence_score != null ? (
                        <div>
                          <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-blue-500/30 bg-blue-500/10 text-blue-400 text-[10px] font-semibold">
                            Confidence: {Math.round(a.confidence_score * 100)}%
                          </span>
                          {a.last_enriched_at && (
                            <div className="text-[9px] text-muted-foreground mt-0.5">
                              {new Date(a.last_enriched_at).toLocaleString()}
                            </div>
                          )}
                        </div>
                      ) : (
                        <span className="text-[10px] text-muted-foreground">Not enriched</span>
                      )}
                    </td>
                    <td className="px-4 py-3">{a.open_alerts}</td>
                    <td className="px-4 py-3">{a.open_incidents}</td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">
                      {a.last_alert_at ? new Date(a.last_alert_at).toLocaleString() : 'No active alerts'}
                    </td>
                    {!isViewer && (
                      <td className="px-4 py-3 text-right">
                        <div className="inline-flex items-center gap-1">
                          <button
                            type="button"
                            onClick={() => enrichMutation.mutate(a.asset_id)}
                            disabled={enrichMutation.isPending}
                            className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs border border-blue-500/40 text-blue-400 hover:bg-blue-500/10 disabled:opacity-40"
                            title="Re-enrich asset from telemetry"
                          >
                            <Zap className="w-3 h-3" /> Enrich
                          </button>
                          <button
                            type="button"
                            onClick={() => openEdit(a)}
                            className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs border border-border hover:bg-muted/40"
                          >
                            <Pencil className="w-3 h-3" /> Edit
                          </button>
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
                {assets.length === 0 && (
                  <tr>
                    <td
                      colSpan={isViewer ? 8 : 9}
                      className="px-4 py-8 text-center text-sm text-muted-foreground"
                    >
                      No assets found. Start by registering your critical servers and endpoints.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {formOpen && (
        <div className="fixed inset-0 z-50 bg-black/55 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-2xl rounded-xl border border-border bg-background shadow-2xl p-4 space-y-3">
            <h2 className="text-lg font-semibold">{editingAssetId ? `Edit Asset ${editingAssetId}` : 'Add Asset'}</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <input
                value={form.asset_id}
                onChange={(e) => setForm((s) => ({ ...s, asset_id: e.target.value }))}
                disabled={!!editingAssetId}
                placeholder="Asset ID (required)"
                className="px-3 py-2 rounded-lg border border-border bg-background text-sm disabled:opacity-60"
              />
              <input
                value={form.hostname}
                onChange={(e) => setForm((s) => ({ ...s, hostname: e.target.value }))}
                placeholder="Hostname"
                className="px-3 py-2 rounded-lg border border-border bg-background text-sm"
              />
              <input
                value={form.ip_address}
                onChange={(e) => setForm((s) => ({ ...s, ip_address: e.target.value }))}
                placeholder="IP address"
                className="px-3 py-2 rounded-lg border border-border bg-background text-sm"
              />
              <input
                value={form.owner}
                onChange={(e) => setForm((s) => ({ ...s, owner: e.target.value }))}
                placeholder="Owner"
                className="px-3 py-2 rounded-lg border border-border bg-background text-sm"
              />
              <input
                value={form.asset_type}
                onChange={(e) => setForm((s) => ({ ...s, asset_type: e.target.value }))}
                placeholder="Asset type (server/workstation/cloud)"
                className="px-3 py-2 rounded-lg border border-border bg-background text-sm"
              />
              <input
                value={form.os}
                onChange={(e) => setForm((s) => ({ ...s, os: e.target.value }))}
                placeholder="Operating system"
                className="px-3 py-2 rounded-lg border border-border bg-background text-sm"
              />
              <input
                value={form.department}
                onChange={(e) => setForm((s) => ({ ...s, department: e.target.value }))}
                placeholder="Department"
                className="px-3 py-2 rounded-lg border border-border bg-background text-sm"
              />
              <select
                value={form.criticality}
                onChange={(e) => setForm((s) => ({ ...s, criticality: e.target.value as Criticality }))}
                className="px-3 py-2 rounded-lg border border-border bg-background text-sm"
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <input
                value={form.risk_score}
                onChange={(e) => setForm((s) => ({ ...s, risk_score: e.target.value }))}
                placeholder="Risk score (0-100)"
                className="px-3 py-2 rounded-lg border border-border bg-background text-sm"
              />
              <input
                value={form.tags}
                onChange={(e) => setForm((s) => ({ ...s, tags: e.target.value }))}
                placeholder="Tags (comma-separated)"
                className="px-3 py-2 rounded-lg border border-border bg-background text-sm"
              />
              <textarea
                value={form.notes}
                onChange={(e) => setForm((s) => ({ ...s, notes: e.target.value }))}
                placeholder="SOC notes"
                rows={3}
                className="md:col-span-2 px-3 py-2 rounded-lg border border-border bg-background text-sm"
              />
            </div>
            {formError && (
              <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2">
                {formError}
              </div>
            )}
            <div className="flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={closeModal}
                className="px-3 py-2 rounded-lg border border-border text-sm hover:bg-muted/40"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={onSubmit}
                disabled={createMutation.isPending || updateMutation.isPending}
                className="px-3 py-2 rounded-lg gradient-primary text-white text-sm font-semibold hover:opacity-90 disabled:opacity-40"
              >
                {createMutation.isPending || updateMutation.isPending ? 'Saving...' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
