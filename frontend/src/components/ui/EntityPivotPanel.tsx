/**
 * EntityPivotPanel — slide-out drawer showing all related alerts for an entity
 * (IP, user, asset, or hostname). Triggered by clicking on any observable.
 */
import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { X, Globe, User, Server, AlertTriangle, ExternalLink, Loader2 } from 'lucide-react'
import { getAlerts } from '@/api/alerts'
import { cn } from '@/utils/cn'
import { formatRelativeTime } from '@/utils/time'

export type EntityType = 'ip' | 'user' | 'asset' | 'indicator'

export interface PivotEntity {
  type: EntityType
  value: string
  label?: string
}

interface EntityPivotPanelProps {
  entity: PivotEntity | null
  onClose: () => void
}

const SEV_COLORS: Record<string, string> = {
  Critical: 'text-severity-critical bg-severity-critical/10 border-severity-critical/30',
  High: 'text-severity-high bg-severity-high/10 border-severity-high/30',
  Medium: 'text-severity-medium bg-severity-medium/10 border-severity-medium/30',
  Low: 'text-severity-low bg-severity-low/10 border-severity-low/30',
}

function EntityIcon({ type }: { type: EntityType }) {
  switch (type) {
    case 'ip': return <Globe className="w-4 h-4 text-primary" />
    case 'user': return <User className="w-4 h-4 text-primary" />
    case 'asset': return <Server className="w-4 h-4 text-primary" />
    default: return <AlertTriangle className="w-4 h-4 text-primary" />
  }
}

export function EntityPivotPanel({ entity, onClose }: EntityPivotPanelProps) {
  const navigate = useNavigate()

  // Build query params based on entity type
  const queryParams = entity
    ? entity.type === 'ip'
      ? { source_ip: entity.value, limit: 20 }
      : entity.type === 'user'
      ? { user_id: entity.value, limit: 20 }
      : entity.type === 'asset'
      ? { asset_id: entity.value, limit: 20 }
      : { search: entity.value, limit: 20 }
    : undefined

  const { data, isLoading } = useQuery({
    queryKey: ['entity-pivot', entity?.type, entity?.value],
    queryFn: () => getAlerts(queryParams),
    enabled: !!entity,
    staleTime: 30_000,
  })

  const alerts = data?.alerts ?? []

  // Close on Escape key
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [onClose])

  if (!entity) return null

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40 bg-black/40 backdrop-blur-sm"
        onClick={onClose}
        aria-hidden
      />

      {/* Panel */}
      <div className="fixed right-0 top-0 h-full w-full max-w-md z-50 flex flex-col bg-card border-l border-border shadow-2xl animate-slide-in-right">
        {/* Header */}
        <div className="flex items-start gap-3 p-5 border-b border-border">
          <div className="h-9 w-9 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
            <EntityIcon type={entity.type} />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-[10px] uppercase tracking-widest text-muted-foreground font-medium">
              {entity.label ?? entity.type} pivot
            </p>
            <p className="text-sm font-mono font-semibold text-foreground truncate mt-0.5">{entity.value}</p>
          </div>
          <button type="button" onClick={onClose} className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent transition-colors shrink-0">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Stats */}
        <div className="px-5 py-3 bg-muted/20 border-b border-border">
          <div className="flex items-center gap-6 text-xs text-muted-foreground">
            <span><span className="font-semibold text-foreground">{data?.total ?? 0}</span> total alerts</span>
            <span><span className="font-semibold text-severity-critical">{alerts.filter(a => a.severity === 'Critical').length}</span> critical</span>
            <span><span className="font-semibold text-severity-high">{alerts.filter(a => a.severity === 'High').length}</span> high</span>
          </div>
        </div>

        {/* Alerts list */}
        <div className="flex-1 overflow-y-auto">
          {isLoading ? (
            <div className="flex items-center justify-center py-12 text-muted-foreground">
              <Loader2 className="w-5 h-5 animate-spin mr-2" />
              <span className="text-sm">Loading related alerts…</span>
            </div>
          ) : alerts.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <AlertTriangle className="w-8 h-8 mb-3 opacity-30" />
              <p className="text-sm">No alerts found for this entity.</p>
            </div>
          ) : (
            <div className="divide-y divide-border/50">
              {alerts.map(alert => (
                <div
                  key={alert.id}
                  className="px-5 py-3 hover:bg-muted/40 transition-colors cursor-pointer"
                  onClick={() => { navigate(`/app/alerts/${alert.id}`); onClose() }}
                  role="button"
                  tabIndex={0}
                  onKeyDown={e => e.key === 'Enter' && (navigate(`/app/alerts/${alert.id}`), onClose())}
                >
                  <div className="flex items-start gap-2">
                    <span className={cn('inline-flex items-center px-1.5 py-0.5 rounded border text-[9px] font-semibold uppercase shrink-0 mt-0.5',
                      SEV_COLORS[alert.severity] || '')}>
                      {alert.severity}
                    </span>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium text-foreground truncate">{alert.title}</p>
                      <div className="flex items-center gap-2 mt-0.5 text-[10px] text-muted-foreground">
                        <span>{alert.source}</span>
                        <span>·</span>
                        <span>{formatRelativeTime(alert.created_at)}</span>
                        {alert.status !== 'open' && (
                          <>
                            <span>·</span>
                            <span className="capitalize">{alert.status.replace(/_/g, ' ')}</span>
                          </>
                        )}
                      </div>
                    </div>
                    <ExternalLink className="w-3 h-3 text-muted-foreground/50 shrink-0 mt-1" />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-border">
          <button
            type="button"
            onClick={() => {
              const param = entity.type === 'ip' ? `source_ip=${entity.value}` : `search=${entity.value}`
              navigate(`/app/alerts?${param}`)
              onClose()
            }}
            className="w-full text-xs text-primary hover:underline text-center"
          >
            View all alerts for this entity →
          </button>
        </div>
      </div>
    </>
  )
}
