import { useQuery } from '@tanstack/react-query'
import { get } from '@/api/client'
import { Card } from '@/components/ui/Card'
import { SpinnerOverlay } from '@/components/ui/Spinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'

interface Source {
  id: string
  name: string
  type: string
  enabled?: boolean
}

export function Sources() {
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['sources'],
    queryFn: () => get<{ items: Source[] }>('/sources'),
  })

  if (isError) return <ErrorState title="Failed to load sources" onRetry={() => refetch()} />
  if (isLoading) return <SpinnerOverlay />

  const items = data?.items ?? []

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold text-soc-text">Connected Sources</h1>
      {items.length === 0 ? (
        <EmptyState
          title="No sources configured"
          description="Add log sources (Sentinel, Suricata, GuardDuty, etc.) to start ingesting alerts."
        />
      ) : (
        <div className="grid gap-4">
          {items.map((source) => (
            <Card key={source.id}>
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="font-medium text-soc-text">{source.name}</h3>
                  <p className="text-sm text-soc-muted">{source.type}</p>
                </div>
                {source.enabled != null && (
                  <span className={source.enabled ? 'text-safe text-sm' : 'text-soc-muted text-sm'}>
                    {source.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                )}
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
