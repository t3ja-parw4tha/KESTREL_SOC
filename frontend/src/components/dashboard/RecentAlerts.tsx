import { useNavigate } from 'react-router-dom'
import { Card, CardHeader } from '@/components/ui/Card'
import { AlertBadge } from '@/components/alerts/AlertBadge'
import { formatRelativeTime } from '@/utils/time'
import type { Alert } from '@/types/alert'
import { Table, TableHead, TableBody, TableRow, TableHeader, TableCell } from '@/components/ui/Table'
import { Spinner } from '@/components/ui/Spinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { cn } from '@/utils/cn'

interface RecentAlertsProps {
  alerts: Alert[]
  loading?: boolean
}

export function RecentAlerts({ alerts, loading }: RecentAlertsProps) {
  const navigate = useNavigate()

  const riskClass = (riskScore: number | null | undefined) => {
    if (riskScore == null) return 'text-soc-muted'
    if (riskScore >= 70) return 'text-red-400'
    if (riskScore >= 40) return 'text-amber-400'
    return 'text-emerald-400'
  }

  const riskDotClass = (riskScore: number | null | undefined) => {
    if (riskScore == null) return 'bg-soc-muted'
    if (riskScore >= 70) return 'bg-red-500'
    if (riskScore >= 40) return 'bg-amber-500'
    return 'bg-emerald-500'
  }

  const formatStatus = (status: Alert['status']) => {
    return status.replace(/_/g, ' ')
  }

  return (
    <Card>
      <CardHeader title="Recent alerts (last 10)" action={<a href="/app/alerts" className="text-sm text-blue-400 hover:underline">View all</a>} />
      {loading && (
        <div className="flex justify-center py-8">
          <Spinner size="lg" />
        </div>
      )}
      {!loading && !alerts?.length && <EmptyState title="No recent alerts" />}
      {!loading && alerts?.length > 0 && (
        <Table>
          <TableHead>
            <TableRow>
              <TableHeader>Title</TableHeader>
              <TableHeader>Severity</TableHeader>
              <TableHeader>Source</TableHeader>
              <TableHeader>Status</TableHeader>
              <TableHeader>Risk Score</TableHeader>
              <TableHeader>Time</TableHeader>
            </TableRow>
          </TableHead>
          <TableBody>
            {alerts.slice(0, 10).map((alert) => (
              <TableRow
                key={alert.id}
                onClick={() => navigate(`/app/alerts/${alert.id}`)}
                className="border-b border-soc-border hover:bg-soc-border/20 cursor-pointer transition-colors"
              >
                <TableCell className="font-medium max-w-[260px] truncate" title={alert.title}>
                  {alert.title}
                </TableCell>
                <TableCell>
                  <AlertBadge severity={alert.severity} />
                </TableCell>
                <TableCell className="text-soc-muted">{alert.source}</TableCell>
                <TableCell className="text-soc-muted capitalize">{formatStatus(alert.status)}</TableCell>
                <TableCell className={riskClass(alert.risk_score)}>
                  <span className="inline-flex items-center gap-2">
                    <span className={cn('w-2 h-2 rounded-full shrink-0', riskDotClass(alert.risk_score))} aria-hidden />
                    {alert.risk_score == null ? '—' : alert.risk_score}
                  </span>
                </TableCell>
                <TableCell className="text-soc-muted">{formatRelativeTime(alert.created_at)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </Card>
  )
}
