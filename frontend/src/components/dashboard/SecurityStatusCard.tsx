import { Card, CardHeader } from '@/components/ui/Card'
import { useSecurityStatus } from '@/hooks/useDashboard'
import { Shield, Loader2 } from 'lucide-react'

interface SecurityStatusResponse {
  dependency_audit: { status: string; python_vulnerabilities: number; npm_vulnerabilities: number }
  sast_scan: { status: string; high_findings: number; medium_findings: number }
  docker_scan: { status: string }
  secrets_scan: { status: string; secrets_found: number }
  dependency_age: { status: string; outdated_packages: number }
}

function StatusDot({ status }: { status: string }) {
  const color =
    status === 'clean'
      ? 'bg-emerald-500'
      : status === 'warning'
        ? 'bg-amber-500'
        : 'bg-red-500'
  return (
    <span
      className={`inline-block w-2.5 h-2.5 rounded-full ${color}`}
      title={status}
      aria-hidden
    />
  )
}

function Row({
  label,
  status,
  detail,
}: {
  label: string
  status: string
  detail?: string
}) {
  return (
    <div className="flex items-center justify-between py-1.5 text-sm">
      <div className="flex items-center gap-2">
        <StatusDot status={status} />
        <span className="text-muted-foreground">{label}</span>
      </div>
      {detail != null && <span className="text-foreground tabular-nums">{detail}</span>}
    </div>
  )
}

export function SecurityStatusCard() {
  const { data, isLoading, isError } = useSecurityStatus()

  if (isLoading) {
    return (
      <Card className="flex items-center justify-center min-h-[200px]">
        <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
      </Card>
    )
  }

  if (isError || !data) {
    return (
      <Card>
        <CardHeader title="Security Status" />
        <p className="text-sm text-muted-foreground">Unable to load security status.</p>
      </Card>
    )
  }

  const d = data as SecurityStatusResponse
  return (
    <Card>
      <div className="flex items-center gap-2 mb-4">
        <Shield className="w-4 h-4 text-muted-foreground" />
        <h3 className="text-sm font-semibold text-foreground">Security Status</h3>
      </div>
      <div className="space-y-0 divide-y divide-border/50">
        <Row
          label="Dependency audit"
          status={d.dependency_audit.status}
          detail={
            d.dependency_audit.python_vulnerabilities + d.dependency_audit.npm_vulnerabilities > 0
              ? `${d.dependency_audit.python_vulnerabilities + d.dependency_audit.npm_vulnerabilities} vulns`
              : undefined
          }
        />
        <Row
          label="SAST scan"
          status={d.sast_scan.status}
          detail={
            d.sast_scan.high_findings + d.sast_scan.medium_findings > 0
              ? `${d.sast_scan.high_findings}H / ${d.sast_scan.medium_findings}M`
              : undefined
          }
        />
        <Row label="Docker scan" status={d.docker_scan.status} />
        <Row
          label="Secrets scan"
          status={d.secrets_scan.status}
          detail={
            d.secrets_scan.secrets_found > 0
              ? `${d.secrets_scan.secrets_found} found`
              : undefined
          }
        />
        <Row
          label="Dependency age"
          status={d.dependency_age.status}
          detail={
            d.dependency_age.outdated_packages > 0
              ? `${d.dependency_age.outdated_packages} outdated`
              : undefined
          }
        />
      </div>
    </Card>
  )
}
