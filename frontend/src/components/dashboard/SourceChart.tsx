import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { Card, CardHeader } from '@/components/ui/Card'

interface SourceChartProps {
  data: Array<{ name: string; count: number }>
}

export function SourceChart({ data }: SourceChartProps) {
  if (!data?.length) {
    return (
      <Card>
        <CardHeader title="Alerts by source" />
        <div className="h-64 flex items-center justify-center text-soc-muted text-sm">No data</div>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader title="Alerts by source" />
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} layout="vertical" margin={{ top: 5, right: 30, left: 80, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--soc-chart-grid)" />
            <XAxis type="number" stroke="var(--soc-muted)" fontSize={11} tick={{ fill: 'var(--soc-muted)' }} />
            <YAxis type="category" dataKey="name" stroke="var(--soc-muted)" fontSize={11} tick={{ fill: 'var(--soc-muted)' }} width={70} />
            <Tooltip
              contentStyle={{
                backgroundColor: 'var(--soc-tooltip-bg)',
                border: '1px solid var(--soc-tooltip-border)',
                borderRadius: '8px',
                color: 'var(--soc-tooltip-text)',
                boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
              }}
              labelStyle={{ color: 'var(--soc-tooltip-text)' }}
            />
            <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Card>
  )
}
