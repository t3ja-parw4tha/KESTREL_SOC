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
            <CartesianGrid strokeDasharray="3 3" stroke="#2a2d3a" />
            <XAxis type="number" stroke="#64748b" fontSize={11} tick={{ fill: '#64748b' }} />
            <YAxis type="category" dataKey="name" stroke="#64748b" fontSize={11} tick={{ fill: '#64748b' }} width={70} />
            <Tooltip
              contentStyle={{ backgroundColor: '#1a1d27', border: '1px solid #2a2d3a', borderRadius: '8px' }}
              labelStyle={{ color: '#e2e8f0' }}
            />
            <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Card>
  )
}
