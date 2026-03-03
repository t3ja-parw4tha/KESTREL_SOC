import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import { formatDateTime } from '@/utils/time'

interface VolumeChartProps {
  data: Array<{ time?: string; date?: string; count: number }>
}

export function VolumeChart({ data }: VolumeChartProps) {
  if (!data?.length) {
    return (
      <div className="rounded-lg border border-soc-border bg-soc-surface p-4 h-full">
        <h3 className="text-sm font-semibold text-soc-muted mb-2">
          Alert Volume (7 days)
        </h3>
        <div className="h-[280px] flex items-center justify-center text-soc-muted text-sm">No data</div>
      </div>
    )
  }

  const chartData = data.map((d) => ({
    ...d,
    label: (d.time ?? d.date) ? formatDateTime(d.time ?? d.date!) : '',
  }))

  return (
    <div className="rounded-lg border border-soc-border bg-soc-surface p-4 h-full">
      <h3 className="text-sm font-semibold text-soc-muted mb-2">
        Alert Volume (7 days)
      </h3>
      <ResponsiveContainer width="100%" height={280}>
        <LineChart data={chartData} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#2a2d3a" />
          <XAxis dataKey="label" stroke="#64748b" fontSize={11} tick={{ fill: '#64748b' }} />
          <YAxis stroke="#64748b" fontSize={11} tick={{ fill: '#64748b' }} />
          <Tooltip
            contentStyle={{ backgroundColor: '#1a1d27', border: '1px solid #2a2d3a', borderRadius: '8px' }}
            labelStyle={{ color: '#e2e8f0' }}
          />
          <Line type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={2} dot={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}
