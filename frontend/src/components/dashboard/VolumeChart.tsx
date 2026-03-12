import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'

interface VolumeChartProps {
  data: Array<{ time?: string; date?: string; count: number }>
}

const TOOLTIP_STYLE = {
  backgroundColor: 'var(--soc-tooltip-bg)',
  border: '1px solid var(--soc-tooltip-border)',
  borderRadius: '10px',
  color: 'var(--soc-tooltip-text)',
  boxShadow: '0 8px 24px rgba(0,0,0,0.2)',
  fontSize: '12px',
  padding: '8px 12px',
}

export function VolumeChart({ data }: VolumeChartProps) {
  if (!data?.length) {
    return (
      <div className="rounded-2xl border border-soc-border bg-soc-surface p-5 h-full" style={{ boxShadow: 'var(--shadow-card)' }}>
        <h3 className="text-sm font-semibold text-soc-text mb-0.5">Alert Volume</h3>
        <p className="text-xs text-soc-muted mb-3">Last 7 days</p>
        <div className="h-[260px] flex items-center justify-center text-soc-muted text-sm">No data yet</div>
      </div>
    )
  }

  const chartData = data.map((d) => ({
    ...d,
    label: d.date
      ? new Date(`${d.date}T00:00:00`).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
      : '',
    count: Number(d.count) || 0,
  }))
  const maxCount = Math.max(1, ...chartData.map((d) => d.count))

  return (
    <div className="rounded-2xl border border-soc-border bg-soc-surface p-5 h-full min-h-[320px]" style={{ boxShadow: 'var(--shadow-card)' }}>
      <h3 className="text-sm font-semibold text-soc-text mb-0.5">Alert Volume</h3>
      <p className="text-xs text-soc-muted mb-4">Last 7 days</p>
      <div className="w-full h-[260px]">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
            <defs>
              <linearGradient id="volumeGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--soc-chart-line)" stopOpacity={0.18} />
                <stop offset="90%" stopColor="var(--soc-chart-line)" stopOpacity={0.0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--soc-chart-grid)" vertical={false} />
            <XAxis
              dataKey="label"
              stroke="transparent"
              tick={{ fill: 'var(--soc-muted)', fontSize: 11 }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              stroke="transparent"
              tick={{ fill: 'var(--soc-muted)', fontSize: 11 }}
              domain={[0, maxCount]}
              allowDecimals={false}
              width={28}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              contentStyle={TOOLTIP_STYLE}
              labelStyle={{ color: 'var(--soc-tooltip-text)', fontWeight: 600, marginBottom: 2 }}
              formatter={(value: number) => [value, 'Alerts']}
              cursor={{ stroke: 'var(--soc-chart-line)', strokeWidth: 1, strokeDasharray: '4 4' }}
            />
            <Area
              type="monotone"
              dataKey="count"
              name="Alerts"
              stroke="var(--soc-chart-line)"
              strokeWidth={2.5}
              fill="url(#volumeGradient)"
              dot={false}
              activeDot={{ r: 5, fill: 'var(--soc-chart-line)', stroke: 'var(--soc-surface)', strokeWidth: 2 }}
              connectNulls
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
