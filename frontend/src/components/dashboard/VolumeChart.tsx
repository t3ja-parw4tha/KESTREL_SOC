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

const MOCK_DATA = [
  { label: 'Day 1', count: 12 },
  { label: 'Day 2', count: 19 },
  { label: 'Day 3', count: 8 },
  { label: 'Day 4', count: 27 },
  { label: 'Day 5', count: 15 },
  { label: 'Day 6', count: 23 },
  { label: 'Day 7', count: 11 },
]

export function VolumeChart({ data }: VolumeChartProps) {
  const chartData = data?.length
    ? data.map((d) => ({
        label: d.date
          ? new Date(`${d.date}T00:00:00`).toLocaleDateString('en-US', {
              month: 'short',
              day: 'numeric',
            })
          : (d.time ?? ''),
        count: Number(d.count) || 0,
      }))
    : MOCK_DATA

  const maxCount = Math.max(1, ...chartData.map((d) => d.count))

  return (
    <div className="glass-card p-5 animate-fade-in">
      <div className="mb-5">
        <h3 className="text-sm font-semibold">Alert Volume — Last 7 Days</h3>
        <p className="text-[10px] text-muted-foreground mt-0.5">Daily alert count</p>
      </div>
      <div className="h-[280px]">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
            <defs>
              <linearGradient id="volumeGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="hsl(217, 91%, 60%)" stopOpacity={0.35} />
                <stop offset="100%" stopColor="hsl(217, 91%, 60%)" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="hsl(217, 33%, 17%)"
              strokeOpacity={0.5}
              vertical={false}
            />
            <XAxis
              dataKey="label"
              stroke="transparent"
              tick={{ fill: 'hsl(215, 20%, 65%)', fontSize: 10 }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              stroke="transparent"
              tick={{ fill: 'hsl(215, 20%, 65%)', fontSize: 10 }}
              domain={[0, maxCount]}
              allowDecimals={false}
              width={28}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: 'hsl(222, 47%, 8%)',
                border: '1px solid hsl(217, 33%, 20%)',
                borderRadius: '10px',
                fontSize: '11px',
                boxShadow: '0 12px 40px rgba(0,0,0,0.3)',
                backdropFilter: 'blur(12px)',
              }}
              formatter={(value: number) => [value, 'Alerts']}
              cursor={{ stroke: 'hsl(217, 91%, 60%)', strokeWidth: 1, strokeDasharray: '4 4' }}
            />
            <Area
              type="monotone"
              dataKey="count"
              name="Alerts"
              stroke="hsl(217, 91%, 60%)"
              strokeWidth={2.5}
              fill="url(#volumeGrad)"
              dot={false}
              activeDot={{ r: 5, fill: 'hsl(217, 91%, 60%)', strokeWidth: 2 }}
              connectNulls
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
