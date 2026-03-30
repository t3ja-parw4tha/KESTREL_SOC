import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts'

interface VolumeDataPoint {
  date: string
  count: number
  critical?: number
  high?: number
  medium?: number
  low?: number
}

interface VolumeChartProps {
  data: VolumeDataPoint[]
}

const TOOLTIP_STYLE = {
  backgroundColor: 'hsl(222, 47%, 8%)',
  border: '1px solid hsl(217, 33%, 20%)',
  borderRadius: '10px',
  fontSize: '11px',
  boxShadow: '0 12px 40px rgba(0,0,0,0.3)',
  backdropFilter: 'blur(12px)',
}

export function VolumeChart({ data }: VolumeChartProps) {
  const rawData = data ?? []
  const hasData = rawData.length > 0

  if (!hasData) {
    return (
      <div className="glass-card p-5 animate-fade-in">
        <div className="mb-5">
          <h3 className="text-sm font-semibold">Alert Volume - Last 7 Days</h3>
          <p className="text-[10px] text-muted-foreground mt-0.5">No volume data available from API</p>
        </div>
        <div className="h-[280px] rounded-lg border border-border/40 bg-muted/20 flex items-center justify-center text-xs text-muted-foreground">
          Alert volume metrics are unavailable.
        </div>
      </div>
    )
  }

  // Check if we have per-severity data
  const hasBreakdown = rawData.some(
    (d) => (d.critical ?? 0) + (d.high ?? 0) + (d.medium ?? 0) + (d.low ?? 0) > 0
  )

  const chartData = rawData.map((d) => ({
    label: d.date
      ? new Date(`${d.date}T00:00:00`).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
      : d.date,
    critical: d.critical ?? 0,
    high: d.high ?? 0,
    medium: d.medium ?? 0,
    low: d.low ?? 0,
    total: d.count,
  }))

  return (
    <div className="glass-card p-5 animate-fade-in">
      <div className="mb-5">
        <h3 className="text-sm font-semibold">Alert Volume — Last 7 Days</h3>
        <p className="text-[10px] text-muted-foreground mt-0.5">
          {hasBreakdown ? 'Breakdown by severity level' : 'Daily alert count'}
        </p>
      </div>
      <div className="h-[280px]">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
            <defs>
              <linearGradient id="gradCritical" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="hsl(0, 84%, 60%)" stopOpacity={0.4} />
                <stop offset="100%" stopColor="hsl(0, 84%, 60%)" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="gradHigh" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="hsl(25, 95%, 53%)" stopOpacity={0.35} />
                <stop offset="100%" stopColor="hsl(25, 95%, 53%)" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="gradMedium" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="hsl(45, 93%, 47%)" stopOpacity={0.3} />
                <stop offset="100%" stopColor="hsl(45, 93%, 47%)" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="gradLow" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="hsl(217, 91%, 60%)" stopOpacity={0.35} />
                <stop offset="100%" stopColor="hsl(217, 91%, 60%)" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="gradTotal" x1="0" y1="0" x2="0" y2="1">
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
              allowDecimals={false}
              width={28}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              contentStyle={TOOLTIP_STYLE}
              cursor={{ stroke: 'hsl(217, 91%, 60%)', strokeWidth: 1, strokeDasharray: '4 4' }}
            />
            {hasBreakdown ? (
              <>
                <Legend
                  iconType="circle"
                  iconSize={8}
                  wrapperStyle={{ fontSize: '10px', paddingTop: '8px' }}
                />
                <Area
                  type="monotone"
                  dataKey="critical"
                  name="Critical"
                  stroke="hsl(0, 84%, 60%)"
                  fill="url(#gradCritical)"
                  strokeWidth={2}
                  dot={false}
                  activeDot={{ r: 4, strokeWidth: 2 }}
                />
                <Area
                  type="monotone"
                  dataKey="high"
                  name="High"
                  stroke="hsl(25, 95%, 53%)"
                  fill="url(#gradHigh)"
                  strokeWidth={2}
                  dot={false}
                  activeDot={{ r: 4, strokeWidth: 2 }}
                />
                <Area
                  type="monotone"
                  dataKey="medium"
                  name="Medium"
                  stroke="hsl(45, 93%, 47%)"
                  fill="url(#gradMedium)"
                  strokeWidth={1.5}
                  strokeDasharray="4 3"
                  dot={false}
                  activeDot={{ r: 3 }}
                />
                <Area
                  type="monotone"
                  dataKey="low"
                  name="Low"
                  stroke="hsl(217, 91%, 60%)"
                  fill="url(#gradLow)"
                  strokeWidth={1.5}
                  strokeDasharray="4 3"
                  dot={false}
                  activeDot={{ r: 3 }}
                />
              </>
            ) : (
              <Area
                type="monotone"
                dataKey="total"
                name="Alerts"
                stroke="hsl(217, 91%, 60%)"
                strokeWidth={2.5}
                fill="url(#gradTotal)"
                dot={false}
                activeDot={{ r: 5, fill: 'hsl(217, 91%, 60%)', strokeWidth: 2 }}
                connectNulls
              />
            )}
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
