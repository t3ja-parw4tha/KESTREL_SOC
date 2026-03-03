import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts'

const SEVERITY_COLORS: Record<string, string> = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#3b82f6',
  Info: '#6b7280',
}

interface SeverityChartProps {
  data: Array<{ name: string; value: number }>
}

export function SeverityChart({ data }: SeverityChartProps) {
  const filtered = data.filter((d) => d.value > 0)

  return (
    <div className="rounded-lg border border-soc-border bg-soc-surface p-4 h-full">
      <h3 className="text-sm font-semibold text-soc-muted mb-2">
        Alerts by Severity
      </h3>
      {filtered.length === 0 ? (
        <div className="h-[280px] flex items-center justify-center text-soc-muted text-sm">
          No alert data yet
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={280}>
          <PieChart margin={{ top: 0, right: 0, bottom: 0, left: 0 }}>
            <Pie
              data={filtered}
              cx="50%"
              cy="50%"
              innerRadius={75}
              outerRadius={110}
              paddingAngle={3}
              dataKey="value"
              startAngle={90}
              endAngle={-270}
            >
              {filtered.map((entry, index) => (
                <Cell
                  key={`cell-${index}`}
                  fill={SEVERITY_COLORS[entry.name] ?? '#6b7280'}
                  stroke="transparent"
                />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: '#1a1d27',
                border: '1px solid #2a2d3a',
                borderRadius: '8px',
                color: '#e2e8f0',
                fontSize: '12px',
              }}
              formatter={(value: number, name: string) => [value, name]}
            />
            <Legend
              verticalAlign="bottom"
              height={36}
              formatter={(value) => (
                <span style={{ color: '#e2e8f0', fontSize: '12px' }}>
                  {value}
                </span>
              )}
            />
          </PieChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}
