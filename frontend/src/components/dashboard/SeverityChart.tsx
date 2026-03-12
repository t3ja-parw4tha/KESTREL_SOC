import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import { useNavigate } from 'react-router-dom'

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
  const navigate = useNavigate()
  const filtered = data.filter((d) => d.value > 0)
  const total = filtered.reduce((s, d) => s + d.value, 0)

  return (
    <div className="rounded-2xl border border-soc-border bg-soc-surface p-5 h-full" style={{ boxShadow: 'var(--shadow-card)' }}>
      <div className="flex items-center justify-between mb-1">
        <h3 className="text-sm font-semibold text-soc-text">Alerts by Severity</h3>
        <span className="text-xs text-soc-muted">Click to filter</span>
      </div>
      {filtered.length === 0 ? (
        <div className="h-[280px] flex items-center justify-center text-soc-muted text-sm">
          No alert data yet
        </div>
      ) : (
        <div className="relative" style={{ height: 280 }}>
          <ResponsiveContainer width="100%" height="100%">
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
                style={{ cursor: 'pointer' }}
                onClick={(entry) => navigate(`/app/alerts?severity=${encodeURIComponent(entry.name)}`)}
              >
                {filtered.map((entry, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={SEVERITY_COLORS[entry.name] ?? '#6b7280'}
                    stroke="transparent"
                    style={{ cursor: 'pointer' }}
                  />
                ))}
              </Pie>
              <Tooltip
              contentStyle={{
                backgroundColor: 'var(--soc-tooltip-bg)',
                border: '1px solid var(--soc-tooltip-border)',
                borderRadius: '8px',
                color: 'var(--soc-tooltip-text)',
                fontSize: '12px',
                boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
              }}
              formatter={(value: number, name: string) => [value, name]}
            />
            <Legend
              verticalAlign="bottom"
              height={36}
              formatter={(value) => (
                <span style={{ color: 'var(--soc-text)', fontSize: '12px' }}>
                  {value}
                </span>
              )}
            />
          </PieChart>
        </ResponsiveContainer>
          <div
            className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none"
            style={{ marginTop: -36 }}
          >
            <span className="text-2xl font-bold text-soc-text">{total}</span>
            <span className="text-xs text-soc-muted">Total</span>
          </div>
        </div>
      )}
    </div>
  )
}
