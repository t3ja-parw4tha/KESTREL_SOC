import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'
import { useNavigate } from 'react-router-dom'
import type { DashboardStats } from '@/api/dashboard'

const SEVERITY_COLORS: Record<string, string> = {
  Critical: 'hsl(0, 84%, 60%)',
  High:     'hsl(25, 95%, 53%)',
  Medium:   'hsl(45, 93%, 47%)',
  Low:      'hsl(217, 91%, 60%)',
}

interface SeverityDonutProps {
  stats?: DashboardStats
}

export function SeverityDonut({ stats }: SeverityDonutProps) {
  const navigate = useNavigate()

  const data = stats?.alerts_by_severity
    ? Object.entries(stats.alerts_by_severity)
        .filter(([, v]) => v > 0)
        .map(([name, value]) => ({ name, value, color: SEVERITY_COLORS[name] ?? 'hsl(215,16%,47%)' }))
    : []

  const total = data.reduce((s, d) => s + d.value, 0)

  return (
    <div className="glass-card p-5 animate-fade-in" style={{ animationDelay: '100ms' }}>
      <div className="mb-2">
        <h3 className="text-sm font-semibold">Alerts by Severity</h3>
        <p className="text-[10px] text-muted-foreground mt-0.5">Current distribution</p>
      </div>

      <div className="flex flex-col items-center">
        <div className="relative w-[220px] h-[220px]">
          {total > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data}
                  cx="50%"
                  cy="50%"
                  innerRadius={70}
                  outerRadius={100}
                  paddingAngle={4}
                  dataKey="value"
                  startAngle={90}
                  endAngle={-270}
                  stroke="none"
                  style={{ cursor: 'pointer' }}
                  animationBegin={200}
                  animationDuration={800}
                  onClick={(entry) =>
                    navigate(`/app/alerts?severity=${encodeURIComponent((entry as { name: string }).name)}`)
                  }
                >
                  {data.map((entry, i) => (
                    <Cell
                      key={i}
                      fill={entry.color}
                      style={{ filter: 'drop-shadow(0 2px 4px rgba(0,0,0,0.2))' }}
                    />
                  ))}
                </Pie>
                <Tooltip
                  content={({ active, payload }) => {
                    if (!active || !payload?.[0]) return null
                    const d = payload[0].payload as { name: string; value: number; color: string }
                    return (
                      <div className="glass-card-elevated px-3 py-2 text-xs font-medium">
                        <span style={{ color: d.color }}>{d.name}</span>:{' '}
                        {d.value} ({((d.value / total) * 100).toFixed(0)}%)
                      </div>
                    )
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-full w-full rounded-full border border-border/40 bg-muted/20 flex items-center justify-center text-[10px] text-muted-foreground px-6 text-center">
              No severity metrics available
            </div>
          )}
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
            <span className="text-3xl font-bold tabular-nums">{total}</span>
            <span className="text-[10px] text-muted-foreground uppercase tracking-widest">Total</span>
          </div>
        </div>

        <div className="flex gap-5 mt-4 flex-wrap justify-center">
          {data.map((d) => (
            <div
              key={d.name}
              className="flex items-center gap-1.5 text-[10px] group cursor-pointer"
              onClick={() => navigate(`/app/alerts?severity=${encodeURIComponent(d.name)}`)}
            >
              <div
                className="h-2.5 w-2.5 rounded-full transition-transform group-hover:scale-125"
                style={{ backgroundColor: d.color }}
              />
              <span className="text-muted-foreground group-hover:text-foreground transition-colors">
                {d.name}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
