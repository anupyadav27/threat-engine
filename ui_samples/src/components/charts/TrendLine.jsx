'use client';

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer
} from 'recharts';

/**
 * TrendLine Component
 * Displays trend data as line chart with multiple data series support
 *
 * @param {Object} props
 * @param {Array<Object>} props.data - Array of data points { date, ...dataKeys }
 * @param {Array<string>} props.dataKeys - Array of data series keys to display
 * @param {string} [props.title] - Optional chart title
 * @param {Array<string>} [props.colors] - Optional array of hex colors for lines
 * @returns {JSX.Element}
 */
export default function TrendLine({
  data = [],
  dataKeys = [],
  title,
  colors = ['#3b82f6', '#10b981', '#f97316', '#ef4444']
}) {
  return (
    <div style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }} className="rounded-xl p-4 border transition-colors duration-200">
      {title && (
        <h3 style={{ color: 'var(--text-primary)' }} className="text-sm font-semibold mb-4">{title}</h3>
      )}
      <ResponsiveContainer width="100%" height={300}>
        <LineChart
          data={data}
          margin={{ top: 5, right: 30, left: 0, bottom: 5 }}
        >
          <CartesianGrid
            strokeDasharray="3 3"
            stroke="var(--border-primary)"
            verticalPoints={[]}
          />
          <XAxis
            dataKey="date"
            stroke="var(--border-secondary)"
            style={{ fontSize: '12px' }}
            tick={{ fill: 'var(--text-tertiary)' }}
          />
          <YAxis
            stroke="var(--border-secondary)"
            style={{ fontSize: '12px' }}
            tick={{ fill: 'var(--text-tertiary)' }}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: 'var(--bg-card)',
              borderColor: 'var(--border-primary)',
              borderRadius: '0.5rem',
              boxShadow: '0 4px 6px rgba(0, 0, 0, 0.3)',
              color: 'var(--text-primary)'
            }}
            labelStyle={{ color: 'var(--text-tertiary)' }}
            cursor={{ stroke: 'rgba(59, 130, 246, 0.3)', strokeWidth: 2 }}
            contentFormatter={(value) => value.toLocaleString()}
          />
          {dataKeys.map((key, index) => (
            <Line
              key={key}
              type="monotone"
              dataKey={key}
              stroke={colors[index % colors.length]}
              strokeWidth={2}
              dot={{ fill: colors[index % colors.length], r: 4 }}
              activeDot={{ r: 6 }}
              isAnimationActive={true}
            />
          ))}
          {dataKeys.length > 0 && (
            <Legend
              wrapperStyle={{ paddingTop: '20px' }}
              contentStyle={{
                color: 'var(--text-tertiary)',
                fontSize: '12px'
              }}
            />
          )}
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
