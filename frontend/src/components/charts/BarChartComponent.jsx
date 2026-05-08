'use client';

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer
} from 'recharts';

/**
 * BarChartComponent
 * Displays data as vertical or horizontal bar chart
 *
 * @param {Object} props
 * @param {Array<{name: string, value: number}>} props.data - Array of data points
 * @param {string} [props.color] - Hex color for bars, defaults to #3b82f6
 * @param {string} [props.title] - Optional chart title
 * @param {boolean} [props.horizontal] - If true, renders horizontal bar chart
 * @returns {JSX.Element}
 */
export default function BarChartComponent({
  data = [],
  color = '#3b82f6',
  title,
  horizontal = false
}) {
  if (!data || data.length === 0) {
    return (
      <div style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }} className="rounded-xl p-4 border h-80 flex items-center justify-center transition-colors duration-200">
        <p style={{ color: 'var(--text-tertiary)' }} className="text-sm">No data available</p>
      </div>
    );
  }

  return (
    <div style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }} className="rounded-xl p-4 border transition-colors duration-200">
      {title && (
        <h3 style={{ color: 'var(--text-primary)' }} className="text-sm font-semibold mb-4">{title}</h3>
      )}
      <ResponsiveContainer width="100%" height={300}>
        {horizontal ? (
          <BarChart
            data={data}
            layout="vertical"
            margin={{ top: 5, right: 30, left: 120, bottom: 5 }}
          >
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="var(--border-primary)"
              horizontalPoints={[]}
            />
            <XAxis
              type="number"
              stroke="var(--border-secondary)"
              style={{ fontSize: '12px' }}
              tick={{ fill: 'var(--text-tertiary)' }}
            />
            <YAxis
              type="category"
              dataKey="name"
              stroke="var(--border-secondary)"
              style={{ fontSize: '12px' }}
              tick={{ fill: 'var(--text-tertiary)' }}
              width={110}
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
              cursor={{ fill: 'rgba(59, 130, 246, 0.1)' }}
            />
            <Bar
              dataKey="value"
              fill={color}
              radius={[0, 4, 4, 0]}
              isAnimationActive={true}
            />
          </BarChart>
        ) : (
          <BarChart
            data={data}
            layout="horizontal"
            margin={{ top: 5, right: 30, left: 0, bottom: 5 }}
          >
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="var(--border-primary)"
              verticalPoints={[]}
            />
            <XAxis
              type="category"
              dataKey="name"
              stroke="var(--border-secondary)"
              style={{ fontSize: '12px' }}
              tick={{ fill: 'var(--text-tertiary)' }}
            />
            <YAxis
              type="number"
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
              cursor={{ fill: 'rgba(59, 130, 246, 0.1)' }}
            />
            <Bar
              dataKey="value"
              fill={color}
              radius={[4, 4, 0, 0]}
              isAnimationActive={true}
            />
          </BarChart>
        )}
      </ResponsiveContainer>
    </div>
  );
}
